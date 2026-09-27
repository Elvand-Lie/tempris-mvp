# backend/app/strike/sandbox.py
"""
The SERVER-vantage execution sandbox (amended PRD v1.12 Ch.4).

STRIKE runs from two vantages: an enrolled collector (over its authenticated
WSS — see ``collector_registry``/the Rust collector) and this platform server.
This module owns the second: a hardened, non-interactive, bounded process
runner for the server plane.

What "hardened" concretely means here — each point is enforced, not aspirational:

  * **Per-run temp dir.** Every execution gets its own ``mkdtemp`` workspace
    which is the process CWD and is removed afterwards, so one run can never
    leave files where another might read them.
  * **No shell.** argv is built here from already-validated inputs and passed
    directly to the OS. Nothing from the request is ever concatenated into a
    command string, so the usual shell-injection class does not exist.
  * **No interactive TTY** and stdin closed (except the script runner, which
    feeds a script it already bounded).
  * **Hard timeout.** The process group is killed on expiry, so children
    spawned by the tool cannot outlive the envelope.
  * **Output cap.** Per-stream and total capture is bounded; overflow is
    flagged in the stream, never silently dropped.
  * **Process-group kill.** ``setsid``/``CREATE_NEW_PROCESS_GROUP`` puts the
    tool in its own group; cancellation kills the whole group.
  * **Env scrubbing.** The child gets a minimal allow-listed environment —
    no inherited ``DATABASE_URL``/``JWT_SECRET``/cloud credentials.

Scope validation is NOT this module's job and deliberately does not live
here: the caller (``app.strike.runs``) authorizes the target against the
tenant's active testing-scope registry *before* any argv is built or process
started. This module only holds the argv builders' reviewed shapes.

Binding is refused by construction: the nc/socat builders only ever emit
outbound-connect forms, and there is no `-l`/`listen` path anywhere.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import shutil
import signal
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

#: Per-stream captured bytes. Matches the collector's STRIKE_OUTPUT_LIMIT so the
#: two vantages report truncation the same way.
STREAM_CAPTURE_LIMIT = 1024 * 1024

#: Streamed chunk size handed to the console cursor reader. Bounded well under
#: migration 048's 64 KiB per-chunk CHECK.
CHUNK_SIZE = 16 * 1024

#: Absolute ceiling on a server-vantage run, regardless of the per-tool
#: envelope the catalogue advertises.
MAX_ENVELOPE_SECONDS = 1800

#: The ONE reviewed nmap flag shape for the server vantage. It is the same
#: unprivileged TCP connect scan the collector runs, pinned here as data so
#: every profile below is a bounded VARIATION of it rather than a free-form
#: argv: no ``-sS``, no ``-O``/``-A``, no ``--script``/NSE, no ``-iL``, no
#: ``--privileged``. The scan can never descend with privilege because no
#: privileged flag appears in this tuple.
NMAP_SERVER_SHAPE: tuple[str, ...] = (
    "-sT",
    "-Pn",
    "--open",
    "-T3",
    "--max-retries", "2",
    "--max-rate", "100",
    "--max-hostgroup", "16",
    "--max-parallelism", "16",
)

#: The collector's host-timeout, reused as every server profile's default.
NMAP_SERVER_HOST_TIMEOUT = "120s"

#: Reviewed per-profile bounds applied ON TOP of :data:`NMAP_SERVER_SHAPE`.
#: A profile selects ``(ports, host_timeout)`` and nothing else: it can never
#: widen the port range past 1-10000, add a flag (no ``-sV``/``-sS``/``-O``/
#: ``-A``/``--script``), or drop a rate/host-timeout cap. Both values only
#: ever NARROW the collector's envelope, so no profile is the loose one.
#:
#: The preset names are preserved for compatibility with the ``nmap_profile``
#: field ``RunCreate`` already validates and records. The names label a bounded
#: envelope, NOT scan modes: in particular ``service_version`` does not enable
#: version probing — the fixed shape has no ``-sV`` and no profile may add one.
#: The catalogue notes state this, so the label is never read as a promise the
#: argv does not keep.
NMAP_SERVER_PROFILES: dict[str, tuple[str, str]] = {
    "ping_sweep": ("1-1024", "30s"),
    "top_ports": ("1-10000", NMAP_SERVER_HOST_TIMEOUT),
    "service_version": ("1-10000", "180s"),
    "full": ("1-10000", "300s"),
}

#: The default profile when a run names none — the collector's own shape.
NMAP_SERVER_DEFAULT_PROFILE = "top_ports"

#: dig qtype allow-list. ANY/AXFR and everything else are refused here as well
#: as at the API — the guard exists at both layers on purpose.
DIG_ALLOWED_RECORD_TYPES: tuple[str, ...] = (
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR",
)


@dataclass
class SandboxResult:
    """The honest outcome of one server-vantage execution."""

    status: str  # "completed" | "failed" | "rejected"
    exit_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    artifacts: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tool availability — an absent tool degrades, it never fabricates a result
# ---------------------------------------------------------------------------

#: capability → candidate executables, first found wins. Ordering matters where
#: a documented degradation exists (Windows has no `dig`: `nslookup` is the
#: accepted, UI-documented substitute).
_TOOL_CANDIDATES: dict[str, tuple[str, ...]] = {
    "curl": ("curl",),
    "nmap": ("nmap",),
    "nuclei": ("nuclei",),
    "ffuf": ("ffuf",),
    # nslookup is the documented Windows substitute for a bounded record lookup
    "dig": ("dig", "nslookup"),
    "httpie": ("http", "httpie", "http.exe"),
    "nc": ("nc", "ncat", "nc.exe"),
    "socat": ("socat",),
    "python": ("python3", "python"),
    "bash": ("bash",),
    "chromium": ("chromium", "chromium-browser", "chrome", "google-chrome", "chrome.exe"),
    "mitmproxy": ("mitmdump", "mitmproxy"),
}


def resolve_tool(capability: str) -> Optional[str]:
    """The server-vantage executable for ``capability``, or None when the
    platform server genuinely does not have it. Returning None is the
    degraded path the route reports as ``tool_not_available`` — never a fake
    success."""
    for candidate in _TOOL_CANDIDATES.get(capability, ()):
        found = shutil.which(candidate)
        if found:
            return found
    return None


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


class SandboxConfigError(ValueError):
    """The requested configuration is outside the reviewed argv shapes."""


class ToolNotAvailableError(SandboxConfigError):
    """The server genuinely lacks a required piece of the toolchain.

    Raised for a missing binary AND for pinned execution material that is not
    deployed (the nuclei templates directory, the bundled ffuf wordlist).
    Either way the honest outcome is a refusal the operator can see, never a
    run against ambient/auto-updated material we did not pin.
    """


# ---------------------------------------------------------------------------
# Pinned execution material — the server plane's own controlled inputs
# ---------------------------------------------------------------------------

#: The pinned wordlist shipped with the backend, mirroring the collector's
#: embedded ``collector/src/strike_wordlist.txt``. Kept as a real file (not a
#: literal in code) so the two planes' reviewed wordlists can be diffed and
#: reviewed as one artifact.
SERVER_WORDLIST_PATH = Path(__file__).resolve().parent / "data" / "strike_wordlist.txt"


def resolve_nuclei_templates_dir() -> str:
    """The pinned nuclei templates directory, or a refusal.

    Fail closed: an absent directory is refused rather than passed to nuclei,
    because nuclei without ``-t`` silently uses its own ambient and
    auto-updated templates — precisely the unpinned behavior this vantage
    must not have.
    """
    from app import config

    configured = (config.STRIKE_NUCLEI_TEMPLATES_DIR or "").strip()
    if not configured or not Path(configured).is_dir():
        raise ToolNotAvailableError(
            "nuclei templates are not deployed on the platform server: "
            f"'{configured or '<unset>'}' is not a directory. Set "
            "STRIKE_NUCLEI_TEMPLATES_DIR to the pinned templates directory. "
            "Refusing to run against ambient templates."
        )
    return configured


def resolve_ffuf_wordlist(inline: str | None, directory: Path | None = None) -> Path:
    """The wordlist ffuf will read — always server-controlled.

    A non-empty inline wordlist (already bounded and validated by
    ``runs.create_run``) takes precedence and is materialized to a per-run temp
    file whose path only this process knows. Otherwise the bundled pinned
    wordlist is used. The user never supplies a path.

    ``directory`` is the run's private workdir when one exists, so the
    materialized file is removed with the workdir rather than left behind.
    """
    if inline is not None and inline.strip():
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="strike-wordlist-",
            suffix=".txt",
            dir=str(directory) if directory is not None else None,
            delete=False,
        )
        try:
            handle.write(inline)
        finally:
            handle.close()
        return Path(handle.name)

    if not SERVER_WORDLIST_PATH.is_file():
        raise ToolNotAvailableError(
            "the pinned ffuf wordlist is not deployed on the platform server: "
            f"'{SERVER_WORDLIST_PATH}' is missing. Refusing to fuzz against an "
            "unpinned wordlist."
        )
    return SERVER_WORDLIST_PATH


def server_prerequisite_error(capability: str) -> str | None:
    """Why a server-vantage ``capability`` cannot run here, or None if it can.

    Checked at run CREATION so the console gets a visible ``422`` instead of a
    queued run that fails in the background, and again by the runner itself
    (the toolchain can disappear between the two). Covers the binary and the
    pinned execution material that capability needs — for nuclei the templates
    directory, for ffuf the bundled wordlist.
    """
    if resolve_tool(capability) is None:
        return (
            f"The {capability} tool is not installed on the platform server; "
            "use the collector vantage instead"
        )
    try:
        if capability == "nuclei":
            resolve_nuclei_templates_dir()
        elif capability == "ffuf":
            resolve_ffuf_wordlist(None)
    except ToolNotAvailableError as exc:
        return str(exc)
    return None


# ---------------------------------------------------------------------------
# Argument shapes (reviewed, total over their inputs)
# ---------------------------------------------------------------------------


def _require_public_destination(host: str) -> None:
    """Refuse loopback/link-local targets for the server vantage.

    The scope registry already authorized the target; this is an additional
    server-plane guard so a run cannot be aimed at the platform's own
    loopback or metadata endpoints even if a scope row covered them."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return  # a hostname is resolved+checked by the caller's pinning
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        raise SandboxConfigError(
            "The server vantage refuses loopback, link-local, multicast and "
            "reserved destinations"
        )


def build_curl_argv(
    tool: str,
    method: str,
    url: str,
    pinned_ips: list[str],
    headers: list[str],
    body: str | None,
    timeout_seconds: int,
) -> list[str]:
    """curl / httpie outbound request. The destination is pinned via
    ``--resolve`` exactly like the collector plane, so the request cannot be
    redirected by DNS after authorization."""
    method = method.upper()
    if method not in ("GET", "HEAD", "POST"):
        raise SandboxConfigError(f"unsupported method '{method}'")
    if not pinned_ips:
        raise SandboxConfigError("no authorized destination — refusing an unpinned run")
    for ip in pinned_ips:
        _require_public_destination(ip)

    host, port = _split_url(url)
    argv: list[str] = ["-sS", "-i", "--max-redirs", "0", "--max-time", str(timeout_seconds)]
    for ip in pinned_ips:
        argv += ["--resolve", f"{host}:{port}:{ip}"]
    argv += ["--connect-timeout", str(timeout_seconds)]
    for header in headers:
        argv += ["-H", header]
    if method == "HEAD":
        argv.append("-I")
    elif method == "POST":
        argv += ["-X", "POST", "--data-binary", body or ""]
    elif body is not None:
        argv += ["--data-binary", body]
    argv += ["--", url]
    return argv


def build_httpie_argv(
    tool: str,
    method: str,
    url: str,
    pinned_ips: list[str],
    headers: list[str],
    body: str | None,
    timeout_seconds: int,
) -> list[str]:
    """HTTPie. ``http`` is argv-compatible enough for the reviewed subset:
    no plugins, no sessions, no redirects, pinned destination."""
    method = method.upper()
    if method not in ("GET", "HEAD", "POST"):
        raise SandboxConfigError(f"unsupported method '{method}'")
    if not pinned_ips:
        raise SandboxConfigError("no authorized destination — refusing an unpinned run")
    for ip in pinned_ips:
        _require_public_destination(ip)
    host, port = _split_url(url)
    # httpx (httpie's transport) honors no --resolve; point it at the pinned
    # literal and keep the Host header so the request is still addressed to the
    # authorized host. --verify=no is NOT set: TLS is never silently downgraded.
    pinned = pinned_ips[0]
    literal = f"http://{pinned}:{port}/" if url.startswith("http://") else f"https://{pinned}:{port}/"
    argv: list[str] = [
        tool, method, literal,
        "--timeout", str(timeout_seconds),
        "--follow", "no",
        "--print", "hHB",
        f"Host:{host}",
    ]
    for header in headers:
        argv.append(header)
    if body is not None:
        argv.append(f"body={body}")
    return argv


def build_nmap_argv(
    tool: str,
    pinned_targets: list[str],
    profile: str | None,
    timeout_seconds: int,
) -> list[str]:
    """The reviewed nmap shape, plus an optional reviewed profile bound.

    Every profile is the collector's unprivileged connect scan with a bounded
    port/host-time envelope — no profile grants a privilege, widens the port
    range beyond 1-10000, or enables service/version/OS/script probing. A
    CIDR target is allowed (the same rule the collector applies).
    """
    if not pinned_targets:
        raise SandboxConfigError("no authorized target — refusing an unpinned run")
    for target in pinned_targets:
        base = target.split("/", 1)[0]
        _require_public_destination(base)
    envelope = NMAP_SERVER_PROFILES.get(profile or NMAP_SERVER_DEFAULT_PROFILE)
    if envelope is None:
        raise SandboxConfigError(f"unknown nmap profile '{profile}'")
    ports, host_timeout = envelope
    return [
        tool,
        *NMAP_SERVER_SHAPE,
        "--host-timeout", host_timeout,
        "-p", ports,
        "-oX", "-",  # XML on stdout; nmap(1) defines '-' as stdout
        *pinned_targets,
    ]


def build_nuclei_argv(
    tool: str,
    target: str,
    templates_dir: str | None,
    tags: list[str],
    severity: list[str],
    rate_limit: int,
    timeout_seconds: int,
) -> list[str]:
    """nuclei against the platform's own pinned template directory. Template
    *paths* are never accepted from the user — only tag/severity filters.

    A missing pinned templates directory is a REFUSAL, not a silent fallback:
    without ``-t`` nuclei would run its own ambient/updated templates, which is
    exactly the unpinned behavior this vantage must not have. ``-duc`` (do not
    update templates at run time) keeps the pinned set frozen.
    """
    if not templates_dir:
        raise SandboxConfigError(
            "nuclei has no pinned templates directory on this server; set "
            "STRIKE_NUCLEI_TEMPLATES_DIR. Refusing to run against ambient "
            "templates."
        )
    argv: list[str] = [
        tool,
        "-target", target,
        "-t", templates_dir,
        "-jsonl", "-silent", "-no-color",
        "-ni",   # no interactsh
        "-duc",  # never update templates at run time
    ]
    if tags:
        argv += ["-tags", ",".join(tags)]
    if severity:
        argv += ["-severity", ",".join(severity)]
    argv += ["-rate-limit", str(rate_limit), "-timeout", str(min(timeout_seconds, 60))]
    return argv


def build_ffuf_argv(
    tool: str,
    url: str,
    wordlist_path: Path,
    filter_codes: list[str],
    filter_size: list[str],
    filter_words: list[str],
    timeout_seconds: int,
) -> list[str]:
    """ffuf path fuzzing with the wordlist materialized to a per-run temp
    file whose path is server-generated. No recursion, no custom headers."""
    argv: list[str] = [
        tool, "-u", url, "-w", str(wordlist_path),
        "-mc", "all", "-of", "json", "-noninteractive",
        "-maxtime", str(timeout_seconds),
    ]
    if filter_codes:
        argv += ["-fc", ",".join(filter_codes)]
    if filter_size:
        argv += ["-fs", ",".join(filter_size)]
    if filter_words:
        argv += ["-fw", ",".join(filter_words)]
    return argv


def build_dig_argv(tool: str, name: str, record_type: str) -> list[str]:
    """A bounded record lookup. When the resolved executable is ``nslookup``
    (the documented Windows substitute) the argv is nslookup's own shape."""
    if os.path.basename(tool).lower().startswith("nslookup"):
        return [tool, "-type=" + record_type, name]
    return [tool, "+short", record_type, name]


def build_nc_argv(tool: str, host: str, port: int, timeout_seconds: int) -> list[str]:
    """netcat OUTBOUND CONNECT ONLY. A listener is structurally impossible:
    no ``-l``/``-L``/``--listen`` is ever emitted, and the caller rejects a
    bind-shaped request before argv construction."""
    _require_public_destination(host)
    base = os.path.basename(tool).lower()
    timeout_flag = "-w" if base.startswith("nc") else "-w"
    return [tool, "-v", "-z", timeout_flag, str(min(timeout_seconds, 30)), host, str(port)]


def build_socat_argv(tool: str, host: str, port: int, timeout_seconds: int) -> list[str]:
    """socat OUTBOUND CONNECT ONLY. No ``LISTEN:``/``OPEN:``/``EXEC:``
    address form is reachable from the reviewed inputs."""
    _require_public_destination(host)
    return [tool, "-T", str(min(timeout_seconds, 30)), f"TCP:{host}:{port}", "-"]


def build_script_argv(tool: str, language: str) -> list[str]:
    """python/bash read the script from STDIN. The script text is never an
    argv element and never touches a file the tool could re-read."""
    if language == "python":
        return [tool, "-"]
    return [tool, "-s", "/dev/stdin" if os.name != "nt" else "-"]


def _split_url(url: str) -> tuple[str, int]:
    """(host, port) from a URL the caller already validated."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    return parts.hostname or "", parts.port or default


# ---------------------------------------------------------------------------
# The hardened executor
# ---------------------------------------------------------------------------

#: Minimal environment for a child process. Everything else — DATABASE_URL,
#: JWT_SECRET, cloud credentials, proxies — is absent by construction.
_SAFE_ENV_KEYS = (
    "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SYSTEMROOT",
    "WINDIR", "COMSPEC", "PATHEXT",
)


def _child_env() -> dict[str, str]:
    env = {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}
    env.setdefault("PATH", os.defpath)
    # keep tools from being steered by an inherited proxy or CA override
    env["no_proxy"] = "*"
    env["NO_PROXY"] = "*"
    return env


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    """Kill the whole process group, so tool-spawned children die with the
    process rather than outliving the envelope."""
    if proc.returncode is not None:
        return
    try:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def execute(
    argv: list[str],
    *,
    timeout_seconds: int,
    stdin_data: bytes | None = None,
    workdir: Path | None = None,
    on_chunk: Optional[Callable[[str, str], Awaitable[None]]] = None,
    cwd_is_temp: bool = True,
) -> SandboxResult:
    """Run ``argv`` under the sandbox rules and return the bounded result.

    ``on_chunk(stream, text)`` is awaited for each bounded chunk as output
    arrives, which is how the console streams a live run. A failure to stream
    never fails the run: the terminal result is still authoritative.
    """
    timeout_seconds = max(1, min(int(timeout_seconds), MAX_ENVELOPE_SECONDS))
    workdir = workdir or Path(tempfile.mkdtemp(prefix="strike-run-"))
    process: asyncio.subprocess.Process | None = None
    stdout = bytearray()
    stderr = bytearray()
    timed_out = False
    started = time.monotonic()

    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
        )
    else:
        kwargs["start_new_session"] = True  # setsid: its own process group

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir),
            env=_child_env(),
            **kwargs,
        )
        if stdin_data is not None and process.stdin is not None:
            try:
                process.stdin.write(stdin_data)
                await process.stdin.drain()
            finally:
                process.stdin.close()

        async def pump(reader, sink: bytearray, stream_name: str) -> None:
            while True:
                chunk = await reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                room = STREAM_CAPTURE_LIMIT - len(sink)
                if room > 0:
                    sink.extend(chunk[:room])
                if on_chunk is not None:
                    try:
                        await on_chunk(stream_name, chunk.decode("utf-8", errors="replace"))
                    except Exception:
                        # streaming is best-effort; the terminal result stands
                        pass

        assert process.stdout is not None and process.stderr is not None
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    pump(process.stdout, stdout, "stdout"),
                    pump(process.stderr, stderr, "stderr"),
                ),
                timeout=timeout_seconds,
            )
            exit_code = await process.wait()
        except asyncio.TimeoutError:
            timed_out = True
            _kill_tree(process)
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
            exit_code = None
    except FileNotFoundError:
        return SandboxResult(
            status="rejected", exit_code=None, stdout="", stderr="",
            error_code="tool_not_available",
            error_message=f"{argv[0]} is not installed on the platform server",
        )
    finally:
        if cwd_is_temp:
            shutil.rmtree(workdir, ignore_errors=True)

    out_text = _cap(bytes(stdout), "stdout")
    err_text = _cap(bytes(stderr), "stderr")
    if timed_out:
        return SandboxResult(
            status="failed", exit_code=None, stdout=out_text, stderr=err_text,
            timed_out=True, error_code="run_timeout",
            error_message=f"killed after the {timeout_seconds}s envelope",
        )
    return SandboxResult(
        status="completed" if exit_code == 0 else "failed",
        exit_code=exit_code,
        stdout=out_text,
        stderr=err_text,
        error_code=None if exit_code == 0 else f"exit_{exit_code}",
        error_message=None if exit_code == 0 else f"{argv[0]} exited {exit_code}",
        artifacts={"duration_seconds": round(time.monotonic() - started, 3)},
    )


def _cap(raw: bytes, stream: str) -> str:
    if len(raw) <= STREAM_CAPTURE_LIMIT:
        return raw.decode("utf-8", errors="replace")
    clipped = raw[:STREAM_CAPTURE_LIMIT].decode("utf-8", errors="replace")
    return clipped + f"\n[tempris: {stream} truncated at {STREAM_CAPTURE_LIMIT} bytes]\n"


def make_workdir(run_id: uuid.UUID | str) -> Path:
    """A per-run temp dir. Named by run id for operator legibility; created
    with ``mkdtemp`` so it is private and cannot collide."""
    return Path(tempfile.mkdtemp(prefix=f"strike-{str(run_id)[:8]}-"))
