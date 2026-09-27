# backend/app/strike/runs.py
"""
The toolbox run (amended PRD v1.12 Ch.4: choose-tool → run → results).

The unit of work is a RUN, not an engagement. This module owns the control
plane for the Phase-1 curl slice: the capability catalogue (curl GET/HEAD
only — a capability is shown as runnable only when it is actually wired),
run creation (scope authorization + DNS pin + durable record), progress
reads, bounded result reads, history, and the runner claim/complete/terminate
transitions.

Scope enforcement (fail closed):
  * one target per run — an exact hostname/IP, or a URL whose host is that
    target (a URL resolves to its host);
  * a hostname target resolves at CREATION time; the resolved IPs are pinned
    into the run's policy_snapshot and are the only destinations the run may
    reach. A hostname entry authorizes exactly those runtime-resolved IPs; an
    IP reached without its own active IP/CIDR entry (and without the target's
    own active hostname entry) refuses the run;
  * only ACTIVE entries count (expiry/revocation derived at read — migration
    041's registry);
  * redirect following is never enabled (curl is invoked without -L; a
    redirect response is returned as-is to the analyst, who decides);
  * mid-run scope death terminates the run and records the stop (the runner
    re-checks the pinned entries at claim time; revocation/expiry derived at
    read can never resurrect a terminated claim).

Limits (Phase 1 approved bounds): 64 KiB inline result; raw_purge_after =
created_at + 30 days; run/audit metadata permanent.

NO approval is required for this routine fixed-input mode (approval is
narrowed to credentialed/agent-deploying/payload/arbitrary-script actions).
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.audit import record_audit_event
from app.strike.errors import StrikeDomainError, StrikeNotFoundError

# ---------------------------------------------------------------------------
# Limits / catalogue
# ---------------------------------------------------------------------------

INLINE_RESULT_LIMIT_BYTES = 64 * 1024
RAW_RETENTION_DAYS = 30
DEFAULT_MAX_TIME_SECONDS = 60

#: Per-tool execution envelope (seconds) the executor must honor with a
#: hard kill. The backend wait adds the registry's result grace on top.
TOOL_ENVELOPE_SECONDS = {
    "curl": 60,
    "nmap": 180,
    "nuclei": 1200,
    "ffuf": 300,
    "dig": 30,
    "httpie": 60,
    "nc": 30,
    "socat": 30,
    "python": 120,
    "bash": 120,
    "chromium": 120,
    "mitmproxy": 180,
}

#: The vantage contract lives in CATALOGUE's per-capability ``planes`` list and
#: nothing else decides it: ``create_run`` refuses a plane that is not in the
#: list before any execution path is reached. Two module-level sets used to
#: duplicate that truth here (SERVER_PLANE_CAPABILITIES /
#: COLLECTOR_ONLY_CAPABILITIES) and had already drifted out of agreement with
#: it, so they are gone rather than kept as a second, wrong answer.

#: The ONE capability deliberately unavailable on the collector vantage: a
#: real headless browser needs a collector-side Chromium plus a per-run
#: mitmproxy instance, which the collector platform does not provide yet.
#: It is reported truthfully rather than faked (see the catalogue's notes).
COLLECTOR_UNAVAILABLE_CAPABILITIES = frozenset({"chromium", "mitmproxy"})

#: Methods a run may carry. GET/HEAD/GET-like reads, POST for a request
#: body, and RUN as the fixed single mode of every non-HTTP tool.
RUN_METHODS = ("GET", "HEAD", "POST", "RUN")

#: nmap preset profiles (the UI offers exactly these; raw flags are refused).
NMAP_PROFILES = ("ping_sweep", "top_ports", "service_version", "full")

#: nuclei severity filter allow-list.
NUCLEI_SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")

#: Script languages for the runner capability.
SCRIPT_LANGUAGES = ("python", "bash")

#: Bounds on the per-tool configuration a client may supply.
MAX_HEADERS = 32
MAX_HEADER_BYTES = 8192
MAX_BODY_BYTES = 256 * 1024
MAX_WORDLIST_BYTES = 256 * 1024
MAX_SCRIPT_BYTES = 128 * 1024

#: dig qtype allow-list — ANY/AXFR and everything else are refused at the API
DIG_ALLOWED_RECORD_TYPES = (
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR",
)

#: Phase 1 catalogue — only what is actually wired and reviewed. All five
#: tools are collector-plane; curl additionally keeps its server plane.
CATALOGUE = [
    {
        "capability": "curl",
        "title": "curl (fixed GET/HEAD)",
        "methods": ["GET", "HEAD"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Fixed argv, no redirects, no request body, no credentials. "
            "GET returns status line + headers + bounded body; HEAD returns "
            "status line + headers."
        ),
    },
    {
        "capability": "nmap",
        "title": "nmap (routine connect scan)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Unprivileged TCP connect scan only: -sT -Pn --open -T3, ports "
            "1-10000, rate- and host-time-capped. No OS detection, no "
            "scripts, no custom NSE. One target (IP, hostname, or a CIDR "
            "fully inside one active scope entry); resolved IPs are pinned. "
            "The optional profile names select a bounded port/host-time "
            "envelope within those caps and never add a flag — no profile "
            "enables version or service probing."
        ),
    },
    {
        "capability": "nuclei",
        "title": "nuclei (managed templates)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Runs a MANAGED template set — the collector's pinned SCOUT "
            "templates directory, or the server's pinned "
            "STRIKE_NUCLEI_TEMPLATES_DIR. Template paths and content are "
            "never accepted from the user, and a missing pinned directory "
            "fails closed rather than running ambient templates. One target "
            "(URL or host), all severities, JSONL output, no redirects "
            "followed."
        ),
    },
    {
        "capability": "ffuf",
        "title": "ffuf (pinned metadata wordlist)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Path fuzzing only: the URL path carries exactly one FUZZ token "
            "(never in the host or query) matched against a pinned reviewed "
            "public-metadata wordlist (the collector's embedded list, or the "
            "server's bundled one). An inline list is bounded and is written "
            "to a server-generated temp path — the user never supplies a "
            "path. No recursion, no request tampering, no custom headers."
        ),
    },
    {
        "capability": "dig",
        "title": "dig (bounded record lookup)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "+short lookups of one allowed record type (A, AAAA, CNAME, MX, "
            "NS, TXT, SOA, CAA, SRV, PTR) for a scoped hostname via the "
            "resolving host's system resolver. ANY/AXFR refused; no @server "
            "override; the name is pinned (no IP pinning for a name lookup)."
        ),
    },
    {
        "capability": "httpie",
        "title": "HTTPie (outbound request)",
        "methods": ["GET", "HEAD", "POST"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Outbound HTTP(S) request with client-supplied method, headers and "
            "body. The destination is pinned to the authorized address set, "
            "redirects are never followed, and request headers are bounded and "
            "refused if they carry credentials."
        ),
    },
    {
        "capability": "nc",
        "title": "netcat (outbound connect probe)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Outbound TCP connect probe to a scoped host and port. LISTENERS "
            "ARE FORBIDDEN: no bind/listen form is reachable, and no data is "
            "sent. Degrades to 'not available on this executor' when the "
            "executor genuinely lacks nc."
        ),
    },
    {
        "capability": "socat",
        "title": "socat (outbound connect probe)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Outbound TCP connect probe to a scoped host and port. LISTENERS "
            "ARE FORBIDDEN: LISTEN/OPEN/EXEC address forms are unreachable from "
            "the reviewed inputs. Degrades when the executor lacks socat."
        ),
    },
    {
        "capability": "python",
        "title": "Python (script runner)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Runs a bounded Python script supplied as text, piped to the "
            "interpreter on stdin — never a file the script could re-read and "
            "never an argv element. Executed in the per-run sandbox with a hard "
            "timeout and an output cap."
        ),
    },
    {
        "capability": "bash",
        "title": "Bash / sh (script runner)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server", "collector"],
        "notes": (
            "Runs a bounded shell script supplied as text, piped to the shell "
            "on stdin. Executed in the per-run sandbox with a hard timeout, "
            "output cap and process-group kill. Unavailable on a collector "
            "platform without a POSIX shell — reported, never faked."
        ),
    },
    {
        "capability": "chromium",
        "title": "Chromium (headless fetch + HAR)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server"],
        "notes": (
            "Headless Chromium fetches a scoped URL through a per-run mitmproxy "
            "instance; the captured HAR flows and response-body snapshots are "
            "the run's output. SERVER VANTAGE ONLY: the collector platform has "
            "no real browser, so the collector vantage reports itself "
            "unavailable rather than faking a result."
        ),
    },
    {
        "capability": "mitmproxy",
        "title": "mitmproxy (per-run capture proxy)",
        "methods": ["RUN"],
        "routine_mode": True,
        "requires_approval": False,
        "runnable": True,
        "requires_collector": False,
        "planes": ["server"],
        "notes": (
            "A per-run mitmproxy instance that captures the flows of the "
            "accompanying fetch as HAR. SERVER VANTAGE ONLY for the same reason "
            "as Chromium; the collector vantage is reported unavailable."
        ),
    },
]


class CapabilityNotFoundError(StrikeDomainError):
    code = "capability_not_found"


class RunTargetOutOfScopeError(StrikeDomainError):
    """The target (or a DNS-resolved destination) has no active scope
    entry — refused, never silently narrowed."""

    code = "run_target_out_of_scope"


class RunConfigInvalidError(StrikeDomainError):
    """Malformed target/URL, disallowed method, userinfo in URL, or any
    configuration beyond the fixed routine mode."""

    code = "run_config_invalid"


class RunStateError(StrikeDomainError):
    code = "run_state"


class CollectorInvalidError(StrikeDomainError):
    """The selected collector does not exist for this tenant or is not an
    enrolled collector — refused, never redirected to another collector."""

    code = "collector_invalid"


class CollectorNotReadyError(StrikeDomainError):
    """The selected collector is offline/inactive, or reports the requested
    capability as unavailable — refused visibly, never redirected."""

    code = "collector_not_ready"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability: str = Field(..., min_length=1, max_length=64)
    # GET/HEAD/POST for the HTTP tools; RUN is the fixed single mode of every
    # other tool
    method: str = Field(default="GET", pattern="^(GET|HEAD|POST|RUN)$")
    # exact hostname/IP, a CIDR (nmap only), or a URL whose host is the
    # target (ffuf's path carries exactly one FUZZ token)
    target: str = Field(..., min_length=1, max_length=2048)
    # dig only: one allow-listed qtype
    record_type: str | None = None
    # EXECUTION VANTAGE. 'collector' runs on the explicitly chosen enrolled
    # collector over its authenticated WSS; 'server' runs in the platform's
    # hardened sandbox. The vantage is pinned into the run and never changed.
    execution_plane: str = Field(default="collector", pattern="^(server|collector)$")
    # required on the collector vantage; must be ABSENT on the server vantage
    collector_id: uuid.UUID | None = None

    # --- per-tool configuration (all optional, all bounded) ---------------
    # HTTP tools: request headers and body
    headers: list[str] = Field(default_factory=list, max_length=MAX_HEADERS)
    body: str | None = Field(default=None, max_length=MAX_BODY_BYTES)
    # nmap: one reviewed preset profile
    nmap_profile: str | None = None
    # nuclei: tag + severity filters and a rate limit
    template_tags: list[str] = Field(default_factory=list, max_length=32)
    severity: list[str] = Field(default_factory=list, max_length=8)
    rate_limit: int | None = Field(default=None, ge=1, le=1000)
    # ffuf: an optional inline wordlist (bounded) plus the standard filters
    wordlist: str | None = Field(default=None, max_length=MAX_WORDLIST_BYTES)
    filter_codes: list[str] = Field(default_factory=list, max_length=32)
    filter_size: list[str] = Field(default_factory=list, max_length=32)
    filter_words: list[str] = Field(default_factory=list, max_length=32)
    # nc/socat: the port to connect to on the scoped host
    port: int | None = Field(default=None, ge=1, le=65535)
    # python/bash: the language and the script text (piped on stdin)
    language: str | None = None
    script: str | None = Field(default=None, max_length=MAX_SCRIPT_BYTES)
    # expert mode: EXTRA flags appended to the reviewed argv. Never a
    # replacement for it — the reviewed flags (destination pin, redirects,
    # bounds) are always present and cannot be removed. See
    # validate_extra_args for the per-tool refusal list.
    extra_args: str | None = Field(default=None, max_length=4096)


# ---------------------------------------------------------------------------
# Target parsing + scope evaluation
# ---------------------------------------------------------------------------


def _parse_target(raw: str) -> dict:
    """Exact host/IP or URL (http/https, no userinfo) → target components.
    A URL resolves to its host; the path/query travels with the run
    verbatim (fixed argv still owns every flag)."""
    value = raw.strip()
    if not value:
        raise RunConfigInvalidError("A target is required")

    if "://" not in value:
        from app.strike.scopes import parse_scope_entry

        entry_kind, host = parse_scope_entry(value)
        if entry_kind == "cidr":
            raise RunConfigInvalidError(
                "A run target is one host: a CIDR is not a single target"
            )
        return {"host": host, "port": 80, "url": None, "path": "/"}

    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise RunConfigInvalidError("Only http/https URLs are supported")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise RunConfigInvalidError("Credentials in the target URL are refused")
    if not parts.hostname:
        raise RunConfigInvalidError("The target URL has no host")

    from app.strike.scopes import parse_scope_entry

    try:
        _entry_kind, host = parse_scope_entry(parts.hostname)
    except StrikeDomainError as exc:
        raise RunConfigInvalidError(f"Invalid target host: {exc}") from exc

    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    if parts.fragment:
        raise RunConfigInvalidError("A target URL fragment is refused")
    return {
        "host": host,
        "port": port,
        "url": f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
        + (f"?{parts.query}" if parts.query else ""),
        "path": path,
        "scheme": parts.scheme,
    }


def _active_scope_entries(conn, tenant_id: uuid.UUID) -> list[dict]:
    from app.strike.scopes import scope_entry_state

    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM strike_testing_scopes WHERE tenant_id = %s;",
            (str(tenant_id),),
        )
        rows = cur.fetchall()
    return [r for r in rows if scope_entry_state(r) == "active"]


def _ip_covered(ip: str, entries: list[dict]) -> bool:
    addr = ipaddress.ip_address(ip)
    for e in entries:
        if e["entry_kind"] == "ip" and e["value"] == str(addr):
            return True
        if e["entry_kind"] == "cidr":
            if addr in ipaddress.ip_network(e["value"]):
                return True
    return False


def _cidr_covered(network: ipaddress._BaseNetwork, entries: list[dict]):
    """The WHOLE range must sit inside ONE active scope CIDR entry — a range
    spanning several entries (or entry + gap) is refused, never split."""
    for e in entries:
        if e["entry_kind"] != "cidr":
            continue
        scope_net = ipaddress.ip_network(e["value"])
        if network.version == scope_net.version and network.subnet_of(scope_net):
            return e
    return None


def resolve_target_scope(
    conn,
    tenant_id: uuid.UUID,
    target: dict,
    *,
    resolver=None,
) -> dict:
    """Authorize the target against ACTIVE registry entries and return the
    policy snapshot. Hostname targets resolve NOW; the resolved IPs are the
    pinned destinations. Any unpinned destination refuses the run (fail
    closed — never silently narrowed)."""
    entries = _active_scope_entries(conn, tenant_id)
    host = target["host"]

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    if addr is not None:
        if not _ip_covered(str(addr), entries):
            raise RunTargetOutOfScopeError(
                "The target IP has no active scope entry"
            )
        pinned = [str(addr)]
        hostname_entry_ids = []
    else:
        resolver = resolver or socket.getaddrinfo
        try:
            infos = resolver(host, None)
        except OSError as exc:
            raise RunTargetOutOfScopeError(
                f"The target hostname does not resolve: {exc}"
            ) from exc
        pinned = sorted({i[4][0] for i in infos})
        if not pinned:
            raise RunTargetOutOfScopeError("The target hostname resolves to no addresses")
        host_entries = [e for e in entries if e["entry_kind"] == "hostname" and e["value"] == host]
        if host_entries:
            # a hostname entry authorizes exactly the runtime-resolved IPs
            hostname_entry_ids = [str(e["id"]) for e in host_entries]
        else:
            uncovered = [ip for ip in pinned if not _ip_covered(ip, entries)]
            if uncovered:
                raise RunTargetOutOfScopeError(
                    "Resolved destination(s) without their own active scope "
                    f"entry: {', '.join(uncovered)}"
                )
            hostname_entry_ids = []

    ip_entry_ids = [
        str(e["id"])
        for e in entries
        if e["entry_kind"] in ("ip", "cidr")
        and any(
            e["entry_kind"] == "ip" and e["value"] == ip
            or e["entry_kind"] == "cidr"
            and ipaddress.ip_address(ip) in ipaddress.ip_network(e["value"])
            for ip in pinned
        )
    ]
    return {
        "scope_entry_ids": sorted(set(hostname_entry_ids + ip_entry_ids)),
        "pinned_ips": pinned,
        "hostname": None if addr is not None else host,
        "scope_expires_at": min(
            e["expires_at"] for e in entries
            if str(e["id"]) in set(hostname_entry_ids + ip_entry_ids)
        ).isoformat(),
    }


# ---------------------------------------------------------------------------
# Per-capability target resolution
# ---------------------------------------------------------------------------


def resolve_nmap_target(conn, tenant_id: uuid.UUID, raw: str, *, resolver=None) -> dict:
    """nmap: IP, hostname (resolve + pin like curl), or a CIDR accepted ONLY
    when the whole range sits inside one active scope CIDR entry."""
    value = raw.strip()
    if "://" in value:
        raise RunConfigInvalidError("An nmap target is an IP, hostname, or CIDR — not a URL")

    from app.strike.scopes import parse_scope_entry

    try:
        entry_kind, host = parse_scope_entry(value)
    except StrikeDomainError as exc:
        raise RunConfigInvalidError(f"Invalid nmap target: {exc}") from exc

    if entry_kind == "cidr":
        network = ipaddress.ip_network(host)
        entries = _active_scope_entries(conn, tenant_id)
        covering = _cidr_covered(network, entries)
        if covering is None:
            raise RunTargetOutOfScopeError(
                "A CIDR target is accepted only when the whole range is "
                "inside one active scope CIDR entry"
            )
        return {
            "host": host,
            "port": None,
            "url": None,
            "scope_entry_ids": [str(covering["id"])],
            "pinned_ips": [],
            "pinned_targets": [host],
            "hostname": None,
            "scope_expires_at": covering["expires_at"].isoformat(),
        }

    target = _parse_target(value)
    snapshot = resolve_target_scope(conn, tenant_id, target, resolver=resolver)
    snapshot["host"] = target["host"]
    snapshot["port"] = target["port"]
    snapshot["url"] = target["url"]
    snapshot["pinned_targets"] = list(snapshot["pinned_ips"])
    return snapshot


def validate_ffuf_url(raw: str) -> dict:
    """ffuf: an http(s) URL whose PATH carries exactly one FUZZ token. FUZZ
    in the authority/host, a missing FUZZ, and a query-string FUZZ are all
    refused; userinfo is refused as everywhere else."""
    value = raw.strip()
    if "://" not in value:
        raise RunConfigInvalidError(
            "An ffuf target is an http(s) URL whose path contains exactly "
            "one FUZZ token"
        )
    parts = urlsplit(value)
    if "FUZZ" in (parts.hostname or "") or "FUZZ" in (parts.netloc or ""):
        raise RunConfigInvalidError("FUZZ is only allowed in the URL path, never in the host")
    if "FUZZ" in (parts.query or "") or parts.fragment:
        raise RunConfigInvalidError("FUZZ is only allowed in the URL path — not in the query")
    if (parts.path or "").count("FUZZ") != 1:
        raise RunConfigInvalidError(
            "The URL path must contain exactly one FUZZ token"
        )
    return _parse_target(value)


def resolve_dig_target(conn, tenant_id: uuid.UUID, raw: str) -> dict:
    """dig: the scoped name itself. A hostname must match an active hostname
    scope entry; an IP target (PTR) must have its own active IP entry. There
    is no IP pinning for a name lookup — the NAME is pinned."""
    value = raw.strip()
    if "://" in value:
        raise RunConfigInvalidError("A dig target is a bare hostname or IP — not a URL")

    from app.strike.scopes import parse_scope_entry

    try:
        entry_kind, name = parse_scope_entry(value)
    except StrikeDomainError as exc:
        raise RunConfigInvalidError(f"Invalid dig target: {exc}") from exc

    entries = _active_scope_entries(conn, tenant_id)
    if entry_kind == "hostname":
        matched = [
            e for e in entries
            if e["entry_kind"] == "hostname" and e["value"] == name
        ]
    else:
        matched = [
            e for e in entries
            if e["entry_kind"] == "ip" and e["value"] == str(ipaddress.ip_address(name))
        ]
    if not matched:
        raise RunTargetOutOfScopeError(
            "The dig target has no active hostname (or, for PTR, IP) scope entry"
        )
    return {
        "host": name,
        "port": None,
        "url": None,
        "scope_entry_ids": sorted(str(e["id"]) for e in matched),
        "pinned_ips": [],
        "pinned_targets": [name],
        "hostname": name,
        "scope_expires_at": min(e["expires_at"] for e in matched).isoformat(),
    }


# ---------------------------------------------------------------------------
# Per-tool configuration validation (Phase 2 execution engine)
# ---------------------------------------------------------------------------

#: Header names whose VALUE is credential material. Request headers are the
#: operator's own, but STRIKE never carries credential material (PRD v1.12),
#: so an auth/cookie header is refused rather than quietly sent.
CREDENTIAL_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token",
})

#: Per-tool refused flags in EXPERT MODE. Expert mode only ever ADDS flags to
#: the reviewed argv — it can never remove the destination pin, re-enable
#: redirects, or grant a privilege the reviewed shape refuses. These are the
#: flags whose ADDITION would break one of those invariants.
EXTRA_ARG_REFUSALS = {
    # no re-resolution, no redirect following, no credential material, no
    # reading a config file, no writing files outside the per-run temp dir
    "curl": {
        "--resolve", "--connect-to", "-x", "--proxy", "--preproxy",
        "-u", "--user", "--netrc", "-K", "--config", "-T", "--upload-file",
        "-L", "--location", "-o", "--output", "-O", "--remote-name",
        "--interface", "--unix-socket", "--cert", "--key", "--cacert",
    },
    "httpie": {
        "-x", "--proxy", "-a", "--auth", "--session", "--session-read-only",
        "--download", "-o", "--output", "--cert", "--cert-key", "--verify",
        "--follow", "--max-redirects", "--netrc",
    },
    # no NSE, no output files, no source spoofing, no privileged/UDP scans
    "nmap": {
        "--script", "-sC", "--script-args", "-oN", "-oX", "-oG", "-oS", "-oA",
        "-S", "--spoof-mac", "-sU", "-iR", "--datadir", "--servicedb",
        "--script-updatedb", "-O", "--osscan-guess", "--privileged",
    },
    # a listener is structurally forbidden, not merely discouraged
    "nc": {
        "-l", "-L", "-e", "-c", "--exec", "-k", "--listen", "--keep-open",
        "-p", "-s", "--source", "--source-port", "-t", "--telnet",
    },
    "socat": set(),  # socat address forms are checked by substring below
    # the wordlist is server-controlled; no output files, no header tampering
    "ffuf": {
        "-o", "-of", "-w", "--wordlist", "-H", "--header", "-request",
        "-request-proto", "-x", "--proxy", "-recursion", "-maxtime-job",
    },
    # template paths are never user-controlled
    "nuclei": {
        "-t", "-templates", "-w", "-workflow", "-o", "-output", "-report-config",
        "-update", "-update-templates", "-esc", "--enable-self-contained",
    },
    # the script text IS the program; extra flags are meaningless and refused
    "python": None,
    "bash": None,
    "chromium": None,
    "mitmproxy": None,
}

#: socat address forms that would bind, execute, or read files.
SOCAT_FORBIDDEN_SUBSTRINGS = ("LISTEN", "EXEC:", "SYSTEM:", "OPEN:", "CREATE:")

#: nmap profiles that carry a raw-argv escape are additionally refused
def validate_extra_args(capability: str, raw: str | None) -> list[str]:
    """Expert mode: additional flags appended to the reviewed argv.

    The reviewed argv is never replaced, so the destination pin, the redirect
    refusal and the output bounds survive expert mode by construction. The
    flags below are refused because adding them would defeat one of those
    invariants (credential material, privilege, a file outside the per-run
    temp dir, or — for nc/socat — a listener).
    """
    if raw is None or not raw.strip():
        return []
    import shlex

    try:
        tokens = shlex.split(raw, posix=(os.name != "nt"))
    except ValueError as exc:
        raise RunConfigInvalidError(f"Expert-mode arguments are malformed: {exc}") from exc

    refusals = EXTRA_ARG_REFUSALS.get(capability, set())
    if refusals is None:
        raise RunConfigInvalidError(
            f"The {capability} capability takes its program as script text, "
            "not as expert-mode flags"
        )
    for token in tokens:
        head = token.split("=", 1)[0]
        if head in refusals:
            raise RunConfigInvalidError(
                f"The {capability} capability refuses '{head}' — it would defeat "
                "a reviewed invariant (direct destination, no redirects, no "
                "credential material, no privilege, no listener)"
            )
        if capability == "socat":
            upper = token.upper()
            if any(bad in upper for bad in SOCAT_FORBIDDEN_SUBSTRINGS):
                raise RunConfigInvalidError(
                    "socat listeners and exec/open address forms are refused"
                )
    return tokens


def validate_headers(headers: list[str]) -> list[str]:
    """Request headers: bounded, CRLF-free, and never credential material."""
    cleaned: list[str] = []
    for raw in headers:
        header = raw.strip()
        if not header:
            continue
        if len(header.encode("utf-8", errors="replace")) > MAX_HEADER_BYTES:
            raise RunConfigInvalidError("A request header exceeds the 8192-byte bound")
        if "\r" in header or "\n" in header:
            raise RunConfigInvalidError("A request header may not contain line breaks")
        name = header.split(":", 1)[0].strip().lower()
        if name in CREDENTIAL_HEADER_NAMES:
            raise RunConfigInvalidError(
                f"The '{name}' header carries credential material, which STRIKE "
                "never sends"
            )
        if not name:
            raise RunConfigInvalidError("A request header needs a name")
        cleaned.append(header)
    return cleaned


def resolve_connect_target(
    conn, tenant_id: uuid.UUID, raw: str, port: int | None, *, resolver=None
) -> dict:
    """nc/socat: a scoped host (IP, hostname, or a CIDR for a connect sweep)
    plus the port to connect to. Outbound only — there is no bind form."""
    if port is None:
        raise RunConfigInvalidError("A connect probe requires a port")
    value = raw.strip()
    if "://" in value:
        raise RunConfigInvalidError(
            "A connect target is a bare host — not a URL (supply the port separately)"
        )

    from app.strike.scopes import parse_scope_entry

    try:
        entry_kind, host = parse_scope_entry(value)
    except StrikeDomainError as exc:
        raise RunConfigInvalidError(f"Invalid connect target: {exc}") from exc

    if entry_kind == "cidr":
        # a connect sweep over an authorized range (nmap-style CIDR rule)
        network = ipaddress.ip_network(host)
        covering = _cidr_covered(network, _active_scope_entries(conn, tenant_id))
        if covering is None:
            raise RunTargetOutOfScopeError(
                "A CIDR target is accepted only when the whole range is inside "
                "one active scope CIDR entry"
            )
        return {
            "host": host, "port": port, "url": None,
            "scope_entry_ids": [str(covering["id"])],
            "pinned_ips": [], "pinned_targets": [host], "hostname": None,
            "scope_expires_at": covering["expires_at"].isoformat(),
        }

    target = _parse_target(value)
    snapshot = resolve_target_scope(conn, tenant_id, target, resolver=resolver)
    snapshot["host"] = target["host"]
    snapshot["port"] = port
    snapshot["url"] = None
    snapshot["pinned_targets"] = list(snapshot["pinned_ips"]) or [target["host"]]
    return snapshot


def resolve_script_target(conn, tenant_id: uuid.UUID, raw: str, *, resolver=None) -> dict:
    """python/bash: every run still carries ONE scope-authorized target.

    The declared target is what is scope-validated, pinned and recorded; the
    script receives it (and the pinned addresses) through the sandbox
    environment. A script runner's egress is NOT kernel-confined on the server
    vantage — see SERVER_PLANE_NOTES — so the target is a declared, audited
    authorization rather than a fence. That limitation is stated in the
    catalogue notes and in the console, never hidden.
    """
    value = raw.strip()
    if "://" in value:
        raise RunConfigInvalidError("A script target is a host, IP, or CIDR — not a URL")

    from app.strike.scopes import parse_scope_entry

    try:
        entry_kind, host = parse_scope_entry(value)
    except StrikeDomainError as exc:
        raise RunConfigInvalidError(f"Invalid script target: {exc}") from exc

    if entry_kind == "cidr":
        network = ipaddress.ip_network(host)
        covering = _cidr_covered(network, _active_scope_entries(conn, tenant_id))
        if covering is None:
            raise RunTargetOutOfScopeError(
                "A CIDR target is accepted only when the whole range is inside "
                "one active scope CIDR entry"
            )
        return {
            "host": host, "port": 0, "url": None,
            "scope_entry_ids": [str(covering["id"])],
            "pinned_ips": [], "pinned_targets": [host], "hostname": None,
            "scope_expires_at": covering["expires_at"].isoformat(),
        }

    target = _parse_target(value)
    snapshot = resolve_target_scope(conn, tenant_id, target, resolver=resolver)
    snapshot["host"] = target["host"]
    snapshot["port"] = target["port"]
    snapshot["url"] = None
    snapshot["pinned_targets"] = list(snapshot["pinned_ips"]) or [target["host"]]
    return snapshot


#: Surfaced verbatim in the catalogue so the limitation is discoverable from
#: the UI rather than only from the source.
SERVER_PLANE_NOTES = {
    "python": (
        "Runs in a per-run temp dir with a scrubbed environment, hard timeout "
        "and output cap. Egress is NOT kernel-confined on the server vantage: "
        "the declared target is scope-validated and audited, and restricting "
        "the script to it is the operator's responsibility."
    ),
    "bash": (
        "Runs in a per-run temp dir with a scrubbed environment, hard timeout "
        "and output cap. Egress is NOT kernel-confined on the server vantage: "
        "the declared target is scope-validated and audited, and restricting "
        "the script to it is the operator's responsibility."
    ),
}


# ---------------------------------------------------------------------------
# Create / read
# ---------------------------------------------------------------------------


def validate_run_collector(conn, tenant_id: uuid.UUID, collector_id: uuid.UUID) -> dict:
    """The run executes on exactly the collector the user selected: it must
    exist, belong to this tenant, and be enrolled. Anything else refuses the
    run — the selection is never silently redirected."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, tenant_id, enrollment_status, operator_status "
            "FROM collectors WHERE id = %s;",
            (str(collector_id),),
        )
        collector = cur.fetchone()
    if (
        collector is None
        or str(collector["tenant_id"]) != str(tenant_id)
        or collector["enrollment_status"] != "enrolled"
    ):
        raise CollectorInvalidError(
            "The selected collector does not exist for this tenant or is not enrolled"
        )
    return collector


def create_run(
    conn,
    tenant_id: uuid.UUID,
    payload: RunCreate,
    *,
    actor_id: str,
    actor_role: str,
    resolver=None,
) -> dict:
    spec = next(
        (c for c in CATALOGUE if c["capability"] == payload.capability), None
    )
    if spec is None:
        raise CapabilityNotFoundError("Capability is not in the catalogue")
    if payload.method not in spec["methods"]:
        raise RunConfigInvalidError(
            f"The {payload.capability} capability supports only "
            f"{' and '.join(spec['methods'])}"
        )
    if payload.record_type is not None and payload.capability != "dig":
        raise RunConfigInvalidError("record_type applies only to the dig capability")
    if payload.capability == "dig":
        if not payload.record_type:
            raise RunConfigInvalidError("A dig run requires a record type")
        qtype = payload.record_type.strip().upper()
        if qtype not in DIG_ALLOWED_RECORD_TYPES:
            raise RunConfigInvalidError(
                "Record type must be one of: " + ", ".join(DIG_ALLOWED_RECORD_TYPES)
            )

    # --- vantage resolution, fail closed ---------------------------------
    plane = payload.execution_plane
    if plane not in spec["planes"]:
        raise RunConfigInvalidError(
            f"The {payload.capability} capability cannot run on the {plane} "
            f"vantage; it is available on: {', '.join(spec['planes'])}"
        )
    if plane == "server":
        if payload.collector_id is not None:
            raise RunConfigInvalidError(
                "A server-vantage run does not select a collector; leaving a "
                "collector set would misstate where the run executed"
            )
        # the toolchain must truly exist here — an absent binary OR undeployed
        # pinned material (nuclei templates, the ffuf wordlist) is a visible
        # refusal, never a queued run that fails in the background
        from app.strike.sandbox import server_prerequisite_error

        prerequisite = server_prerequisite_error(payload.capability)
        if prerequisite is not None:
            raise RunConfigInvalidError(prerequisite)
    else:
        if payload.collector_id is None:
            raise RunConfigInvalidError(
                "A collector-vantage run requires the collector to execute on"
            )
        collector = validate_run_collector(conn, tenant_id, payload.collector_id)

    if payload.capability == "nmap":
        if payload.nmap_profile is not None and payload.nmap_profile not in NMAP_PROFILES:
            raise RunConfigInvalidError(
                "nmap profile must be one of: " + ", ".join(NMAP_PROFILES)
            )
        snapshot = resolve_nmap_target(conn, tenant_id, payload.target, resolver=resolver)
    elif payload.capability == "dig":
        snapshot = resolve_dig_target(conn, tenant_id, payload.target)
    elif payload.capability in ("nc", "socat"):
        snapshot = resolve_connect_target(
            conn, tenant_id, payload.target, payload.port, resolver=resolver
        )
    elif payload.capability in ("python", "bash"):
        snapshot = resolve_script_target(conn, tenant_id, payload.target, resolver=resolver)
    else:
        if payload.capability == "ffuf":
            target = validate_ffuf_url(payload.target)
        else:
            target = _parse_target(payload.target)
        snapshot = resolve_target_scope(conn, tenant_id, target, resolver=resolver)
        snapshot["host"] = target["host"]
        snapshot["port"] = target["port"]
        snapshot["url"] = target["url"]

    # --- per-tool configuration (all validated before it is recorded) -----
    headers = validate_headers(payload.headers)
    extra_args = validate_extra_args(payload.capability, payload.extra_args)

    if payload.capability == "nuclei":
        if payload.rate_limit is None:
            payload.rate_limit = 150
        for sev in payload.severity:
            if sev.strip().lower() not in NUCLEI_SEVERITIES:
                raise RunConfigInvalidError(
                    "nuclei severity must be one of: " + ", ".join(NUCLEI_SEVERITIES)
                )
    if payload.capability == "ffuf":
        if payload.wordlist is not None:
            if len(payload.wordlist.encode("utf-8", errors="replace")) > MAX_WORDLIST_BYTES:
                raise RunConfigInvalidError(
                    f"An inline wordlist is bounded to {MAX_WORDLIST_BYTES} bytes"
                )
            if not payload.wordlist.strip():
                raise RunConfigInvalidError("An inline wordlist must not be blank")
    if payload.capability in ("python", "bash"):
        language = (payload.language or payload.capability).strip().lower()
        if language not in SCRIPT_LANGUAGES:
            raise RunConfigInvalidError(
                "language must be one of: " + ", ".join(SCRIPT_LANGUAGES)
            )
        if payload.capability == "python" and language != "python":
            raise RunConfigInvalidError("A python run's language must be 'python'")
        if payload.capability == "bash" and language != "bash":
            raise RunConfigInvalidError("A bash run's language must be 'bash'")
        if not (payload.script or "").strip():
            raise RunConfigInvalidError(
                f"A {payload.capability} run requires the script text to execute"
            )
    if payload.body is not None and payload.capability not in ("curl", "httpie"):
        raise RunConfigInvalidError("A request body applies only to the HTTP tools")

    snapshot["pinned_targets"] = snapshot.get("pinned_targets") or list(snapshot["pinned_ips"])
    snapshot["execution_plane"] = plane
    snapshot["capability"] = payload.capability
    if plane == "collector":
        snapshot["collector_id"] = str(payload.collector_id)
    if payload.capability == "dig":
        snapshot["record_type"] = payload.record_type.strip().upper()
    if payload.capability == "nmap" and payload.nmap_profile:
        snapshot["nmap_profile"] = payload.nmap_profile
    if payload.capability == "nuclei":
        snapshot["template_tags"] = [t.strip() for t in payload.template_tags if t.strip()]
        snapshot["severity"] = [s.strip().lower() for s in payload.severity if s.strip()]
        snapshot["rate_limit"] = payload.rate_limit
    if payload.capability == "ffuf":
        snapshot["filter_codes"] = [c.strip() for c in payload.filter_codes if c.strip()]
        snapshot["filter_size"] = [s.strip() for s in payload.filter_size if s.strip()]
        snapshot["filter_words"] = [w.strip() for w in payload.filter_words if w.strip()]
    if payload.capability in ("nc", "socat"):
        snapshot["connect_port"] = payload.port
    if payload.capability in ("python", "bash"):
        snapshot["language"] = (payload.language or payload.capability).strip().lower()
    if headers:
        snapshot["headers"] = headers
    if extra_args:
        snapshot["extra_args"] = extra_args
    if payload.body is not None:
        snapshot["body_bytes"] = len(payload.body.encode("utf-8", errors="replace"))

    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO strike_runs (
                tenant_id, capability, method, target_url, target_host,
                target_port, state, policy_snapshot, requested_by,
                raw_purge_after, execution_plane
            ) VALUES (%s, %s, %s, %s, %s, %s, 'queued', %s, %s, %s, %s)
            RETURNING *;
            """,
            (
                str(tenant_id), payload.capability, payload.method,
                snapshot["url"], snapshot["host"], snapshot["port"] or 0,
                json.dumps(snapshot), actor_id,
                now + timedelta(days=RAW_RETENTION_DAYS), plane,
            ),
        )
        row = cur.fetchone()

    record_audit_event(
        conn, tenant_id, actor_id, actor_role,
        "strike.run.created",
        asset_id=row["id"],
        details={
            "capability": payload.capability,
            "method": payload.method,
            "target_host": snapshot["host"],
            "execution_plane": plane,
            "collector_id": str(payload.collector_id) if payload.collector_id else None,
            "pinned_ips": snapshot["pinned_ips"],
            "scope_entry_ids": snapshot["scope_entry_ids"],
        },
    )
    return row


def activate_run(conn, run: dict, runner_id: str) -> dict:
    """queued → running with an at-claim scope-liveness re-check (the same
    gate the VPS runner applies): a dead snapshot never dispatches. Returns
    the claimed run, having already marked a dead-scope stop."""
    claimed = claim_run(conn, run["id"], runner_id)
    if not scope_snapshot_alive(conn, claimed):
        request_scope_stop(
            conn, claimed,
            "testing scope expired or revoked before execution",
        )
        # nothing was ever dispatched — the stop is trivially confirmed
        confirm_cancel(conn, claimed, confirmed=True)
    return claimed


def get_run(conn, tenant_id: uuid.UUID, run_id: uuid.UUID) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM strike_runs WHERE id = %s AND tenant_id = %s;",
            (str(run_id), str(tenant_id)),
        )
        row = cur.fetchone()
    if row is None:
        # unknown and cross-tenant are the identical not-found
        raise StrikeNotFoundError("Run not found")
    return row


def list_runs(conn, tenant_id: uuid.UUID) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM strike_runs WHERE tenant_id = %s "
            "ORDER BY created_at DESC, id;",
            (str(tenant_id),),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Cursor-based output streaming (migration 048)
# ---------------------------------------------------------------------------


def append_output_chunk(
    conn, run: dict, *, stream: str, content: str, max_chunks: int = 4096
) -> int | None:
    """Append one bounded output chunk and return its seq.

    ``seq`` is assigned as ``max(seq)+1`` for the run inside this statement, so
    the stream has one total order even with concurrent writers; the UNIQUE
    (run_id, seq) constraint makes a lost race a retryable error rather than a
    silent reorder. Chunk content is capped at the 64 KiB the CHECK allows.
    Returns None when the per-run chunk ceiling is reached — the run continues,
    the terminal result is still recorded, and the truncation is honest."""
    if stream not in ("stdout", "stderr", "system"):
        raise ValueError(f"unknown output stream '{stream}'")
    raw = content.encode("utf-8", errors="replace")
    if not raw:
        return None
    bounded = raw[:INLINE_RESULT_LIMIT_BYTES].decode("utf-8", errors="replace")
    if len(raw) > INLINE_RESULT_LIMIT_BYTES:
        bounded += "\n[tempris: chunk truncated]\n"
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO strike_run_output_chunks (run_id, seq, stream, content)
            SELECT %s,
                   COALESCE(MAX(seq), 0) + 1,
                   %s,
                   %s
            FROM strike_run_output_chunks
            WHERE run_id = %s
            HAVING COALESCE(MAX(seq), 0) < %s
            ON CONFLICT (run_id, seq) DO NOTHING
            RETURNING seq;
            """,
            (str(run["id"]), stream, bounded, str(run["id"]), max_chunks),
        )
        row = cur.fetchone()
    return row["seq"] if row else None


def read_output_chunks(
    conn, tenant_id: uuid.UUID, run_id: uuid.UUID, *, after: int = 0, limit: int = 200
) -> dict:
    """Read the run's output after cursor ``after``.

    Tenant-scoped exactly like every other run read: an unknown or cross-tenant
    run id is the identical not-found, so this can never be used to probe for
    another tenant's run. ``next_cursor`` is the seq of the last chunk
    returned, so the caller's next read never re-delivers or skips."""
    run = get_run(conn, tenant_id, run_id)
    limit = max(1, min(int(limit), 1000))
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT seq, stream, content, created_at
            FROM strike_run_output_chunks
            WHERE run_id = %s AND seq > %s
            ORDER BY seq
            LIMIT %s;
            """,
            (str(run_id), int(after), limit),
        )
        rows = cur.fetchall()
    return {
        "run_id": str(run_id),
        "state": run["state"],
        "chunks": [
            {
                "seq": r["seq"],
                "stream": r["stream"],
                "content": r["content"],
                "created_at": r["created_at"].isoformat()
                if hasattr(r["created_at"], "isoformat")
                else r["created_at"],
            }
            for r in rows
        ],
        "next_cursor": rows[-1]["seq"] if rows else int(after),
        # the terminal view, so one poll serves both a live and a finished run
        "inline_result": run["inline_result"],
        "inline_truncated": run["inline_truncated"],
        "terminal": run["state"] in (
            "completed", "failed", "cancelled", "cancel_unconfirmed",
        ),
    }


# ---------------------------------------------------------------------------
# Runner transitions — guarded state machine, one winner per UPDATE
# ---------------------------------------------------------------------------


def scope_snapshot_alive(conn, run: dict) -> bool:
    """Re-derive the pinned entries' liveness (revocation/expiry derived at
    read): the run's authorized set must still hold at enforcement time."""
    tenant_id = uuid.UUID(run["tenant_id"]) if isinstance(run["tenant_id"], str) else run["tenant_id"]
    entries = {str(e["id"]): e for e in _active_scope_entries(conn, tenant_id)}
    needed = run["policy_snapshot"].get("scope_entry_ids") or []
    if not needed:
        return False
    return all(entry_id in entries for entry_id in needed)


def claim_run(conn, run_id: uuid.UUID, runner_id: str) -> dict:
    """queued → running (the runner owes an execution or a stop)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE strike_runs
            SET state = 'running', started_at = now(), runner_id = %s
            WHERE id = %s AND state = 'queued'
            RETURNING *;
            """,
            (runner_id, str(run_id)),
        )
        row = cur.fetchone()
    if row is None:
        raise RunStateError("Run is not claimable")
    return row


def request_scope_stop(conn, run: dict, reason: str) -> dict:
    """running → cancel_requested. Mid-run scope death (or a cancellation
    request against a running run) is recorded as a stop REQUEST first —
    'cancelled' only ever follows a runner-CONFIRMED container stop."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE strike_runs
            SET state = 'cancel_requested', stop_reason = %s
            WHERE id = %s AND state = 'running'
            RETURNING *;
            """,
            (reason, str(run["id"])),
        )
        row = cur.fetchone()
    if row is None:
        raise RunStateError("Run is not running")
    return row


def confirm_cancel(conn, run: dict, *, confirmed: bool) -> dict:
    """cancel_requested → cancelled (runner confirmed the container stop)
    or cancel_unconfirmed (stop could not be verified — stays visible for
    reconciliation, never silently resolved)."""
    state = "cancelled" if confirmed else "cancel_unconfirmed"
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE strike_runs
            SET state = %s, completed_at = now()
            WHERE id = %s AND state = 'cancel_requested'
            RETURNING *;
            """,
            (state, str(run["id"])),
        )
        row = cur.fetchone()
    if row is None:
        raise RunStateError("Run is not awaiting stop confirmation")
    return row


def complete_run(
    conn,
    run: dict,
    *,
    exit_code: int,
    output: str,
    error_code: str | None = None,
) -> dict:
    """running → completed | failed with the bounded inline result. The raw
    output is truncated to the Phase-1 64 KiB inline bound; the truncation
    is flagged, never silent."""
    raw = output.encode("utf-8", errors="replace")
    truncated = len(raw) > INLINE_RESULT_LIMIT_BYTES
    inline = raw[:INLINE_RESULT_LIMIT_BYTES].decode("utf-8", errors="replace")
    state = "completed" if exit_code == 0 else "failed"
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE strike_runs
            SET state = %s, completed_at = now(), exit_code = %s,
                error_code = %s, inline_result = %s, inline_truncated = %s
            WHERE id = %s AND state = 'running'
            RETURNING *;
            """,
            (state, exit_code, error_code, inline, truncated, str(run["id"])),
        )
        row = cur.fetchone()
    if row is None:
        raise RunStateError("Run is not running")
    return row


def cancel_run(conn, tenant_id: uuid.UUID, run_id: uuid.UUID) -> dict:
    """Analyst cancellation. A QUEUED run is cancelled immediately — nothing
    was ever dispatched, so the stop is trivially confirmed (the runner can
    never claim it: claim requires state='queued'). A RUNNING run becomes
    cancel_requested; 'cancelled' follows only the runner's confirmed
    container stop."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE strike_runs
            SET state = CASE state
                    WHEN 'queued' THEN 'cancelled'
                    WHEN 'running' THEN 'cancel_requested'
                END,
                completed_at = CASE state
                    WHEN 'queued' THEN now() ELSE completed_at
                END,
                stop_reason = 'cancellation requested'
            WHERE id = %s AND tenant_id = %s AND state IN ('queued', 'running')
            RETURNING *;
            """,
            (str(run_id), str(tenant_id)),
        )
        row = cur.fetchone()
    if row is None:
        raise RunStateError("Run is not queued or running")
    return row
