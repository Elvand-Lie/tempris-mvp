# backend/runner/execution.py
"""
Fixed-argv execution for the curl capability — the runner's only tool path.

Every argument is composed HERE, reviewed, and passed to subprocess without
a shell (shell=False always). There is no user-controlled flag anywhere: the
run contributes exactly scheme://host:port/path (validated and DNS-pinned at
creation), the method, and fixed time/size bounds. Redirect following is
never enabled (no -L), request bodies are impossible (no -d/-F flags exist
on this path), and no credentials are ever passed.

Containment plan (one docker invocation per run, sequential claim loop —
one run at a time, hence the fixed run subnet):

  * a plain (NOT --internal) user-defined bridge network with a FIXED
    subnet — `--internal` would block all external egress and make the
    pinned target unreachable;
  * DOCKER-USER policy: the container SUBNET is the source. A default DROP
    for the whole subnet is inserted FIRST, then one ACCEPT per pinned
    destination (each -I lands above the DROP) — the container can reach
    its pinned targets and nothing else. Every policy command is check=True:
    a failed rule installation fails the run closed, never weakly;
  * the container is unprivileged (cap-drop ALL, no-new-privileges,
    read-only, cpu/mem/pid caps), has no Docker socket and no secrets;
  * the container gets a deterministic --name so a stop is a CONFIRMED
    stop: `docker kill` + `docker wait` + `docker inspect` Running=false.
    Killing only the docker CLIENT would leave the container running — that
    path records cancel_unconfirmed, never cancelled.

DNS pinning at execution: curl receives one `--resolve host:port:ip` per
pinned IP, so the connection is bound to the approved address set while
Host/TLS SNI keep the real name — the container never performs a fresh DNS
resolution that could land outside the pin.

Output bound at the runner boundary: stdout/stderr go to temp files (never
`capture_output` into host memory), curl carries --max-filesize (8 MiB
aborts oversized bodies), and the host reads at most the 64 KiB inline
bound back. The bound is enforced while reading, not after allocation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import subprocess
import tempfile
import time

from app.strike.runs import INLINE_RESULT_LIMIT_BYTES

#: pinned tool image — reviewed content, never a floating tag
CURL_IMAGE = "curlimages/curl:8.10.1"

RUNNER_CPU = "0.5"
RUNNER_MEMORY = "256m"
RUNNER_PIDS = "64"
RUNNER_MAX_TIME = "60"
#: Phase-1 per-artifact bound fed to curl --max-filesize (curl aborts
#: oversized downloads with exit 63)
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024

#: fixed subnet for the per-run network — the sequential claim loop runs
#: one container at a time, so one subnet is unambiguous
RUN_SUBNET = "172.31.255.0/24"

#: error-code sentinel: the scope died mid-run and the container was asked
#: to stop (the control plane turns this into cancel_requested → cancelled)
SCOPE_STOP_CODE = "scope_revoked_or_expired_confirmed_stop"
SCOPE_STOP_UNCONFIRMED_CODE = "scope_revoked_or_expired_stop_unconfirmed"


class TeardownError(RuntimeError):
    """One or more fence-teardown commands failed: the run subnet still has
    DOCKER-USER rules (possibly ACCEPTs above DROP). The runner must not
    claim another run until reconcile_stale_networks() succeeds."""


def network_name(run: dict) -> str:
    return f"strike-run-{run['id']}"


def curl_argv(run: dict) -> list[str]:
    """The in-container curl argv. Fixed flags only; the URL is the
    creation-time validated scheme://host:port + path, and --resolve binds
    every connection to the pinned destination set."""
    host = run["target_host"]
    port = run["target_port"]
    url = run["target_url"] or f"http://{host}:{port}/"
    argv = [
        "curl", "--silent", "--show-error",
        "--max-time", RUNNER_MAX_TIME,
        "--max-filesize", str(MAX_ARTIFACT_BYTES),
    ]
    pinned = run["policy_snapshot"]["pinned_ips"]
    is_literal_ip = ":" in host or host.replace(".", "").isdigit()
    if not is_literal_ip:
        for ip in pinned:
            argv += ["--resolve", f"{host}:{port}:{ip}"]
    if run["method"] == "HEAD":
        argv.append("--head")
    else:
        argv.append("--include")
    argv.append(url)
    return argv


def container_argv(run: dict, argv: list[str] | None = None) -> list[str]:
    """The docker run argv for one run: the DOCKER-USER subnet policy (see
    prepare_network) is the external egress fence; the container itself is
    unprivileged and capped."""
    return [
        "docker", "run", "--rm", "--name", network_name(run),
        "--network", network_name(run),
        "--cpus", RUNNER_CPU, "--memory", RUNNER_MEMORY,
        "--pids-limit", RUNNER_PIDS,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only",
        CURL_IMAGE,
        *(argv if argv is not None else curl_argv(run)),
    ]


def _accept_rule(run: dict, ip: str) -> list[str]:
    """The kernel stops matching this permit at the scope's UTC expiry,
    even if the runner is dead and cannot remove the rule."""
    expires = datetime.fromisoformat(run["policy_snapshot"]["scope_expires_at"])
    if expires.tzinfo is None:
        raise ValueError("scope expiry must include a timezone")
    stop = expires.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return [
        "DOCKER-USER", "-s", RUN_SUBNET, "-d", f"{ip}/32",
        "-m", "time", "--datestop", stop, "-j", "ACCEPT",
    ]


def prepare_network(run: dict, pinned_ips: list[str]) -> list[list[str]]:
    """Host commands (in order, shell=False, all check=True) that create the
    run network and fence its egress: DROP the whole container subnet
    FIRST, then insert one ACCEPT per pinned destination — each -I lands at
    the top, so the final order is ACCEPT(s) above DROP. Source is always
    the container SUBNET, never the target IP."""
    net = network_name(run)
    cmds: list[list[str]] = [
        ["docker", "network", "create", "--subnet", RUN_SUBNET, net],
        ["iptables", "-I", "DOCKER-USER", "-s", RUN_SUBNET, "-j", "DROP"],
    ]
    for ip in pinned_ips:
        cmds.append(["iptables", "-I", *_accept_rule(run, ip)])
    return cmds


def teardown_network(run: dict, pinned_ips: list[str]) -> list[list[str]]:
    """Exact inverse of prepare_network: delete the ACCEPTs and the DROP
    (each -D removes one matching rule), then remove the network."""
    net = network_name(run)
    cmds: list[list[str]] = [
        ["iptables", "-D", *_accept_rule(run, ip)]
        for ip in pinned_ips
    ]
    cmds.append(["iptables", "-D", "DOCKER-USER", "-s", RUN_SUBNET, "-j", "DROP"])
    cmds.append(["docker", "network", "rm", "-f", net])
    return cmds


def cut_egress(run: dict) -> list[list[str]]:
    """QUARANTINE (PRD Ch4 1009-1012 / PATCH-02): authorization dies FIRST.
    Insert a top-priority DROP for the run subnet at position 1 of
    DOCKER-USER — above every ACCEPT — so the active container instantly
    loses ALL egress (including to a just-revoked pinned IP), even if the
    subsequent container stop cannot be verified. The deny stays in place
    until a confirmed stop; reconcile sweeps it at the next pass."""
    return [
        ["iptables", "-I", "DOCKER-USER", "-s", RUN_SUBNET, "-j", "DROP"],
    ]


def reconcile_stale_networks() -> list[str]:
    """Startup sweep (B2): a crashed runner can leave the per-run network and
    its DOCKER-USER rules installed — including ACCEPTs sitting above the
    subnet DROP, which would let a FUTURE run reach a revoked destination.
    Every new claim is gated behind this sweep succeeding; it raises on any
    failure instead of continuing weakly."""
    proc = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"],
        shell=False, capture_output=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"reconcile: cannot list docker networks ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
        )
    stale = sorted(
        name for name in proc.stdout.decode().split()
        if name.startswith("strike-run-")
    )
    for name in stale:
        _run_checked(["docker", "network", "rm", "-f", name])

    proc = subprocess.run(
        ["iptables", "-S", "DOCKER-USER"],
        shell=False, capture_output=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"reconcile: cannot read DOCKER-USER rules ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
        )
    for line in proc.stdout.decode().splitlines():
        line = line.strip()
        if line.startswith("-A DOCKER-USER") and RUN_SUBNET in line:
            # delete exactly the rule this line declares (one -D per -A)
            _run_checked(["iptables", "-D", "DOCKER-USER", *line.split()[2:]])
    return stale


def _run_checked(cmd: list[str], timeout: float = 30) -> None:
    """Every host policy command must succeed — a failed fence fails the
    run closed (never executes with partial containment)."""
    proc = subprocess.run(cmd, shell=False, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"runner policy command failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
        )


def _container_state(name: str, timeout: float = 15) -> bool | None:
    """True/False ONLY when Docker verifiably answers; None = unknown.

    docker inspect alone cannot prove absence: with --rm the container is
    gone (rc 1, "No such object") while a daemon outage ALSO fails with
    rc != 0 — conflating those could confirm a stop that never happened.
    So a failed inspect falls through to `docker ps -a`, which returns
    rc 0 whenever the daemon answers: empty output PROVES the container is
    absent; a listed State answers definitively. Any query failure is
    UNKNOWN, and UNKNOWN is never a confirmed stop."""
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        shell=False, capture_output=True, timeout=timeout,
    )
    if proc.returncode == 0:
        return proc.stdout.decode().strip() == "true"
    ps = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$",
         "--format", "{{.State}}"],
        shell=False, capture_output=True, timeout=timeout,
    )
    if ps.returncode != 0:
        return None  # daemon unreachable — UNKNOWN, fail closed
    states = ps.stdout.decode().split()
    if not states:
        return False  # absent — proven, verified stop
    return "running" in states or "restarting" in states


def stop_container(run: dict, timeout: float = 20) -> bool:
    """CONFIRMED container stop: kill + wait + a Docker query that PROVES
    the container absent or State.Running=false. A Docker outage (kill/
    wait/inspect all failing) is UNKNOWN and returns False — an unverified
    stop is never a confirmed stop."""
    name = network_name(run)
    try:
        subprocess.run(["docker", "kill", name], shell=False,
                       capture_output=True, timeout=timeout)
        subprocess.run(["docker", "wait", name], shell=False,
                       capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    try:
        return _container_state(name, timeout=timeout) is False
    except subprocess.TimeoutExpired:
        return False


def _bounded_read(f, limit: int = INLINE_RESULT_LIMIT_BYTES) -> str:
    """Read at most `limit` bytes back from the output temp file — the host
    never materializes more than the inline bound."""
    return f.read(limit).decode("utf-8", errors="replace")


def _drain(proc) -> None:
    """Reap the container process if it exits; never block forever on an
    unverified stop."""
    try:
        proc.wait(timeout=15)
    except Exception:
        pass


class ExecutionResult:
    __slots__ = ("exit_code", "output", "error_code", "scope_stop", "stop_confirmed")

    def __init__(self, exit_code: int, output: str, error_code: str | None = None,
                 *, scope_stop: bool = False, stop_confirmed: bool = False):
        self.exit_code = exit_code
        self.output = output
        self.error_code = error_code
        self.scope_stop = scope_stop
        self.stop_confirmed = stop_confirmed


def run_in_container(
    run: dict,
    check_alive=None,
    *,
    poll_seconds: float = 1.0,
    timeout: float = float(RUNNER_MAX_TIME) + 30,
    popen=None,
    stop=None,
    prepare=None,
    teardown=None,
    cut=None,
) -> ExecutionResult:
    """The real backend: fence the network, run the container, watch the
    scope, capture bounded output, tear the fence down. Shell=False
    everywhere. `popen`/`stop`/`prepare`/`teardown` are injectable so the
    watched path is testable without Docker; `check_alive() -> bool`
    re-derives the pinned scope's liveness in fresh transactions."""
    popen = popen or (
        lambda cmd, stdout=None, stderr=None: subprocess.Popen(
            cmd, shell=False, stdout=stdout, stderr=stderr,
        )
    )
    stop = stop or stop_container
    run_id = str(run["id"])
    pinned = run["policy_snapshot"]["pinned_ips"]

    if cut is None:
        def cut():
            # PRD Ch4 1009-1012 / PATCH-02: on scope death / cancel the
            # egress authorization dies BEFORE the container stop is even
            # attempted. If the quarantine DROP itself cannot be installed,
            # containment is NOT established — fail loud, halt claiming.
            try:
                for cmd in cut_egress(run):
                    _run_checked(cmd)
            except Exception as exc:
                raise TeardownError(
                    f"quarantine drop could not be installed; containment "
                    f"not established: {exc}"
                )

    if prepare is None:
        for cmd in prepare_network(run, pinned):
            _run_checked(cmd)
    else:
        prepare()

    if teardown is None:
        def teardown():
            # B2: teardown is CHECKED — a failed fence removal is loud, never
            # a silent check=False shrug that leaves ACCEPTs above DROP.
            failures: list[str] = []
            for cmd in teardown_network(run, pinned):
                try:
                    _run_checked(cmd, timeout=30)
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    failures.append(f"{' '.join(cmd)}: {exc}")
            if failures:
                raise TeardownError("; ".join(failures))
            # best-effort removal of the quarantine DROP (only present when a
            # cut ran). A failed deletion is fail-closed: a leftover subnet
            # DROP blocks egress, it never permits it, and reconcile sweeps
            # it before the next claim.
            subprocess.run(
                ["iptables", "-D", "DOCKER-USER", "-s", RUN_SUBNET, "-j", "DROP"],
                shell=False, capture_output=True, timeout=30,
            )

    outcome: ExecutionResult | None = None
    teardown_errors: list[BaseException] = []
    proc = None
    fence_kept = False
    fatal: TeardownError | None = None
    try:
        with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
            proc = popen(container_argv(run), stdout=out_f, stderr=err_f)
            scope_stop = False
            stop_confirmed = False
            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                if time.monotonic() >= deadline:
                    stop_confirmed = stop(run)
                    _drain(proc)
                    if not stop_confirmed:
                        # an unverified stop NEVER makes fence removal safe:
                        # the Docker client may have died while the container
                        # lives — keep the fence and halt the runner (B2)
                        fence_kept = True
                        outcome = ExecutionResult(-1, _bounded_read(out_f),
                                                  "runner_timeout_stop_unconfirmed")
                        break
                    outcome = ExecutionResult(
                        proc.returncode if proc.returncode is not None else -1,
                        _bounded_read(out_f),
                        "runner_timeout_stop_confirmed",
                        scope_stop=False, stop_confirmed=True,
                    )
                    break
                if check_alive is not None and not check_alive():
                    # mid-run scope death / cancel: egress dies FIRST — the
                    # quarantine DROP lands above every ACCEPT before the
                    # stop is attempted, so a revoked pinned destination is
                    # unreachable even when the stop stays unverified
                    try:
                        cut()
                    except TeardownError as exc:
                        exc.containment = True  # fatal: never stop/teardown past this
                        raise
                    except Exception as exc:
                        fatal_cut = TeardownError(
                            f"quarantine drop could not be installed; "
                            f"containment not established: {exc}"
                        )
                        fatal_cut.containment = True
                        raise fatal_cut
                    stop_confirmed = stop(run)
                    _drain(proc)
                    scope_stop = True
                    if not stop_confirmed:
                        fence_kept = True
                        fatal = TeardownError(
                            f"{SCOPE_STOP_UNCONFIRMED_CODE}: mid-run scope "
                            "stop could not be verified; fence left in "
                            "place — claiming halted until reconcile"
                        )
                        fatal.scope_stop = True  # PRD Ch4 typed reason
                        outcome = ExecutionResult(-1, _bounded_read(out_f),
                                                  SCOPE_STOP_UNCONFIRMED_CODE,
                                                  scope_stop=True)
                        break
                    outcome = ExecutionResult(
                        proc.returncode if proc.returncode is not None else -1,
                        _bounded_read(out_f),
                        SCOPE_STOP_CODE,
                        scope_stop=True, stop_confirmed=True,
                    )
                    break
                time.sleep(poll_seconds)

            if outcome is None:
                proc.wait()
                out_f.seek(0)
                err_f.seek(0)
                output = _bounded_read(out_f)
                if proc.returncode != 0:
                    err_f.seek(0)
                    output += _bounded_read(err_f)
                error_code = None if proc.returncode == 0 else f"curl_exit_{proc.returncode}"
                outcome = ExecutionResult(proc.returncode, output, error_code)
    except BaseException as exc:
        # Never expose a live container by deleting the fence first: the
        # fence is kept by DEFAULT and cleared ONLY on a positive verified
        # stop — including when stop(run) itself raises (Docker outage).
        if getattr(exc, "containment", False):
            # quarantine never landed: containment is NOT established. No
            # stop attempt, NO teardown — raise fatal, halt claiming.
            fence_kept = True
            fatal = exc if isinstance(exc, TeardownError) else fatal
        else:
            live = True
            try:
                live = proc is not None and proc.poll() is None
            except Exception:
                live = True
            if not live:
                fence_kept = False
            else:
                try:
                    confirmed = bool(stop(run))
                except Exception:
                    confirmed = False
                if confirmed:
                    _drain(proc)
                    fence_kept = False
                else:
                    fence_kept = True
            if not fence_kept:
                teardown_errors.append(exc)
    finally:
        if fence_kept:
            pass  # the fence deliberately stays up; teardown is FORBIDDEN
        else:
            try:
                teardown()
            except Exception as exc:
                teardown_errors.append(exc)

    if fence_kept:
        # unverified stop + intact fence: the container may still be running
        # inside a fully fenced network. LOUD fatal — the claim loop stops
        # until reconcile_stale_networks() succeeds. The typed scope_stop
        # reason lets the control plane ALSO record the PRD Ch4
        # cancel_requested → cancel_unconfirmed alarm while halting.
        raise fatal if fatal is not None else TeardownError(
            "stop could not be verified; fence left in place — claiming "
            "is halted until reconcile succeeds"
        )
    if teardown_errors:
        # an execution crash (or a fence that could not be removed) is LOUD:
        # the caller records the run truthfully and the next claim is gated
        # on a fresh reconcile sweep.
        raise teardown_errors[-1]
    assert outcome is not None
    return outcome
