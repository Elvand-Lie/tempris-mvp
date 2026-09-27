# backend/app/strike/server_runner.py
"""Server-vantage execution for STRIKE toolbox runs (migration 048).

A run whose ``execution_plane`` is ``server`` executes in the platform's own
hardened sandbox (``app/strike/sandbox.py``) instead of being dispatched to a
collector over its authenticated WSS. This module owns that path so the import
graph stays a DAG — ``routes.strike`` -> ``server_runner`` ->
``{runs, sandbox}``, and nothing imports ``server_runner`` in turn.

Scope enforcement is NOT re-decided here. ``runs.create_run`` already validated
the target against the tenant's active testing-scope registry and pinned the
resolved addresses before this module is reached, and ``runs.activate_run``
re-checks the snapshot's liveness at claim time — the same gate the collector
plane passes. Nothing in this module can widen an authorization.

Output streams to the console through the ordered, bounded chunk table, and the
terminal result is recorded by the same state machine the collector plane uses,
so a server-vantage run is indistinguishable from a collector-vantage run in
the run history.
"""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from app.db import get_db_connection
from app.strike import sandbox
from app.strike.runs import (
    TOOL_ENVELOPE_SECONDS,
    RunCreate,
    RunStateError,
    activate_run,
    append_output_chunk,
    complete_run,
    confirm_cancel,
    get_run,
)

#: The envelope used when a capability advertises no per-tool value.
DEFAULT_ENVELOPE_SECONDS = 60


def build_server_argv(
    spec: dict, tool: str, timeout_seconds: int, *, workdir: Path | None = None
) -> list[str]:
    """The reviewed argv for a server-vantage run.

    Only capabilities with a reviewed argv shape are buildable. A capability
    whose mechanism has not been reviewed for this vantage is REFUSED with a
    config error rather than executed with a guessed command line — an
    unreviewed argv is exactly what the sandbox exists to prevent. The
    buildable set is a subset of the capabilities whose catalogue ``planes``
    include ``server``; the difference (chromium, mitmproxy) is refused here
    rather than executed with an argv slot the sandbox never reviewed.
    """
    capability = spec["capability"]
    headers = list(spec.get("headers") or [])
    body = spec.get("body")
    pinned_ips = list(spec.get("pinned_ips") or [])
    pinned_targets = list(spec.get("pinned_targets") or [])
    extra = list(spec.get("extra_args") or [])

    if capability == "curl":
        argv = sandbox.build_curl_argv(
            tool,
            spec.get("method") or "GET",
            spec.get("url") or "",
            pinned_ips,
            headers,
            body,
            timeout_seconds,
        )
    elif capability == "httpie":
        argv = sandbox.build_httpie_argv(
            tool,
            spec.get("method") or "GET",
            spec.get("url") or "",
            pinned_ips,
            headers,
            body,
            timeout_seconds,
        )
    elif capability in ("nc", "socat"):
        host = spec.get("host") or (pinned_targets[0] if pinned_targets else "")
        port = int(spec.get("port") or 0)
        if not host or port <= 0:
            raise sandbox.SandboxConfigError(
                "a connect probe requires a scoped host and port"
            )
        if capability == "nc":
            argv = sandbox.build_nc_argv(tool, host, port, timeout_seconds)
        else:
            argv = sandbox.build_socat_argv(tool, host, port, timeout_seconds)
    elif capability in ("python", "bash"):
        argv = sandbox.build_script_argv(tool, spec.get("language") or capability)
    elif capability == "nmap":
        argv = sandbox.build_nmap_argv(
            tool,
            pinned_targets,
            spec.get("nmap_profile"),
            timeout_seconds,
        )
    elif capability == "nuclei":
        argv = sandbox.build_nuclei_argv(
            tool,
            spec.get("url") or spec.get("host") or "",
            sandbox.resolve_nuclei_templates_dir(),
            list(spec.get("template_tags") or []),
            list(spec.get("severity") or []),
            int(spec.get("rate_limit") or 150),
            timeout_seconds,
        )
    elif capability == "ffuf":
        argv = sandbox.build_ffuf_argv(
            tool,
            spec.get("url") or "",
            sandbox.resolve_ffuf_wordlist(spec.get("wordlist"), workdir),
            list(spec.get("filter_codes") or []),
            list(spec.get("filter_size") or []),
            list(spec.get("filter_words") or []),
            timeout_seconds,
        )
    elif capability == "dig":
        name = spec.get("hostname") or spec.get("host") or ""
        record_type = spec.get("record_type") or ""
        if not name or not record_type:
            raise sandbox.SandboxConfigError(
                "a dig run requires the scoped name and an allowed record type"
            )
        argv = sandbox.build_dig_argv(tool, name, record_type)
    else:
        raise sandbox.SandboxConfigError(
            f"the {capability} capability has no reviewed server-vantage argv; "
            "it is refused rather than executed with an unreviewed command line"
        )
    return argv + extra


def _append_chunk(run_id: uuid.UUID, stream: str, text: str) -> None:
    """Best-effort streaming: a failed append never fails the run."""
    if not text:
        return
    try:
        with get_db_connection() as conn:
            append_output_chunk(conn, {"id": run_id}, stream=stream, content=text)
            conn.commit()
    except Exception:
        pass


def _finish(
    claimed: dict, *, exit_code: int, output: str, error_code: str | None
) -> None:
    """running -> completed | failed, mirroring the collector path exactly."""
    with get_db_connection() as conn:
        try:
            complete_run(
                conn,
                claimed,
                exit_code=exit_code,
                output=output,
                error_code=error_code,
            )
        except RunStateError:
            # the run left 'running' while executing (analyst cancellation).
            # The sandbox process has verifiably returned — a confirmed stop.
            conn.rollback()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT state FROM strike_runs WHERE id = %s;",
                    (str(claimed["id"]),),
                )
                current = cur.fetchone()
            if current is not None and current["state"] == "cancel_requested":
                confirm_cancel(conn, claimed, confirmed=True)
        conn.commit()


async def execute_server_run(
    run_id: uuid.UUID, tenant_id: uuid.UUID, payload: RunCreate
) -> None:
    """Execute one server-vantage run end to end.

    Runs as a FastAPI background task: the route returns the durable ``queued``
    run immediately and the console follows it through the chunk cursor. The
    request payload is passed rather than a pre-built spec so that the script
    text and request body — the only two values that exist nowhere durable —
    stay in this task's memory and cannot be reached by any code path that
    persists a run.
    """
    capability = payload.capability
    timeout_seconds = int(
        TOOL_ENVELOPE_SECONDS.get(capability, DEFAULT_ENVELOPE_SECONDS)
    )

    with get_db_connection() as conn:
        row = get_run(conn, tenant_id, run_id)
        claimed = activate_run(conn, row, f"server:{capability}")
        conn.commit()

    # activate_run refuses a dead scope snapshot by marking a stop instead of
    # claiming the run; nothing is executed in that case.
    if claimed["state"] != "running":
        return

    # --- the execution spec, assembled inline -----------------------------
    # The durable policy_snapshot already pins the authorized addresses, the
    # resolved host/port/url, the validated headers and extra_args, and the
    # language. It deliberately does NOT hold a runner script (piped to the
    # interpreter on stdin), a request body (recorded only as body_bytes), or
    # the inline ffuf wordlist, so those ride in from the payload here and die
    # with this task.
    spec = dict(row["policy_snapshot"])
    spec["method"] = row["method"] or payload.method
    spec["script"] = payload.script
    spec["body"] = payload.body
    spec["wordlist"] = payload.wordlist

    _append_chunk(run_id, "system", "run started on the platform server vantage\n")

    tool = sandbox.resolve_tool(capability)
    if tool is None:
        _append_chunk(
            run_id,
            "system",
            f"{capability} is not installed on the platform server\n",
        )
        _finish(claimed, exit_code=-1, output="", error_code="tool_not_available")
        return

    # Created before argv construction because an inline ffuf wordlist is
    # materialized inside it; removed on every exit path below.
    workdir = sandbox.make_workdir(run_id)
    try:
        argv = build_server_argv(spec, tool, timeout_seconds, workdir=workdir)
    except sandbox.SandboxConfigError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        _append_chunk(run_id, "system", f"refused before execution: {exc}\n")
        _finish(
            claimed, exit_code=-1, output=str(exc), error_code="run_config_invalid"
        )
        return

    stdin_data = None
    if capability in ("python", "bash"):
        stdin_data = (spec.get("script") or "").encode("utf-8", errors="replace")

    async def on_chunk(stream: str, text: str) -> None:
        _append_chunk(run_id, stream, text)

    result = await sandbox.execute(
        argv,
        timeout_seconds=timeout_seconds,
        stdin_data=stdin_data,
        workdir=workdir,
        on_chunk=on_chunk,
    )

    _append_chunk(
        run_id,
        "system",
        f"run finished: status={result.status} exit_code={result.exit_code}\n",
    )
    _finish(
        claimed,
        exit_code=result.exit_code if isinstance(result.exit_code, int) else -1,
        output=result.stdout or result.stderr or "",
        error_code=result.error_code,
    )
