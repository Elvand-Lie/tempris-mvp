# backend/runner/main.py
"""
The runner claim loop — ``python -m runner.main [--once]``.

Claims pending runs, re-checks the pinned scope at enforcement time, executes
the capability through runner.execution, and writes the guarded result back.
The executor is injectable (``--once`` + ``TEMPRIS_RUNNER_EXECUTOR``) so the
test suite drives the loop without Docker.
"""
from __future__ import annotations

import argparse
import os
import time
import uuid

from app.db import get_db_connection
from app.strike import runs as strike_runs
from runner import execution

RUNNER_ID = os.environ.get("TEMPRIS_RUNNER_ID", "runner-local")

#: B1/B2 honesty hook: a stop is CONFIRMED only when the container is
#: verifiably not running; injectable for tests.
_verify_stop = execution.stop_container


def _executor():
    override = os.environ.get("TEMPRIS_RUNNER_EXECUTOR")
    if override:
        module_name, _, attr = override.rpartition(".")
        module = __import__(module_name, fromlist=[attr])
        return getattr(module, attr)
    return execution.run_in_container


def _record_runner_failure(conn, claimed: dict, error_code: str, detail: str) -> None:
    """B1: an executor crash (Docker down, iptables failure, teardown
    residue) can never leave a run stuck in 'running' — it is recorded as a
    truthful failed outcome, and a cancel_requested race reconciles to a
    confirmed stop (the executor is no longer running anything)."""
    try:
        strike_runs.complete_run(
            conn, claimed,
            exit_code=-1,
            output=detail[:2000],
            error_code=error_code,
        )
        conn.commit()
    except strike_runs.RunStateError:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT state FROM strike_runs WHERE id = %s;",
                (str(claimed["id"]),),
            )
            row = cur.fetchone()
        if row is not None and row["state"] == "cancel_requested":
            # B1 honesty: an executor exception can leave a container alive —
            # a stop is confirmed ONLY if verified; otherwise the run records
            # the cancel_unconfirmed alarm, never a clean cancelled.
            confirmed = _verify_stop(claimed)
            strike_runs.confirm_cancel(conn, claimed, confirmed=confirmed)
            conn.commit()


def process_pending(
    *,
    once: bool = False,
    executor=None,
    reconcile=None,
) -> int:
    """One poll pass: reconcile stale fences, claim queued runs, enforce
    scope liveness, execute under a scope watch, record the confirmed (or
    honestly unconfirmed) outcome. Returns the number of runs processed.

    B1: the executor call is bounded — any crash is recorded as a failed
    run and the claim loop SURVIVES (except a teardown failure, which halts
    claiming: fence residue must never enable the next run).
    B2: `reconcile` (the service passes reconcile_stale_networks) gates
    every pass — stale per-run networks / DOCKER-USER rules are swept
    BEFORE any claim, and a failed reconcile raises instead of claiming."""
    executor = executor if executor is not None else _executor()
    processed = 0
    while True:
        if reconcile is not None:
            # B2: gate EVERY claim — including the first and any claim after
            # an executor exception — on a successful fence sweep.
            reconcile()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id FROM strike_runs
                    WHERE state = 'queued'
                      AND COALESCE(policy_snapshot->>'execution_plane', '')
                          <> 'collector'
                    ORDER BY created_at
                    FOR UPDATE SKIP LOCKED LIMIT 1;
                    """
                )
                queued = cur.fetchone()
                if queued is None:
                    break
                run_id = queued["id"]
            try:
                claimed = strike_runs.claim_run(conn, run_id, RUNNER_ID)
                if not strike_runs.scope_snapshot_alive(conn, claimed):
                    strike_runs.request_scope_stop(
                        conn, claimed,
                        "testing scope expired or revoked before execution",
                    )
                    # nothing was ever dispatched — the stop is trivially
                    # confirmed (no container exists)
                    strike_runs.confirm_cancel(conn, claimed, confirmed=True)
                    conn.commit()
                    processed += 1
                    continue
                conn.commit()
            except strike_runs.RunStateError:
                conn.rollback()
                continue

        def check_alive() -> bool:
            # fresh transaction per check — revocation/expiry is derived at
            # read, and a cancel_requested run stops exactly like a dead scope
            with get_db_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT state FROM strike_runs WHERE id = %s;",
                    (str(claimed["id"]),),
                )
                row = cur.fetchone()
                if row is None or row["state"] != "running":
                    return False
                return strike_runs.scope_snapshot_alive(conn, claimed)

        try:
            result = executor(claimed, check_alive)
        except execution.TeardownError as exc:
            # B2: fence residue — record the run truthfully, then STOP
            # claiming; the service dies loudly and the next boot is gated
            # behind a successful reconcile sweep. The typed scope_stop
            # reason additionally records the PRD Ch4 alarm: scope death
            # with unverified termination is cancel_requested →
            # cancel_unconfirmed, NEVER a clean cancelled and never merely
            # a failed run.
            if getattr(exc, "scope_stop", False):
                with get_db_connection() as conn:
                    strike_runs.request_scope_stop(conn, claimed, str(exc))
                    strike_runs.confirm_cancel(conn, claimed, confirmed=False)
                    conn.commit()
            else:
                with get_db_connection() as conn:
                    _record_runner_failure(
                        conn, claimed, "runner_teardown_failed", str(exc))
            raise
        except Exception as exc:
            # B1: Docker/iptables crashes never leave a run 'running' and
            # never kill the claim loop — a truthful failed outcome, then
            # the next claim is attempted after a fresh reconcile.
            with get_db_connection() as conn:
                _record_runner_failure(
                    conn, claimed, "runner_executor_failure",
                    f"{type(exc).__name__}: {exc}",
                )
            processed += 1
            if once:
                break
            continue

        with get_db_connection() as conn:
            try:
                if result.scope_stop:
                    strike_runs.request_scope_stop(conn, claimed, result.error_code)
                    strike_runs.confirm_cancel(conn, claimed, confirmed=result.stop_confirmed)
                else:
                    strike_runs.complete_run(
                        conn, claimed,
                        exit_code=result.exit_code,
                        output=result.output,
                        error_code=result.error_code,
                    )
            except strike_runs.RunStateError:
                # the run left 'running' while executing (e.g. the analyst
                # cancel endpoint set cancel_requested). The container has now
                # verifiably exited (executor returned) — a confirmed stop
                # unless a scope stop already recorded otherwise.
                conn.rollback()
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT state FROM strike_runs WHERE id = %s;",
                        (str(claimed["id"]),),
                    )
                    row = cur.fetchone()
                if row is not None and row["state"] == "cancel_requested":
                    strike_runs.confirm_cancel(conn, claimed, confirmed=True)
            conn.commit()
        processed += 1
        if once:
            break
    return processed


def main() -> None:
    parser = argparse.ArgumentParser(description="STRIKE runner service")
    parser.add_argument("--once", action="store_true", help="process one run then exit")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    args = parser.parse_args()

    if args.once:
        process_pending(once=True, reconcile=execution.reconcile_stale_networks)
        return
    while True:
        # A TeardownError or failed reconcile propagates: fence residue makes
        # further claiming FORBIDDEN — the service crashes loudly and the
        # next boot is gated behind the reconcile sweep.
        process_pending(reconcile=execution.reconcile_stale_networks)
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
