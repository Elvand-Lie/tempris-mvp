# backend/app/vuln_intelligence/sync_engine.py
"""
Generic source synchronization engine for the vulnerability intelligence library.

Lifecycle per source:
  1. Acquire PostgreSQL advisory lock (prevent overlapping runs)
  2. Create sync_snapshot (running)
  3. Fetch candidates from source (bootstrap or incremental)
  4. Validate complete batch
  5. Stage/reconcile each record through the adapter
  6. Atomically activate: complete snapshot, advance cursor
  7. Release lock (automatic with transaction)

Failure model:
  - Malformed/failed validation → snapshot marked failed, cursor unchanged
  - Source outage → last-known-good remains active, health degraded
  - Sources fail independently (one failure never blocks another)
  - Cursor advances ONLY after successful activation

Advisory lock keys: use pg_advisory_xact_lock with a hash of the source name.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Protocol, Union

import psycopg

from app.vuln_intelligence.models import SyncSnapshot, SyncState, MassWithdrawalExceededError
from app.vuln_intelligence.repository import (
    create_sync_snapshot,
    complete_sync_snapshot,
    get_sync_state,
    update_sync_state,
    reconcile_full_snapshot_absence,
)

logger = logging.getLogger(__name__)


def _ensure_sync_log_visibility() -> None:
    """P1-02 item 4: make SYNC snapshot log lines actually reach pm2 logs.

    The app configures uvicorn's loggers but never the root logger, so a bare
    module ``logger.info`` is silently dropped (root defaults to WARNING with
    no handler). Attach one contained stdout handler to this module's logger;
    the DB ledger stays authoritative.
    """
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


_ensure_sync_log_visibility()


# ---------------------------------------------------------------------------
# Source adapter protocol — each source implements this
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    """Result of fetching candidates from a source."""
    records: list[Any] = field(default_factory=list)
    cursor_after: Optional[str] = None
    is_bootstrap: bool = False
    is_exhausted: bool = True
    seen_ids: Optional[Union[set[str], list[str]]] = None
    metadata: Optional[dict] = None
    error: Optional[str] = None
    # P1-02 review: set when the client detected the upstream artifact changed
    # under a continuation cursor and RESTARTED at batch 0 (KEV/EPSS
    # content-hash mismatch, CVE staging identity invalid). The engine uses
    # this to discard the open shared snapshot (artifact A's writes) and let
    # the round proceed as a fresh run (new snapshot at batch 0).
    artifact_restarted: bool = False


@dataclass
class ProcessResult:
    """Aggregate result of processing a batch of records."""
    processed: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


class SourceAdapter(Protocol):
    """Protocol that each source-specific adapter implements."""

    source_name: str

    def fetch(
        self,
        conn: psycopg.Connection,
        cursor: Optional[str],
        *,
        batch_size: int = 1000,
        timeout_seconds: int = 300,
    ) -> FetchResult:
        """Fetch candidates from the source. Returns FetchResult."""
        ...

    def process_record(
        self,
        conn: psycopg.Connection,
        record: Any,
        snapshot_id: str,
    ) -> tuple[bool, bool, Optional[str]]:
        """
        Process a single record through the adapter.
        Returns (success, is_new_revision, error_message).
        """
        ...

    def validate_batch(self, records: list[Any]) -> tuple[bool, Optional[str]]:
        """
        Validate a complete batch of candidates before processing.
        Returns (valid, error_message).
        """
        ...


# ---------------------------------------------------------------------------
# Advisory lock helpers
# ---------------------------------------------------------------------------

def _source_lock_key(source: str) -> int:
    """
    Derive a stable int64 advisory lock key from the source name.
    Uses a fixed namespace prefix + hash to avoid collisions with
    other advisory locks in the application.
    """
    h = hashlib.sha256(f"vuln_sync:{source}".encode()).digest()
    # Use first 8 bytes as signed int64
    return struct.unpack(">q", h[:8])[0]


def try_advisory_lock(conn: psycopg.Connection, source: str) -> bool:
    """
    Try to acquire a PostgreSQL session-level advisory lock for the source.
    Returns True if acquired, False if another session holds it (overlap).
    Uses pg_try_advisory_lock (session-level, non-blocking).
    """
    key = _source_lock_key(source)
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s);", (key,))
        row = cur.fetchone()
        return row["pg_try_advisory_lock"] if isinstance(row, dict) else row[0]


def release_advisory_lock(conn: psycopg.Connection, source: str) -> None:
    """Release the session-level advisory lock for the source."""
    key = _source_lock_key(source)
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(%s);", (key,))


# ---------------------------------------------------------------------------
# Sync orchestrator
# ---------------------------------------------------------------------------

@dataclass
class SyncOutcome:
    """Result of a single source synchronization run.

    For atomic-artifact sources (kev, epss) a scheduled run drains the entire
    current artifact inside this one outcome; ``internal_rounds`` counts the
    bounded fetch/apply rounds consumed and ``continuation_completed``
    reports whether the artifact reached exhaustion (False means a bounded
    partial drain that left the continuation cursor in place).
    """
    source: str
    success: bool
    snapshot_id: Optional[str] = None
    sync_mode: str = ""
    records_processed: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_unchanged: int = 0
    records_failed: int = 0
    cursor_before: Optional[str] = None
    cursor_after: Optional[str] = None
    error: Optional[str] = None
    duration_ms: int = 0
    skipped_overlap: bool = False
    internal_rounds: int = 0
    continuation_completed: bool = True
    continuation_cursor: Optional[str] = None


# P1-02 Defect 2: these sources are SINGLE ATOMIC upstream artifacts (one KEV
# catalog JSON, one daily EPSS CSV). A scheduled run must process the entire
# current artifact inside one snapshot, labeled with the artifact's own header
# date; internal batching below is only a memory/snapshot-boundedness
# discipline, never a semantics boundary.
ATOMIC_ARTIFACT_SOURCES = frozenset({"kev", "epss"})
# Bounded loop-within-run cap for atomic artifacts (worst case: a ~472k-row
# EPSS artifact at batch_size=1000 → ~472 rounds; the cap bounds a single
# run's wall time while still converging in ONE run at default batch).
ATOMIC_ARTIFACT_MAX_ROUNDS = 1000
# P1-02 item 3: NVD drains its modification backlog within one run, bounded —
# the cursor advances only to the last processed position, so any residue
# stays due for the next cycle.
NVD_DRAIN_MAX_ROUNDS = 24


def _log_sync_snapshot(outcome: SyncOutcome) -> None:
    """P1-02 item 4: one log line per snapshot, reaching stdout/pm2 logs.
    The sync_snapshots ledger stays the authoritative record."""
    logger.info(
        "SYNC %s: mode=%s success=%s snapshot=%s processed=%d created=%d "
        "unchanged=%d failed=%d cursor_moved=%s duration_ms=%d",
        outcome.source,
        outcome.sync_mode or "-",
        outcome.success,
        outcome.snapshot_id or "-",
        outcome.records_processed,
        outcome.records_created,
        outcome.records_unchanged,
        outcome.records_failed,
        outcome.cursor_after is not None,
        outcome.duration_ms,
    )


def _fail_shared_snapshot(
    conn: psycopg.Connection,
    carried: Optional[SyncOutcome],
    error_msg: str,
) -> None:
    """Mark a still-open shared (atomic-artifact) snapshot as failed.

    Called from early failure paths (fetch/validation) when a continuation
    round aborts a run whose snapshot was opened by an earlier internal round
    of the same run. Best-effort: the ledger row must not mask the original
    error.
    """
    if carried is None or not carried.snapshot_id:
        return
    try:
        complete_sync_snapshot(
            conn, carried.snapshot_id,
            status="failed",
            records_processed=carried.records_processed,
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_failed=carried.records_processed or 1,
            error_message=error_msg,
        )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def sync_source(
    conn: psycopg.Connection,
    adapter: SourceAdapter,
    *,
    batch_size: int = 1000,
    timeout_seconds: int = 300,
) -> SyncOutcome:
    """
    Execute a full synchronization cycle for a single source.

    1. Acquire advisory lock (prevent overlap)
    2. Read current cursor/state
    3. Fetch candidates (bootstrap if no cursor, else incremental)
    4. Validate batch
    5. Create snapshot, process records, complete snapshot
    6. Advance cursor only on success
    7. Release lock

    Failed validation/activation leaves cursor and active data unchanged.
    """
    source = adapter.source_name
    start_ms = _now_ms()

    # Step 1: Advisory lock
    if not try_advisory_lock(conn, source):
        return SyncOutcome(
            source=source,
            success=False,
            error="Overlapping sync: advisory lock held by another session",
            skipped_overlap=True,
            duration_ms=_now_ms() - start_ms,
        )

    try:
        # P1-02 Defect 2: atomic-artifact sources (kev, epss) drain the ENTIRE
        # current artifact inside one snapshot via bounded internal rounds.
        # P1-02 item 3: nvd likewise drains its modification backlog (bounded),
        # and its client pins the cursor to the last processed position so any
        # residue stays due. Every other source keeps the single-round shape.
        max_rounds = 1
        if source in ATOMIC_ARTIFACT_SOURCES:
            max_rounds = ATOMIC_ARTIFACT_MAX_ROUNDS
        elif source == "nvd":
            max_rounds = NVD_DRAIN_MAX_ROUNDS

        carried: Optional[SyncOutcome] = None
        outcome: Optional[SyncOutcome] = None
        for _round in range(max_rounds):
            round_outcome = _do_sync(
                conn, adapter,
                batch_size=batch_size,
                timeout_seconds=timeout_seconds,
                start_ms=start_ms,
                _outcome_override=carried,
                _continuation_cursor=(
                    carried.continuation_cursor
                    if carried is not None and source in ATOMIC_ARTIFACT_SOURCES
                    else None
                ),
            )
            outcome = round_outcome
            if not round_outcome.success or round_outcome.skipped_overlap:
                break
            if source in ATOMIC_ARTIFACT_SOURCES:
                # One shared snapshot across the artifact's internal rounds.
                # Intermediate continuation cursors are NEVER persisted (the
                # snapshot is still open), so the next round resumes from the
                # previous round's in-memory cursor. P1-02 review: if the
                # client detected an artifact change and RESTARTED, _do_sync
                # already discarded the old snapshot (rolled back + failed)
                # and opened a FRESH one — carry THAT outcome forward so the
                # fresh snapshot's continuation cursor threads to the next
                # round and the fresh snapshot itself is the one completed at
                # exhaustion (carrying None here would leak it as a zombie
                # 'running' row and re-fetch batch 0 every round).
                carried = round_outcome
                if round_outcome.continuation_completed:
                    break
            elif source == "nvd":
                # Independent snapshots per window; drain while the processed
                # window keeps moving the cursor forward.
                carried = None
                if (
                    round_outcome.sync_mode == "bootstrap"
                    or round_outcome.records_processed == 0
                    or round_outcome.cursor_after == round_outcome.cursor_before
                ):
                    break
            else:
                break
        assert outcome is not None
        # P1-02 review: the atomic-artifact round cap expired before the
        # artifact was exhausted. The shared snapshot is still open and
        # NOTHING was committed (intermediate rounds never persist) — letting
        # this return as success would let a caller's commit persist a
        # partial artifact while the source cursor stays unchanged. Fail
        # closed: discard all artifact writes and mark the snapshot failed.
        if (
            source in ATOMIC_ARTIFACT_SOURCES
            and outcome.success
            and not outcome.continuation_completed
        ):
            error_msg = (
                f"Atomic-artifact drain hit the internal round cap "
                f"({ATOMIC_ARTIFACT_MAX_ROUNDS}) before exhaustion; rolling "
                "back the partial artifact (cursor unchanged)"
            )
            try:
                conn.rollback()
            except Exception:
                pass
            _fail_shared_snapshot(conn, outcome, error_msg)
            # P1-02 recheck: the failed snapshot exists — the operational
            # pointer must advance to it (never regress to NULL).
            _record_failure(
                conn, source, error_msg, start_ms,
                snapshot_id=outcome.snapshot_id,
            )
            outcome = SyncOutcome(
                source=source,
                success=False,
                snapshot_id=outcome.snapshot_id,
                sync_mode=outcome.sync_mode,
                records_processed=outcome.records_processed,
                records_created=0,
                records_updated=0,
                records_unchanged=0,
                records_failed=outcome.records_processed,
                cursor_before=outcome.cursor_before,
                cursor_after=None,
                error=error_msg,
                duration_ms=_now_ms() - start_ms,
                internal_rounds=outcome.internal_rounds,
                continuation_completed=False,
            )
        _log_sync_snapshot(outcome)
        return outcome
    finally:
        release_advisory_lock(conn, source)


def _do_sync(
    conn: psycopg.Connection,
    adapter: SourceAdapter,
    *,
    batch_size: int,
    timeout_seconds: int,
    start_ms: int,
    _outcome_override: Optional[SyncOutcome] = None,
    _continuation_cursor: Optional[str] = None,
) -> SyncOutcome:
    """Inner sync logic, called with lock held.

    P1-02 Defect 2 (atomic-artifact sources): when ``_outcome_override`` is
    carried from a previous internal round of the same run, this round does
    NOT open its own snapshot/savepoint or write the cursor — it processes its
    batch inside the SHARED, still-open snapshot. Failure semantics stay
    intact: the savepoint spans the whole artifact, so any failure rolls back
    the entire snapshot and the cursor stays untouched (fail closed).
    """
    source = adapter.source_name

    # Step 2: Read current state
    state = get_sync_state(conn, source)
    # P1-02 Defect 2: a shared-snapshot (atomic-artifact) round resumes from
    # the PREVIOUS round's in-memory continuation cursor — intermediate
    # cursors are never persisted while the shared snapshot is open.
    cursor_before = (
        _continuation_cursor
        if _continuation_cursor is not None
        else (state.cursor_value if state else None)
    )

    # Step 3: Fetch candidates
    try:
        fetch_result = adapter.fetch(
            conn, cursor_before,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        # Source outage / network error
        carried_failure = (
            _outcome_override
            if _outcome_override is not None and _outcome_override.snapshot_id
            else None
        )
        if carried_failure is not None:
            try:
                conn.rollback()
            except Exception:
                pass
            _fail_shared_snapshot(conn, carried_failure, f"Fetch failed: {e}")
        _record_failure(
            conn, source, str(e), start_ms,
            snapshot_id=carried_failure.snapshot_id if carried_failure else None,
        )
        # P1-02 review: the failure outcome carries the failed snapshot's
        # identity/counts so the SYNC log line identifies the real snapshot.
        return SyncOutcome(
            source=source,
            success=False,
            snapshot_id=carried_failure.snapshot_id if carried_failure else None,
            sync_mode=carried_failure.sync_mode if carried_failure else "",
            records_processed=(
                carried_failure.records_processed if carried_failure else 0
            ),
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_failed=(
                carried_failure.records_processed if carried_failure else 0
            ),
            cursor_before=(
                carried_failure.cursor_before if carried_failure else cursor_before
            ),
            error=f"Fetch failed: {e}",
            duration_ms=_now_ms() - start_ms,
            internal_rounds=(
                carried_failure.internal_rounds + 1 if carried_failure else 0
            ),
            continuation_completed=False,
        )

    if fetch_result.error:
        # P1-02 Defect 2: a shared-snapshot round that aborts at fetch must
        # first DISCARD the earlier rounds' uncommitted record writes, then
        # mark the carried snapshot failed (fail closed, cursor untouched).
        carried_failure = (
            _outcome_override
            if _outcome_override is not None and _outcome_override.snapshot_id
            else None
        )
        if carried_failure is not None:
            try:
                conn.rollback()
            except Exception:
                pass
            _fail_shared_snapshot(conn, carried_failure, f"Fetch error: {fetch_result.error}")
        _record_failure(
            conn, source, fetch_result.error, start_ms,
            snapshot_id=carried_failure.snapshot_id if carried_failure else None,
        )
        # P1-02 review: carry the failed snapshot's identity/counts for the log.
        return SyncOutcome(
            source=source,
            success=False,
            snapshot_id=carried_failure.snapshot_id if carried_failure else None,
            sync_mode=carried_failure.sync_mode if carried_failure else "",
            records_processed=(
                carried_failure.records_processed if carried_failure else 0
            ),
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_failed=(
                carried_failure.records_processed if carried_failure else 0
            ),
            cursor_before=(
                carried_failure.cursor_before if carried_failure else cursor_before
            ),
            error=f"Fetch error: {fetch_result.error}",
            duration_ms=_now_ms() - start_ms,
            internal_rounds=(
                carried_failure.internal_rounds + 1 if carried_failure else 0
            ),
            continuation_completed=False,
        )

    records = fetch_result.records
    sync_mode = "bootstrap" if fetch_result.is_bootstrap else "incremental"
    # Identity of a snapshot retired by an in-round artifact restart (set in
    # the restart boundary below; carried so a subsequent snapshot-less
    # failure still names it instead of NULLing the operational pointer).
    retired_failure: Optional[SyncOutcome] = None

    # P1-02 review: the client detected that the upstream artifact changed
    # under a continuation cursor (KEV/EPSS content-hash mismatch, CVE
    # staging identity invalid). The open shared snapshot belongs to the
    # ABANDONED artifact: rows already written from artifact A must not
    # survive alongside artifact B's restart-at-batch-0 batch. Roll the whole
    # transaction back, fail the old snapshot, and let this round proceed as
    # a FRESH run (new snapshot at batch 0 under the CURRENT artifact).
    if (
        getattr(fetch_result, "artifact_restarted", False)
        and _outcome_override is not None and _outcome_override.snapshot_id
    ):
        restart_reason = "Artifact changed under continuation cursor; restarting at batch 0 in a fresh snapshot"
        try:
            conn.rollback()
        except Exception:
            pass
        _fail_shared_snapshot(conn, _outcome_override, restart_reason)
        # P1-02 recheck: the abandoned artifact-A snapshot is a real failed
        # snapshot — it gets (a) its own SYNC log line (one line per
        # snapshot; the final log after sync_source() belongs to artifact B)
        # and (b) the operational last_snapshot_id pointer (P2-2's contract
        # applies at this boundary too: if artifact B's round then fails,
        # the pointer must still name A's failed snapshot).
        _log_sync_snapshot(SyncOutcome(
            source=source,
            success=False,
            snapshot_id=_outcome_override.snapshot_id,
            sync_mode=_outcome_override.sync_mode,
            records_processed=_outcome_override.records_processed,
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_failed=_outcome_override.records_processed,
            cursor_before=_outcome_override.cursor_before,
            error=restart_reason,
            duration_ms=_now_ms() - start_ms,
            internal_rounds=_outcome_override.internal_rounds,
            continuation_completed=False,
        ))
        _record_failure(
            conn, source, restart_reason, start_ms,
            snapshot_id=_outcome_override.snapshot_id,
        )
        # P1-02 recheck round 2: the retired artifact-A snapshot must stay
        # reachable through artifact B's FIRST validation. Clearing the
        # override entirely made a subsequent validation failure record a
        # snapshot-less failure — NULLing the last_snapshot_id pointer that
        # was just advanced to A (the review's exact edge). The retired
        # outcome is identity-only: its ledger row is already failed and
        # must NOT be re-completed or re-logged.
        retired_failure = _outcome_override
        _outcome_override = None
        _continuation_cursor = None
        state = get_sync_state(conn, source)
        cursor_before = state.cursor_value if state else None

    # Step 4: Validate batch
    try:
        valid, validation_error = adapter.validate_batch(records)
    except Exception as e:
        valid, validation_error = False, f"Validation exception: {e}"

    if not valid:
        # Failed validation → cursor unchanged, active data unchanged
        # P1-02 Defect 2: shared-snapshot round — discard partial artifact
        # batch and mark the carried snapshot failed.
        carried_failure = (
            _outcome_override
            if _outcome_override is not None and _outcome_override.snapshot_id
            else None
        )
        # P1-02 recheck round 2: after an in-round restart, A's failed
        # snapshot is retired (not carried) — a B-batch validation failure
        # must still name it in the outcome AND the operational pointer.
        failed_ref = carried_failure if carried_failure is not None else retired_failure
        if carried_failure is not None:
            try:
                conn.rollback()
            except Exception:
                pass
            _fail_shared_snapshot(
                conn, carried_failure,
                validation_error or "Batch validation failed",
            )
        _record_failure(
            conn, source, validation_error or "Batch validation failed", start_ms,
            snapshot_id=failed_ref.snapshot_id if failed_ref else None,
        )
        # P1-02 review: carry the failed snapshot's identity/counts for the log.
        return SyncOutcome(
            source=source,
            success=False,
            snapshot_id=failed_ref.snapshot_id if failed_ref else None,
            sync_mode=failed_ref.sync_mode if failed_ref else sync_mode,
            records_processed=(
                failed_ref.records_processed if failed_ref else 0
            ),
            records_created=0,
            records_updated=0,
            records_unchanged=0,
            records_failed=(
                failed_ref.records_processed if failed_ref else 0
            ),
            cursor_before=(
                failed_ref.cursor_before if failed_ref else cursor_before
            ),
            error=validation_error or "Batch validation failed",
            duration_ms=_now_ms() - start_ms,
            internal_rounds=(
                failed_ref.internal_rounds + 1 if failed_ref else 0
            ),
            continuation_completed=False,
        )

    # Step 5: Create snapshot and process records using savepoint protocol
    # -----------------------------------------------------------------------
    # 4-step savepoint protocol (Sprint 01 — CRIT-2 resolution):
    #   1. Create snapshot (status="running"), COMMIT — visible to health queries
    #   2. SAVEPOINT before_records
    #   3. Process all records in the batch
    #   4a. All succeed → complete snapshot, advance cursor, COMMIT
    #   4b. Any fail → ROLLBACK TO SAVEPOINT before_records
    #       → write failure metadata → COMMIT
    # Record data and failure metadata are never in the same transaction scope.
    # -----------------------------------------------------------------------

    # Step 5.1: Create snapshot and COMMIT (visible to health queries even on failure)
    # P1-02 Defect 2: internal continuation rounds REUSE the snapshot opened by
    # the run's first round (carried via _outcome_override) — the artifact is
    # one snapshot, so completion/exhaustion and the label are snapshot-level.
    if _outcome_override is not None and _outcome_override.snapshot_id:
        snapshot_id = _outcome_override.snapshot_id
    else:
        snapshot = create_sync_snapshot(conn, SyncSnapshot(
            source=source,
            sync_mode=sync_mode,
            status="running",
            cursor_before=cursor_before,
            metadata=fetch_result.metadata,
        ))
        snapshot_id = snapshot.id
        conn.commit()

    # Step 5.2: SAVEPOINT before processing records
    if _outcome_override is None:
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT before_records;")

    # Step 5.3: Process all records
    result = ProcessResult()
    for record in records:
        try:
            success, is_new, error = adapter.process_record(conn, record, snapshot_id)
            result.processed += 1
            if not success:
                result.failed += 1
                if error:
                    result.errors.append(error)
            elif is_new:
                result.created += 1
            else:
                result.unchanged += 1
        except Exception as e:
            result.processed += 1
            result.failed += 1
            result.errors.append(str(e))

    # Step 5.4: Complete or rollback
    if result.failed == 0:
        # Step 4a: All succeeded — complete snapshot, advance cursor, COMMIT
        cursor_after = fetch_result.cursor_after

        # P1-02 Defect 2: an ATOMIC-ARTIFACT source whose batch did not
        # exhaust the artifact stays INSIDE the shared snapshot — no
        # completion, no cursor write, no commit (this includes the run's
        # FIRST round, whose _outcome_override is None: completing round 1
        # would commit a partial artifact). The savepoint spans the whole
        # artifact, so a failure in any later round rolls everything back.
        # Non-atomic sources keep the historical semantics: every run
        # completes its snapshot and persists any continuation cursor.
        if source in ATOMIC_ARTIFACT_SOURCES and not fetch_result.is_exhausted:
            carried_counts = (
                _outcome_override
                if _outcome_override is not None and _outcome_override.snapshot_id
                else None
            )
            return SyncOutcome(
                source=source,
                success=True,
                snapshot_id=snapshot_id,
                sync_mode=sync_mode,
                records_processed=(
                    (carried_counts.records_processed if carried_counts else 0)
                    + result.processed
                ),
                records_created=(
                    (carried_counts.records_created if carried_counts else 0)
                    + result.created
                ),
                records_updated=(
                    (carried_counts.records_updated if carried_counts else 0)
                    + result.created
                ),
                records_unchanged=(
                    (carried_counts.records_unchanged if carried_counts else 0)
                    + result.unchanged
                ),
                records_failed=0,
                cursor_before=(
                    carried_counts.cursor_before
                    if carried_counts
                    else cursor_before
                ),
                cursor_after=None,
                duration_ms=_now_ms() - start_ms,
                internal_rounds=(
                    (carried_counts.internal_rounds + 1) if carried_counts else 1
                ),
                continuation_completed=False,
                continuation_cursor=fetch_result.cursor_after,
            )

        try:
            # Check for full-snapshot absence reconciliation on exhaustion
            if fetch_result.is_exhausted:
                # KEV absence reconciliation
                if source == "kev":
                    seen_ids = fetch_result.seen_ids
                    if not seen_ids and fetch_result.metadata:
                        seen_ids = fetch_result.metadata.get("seen_ids")
                    if seen_ids:
                        reconcile_full_snapshot_absence(
                            conn, source="kev", seen_declared_ids=seen_ids
                        )
                # OSV full-snapshot absence reconciliation (for ecosystems completed in this batch)
                elif source == "osv":
                    seen_ids = fetch_result.seen_ids
                    if not seen_ids and fetch_result.metadata:
                        seen_ids = fetch_result.metadata.get("seen_ids")
                    ecosystem = fetch_result.metadata.get("ecosystem") if fetch_result.metadata else None
                    if seen_ids and ecosystem:
                        reconcile_full_snapshot_absence(
                            conn, source="osv", seen_declared_ids=seen_ids, ecosystem=ecosystem
                        )

            # P1-02 Defect 2: completion writes the WHOLE-artifact aggregate
            # (carried counts + this batch), so the snapshot ledger row and
            # active_record_count describe the full artifact run.
            agg_processed = (
                (_outcome_override.records_processed if _outcome_override else 0)
                + result.processed
            )
            agg_created = (
                (_outcome_override.records_created if _outcome_override else 0)
                + result.created
            )
            agg_unchanged = (
                (_outcome_override.records_unchanged if _outcome_override else 0)
                + result.unchanged
            )
            complete_sync_snapshot(
                conn, snapshot_id,
                status="completed",
                records_processed=agg_processed,
                records_created=agg_created,
                records_updated=agg_created,
                records_unchanged=agg_unchanged,
                records_failed=0,
                cursor_after=cursor_after,
            )
            sync_state = update_sync_state(
                conn, source,
                cursor_value=cursor_after,
                last_snapshot_id=snapshot_id,
                success=True,
            )
            _update_operational_fields(conn, source, snapshot_id, _now_ms() - start_ms, agg_processed)
            conn.commit()
        except Exception as e:
            # P1-02: shared-snapshot rounds have no savepoint — a full ROLLBACK
            # already discards everything uncommitted; mark the snapshot failed.
            if _outcome_override is not None and _outcome_override.snapshot_id:
                conn.rollback()
                _fail_shared_snapshot(
                    conn, _outcome_override, f"Activation failed: {e}"
                )
            else:
                with conn.cursor() as cur:
                    cur.execute("ROLLBACK TO SAVEPOINT before_records;")
            error_msg = f"Activation failed: {e}"
            logger.error("Sync activation failed for %s: %s", source, e)
            try:
                complete_sync_snapshot(
                    conn, snapshot_id,
                    status="failed",
                    records_processed=result.processed,
                    records_created=0,
                    records_updated=0,
                    records_unchanged=0,
                    records_failed=result.processed if result.processed > 0 else 1,
                    error_message=error_msg,
                )
                update_sync_state(
                    conn, source,
                    last_snapshot_id=snapshot_id,
                    success=False,
                    error=error_msg,
                )
                conn.commit()
            except Exception as ex:
                conn.rollback()
                # P1-02 recheck round 2: the failed snapshot exists — the
                # pointer must advance to it, never regress to NULL.
                _record_failure(
                    conn, source, f"Failed to record failure metadata: {ex}",
                    start_ms, snapshot_id=snapshot_id,
                )

            return SyncOutcome(
                source=source,
                success=False,
                snapshot_id=snapshot_id,
                sync_mode=sync_mode,
                cursor_before=cursor_before,
                cursor_after=None,
                error=error_msg,
                duration_ms=_now_ms() - start_ms,
            )
    else:
        # Step 4b: Any failed — ROLLBACK TO SAVEPOINT (undo ALL record-level writes)
        cursor_after = fetch_result.cursor_after
        with conn.cursor() as cur:
            cur.execute("ROLLBACK TO SAVEPOINT before_records;")

        # Now write failure metadata in a clean scope (after rollback)
        error_msg = "; ".join(result.errors[:5])
        # P1-02 Defect 2: a shared-snapshot (atomic-artifact) round with any
        # record failure must discard the ENTIRE artifact — the savepoint
        # rollback above undoes only this batch; conn.rollback() aborts the
        # earlier rounds' uncommitted writes too — then fail the snapshot.
        if _outcome_override is not None and _outcome_override.snapshot_id:
            conn.rollback()
            _fail_shared_snapshot(conn, _outcome_override, error_msg)
            try:
                update_sync_state(
                    conn, source,
                    last_snapshot_id=_outcome_override.snapshot_id,
                    success=False,
                    error=f"{result.failed} records failed",
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                # P1-02 recheck round 2: same pointer contract as above.
                _record_failure(
                    conn, source, f"Failed to record failure metadata: {e}",
                    start_ms, snapshot_id=snapshot_id,
                )
        else:
            try:
                complete_sync_snapshot(
                    conn, snapshot_id,
                    status="failed",
                    records_processed=result.processed,
                    records_created=0,
                    records_updated=0,
                    records_unchanged=0,
                    records_failed=result.failed,
                    error_message=error_msg,
                )
                update_sync_state(
                    conn, source,
                    last_snapshot_id=snapshot_id,
                    success=False,
                    error=f"{result.failed} records failed",
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                _record_failure(conn, source, f"Failed to record failure metadata: {e}", start_ms)

    # P1-02 Defect 2: aggregate a shared-snapshot round's counts onto the
    # carried outcome so the returned/logged outcome describes the whole
    # artifact, not just the final batch.
    carried = _outcome_override if (
        _outcome_override is not None and _outcome_override.snapshot_id
    ) else None
    n_created = (result.created if result.failed == 0 else 0) + (
        carried.records_created if carried else 0
    )
    n_updated = (result.created if result.failed == 0 else 0) + (
        carried.records_updated if carried else 0
    )
    return SyncOutcome(
        source=source,
        success=result.failed == 0,
        snapshot_id=snapshot_id,
        sync_mode=sync_mode,
        records_processed=(
            carried.records_processed + result.processed if carried else result.processed
        ),
        records_created=n_created,
        records_updated=n_updated,
        records_unchanged=(
            (carried.records_unchanged + result.unchanged)
            if carried and result.failed == 0
            else (carried.records_unchanged if carried else result.unchanged)
        ),
        records_failed=result.failed,
        cursor_before=carried.cursor_before if carried else cursor_before,
        cursor_after=cursor_after if result.failed == 0 else None,
        error="; ".join(result.errors[:5]) if result.errors else None,
        duration_ms=_now_ms() - start_ms,
        internal_rounds=(carried.internal_rounds + 1) if carried else 1,
        continuation_completed=fetch_result.is_exhausted,
        continuation_cursor=None if fetch_result.is_exhausted else fetch_result.cursor_after,
    )


def _record_failure(
    conn: psycopg.Connection,
    source: str,
    error: str,
    start_ms: int,
    snapshot_id: Optional[str] = None,
) -> None:
    """Record a sync failure in sync_state without advancing the cursor.

    P1-02 recheck: when a failed snapshot exists, the operational
    ``last_snapshot_id`` pointer must ADVANCE to it (repository contract:
    a failure moves the last-attempt pointer, never last_good_snapshot_id).
    Passing no id NULLed the pointer while the ledger row named a real
    failed snapshot — callers carrying a failed snapshot must pass it.
    """
    try:
        update_sync_state(
            conn, source, success=False, error=error,
            last_snapshot_id=snapshot_id,
        )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def _update_operational_fields(
    conn: psycopg.Connection,
    source: str,
    snapshot_id: str,
    duration_ms: int,
    record_count: int,
) -> None:
    """Update operational tracking columns on sync_state."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_state SET
                last_sync_duration_ms = %s,
                active_record_count = %s,
                last_good_snapshot_id = %s
            WHERE source = %s;
            """,
            (duration_ms, record_count, snapshot_id, source),
        )


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


# ---------------------------------------------------------------------------
# Scheduling configuration
# ---------------------------------------------------------------------------

# Default intervals (seconds) per source. Scheduling is DISABLED by default.
DEFAULT_INTERVALS = {
    "cve": 1200,    # 20 minutes
    "nvd": 1200,    # 20 minutes
    "kev": 1200,    # 20 minutes
    "osv": 1200,    # 20 minutes
    "epss": 86400,  # daily
}


def get_schedule_config(conn: psycopg.Connection, source: str) -> dict:
    """Get scheduling configuration for a source."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT sync_interval_seconds, sync_enabled, next_sync_at FROM sync_state WHERE source = %s;",
            (source,),
        )
        row = cur.fetchone()
    if row is None:
        return {"enabled": False, "interval_seconds": DEFAULT_INTERVALS.get(source, 1200)}
    return {
        "enabled": row["sync_enabled"],
        "interval_seconds": row["sync_interval_seconds"] or DEFAULT_INTERVALS.get(source, 1200),
        "next_sync_at": row["next_sync_at"],
    }


def set_schedule_config(
    conn: psycopg.Connection,
    source: str,
    *,
    enabled: Optional[bool] = None,
    interval_seconds: Optional[int] = None,
) -> None:
    """Update scheduling configuration for a source."""
    updates = []
    params = []
    if enabled is not None:
        updates.append("sync_enabled = %s")
        params.append(enabled)
    if interval_seconds is not None:
        updates.append("sync_interval_seconds = %s")
        params.append(interval_seconds)
    if not updates:
        return
    params.append(source)
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE sync_state SET {', '.join(updates)}, updated_at = now() WHERE source = %s;",
            params,
        )


def get_sources_due_for_sync(conn: psycopg.Connection) -> list[str]:
    """
    Return source names where scheduling is enabled and the next sync
    is due (next_sync_at <= now or NULL with no prior run).
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT source FROM sync_state
            WHERE sync_enabled = TRUE
              AND (next_sync_at IS NULL OR next_sync_at <= now())
            ORDER BY source;
            """
        )
        return [row["source"] for row in cur.fetchall()]


def advance_next_sync(conn: psycopg.Connection, source: str) -> None:
    """Set next_sync_at based on the configured interval."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_state SET
                next_sync_at = now() + (sync_interval_seconds || ' seconds')::interval
            WHERE source = %s AND sync_enabled = TRUE;
            """,
            (source,),
        )


# ---------------------------------------------------------------------------
# Source health / observable state
# ---------------------------------------------------------------------------

@dataclass
class SourceHealth:
    """Observable per-source health state."""
    source: str
    is_healthy: bool
    last_attempted_at: Optional[datetime] = None
    last_successful_at: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    cursor_value: Optional[str] = None
    active_record_count: int = 0
    last_snapshot_id: Optional[str] = None
    last_good_snapshot_id: Optional[str] = None
    last_sync_duration_ms: Optional[int] = None
    sync_enabled: bool = False
    sync_interval_seconds: Optional[int] = None
    next_sync_at: Optional[datetime] = None
    data_age_seconds: Optional[int] = None


def get_source_health(conn: psycopg.Connection, source: str) -> Optional[SourceHealth]:
    """Get observable health state for a source."""
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM sync_state WHERE source = %s;", (source,))
        row = cur.fetchone()
    if row is None:
        return None
    last_success = row.get("last_successful_at")
    data_age = None
    if last_success:
        now = datetime.now(timezone.utc)
        data_age = int((now - last_success).total_seconds())
    return SourceHealth(
        source=row["source"],
        is_healthy=row["is_healthy"],
        last_attempted_at=row.get("last_attempted_at"),
        last_successful_at=last_success,
        last_error=row.get("last_error"),
        consecutive_failures=row.get("consecutive_failures", 0),
        cursor_value=row.get("cursor_value"),
        active_record_count=row.get("active_record_count", 0),
        last_snapshot_id=str(row["last_snapshot_id"]) if row.get("last_snapshot_id") else None,
        last_good_snapshot_id=str(row["last_good_snapshot_id"]) if row.get("last_good_snapshot_id") else None,
        last_sync_duration_ms=row.get("last_sync_duration_ms"),
        sync_enabled=row.get("sync_enabled", False),
        sync_interval_seconds=row.get("sync_interval_seconds"),
        next_sync_at=row.get("next_sync_at"),
        data_age_seconds=data_age,
    )


def get_all_source_health(conn: psycopg.Connection) -> list[SourceHealth]:
    """Get health state for all sources."""
    sources = ["cve", "nvd", "kev", "epss", "osv"]
    return [h for s in sources if (h := get_source_health(conn, s)) is not None]


# ---------------------------------------------------------------------------
# Async scheduling loop (runs in FastAPI lifespan when enabled)
# ---------------------------------------------------------------------------

async def run_sync_loop(
    get_connection: Callable,
    adapters: dict[str, SourceAdapter],
    *,
    check_interval: int = 60,
    shutdown_event: Optional[asyncio.Event] = None,
) -> None:
    """
    Background scheduling loop. Checks for due sources every check_interval
    seconds and runs their sync. Only active when scheduling is enabled.

    This runs as an asyncio task in the FastAPI lifespan. It does NOT start
    unless explicitly configured — scheduling is disabled by default.
    """
    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    while not shutdown_event.is_set():
        try:
            with get_connection() as conn:
                due_sources = get_sources_due_for_sync(conn)

            for source_name in due_sources:
                if shutdown_event.is_set():
                    break
                adapter = adapters.get(source_name)
                if adapter is None:
                    continue
                try:
                    with get_connection() as conn:
                        outcome = sync_source(conn, adapter)
                        if not outcome.skipped_overlap:
                            advance_next_sync(conn, source_name)
                            conn.commit()
                        logger.info(
                            "Sync %s: success=%s processed=%d created=%d",
                            source_name, outcome.success,
                            outcome.records_processed, outcome.records_created,
                        )
                except Exception as e:
                    logger.error("Sync loop error for %s: %s", source_name, e)

        except Exception as e:
            logger.error("Sync loop check error: %s", e)

        # Wait for next check or shutdown
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=check_interval)
        except asyncio.TimeoutError:
            pass
