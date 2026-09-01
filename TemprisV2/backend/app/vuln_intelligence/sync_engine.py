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
    """Result of a single source synchronization run."""
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
        return _do_sync(conn, adapter, batch_size=batch_size, timeout_seconds=timeout_seconds, start_ms=start_ms)
    finally:
        release_advisory_lock(conn, source)


def _do_sync(
    conn: psycopg.Connection,
    adapter: SourceAdapter,
    *,
    batch_size: int,
    timeout_seconds: int,
    start_ms: int,
) -> SyncOutcome:
    """Inner sync logic, called with lock held."""
    source = adapter.source_name

    # Step 2: Read current state
    state = get_sync_state(conn, source)
    cursor_before = state.cursor_value if state else None

    # Step 3: Fetch candidates
    try:
        fetch_result = adapter.fetch(
            conn, cursor_before,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        # Source outage / network error
        _record_failure(conn, source, str(e), start_ms)
        return SyncOutcome(
            source=source,
            success=False,
            cursor_before=cursor_before,
            error=f"Fetch failed: {e}",
            duration_ms=_now_ms() - start_ms,
        )

    if fetch_result.error:
        _record_failure(conn, source, fetch_result.error, start_ms)
        return SyncOutcome(
            source=source,
            success=False,
            cursor_before=cursor_before,
            error=f"Fetch error: {fetch_result.error}",
            duration_ms=_now_ms() - start_ms,
        )

    records = fetch_result.records
    sync_mode = "bootstrap" if fetch_result.is_bootstrap else "incremental"

    # Step 4: Validate batch
    try:
        valid, validation_error = adapter.validate_batch(records)
    except Exception as e:
        valid, validation_error = False, f"Validation exception: {e}"

    if not valid:
        # Failed validation → cursor unchanged, active data unchanged
        _record_failure(conn, source, validation_error or "Batch validation failed", start_ms)
        return SyncOutcome(
            source=source,
            success=False,
            sync_mode=sync_mode,
            cursor_before=cursor_before,
            error=validation_error or "Batch validation failed",
            duration_ms=_now_ms() - start_ms,
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
    snapshot = create_sync_snapshot(conn, SyncSnapshot(
        source=source,
        sync_mode=sync_mode,
        status="running",
        cursor_before=cursor_before,
        metadata=fetch_result.metadata,
    ))
    conn.commit()

    # Step 5.2: SAVEPOINT before processing records
    with conn.cursor() as cur:
        cur.execute("SAVEPOINT before_records;")

    # Step 5.3: Process all records
    result = ProcessResult()
    for record in records:
        try:
            success, is_new, error = adapter.process_record(conn, record, snapshot.id)
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

            complete_sync_snapshot(
                conn, snapshot.id,
                status="completed",
                records_processed=result.processed,
                records_created=result.created,
                records_updated=result.created,
                records_unchanged=result.unchanged,
                records_failed=0,
                cursor_after=cursor_after,
            )
            sync_state = update_sync_state(
                conn, source,
                cursor_value=cursor_after,
                last_snapshot_id=snapshot.id,
                success=True,
            )
            _update_operational_fields(conn, source, snapshot.id, _now_ms() - start_ms, result.processed)
            conn.commit()
        except Exception as e:
            with conn.cursor() as cur:
                cur.execute("ROLLBACK TO SAVEPOINT before_records;")
            error_msg = f"Activation failed: {e}"
            logger.error("Sync activation failed for %s: %s", source, e)
            try:
                complete_sync_snapshot(
                    conn, snapshot.id,
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
                    last_snapshot_id=snapshot.id,
                    success=False,
                    error=error_msg,
                )
                conn.commit()
            except Exception as ex:
                conn.rollback()
                _record_failure(conn, source, f"Failed to record failure metadata: {ex}", start_ms)

            return SyncOutcome(
                source=source,
                success=False,
                snapshot_id=snapshot.id,
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
        try:
            complete_sync_snapshot(
                conn, snapshot.id,
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
                last_snapshot_id=snapshot.id,
                success=False,
                error=f"{result.failed} records failed",
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            _record_failure(conn, source, f"Failed to record failure metadata: {e}", start_ms)

    return SyncOutcome(
        source=source,
        success=result.failed == 0,
        snapshot_id=snapshot.id,
        sync_mode=sync_mode,
        records_processed=result.processed,
        records_created=result.created if result.failed == 0 else 0,
        records_updated=result.created if result.failed == 0 else 0,
        records_unchanged=result.unchanged if result.failed == 0 else 0,
        records_failed=result.failed,
        cursor_before=cursor_before,
        cursor_after=cursor_after if result.failed == 0 else None,
        error="; ".join(result.errors[:5]) if result.errors else None,
        duration_ms=_now_ms() - start_ms,
    )


def _record_failure(conn: psycopg.Connection, source: str, error: str, start_ms: int) -> None:
    """Record a sync failure in sync_state without advancing cursor."""
    try:
        update_sync_state(conn, source, success=False, error=error)
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
