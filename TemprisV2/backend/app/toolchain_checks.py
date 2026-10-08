# backend/app/toolchain_checks.py
"""Lifecycle tracking for collector toolchain update checks.

Dispatch alone is not completion: a check row starts as 'dispatched' and only
a real SCOUT_CAPABILITIES response (or an explicit failure) moves it out of
that state. Stale dispatches expire to 'timed_out'; a newer request
supersedes a still-pending one.
"""
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.db import get_db_connection

logger = logging.getLogger("toolchain_checks")

CHECK_TIMEOUT_SECONDS = 90

_PENDING_STATUSES = ("dispatched",)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def begin_check(tenant_id: uuid.UUID, collector_id: uuid.UUID, requested_by: Optional[str]) -> dict:
    """Supersede any pending check and record a new dispatched check row."""
    check_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE collector_toolchain_checks
                SET status = 'superseded', finished_at = now()
                WHERE collector_id = %s AND status = ANY(%s);
                """,
                (str(collector_id), list(_PENDING_STATUSES)),
            )
            cur.execute(
                """
                INSERT INTO collector_toolchain_checks
                    (tenant_id, collector_id, check_id, status, requested_by, timeout_at)
                VALUES (%s, %s, %s, 'dispatched', %s, %s)
                RETURNING check_id, status, requested_at, timeout_at;
                """,
                (str(tenant_id), str(collector_id), str(check_id), requested_by,
                 _now() + timedelta(seconds=CHECK_TIMEOUT_SECONDS)),
            )
            row = cur.fetchone()
        conn.commit()
    return dict(row)


def expire_stale_checks(cur, collector_id: uuid.UUID) -> None:
    cur.execute(
        """
        UPDATE collector_toolchain_checks
        SET status = 'timed_out', finished_at = now()
        WHERE collector_id = %s AND status = 'dispatched' AND timeout_at < now();
        """,
        (str(collector_id),),
    )


def latest_check(cur, tenant_id: uuid.UUID, collector_id: uuid.UUID) -> Optional[dict]:
    expire_stale_checks(cur, collector_id)
    cur.execute(
        """
        SELECT check_id, status, requested_at, finished_at, result
        FROM collector_toolchain_checks
        WHERE collector_id = %s AND tenant_id = %s
        ORDER BY requested_at DESC
        LIMIT 1;
        """,
        (str(collector_id), str(tenant_id)),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def complete_check(collector_id: uuid.UUID, capabilities: dict) -> None:
    """Complete the pending check when the collector's SCOUT_CAPABILITIES response
    arrives. A generic heartbeat never reaches this path. A new-collector payload
    may carry an explicit `update_check` outcome; absent that, arrival of the
    capabilities frame after a dispatched CHECK_UPDATE is itself the result."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, check_id FROM collector_toolchain_checks
                    WHERE collector_id = %s AND status = 'dispatched'
                    ORDER BY requested_at DESC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED;
                    """,
                    (str(collector_id),),
                )
                row = cur.fetchone()
                if not row:
                    return
                update_check = capabilities.get("update_check") if isinstance(capabilities, dict) else None
                succeeded = True
                error = None
                if isinstance(update_check, dict):
                    succeeded = bool(update_check.get("succeeded", True))
                    error = update_check.get("error")
                result = {
                    "received_at": _now().isoformat(),
                    "update_status": capabilities.get("update_status"),
                    "last_checked_at": capabilities.get("last_checked_at"),
                    "nmap_version": (capabilities.get("nmap") or {}).get("version")
                        if isinstance(capabilities.get("nmap"), dict) else None,
                    "nuclei_version": (capabilities.get("nuclei") or {}).get("version")
                        if isinstance(capabilities.get("nuclei"), dict) else None,
                    "templates_version": (capabilities.get("nuclei_templates") or {}).get("version")
                        if isinstance(capabilities.get("nuclei_templates"), dict) else None,
                    "update_check": update_check,
                }
                cur.execute(
                    """
                    UPDATE collector_toolchain_checks
                    SET status = %s, finished_at = now(), result = %s
                    WHERE id = %s;
                    """,
                    ("failed" if not succeeded else "completed",
                     json.dumps({**result, **({"error": error} if error else {})}),
                     str(row["id"])),
                )
            conn.commit()
    except Exception:
        logger.exception("Failed to persist toolchain check completion for collector %s", collector_id)


def fail_pending_check(collector_id: uuid.UUID, error: str) -> None:
    """Mark a pending check failed (e.g. the collector disconnected mid-check)."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE collector_toolchain_checks
                    SET status = 'failed', finished_at = now(), result = %s
                    WHERE collector_id = %s AND status = 'dispatched';
                    """,
                    (json.dumps({"error": error}), str(collector_id)),
                )
            conn.commit()
    except Exception:
        logger.debug("Could not fail pending toolchain check for collector %s", collector_id)
