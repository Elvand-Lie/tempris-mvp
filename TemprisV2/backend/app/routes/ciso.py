# backend/app/routes/ciso.py
"""
CISO / SPOTLIGHT — Executive View REST API (PRD-000 v1.11 Ch.10).

Read-only consumer, module-gated (SPOTLIGHT entitlement; platform sessions
blocked at the root). Reads are analyst+; snapshot capture is admin+ (PRD:
"manual capture, admin+"). Every read is read-through inside ONE
REPEATABLE READ boundary — the same PATCH-13 shape as the Ch.3/Ch.7 reads —
and never writes upstream state. The module's only owned state is its own
append-only posture_snapshots.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import AuthContext, require_module, require_roles
from app.ciso import service
from app.ciso.errors import SnapshotNotFoundError
from app.db import get_db_connection
from app.exposure.exceptions import ExposureConflictError
from app.exposure.tes_read_model import _jsonify

router = APIRouter(
    prefix="/api/ciso",
    tags=["CISO / SPOTLIGHT"],
    dependencies=[Depends(require_module("SPOTLIGHT"))],
)


def _require_read(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


def _require_capture_admin(
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"])),
) -> AuthContext:
    return auth


def _snapshot_boundary(conn) -> None:
    """One REPEATABLE READ boundary established BEFORE the service's first
    query — the shared read-through contract."""
    with conn.cursor() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")


@router.get(
    "/summary",
    status_code=status.HTTP_200_OK,
    summary="Executive posture summary (read-only projection; never a source of record)",
)
def get_summary(auth: AuthContext = Depends(_require_read)):
    """Severe-exposure tiles (counts + maxima by score state — FINAL and
    PROVISIONAL rendered separately, never a mean), workflow posture, the
    coverage/quality strip, and the upstream decision domains. A domain that
    is not present renders 'unavailable' — never zero."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            as_of = datetime.now(timezone.utc)
            payload, _refs = service.build_executive_summary(
                conn, auth.tenant_id, as_of=as_of
            )
            payload["trend"] = service.snapshot_trend(conn, auth.tenant_id)
            conn.commit()
            return _jsonify(payload)
    except ExposureConflictError as e:
        # A supersession raced the snapshot boundary mid-summary — the read
        # never claims a mixed result; the client retries.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.post(
    "/snapshots",
    status_code=status.HTTP_201_CREATED,
    summary="Capture one append-only posture snapshot (admin+)",
)
def capture_snapshot(auth: AuthContext = Depends(_require_capture_admin)):
    """Manual capture (scheduled cadence is an OPEN decision). The snapshot
    seals the summary payload with a hash and the upstream source identities;
    history is never overwritten and the capture is audited."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            snapshot = service.capture_snapshot(
                conn, auth.tenant_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(snapshot)
    except ExposureConflictError as e:
        # Failed capture leaves NO snapshot row and NO upstream change — the
        # capture is atomic with its boundary.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.get(
    "/snapshots",
    status_code=status.HTTP_200_OK,
    summary="List posture snapshots (bounded, newest first)",
)
def list_snapshots(
    limit: int = Query(50, ge=1, le=service.SNAPSHOT_LIST_LIMIT),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(_require_read),
):
    with get_db_connection() as conn:
        result = service.list_snapshots(
            conn, auth.tenant_id, limit=limit, offset=offset
        )
        conn.commit()
    return _jsonify(result)


@router.get(
    "/snapshots/{snapshot_id}",
    status_code=status.HTTP_200_OK,
    summary="One sealed posture snapshot",
)
def get_snapshot(
    snapshot_id: uuid.UUID,
    auth: AuthContext = Depends(_require_read),
):
    try:
        with get_db_connection() as conn:
            snapshot = service.get_snapshot(conn, auth.tenant_id, snapshot_id)
            conn.commit()
            return _jsonify(snapshot)
    except SnapshotNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": e.code, "message": str(e)},
        )


@router.get(
    "/trend",
    status_code=status.HTTP_200_OK,
    summary="Trend deltas between the two most recent snapshots",
)
def get_trend(auth: AuthContext = Depends(_require_read)):
    with get_db_connection() as conn:
        trend = service.snapshot_trend(conn, auth.tenant_id)
        conn.commit()
    return _jsonify(trend)
