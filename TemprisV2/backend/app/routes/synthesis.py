# backend/app/routes/synthesis.py
"""
SYNTHESIS — Deterministic Correlation REST API (PRD-000 v1.11 Ch.12).

Module-gated (SYNTHESIS entitlement; platform sessions blocked at the
root), analyst+ reads, tenant-scoped joins. GET-only: v1 is read-time joins
ONLY (the frozen decision) — the API writes nothing, has no snapshot or
materialization surface, and has no AI/narrative endpoints (those are
Ch.11's SPEAK, which consumes these outputs).

Every answer is computed inside ONE REPEATABLE READ boundary with a single
``as_of`` (the shared PATCH-13 read shape) and carries its own deterministic
definition, per-domain availability, and source-object links.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import AuthContext, require_module, require_roles
from app.db import get_db_connection
from app.exposure.exceptions import ExposureConflictError
from app.exposure.tes_read_model import _jsonify
from app.synthesis import service

router = APIRouter(
    prefix="/api/synthesis",
    tags=["SYNTHESIS"],
    dependencies=[Depends(require_module("SYNTHESIS"))],
)


def _require_analyst(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


def _answer(join: Callable) -> dict:
    """Run one correlation join inside its boundary. ``join`` receives the
    captured ``as_of`` and the open connection."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;"
                )
            as_of = datetime.now(timezone.utc)
            answer = join(conn, as_of)
            conn.commit()
            return _jsonify(answer)
    except ExposureConflictError as e:
        # A supersession raced the boundary mid-join — the answer never
        # claims a mixed-time result; the client retries.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.get(
    "/unremediated-serious",
    status_code=status.HTTP_200_OK,
    summary="Unremediated serious exposures (read-time join: TES ⋈ SPECTRUM workflow)",
)
def unremediated_serious(
    threshold: Decimal = Query(service.SERIOUS_TES_THRESHOLD, ge=0, le=10),
    limit: int = Query(service.QUERY_LIMIT, ge=1, le=service.QUERY_LIMIT),
    auth: AuthContext = Depends(_require_analyst),
):
    return _answer(
        lambda conn, as_of: service.unremediated_serious(
            conn, auth.tenant_id, as_of=as_of, threshold=threshold, limit=limit,
        )
    )


@router.get(
    "/accepted-risks-vs-obligations",
    status_code=status.HTTP_200_OK,
    summary="Accepted risks ⋈ obligations (degrades loudly while Ch.8/Ch.9 are absent)",
)
def accepted_risks_vs_obligations(
    auth: AuthContext = Depends(_require_analyst),
):
    return _answer(
        lambda conn, as_of: service.accepted_risks_vs_obligations(
            conn, auth.tenant_id, as_of=as_of,
        )
    )


@router.get(
    "/remediation-recurrence",
    status_code=status.HTTP_200_OK,
    summary="Findings that return (PATCH-14: resolved predecessors of the same tuple)",
)
def remediation_recurrence(
    limit: int = Query(service.QUERY_LIMIT, ge=1, le=service.QUERY_LIMIT),
    auth: AuthContext = Depends(_require_analyst),
):
    return _answer(
        lambda conn, as_of: service.remediation_recurrence(
            conn, auth.tenant_id, as_of=as_of, limit=limit,
        )
    )


@router.get(
    "/coverage-gaps",
    status_code=status.HTTP_200_OK,
    summary="Evidence strength vs coverage gaps (UNSCOREABLE renders, never hides)",
)
def coverage_gaps(
    limit: int = Query(service.QUERY_LIMIT, ge=1, le=service.QUERY_LIMIT),
    auth: AuthContext = Depends(_require_analyst),
):
    return _answer(
        lambda conn, as_of: service.coverage_gaps(
            conn, auth.tenant_id, as_of=as_of, limit=limit,
        )
    )


@router.get(
    "/weakness-recurrence",
    status_code=status.HTTP_200_OK,
    summary="Recurring weakness classes across assets (max per state, never a mean)",
)
def weakness_recurrence(
    min_assets: int = Query(2, ge=2, le=100),
    limit: int = Query(service.QUERY_LIMIT, ge=1, le=service.QUERY_LIMIT),
    auth: AuthContext = Depends(_require_analyst),
):
    return _answer(
        lambda conn, as_of: service.weakness_recurrence(
            conn, auth.tenant_id, as_of=as_of, min_assets=min_assets, limit=limit,
        )
    )
