# backend/app/routes/spectrum.py
"""
SPECTRUM — Confirmed-Exposure Workbench REST API (PRD-000 v1.11 Ch.7).

Module-gated (SPECTRUM entitlement, tenant-level; platform sessions blocked
at the root), analyst+ for every workflow action. Every read is read-through
to the Ch.3 recompute — there is no local score state to corrupt.

Business Impact editing: SPECTRUM owns the analyst edit SURFACE at the
exposure grain, which is the existing Ch.3 route
``POST /api/exposure/{exposure_id}/business-impact`` (versioned ledger, who/
when, optional reason). The workbench renders the current assessment from the
same ledger; storage and score semantics stay Ch.3's.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth import AuthContext, require_module, require_roles
from app.db import get_db_connection
from app.exposure.exceptions import ExposureConflictError, ExposureNotFoundError
from app.exposure.tes_read_model import _jsonify
from app.spectrum import service
from app.edip.errors import (
    EdipConflictError,
    EdipExposureNotFoundError,
    EdipWorkflowError,
)
from app.spectrum.errors import SpectrumExposureNotFoundError, SpectrumWorkflowError

router = APIRouter(
    prefix="/api/spectrum",
    tags=["SPECTRUM"],
    dependencies=[Depends(require_module("SPECTRUM"))],
)


def _require_analyst(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


class AssignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee: str = Field(..., min_length=1)


class AnalysisStateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_state: str
    note: Optional[str] = None


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(..., min_length=1)


class RequestNoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: Optional[str] = None


def _snapshot_boundary(conn):
    """One REPEATABLE READ boundary established BEFORE the service's first
    query — the read-through contract shared with the Ch.3 TES reads."""
    with conn.cursor() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")


@router.get(
    "/queue",
    status_code=status.HTTP_200_OK,
    summary="The operational queue over current exposures (read-through TES)",
)
def get_queue(
    finding_id: Optional[uuid.UUID] = Query(None),
    asset_id: Optional[uuid.UUID] = Query(None),
    analysis_state: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(_require_analyst),
):
    """Current confirmed exposures on active assets only — the V1 scope-label
    taxonomy is NOT carried. Each row summarizes its own recomputed TES
    (state / value / display_value / formula_version), the workflow fields,
    and the current Business Impact. UNSCOREABLE rows render explicitly and
    are never hidden (Ch.3 forbids hiding them)."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            as_of = datetime.now(timezone.utc)
            payload = service.get_spectrum_queue(
                conn, auth.tenant_id, as_of=as_of,
                finding_id=finding_id, asset_id=asset_id,
                analysis_state=analysis_state, assigned_to=assigned_to,
                limit=limit, offset=offset,
            )
            conn.commit()
            return _jsonify(payload)
    except SpectrumWorkflowError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )
    except ExposureConflictError as e:
        # A supersession raced the snapshot boundary mid-queue — the read
        # never claims a mixed result; the client retries.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.get(
    "/exposures/{exposure_id}",
    status_code=status.HTTP_200_OK,
    summary="Workbench detail: decomposition + workflow + history + Business Impact",
)
def get_exposure_detail(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            as_of = datetime.now(timezone.utc)
            payload = service.get_spectrum_exposure(
                conn, auth.tenant_id, exposure_id, as_of=as_of
            )
            conn.commit()
            return _jsonify(payload)
    except ExposureNotFoundError:
        # the Ch.3 read contract: unknown, cross-tenant, non-current, and
        # inactive-asset exposures are the same fail-closed 404
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.get(
    "/exposures/{exposure_id}/history",
    status_code=status.HTTP_200_OK,
    summary="The workflow journal (readable for any tenant-scoped exposure)",
)
def get_exposure_history(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            history = service.get_spectrum_history(conn, auth.tenant_id, exposure_id)
            conn.commit()
            return _jsonify({"exposure_id": exposure_id, "history": history})
    except SpectrumExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")


@router.post(
    "/exposures/{exposure_id}/assign",
    status_code=status.HTTP_200_OK,
    summary="Assign the exposure to an analyst (exposure grain)",
)
def assign_exposure(
    exposure_id: uuid.UUID,
    payload: AssignIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            workflow = service.assign_exposure(
                conn, auth.tenant_id, exposure_id, payload.assignee,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"exposure_id": exposure_id, "workflow": workflow})
    except SpectrumExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except SpectrumWorkflowError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/exposures/{exposure_id}/unassign",
    status_code=status.HTTP_200_OK,
    summary="Clear the assignment (analysis_state untouched)",
)
def unassign_exposure(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            workflow = service.unassign_exposure(
                conn, auth.tenant_id, exposure_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"exposure_id": exposure_id, "workflow": workflow})
    except SpectrumExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")


@router.post(
    "/exposures/{exposure_id}/analysis-state",
    status_code=status.HTTP_200_OK,
    summary="Set the analyst process state (new / assigned / in_analysis / action_required)",
)
def set_analysis_state(
    exposure_id: uuid.UUID,
    payload: AnalysisStateIn,
    auth: AuthContext = Depends(_require_analyst),
):
    """``analysis_state`` is the analyst PROCESS state — deliberately never
    named 'status' (Ch.3 owns the exposure lifecycle); the two never gate
    each other. Every change lands on the journal with who/when/from/to."""
    try:
        with get_db_connection() as conn:
            workflow = service.set_analysis_state(
                conn, auth.tenant_id, exposure_id, payload.analysis_state,
                actor_id=auth.actor_id, actor_role=auth.role, note=payload.note,
            )
            conn.commit()
            return _jsonify({"exposure_id": exposure_id, "workflow": workflow})
    except SpectrumExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except SpectrumWorkflowError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/exposures/{exposure_id}/notes",
    status_code=status.HTTP_201_CREATED,
    summary="Add a workflow note",
)
def add_note(
    exposure_id: uuid.UUID,
    payload: NoteIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            service.add_workflow_note(
                conn, auth.tenant_id, exposure_id, payload.note,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return {"exposure_id": exposure_id, "ok": True}
    except SpectrumExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except SpectrumWorkflowError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/exposures/{exposure_id}/strike-request",
    status_code=status.HTTP_410_GONE,
    summary="Superseded: the engagement-scoped STRIKE model is retired (PRD v1.12)",
)
def request_strike(
    exposure_id: uuid.UUID,
    payload: Optional[RequestNoteIn] = None,
    auth: AuthContext = Depends(_require_analyst),
):
    """The v1.12 toolbox model supersedes the engagement-scoped chain: no NEW
    legacy engagement state may be created. The corrected Ch.7 handoff is an
    OPTIONAL pre-filled run request in the STRIKE toolbox console; historical
    rows are retained read-only."""
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "code": "legacy_strike_model_superseded",
            "message": (
                "The engagement-scoped STRIKE model is superseded by the "
                "toolbox run model (PRD v1.12); existing history is "
                "retained read-only"
            ),
        },
    )


@router.post(
    "/exposures/{exposure_id}/edip-handoff",
    status_code=status.HTTP_201_CREATED,
    summary="Hand off to EDIP (action_required + a Needs-Decision decision)",
)
def request_edip_handoff(
    exposure_id: uuid.UUID,
    payload: Optional[RequestNoteIn] = None,
    auth: AuthContext = Depends(_require_analyst),
):
    """The explicit action-required transition: analysis_state becomes
    'action_required' and the EDIP decision is created in Needs-Decision
    state and consumes the handoff ATOMICALLY — retryable, upstream truth
    intact. Manual at v1; auto-handoff policy is reserved (§3.6.6 #9). One
    decision per exposure (409 on a second while one stands). The REPEATABLE
    READ boundary is established first so the sealed score snapshot is one
    coherent source view (PATCH-13)."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
            result = service.request_edip_handoff(
                conn, auth.tenant_id, exposure_id,
                actor_id=auth.actor_id, actor_role=auth.role,
                note=payload.note if payload else None,
            )
            conn.commit()
            return _jsonify({
                "exposure_id": exposure_id,
                "edip_handoff": result["handoff"],
                "decision": result["decision"],
                "workflow": result["workflow"],
            })
    except SpectrumExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except EdipExposureNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except EdipConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "edip_conflict", "message": str(e)},
        )
    except EdipWorkflowError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )
    except SpectrumWorkflowError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )
