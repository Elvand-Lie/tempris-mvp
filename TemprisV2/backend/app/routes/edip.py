# backend/app/routes/edip.py
"""
EDIP — Remediation & Risk Decisions REST API (PRD-000 v1.11 Ch.8).

Module-gated (EDIP entitlement, tenant-level; platform sessions blocked at
the root). Decision creation analyst+; transitions by owner or admin;
closure requires verification evidence; accepted risk is dual-controlled
(propose = analyst+, decide/apply = admin+ via the Ch.5 primitive).

Snapshot-sealing routes establish ONE REPEATABLE READ boundary as the FIRST
statement of their transaction, so every sealed payload is one coherent
``as_of`` source view (PATCH-13) — the same boundary contract as the Ch.3
TES reads and the Ch.7 workbench.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth import AuthContext, require_module, require_roles
from app.approvals import (
    ApprovalAuthorityError,
    ApprovalDomainError,
    ApprovalSubjectError,
)
from app.db import get_db_connection
from app.edip import service
from app.edip.errors import (
    EdipConflictError,
    EdipDecisionNotFoundError,
    EdipExposureNotFoundError,
    EdipWorkflowError,
)
from app.exposure.exceptions import ExposureConflictError
from app.exposure.tes_read_model import _jsonify

router = APIRouter(
    prefix="/api/edip",
    tags=["EDIP"],
    dependencies=[Depends(require_module("EDIP"))],
)


def _require_analyst(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


def _require_admin(
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"])),
) -> AuthContext:
    return auth


def _require_owner_or_admin(
    decision_id: uuid.UUID,
    auth: AuthContext,
) -> None:
    """Transitions are by the decision's owner or an admin (Ch.8 security
    boundaries). Analysts without ownership are refused 403."""
    if auth.role in ("admin", "superadmin"):
        return
    with get_db_connection() as conn:
        owner = service.decision_owner(conn, auth.tenant_id, decision_id)
        conn.commit()
    if owner != auth.actor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the decision owner or an admin may transition it.",
        )


def _snapshot_boundary(conn):
    """One REPEATABLE READ boundary established BEFORE the transaction's
    first query — the coherent-source-view contract shared with the Ch.3 TES
    reads (PATCH-13)."""
    with conn.cursor() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")


# --- request shapes -------------------------------------------------------


class DecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exposure_id: uuid.UUID
    decision_type: str
    owner: Optional[str] = None
    rationale: Optional[str] = None
    plan: Optional[str] = None
    due_at: Optional[datetime] = None
    handoff_id: Optional[uuid.UUID] = None
    previous_decision_id: Optional[uuid.UUID] = None


class TransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: str
    note: Optional[str] = None


class DeferIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(..., min_length=1)
    review_due_at: datetime
    mitigation_type: Optional[str] = None


class AcceptRiskProposeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(..., min_length=1)
    review_due_at: datetime
    mitigation_type: Optional[str] = None


class AcceptRiskDecideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str


class VerificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_kind: str
    evidence_ref: dict
    verdict: str
    note: Optional[str] = None


class ReopenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1)


def _raise_domain_error(e: Exception):
    if isinstance(e, EdipDecisionNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    if isinstance(e, EdipExposureNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    if isinstance(e, EdipWorkflowError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )
    if isinstance(e, (EdipConflictError, ExposureConflictError)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": getattr(e, "code", "exposure_conflict"), "message": str(e)},
        )
    # Chapter 5 primitive refusals surface with their stable codes — a
    # self-approval or a replayed apply is a visible conflict, never a 500.
    if isinstance(e, ApprovalSubjectError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "approval_subject", "message": str(e)},
        )
    if isinstance(e, ApprovalAuthorityError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "approval_authority", "message": str(e)},
        )
    if isinstance(e, ApprovalDomainError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": getattr(e, "code", "approval_refused"), "message": str(e)},
        )
    raise e


# --- endpoints ------------------------------------------------------------


@router.get(
    "/queue",
    status_code=status.HTTP_200_OK,
    summary="The EDIP queue: current non-terminal decisions at effective state",
)
def get_queue(
    owner: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(_require_analyst),
):
    """Accepted-risk and deferred decisions stay in the queue — they are
    ACTIVE dispositions (the exposure stays confirmed and visible). Review
    expiry materializes on read; overdue due-dates derive at read (no
    scheduler, rule 6)."""
    try:
        with get_db_connection() as conn:
            payload = service.list_open_decisions(
                conn, auth.tenant_id,
                actor_id=auth.actor_id, owner=owner, state=state,
                limit=limit, offset=offset,
            )
            conn.commit()
            return _jsonify(payload)
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/exposures/{exposure_id}/decisions",
    status_code=status.HTTP_200_OK,
    summary="The full decision history for one exposure",
)
def get_exposure_decisions(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            payload = service.list_exposure_decisions(
                conn, auth.tenant_id, exposure_id, actor_id=auth.actor_id
            )
            conn.commit()
            return _jsonify({"exposure_id": exposure_id, "decisions": payload})
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/decisions/{decision_id}",
    status_code=status.HTTP_200_OK,
    summary="Decision detail: effective state, revision chain, verifications",
)
def get_decision(
    decision_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            payload = service.get_decision(
                conn, auth.tenant_id, decision_id, actor_id=auth.actor_id
            )
            conn.commit()
            return _jsonify(payload)
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions",
    status_code=status.HTTP_201_CREATED,
    summary="Create a decision (Needs-Decision) — seals the score snapshot it consumes",
)
def create_decision(
    payload: DecisionCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    """From a SPECTRUM handoff (handoff_id) or directly on a current
    exposure. Missing decomposition payload at handoff ⇒ no decision (the
    snapshot seal fails closed)."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            decision = service.create_decision(
                conn, auth.tenant_id,
                exposure_id=payload.exposure_id,
                decision_type=payload.decision_type,
                owner=payload.owner or auth.actor_id,
                rationale=payload.rationale,
                plan=payload.plan,
                due_at=payload.due_at,
                handoff_id=payload.handoff_id,
                previous_decision_id=payload.previous_decision_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"decision": decision})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/transition",
    status_code=status.HTTP_200_OK,
    summary="CAS lifecycle transition (planned / in_progress / mitigated / verification)",
)
def transition_decision(
    decision_id: uuid.UUID,
    payload: TransitionIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        _require_owner_or_admin(decision_id, auth)
        with get_db_connection() as conn:
            decision = service.transition_decision(
                conn, auth.tenant_id, decision_id, payload.to,
                actor_id=auth.actor_id, actor_role=auth.role, note=payload.note,
            )
            conn.commit()
            return _jsonify({"decision": decision})
    except HTTPException:
        raise
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/defer",
    status_code=status.HTTP_200_OK,
    summary="Defer (active disposition, mandatory review date, fresh snapshot)",
)
def defer_decision(
    decision_id: uuid.UUID,
    payload: DeferIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        _require_owner_or_admin(decision_id, auth)
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            decision = service.defer_decision(
                conn, auth.tenant_id, decision_id,
                rationale=payload.rationale,
                review_due_at=payload.review_due_at,
                mitigation_type=payload.mitigation_type,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"decision": decision})
    except HTTPException:
        raise
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/verifications",
    status_code=status.HTTP_201_CREATED,
    summary="Attach verification evidence (SCOUT job / STRIKE artifact / attestation)",
)
def record_verification(
    decision_id: uuid.UUID,
    payload: VerificationIn,
    auth: AuthContext = Depends(_require_analyst),
):
    """Ch.8's own evidence class — remediation proof lives HERE, bound to the
    decision revision and the exposure's current row version (PATCH-09)."""
    try:
        _require_owner_or_admin(decision_id, auth)
        with get_db_connection() as conn:
            result = service.record_verification(
                conn, auth.tenant_id, decision_id,
                evidence_kind=payload.evidence_kind,
                evidence_ref=payload.evidence_ref,
                verdict=payload.verdict,
                note=payload.note,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(result)
    except HTTPException:
        raise
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/close",
    status_code=status.HTTP_200_OK,
    summary="Verified closure — one version-checked transaction with the Ch.3 exposure resolve",
)
def close_decision(
    decision_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    """Emits the transition intent THROUGH the Ch.3 exposure service (the
    only writer of exposure status); compare-and-set on both states
    (PATCH-09). Any refusal rolls the whole boundary back."""
    try:
        _require_owner_or_admin(decision_id, auth)
        with get_db_connection() as conn:
            decision = service.close_decision(
                conn, auth.tenant_id, decision_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"decision": decision})
    except HTTPException:
        raise
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/reopen",
    status_code=status.HTTP_200_OK,
    summary="Decision-level reopen (dispute) — the same decision, exposure still confirmed",
)
def reopen_decision(
    decision_id: uuid.UUID,
    payload: ReopenIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        _require_owner_or_admin(decision_id, auth)
        with get_db_connection() as conn:
            decision = service.reopen_decision(
                conn, auth.tenant_id, decision_id,
                reason=payload.reason,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"decision": decision})
    except HTTPException:
        raise
    except Exception as e:
        _raise_domain_error(e)


# --- accepted risk (dual control — decided) -------------------------------


@router.post(
    "/decisions/{decision_id}/accept-risk/propose",
    status_code=status.HTTP_201_CREATED,
    summary="Propose accepted risk (dual-controlled; an admin must decide)",
)
def propose_accept_risk(
    decision_id: uuid.UUID,
    payload: AcceptRiskProposeIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            proposal = service.propose_accepted_risk(
                conn, auth.tenant_id, decision_id,
                rationale=payload.rationale,
                review_due_at=payload.review_due_at,
                mitigation_type=payload.mitigation_type,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(proposal)
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/accept-risk/decide",
    status_code=status.HTTP_200_OK,
    summary="Decide the accepted-risk proposal (admin+; approver ≠ proposer)",
)
def decide_accept_risk(
    decision_id: uuid.UUID,
    payload: AcceptRiskDecideIn,
    auth: AuthContext = Depends(_require_admin),
):
    try:
        with get_db_connection() as conn:
            result = service.decide_accepted_risk(
                conn, auth.tenant_id, decision_id,
                decision=payload.decision,
                approver_id=auth.actor_id, approver_role=auth.role,
            )
            conn.commit()
            return _jsonify({"approval": result})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/decisions/{decision_id}/accept-risk/apply",
    status_code=status.HTTP_200_OK,
    summary="Apply the approved acceptance — new revision, fresh snapshot, single-use",
)
def apply_accept_risk(
    decision_id: uuid.UUID,
    auth: AuthContext = Depends(_require_admin),
):
    """Approve + apply may also be one atomic pair: an admin who both decides
    and applies calls decide (approved) then apply in sequence — two requests,
    or use the decide endpoint followed by this one in immediate succession.
    The primitive enforces approver ≠ proposer and approver-executes-apply."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            result = service.apply_accepted_risk(
                conn, auth.tenant_id, decision_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"apply": result})
    except Exception as e:
        _raise_domain_error(e)
