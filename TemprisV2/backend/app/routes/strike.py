# backend/app/routes/strike.py
"""
STRIKE — Offensive Security Workspace REST API (PRD-000 v1.11 Ch.4).

Module-gated (STRIKE entitlement, tenant-level; platform sessions blocked at
the root, the V2 pattern). Requests are analyst+; approvals, revocations,
aborts, reconciliation, and relay deployment are admin+ — every approval via
the Ch.5 dual-control primitive (approver ≠ proposer, payload-bound,
single-use apply). V1's auto-signing quick-scan has no successor here.

DOMAIN-LOCAL ROUTER: this module is self-contained and is NOT wired into
app.main by this changeset (parallel-safety). Final wiring is two lines in
app/main.py:

    from app.routes.strike import router as strike_router
    ...
    app.include_router(strike_router)

The router import registers the Ch.5 approval subject types
(app.strike.approvals) as an import side effect.
"""
from __future__ import annotations

import base64
import inspect
import uuid
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.approvals import (
    ApprovalAlreadyAppliedError,
    ApprovalAuthorityError,
    ApprovalDualControlError,
    ApprovalNotFoundError,
    ApprovalPayloadMismatchError,
    ApprovalStaleSubjectError,
    ApprovalStateError,
    ApprovalSubjectError,
    decide_and_apply,
)
from app.auth import AuthContext, require_module, require_roles
from app.db import get_db_connection
from app.exposure.exceptions import (
    EntityNotFoundError,
    EvidencePolicyError,
    ExposureConflictError,
    ExposureDomainError,
    ExposureNotFoundError,
    TenantMismatchError,
)
from app.intake.errors import IntakeEventConflictError
from app.strike import evidence as strike_evidence
from app.strike import operations as strike_operations
from app.strike import relays as strike_relays
from app.strike import service as strike_service
from app.strike import workspaces as strike_workspaces

# import side effect: registers the strike_engagement / strike_target
# subject types with the Chapter 5 approval primitive
from app.strike.approvals import register as _register_approval_subjects
from app.strike.errors import (
    AbilityNotAllowlistedError,
    EngagementExpiredError,
    EngagementNotFoundError,
    EngagementStateError,
    EvidencePromotionError,
    OperationNotFoundError,
    OperationStateError,
    OutcomeClassificationError,
    OutputBoundError,
    RelayNotFoundError,
    RelayStateError,
    StrikeDomainError,
    StrikeNotFoundError,
    TargetExpiredError,
    TargetNotFoundError,
    TargetStateError,
    WorkspaceCardinalityError,
    WorkspaceNotFoundError,
    WorkspaceProviderUnavailableError,
    WorkspaceStateError,
)
from app.strike.models import (
    ArtifactStore,
    DiscoveryReport,
    EngagementAbort,
    EngagementCreate,
    EvidencePromote,
    OperationComplete,
    OperationDispatch,
    RelayRevoke,
    TargetCreate,
    WorkspaceReserve,
)

# registration side effect: the strike_engagement / strike_target subject
# types become consumable the moment this router module is imported — which
# is exactly when main.py (or a test app) mounts the STRIKE API
_register_approval_subjects()


class DeciderIn(BaseModel):
    """The decision request. The approver identity is the AUTHENTICATED
    actor (server-owned) — the client never names an approver."""

    model_config = ConfigDict(extra="forbid")


class PairRelayIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pairing_secret: str = Field(..., min_length=1)


class ReconcileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed_fenced: bool
    note: str = Field(..., min_length=1, max_length=4000)

router = APIRouter(
    prefix="/api/strike",
    tags=["STRIKE"],
    dependencies=[Depends(require_module("STRIKE"))],
)


def _require_analyst(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


def _require_admin(
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"])),
) -> AuthContext:
    return auth


# ---------------------------------------------------------------------------
# Error mapping — named, fail-closed, no disclosure
# ---------------------------------------------------------------------------

_REFUSAL_422 = (
    AbilityNotAllowlistedError,
    EngagementStateError,      # wrong-state command shape
    EngagementExpiredError,    # derived-expiry enforcement (named subclass)
    EvidencePromotionError,
    OperationStateError,
    OutcomeClassificationError,
    OutputBoundError,
    RelayStateError,
    TargetStateError,
    TargetExpiredError,
    WorkspaceStateError,
    EvidencePolicyError,       # Ch.3 policy refusals surface verbatim
)

_CONFLICT_409 = (
    ApprovalAlreadyAppliedError,
    ApprovalPayloadMismatchError,
    ApprovalStaleSubjectError,
    ApprovalStateError,
    ExposureConflictError,
    IntakeEventConflictError,
    WorkspaceCardinalityError,
)

_FORBIDDEN_403 = (
    ApprovalAuthorityError,
    ApprovalDualControlError,
    WorkspaceProviderUnavailableError,
)


#: stable wire codes for the primitive's error classes (the primitive
#: itself is Ch.5's module — the STRIKE surface names its own codes)
_APPROVAL_ERROR_CODES = {
    ApprovalDualControlError: "approval_self_approval_refused",
    ApprovalAuthorityError: "approval_authority_missing",
    ApprovalAlreadyAppliedError: "approval_already_applied",
    ApprovalStaleSubjectError: "approval_stale_subject",
    ApprovalPayloadMismatchError: "approval_payload_mismatch",
    ApprovalStateError: "approval_state",
}


def _map_domain_errors(exc: Exception) -> HTTPException:
    """One mapping for every STRIKE-domain failure: named codes, no
    disclosure (unknown and cross-tenant are the identical 404)."""
    if isinstance(exc, (EngagementNotFoundError, TargetNotFoundError,
                        WorkspaceNotFoundError, OperationNotFoundError,
                        RelayNotFoundError, StrikeNotFoundError,
                        ApprovalNotFoundError, ExposureNotFoundError,
                        EntityNotFoundError, TenantMismatchError)):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if isinstance(exc, _FORBIDDEN_403):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": _APPROVAL_ERROR_CODES.get(
                    type(exc), getattr(exc, "code", "forbidden")
                ),
                "message": str(exc),
            },
        )
    if isinstance(exc, _CONFLICT_409):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": _APPROVAL_ERROR_CODES.get(
                    type(exc), getattr(exc, "code", "conflict")
                ),
                "message": str(exc),
            },
        )
    if isinstance(exc, _REFUSAL_422):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": getattr(exc, "code", "refused"), "message": str(exc)},
        )
    if isinstance(exc, StrikeDomainError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": getattr(exc, "code", "strike_error"), "message": str(exc)},
        )
    if isinstance(exc, ApprovalSubjectError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "approval_subject_invalid", "message": str(exc)},
        )
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"code": "strike_error", "message": str(exc)},
    )


def _endpoint(fn: Callable) -> Callable:
    """Wrap a route body: domain errors → mapped HTTP, everything else
    propagates (500s are never masked)."""
    sig = inspect.signature(fn)

    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (StrikeDomainError, ApprovalStateError, ApprovalSubjectError,
                EvidencePolicyError, ExposureConflictError,
                ExposureNotFoundError, ExposureDomainError,
                TenantMismatchError) as exc:
            raise _map_domain_errors(exc) from exc
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__annotations__ = fn.__annotations__
    wrapper.__signature__ = sig  # keep FastAPI's dependency introspection
    return wrapper


def _jsonify(row: dict) -> dict:
    """JSON-safe rendering (datetimes/UUIDs/decimals) — the Ch.3 read
    contract's helper, mirrored locally to stay domain-local."""
    from app.exposure.tes_read_model import _jsonify as _ch3_jsonify

    return _ch3_jsonify(row)


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------


@router.post(
    "/engagements",
    status_code=status.HTTP_201_CREATED,
    summary="Create an engagement draft (analyst+; ROE frozen at creation)",
)
@_endpoint
def create_engagement(
    payload: EngagementCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_service.create_engagement(
            conn, auth.tenant_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.get(
    "/engagements",
    status_code=status.HTTP_200_OK,
    summary="List engagements (permanent history, newest first)",
)
@_endpoint
def list_engagements(auth: AuthContext = Depends(_require_analyst)):
    with get_db_connection() as conn:
        rows = strike_service.list_engagements(conn, auth.tenant_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


@router.get(
    "/engagements/{engagement_id}",
    status_code=status.HTTP_200_OK,
    summary="Engagement detail with derived expiry and target summary",
)
@_endpoint
def get_engagement(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_service.get_engagement(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/engagements/{engagement_id}/submit",
    status_code=status.HTTP_201_CREATED,
    summary="Submit the draft for authorization (proposes the dual-control approval)",
)
@_endpoint
def submit_engagement(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        result = strike_service.submit_engagement(
            conn, auth.tenant_id, engagement_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify({
            "engagement": _render(result["engagement"]),
            "approval_id": result["approval_id"],
        })


@router.post(
    "/engagements/{engagement_id}/approve",
    status_code=status.HTTP_200_OK,
    summary="Authorize the engagement (admin+, dual control via the Ch.5 primitive)",
)
@_endpoint
def approve_engagement(
    engagement_id: uuid.UUID,
    payload: DeciderIn,
    auth: AuthContext = Depends(_require_admin),
):
    """The authenticated admin is the APPROVER (server-owned identity — the
    client never names one). decide+apply is atomic: a proposal altered
    after approval, or an approval rebased onto different engagement state,
    fails closed with nothing written."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id FROM chapter5_approvals
            WHERE tenant_id = %s AND subject_type = 'strike_engagement'
              AND subject_id = %s AND state = 'pending'
            ORDER BY proposed_at DESC, id LIMIT 1;
            """,
            (str(auth.tenant_id), str(engagement_id)),
        )
        row = cur.fetchone()
        cur.close()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )
        result = decide_and_apply(
            conn, auth.tenant_id, row["id"],
            approver_id=auth.actor_id, approver_role=auth.role,
        )
        engagement = strike_service.get_engagement(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return _jsonify({
            "approval": result["decision"],
            "applied": result["apply"],
            "engagement": _render(engagement),
        })


@router.post(
    "/engagements/{engagement_id}/abort",
    status_code=status.HTTP_200_OK,
    summary="Abort the engagement (admin+; enforcement-immediate safety action)",
)
@_endpoint
def abort_engagement(
    engagement_id: uuid.UUID,
    payload: EngagementAbort,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        row = strike_service.abort_engagement(
            conn, auth.tenant_id, engagement_id, payload.reason,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/engagements/{engagement_id}/activate",
    status_code=status.HTTP_200_OK,
    summary="Activate an authorized engagement (requires an approved fresh target)",
)
@_endpoint
def activate_engagement(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_service.activate_engagement(
            conn, auth.tenant_id, engagement_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/engagements/{engagement_id}/complete",
    status_code=status.HTTP_200_OK,
    summary="Complete an active engagement (the record stays as permanent history)",
)
@_endpoint
def complete_engagement(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_service.complete_engagement(
            conn, auth.tenant_id, engagement_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/targets",
    status_code=status.HTTP_201_CREATED,
    summary="Request a target authorization (analyst+; tuple snapshotted; proposes the approval)",
)
@_endpoint
def request_target(
    engagement_id: uuid.UUID,
    payload: TargetCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        result = strike_service.request_target(
            conn, auth.tenant_id, engagement_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify({
            "target": _render(result["target"]),
            "approval_id": result["approval_id"],
        })


@router.get(
    "/engagements/{engagement_id}/targets",
    status_code=status.HTTP_200_OK,
    summary="List the engagement's target authorizations (expiry derived at read)",
)
@_endpoint
def list_targets(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        rows = strike_service.list_targets(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


@router.post(
    "/targets/{target_id}/approve",
    status_code=status.HTTP_200_OK,
    summary="Approve the target (admin+, dual control via the Ch.5 primitive)",
)
@_endpoint
def approve_target(
    target_id: uuid.UUID,
    payload: DeciderIn,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id FROM chapter5_approvals
            WHERE tenant_id = %s AND subject_type = 'strike_target'
              AND subject_id = %s AND state = 'pending'
            ORDER BY proposed_at DESC, id LIMIT 1;
            """,
            (str(auth.tenant_id), str(target_id)),
        )
        row = cur.fetchone()
        cur.close()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )
        result = decide_and_apply(
            conn, auth.tenant_id, row["id"],
            approver_id=auth.actor_id, approver_role=auth.role,
        )
        target = strike_service.get_target(conn, auth.tenant_id, target_id)
        conn.commit()
        return _jsonify({
            "approval": result["decision"],
            "applied": result["apply"],
            "target": _render(target),
        })


@router.post(
    "/targets/{target_id}/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke the target (admin+; enforcement-immediate: egress generation bumps at once)",
)
@_endpoint
def revoke_target(
    target_id: uuid.UUID,
    payload: RelayRevoke,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        row = strike_service.revoke_target(
            conn, auth.tenant_id, target_id, payload.reason,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


# ---------------------------------------------------------------------------
# Workspaces
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/workspaces",
    status_code=status.HTTP_201_CREATED,
    summary="Reserve a workspace generation (PATCH-04: durable before any provider call)",
)
@_endpoint
def reserve_workspace(
    engagement_id: uuid.UUID,
    payload: WorkspaceReserve,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        reservation = strike_workspaces.reserve_workspace(
            conn, auth.tenant_id, engagement_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()

    # phase 2 runs in its OWN committed transaction: the reservation is
    # durable BEFORE any external provider call (PATCH-04)
    with get_db_connection() as conn:
        result = strike_workspaces.provision_reservation(
            conn, auth.tenant_id, reservation["id"],
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(result))


@router.get(
    "/engagements/{engagement_id}/workspaces",
    status_code=status.HTTP_200_OK,
    summary="Workspace generations for the engagement (history retained)",
)
@_endpoint
def list_workspaces(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        rows = strike_workspaces.list_workspaces(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


@router.post(
    "/workspaces/{workspace_id}/in-use",
    status_code=status.HTTP_200_OK,
    summary="Mark the workspace in_use (ready → in_use)",
)
@_endpoint
def workspace_in_use(
    workspace_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_workspaces.mark_workspace_in_use(
            conn, auth.tenant_id, workspace_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/workspaces/{workspace_id}/collect",
    status_code=status.HTTP_200_OK,
    summary="Start artifact collection (in_use → collecting)",
)
@_endpoint
def workspace_collect(
    workspace_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_workspaces.mark_collecting(
            conn, auth.tenant_id, workspace_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/workspaces/{workspace_id}/destroy",
    status_code=status.HTTP_200_OK,
    summary="Destroy the workspace (explicit, audited; unconfirmed ⇒ destroy_failed alarm)",
)
@_endpoint
def destroy_workspace(
    workspace_id: uuid.UUID,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        strike_workspaces.begin_workspace_destroy(
            conn, auth.tenant_id, workspace_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()

    with get_db_connection() as conn:
        row = strike_workspaces.finish_workspace_destroy(
            conn, auth.tenant_id, workspace_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/workspaces/{workspace_id}/reconcile",
    status_code=status.HTTP_200_OK,
    summary="Operator reconciliation of an alarmed/unknown workspace (confirmed fencing retires it)",
)
@_endpoint
def reconcile_workspace(
    workspace_id: uuid.UUID,
    payload: ReconcileIn,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        row = strike_workspaces.reconcile_workspace(
            conn, auth.tenant_id, workspace_id,
            confirmed_fenced=payload.confirmed_fenced, note=payload.note,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/operations",
    status_code=status.HTTP_201_CREATED,
    summary="Dispatch an approved ability against an approved target (fail-closed gates)",
)
@_endpoint
def dispatch_operation(
    engagement_id: uuid.UUID,
    payload: OperationDispatch,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        operation = strike_operations.dispatch_operation(
            conn, auth.tenant_id, engagement_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()

    # engine phase in its own committed transaction (the dispatch record is
    # durable before the engine is asked anything — PATCH-04 shape)
    with get_db_connection() as conn:
        result = strike_operations.dispatch_to_engine(
            conn, auth.tenant_id, operation["id"],
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(result))


@router.get(
    "/engagements/{engagement_id}/operations",
    status_code=status.HTTP_200_OK,
    summary="Operations for the engagement (execution truth)",
)
@_endpoint
def list_operations(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        rows = strike_operations.list_operations(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


@router.get(
    "/operations/{operation_id}",
    status_code=status.HTTP_200_OK,
    summary="One operation (execution truth)",
)
@_endpoint
def get_operation(
    operation_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            from app.strike.operations import load_operation

            row = load_operation(cur, auth.tenant_id, operation_id)
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/operations/{operation_id}/complete",
    status_code=status.HTTP_200_OK,
    summary="Record a collected result (classifier refuses EXPLOITABLE/PREVENTED)",
)
@_endpoint
def complete_operation(
    operation_id: uuid.UUID,
    payload: OperationComplete,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_operations.complete_operation(
            conn, auth.tenant_id, operation_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.post(
    "/operations/{operation_id}/cancel",
    status_code=status.HTTP_200_OK,
    summary="Cancel an operation (cancelled ONLY on confirmed stop; otherwise cancel_unconfirmed)",
)
@_endpoint
def cancel_operation(
    operation_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_operations.cancel_operation(
            conn, auth.tenant_id, operation_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


@router.post(
    "/operations/{operation_id}/artifacts",
    status_code=status.HTTP_201_CREATED,
    summary="Store an artifact (bounded, SHA-256 server-side, immutable)",
)
@_endpoint
def store_artifact(
    operation_id: uuid.UUID,
    payload: ArtifactStore,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_operations.store_artifact(
            conn, auth.tenant_id, operation_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.get(
    "/artifacts/{artifact_id}",
    status_code=status.HTTP_200_OK,
    summary="Read an artifact (hash-verified; audited as an evidence download)",
)
@_endpoint
def read_artifact(
    artifact_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        artifact = strike_operations.read_artifact(
            conn, auth.tenant_id, artifact_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        body = artifact["content"]
        return _jsonify({
            "id": str(artifact["id"]),
            "operation_id": str(artifact["operation_id"]),
            "name": artifact["name"],
            "media_type": artifact["media_type"],
            "size_bytes": artifact["size_bytes"],
            "sha256": artifact["sha256"],
            "retention_tier": artifact["retention_tier"],
            "content_b64": base64.b64encode(bytes(body)).decode("ascii"),
            "created_at": artifact["created_at"],
        })


# ---------------------------------------------------------------------------
# Evidence promotion (the only score-affecting path)
# ---------------------------------------------------------------------------


@router.post(
    "/evidence",
    status_code=status.HTTP_201_CREATED,
    summary="Promote a completed operation to a Ch.3 §3.3.3 evidence record (PATCH-01)",
)
@_endpoint
def promote_evidence(
    payload: EvidencePromote,
    auth: AuthContext = Depends(_require_analyst),
):
    """The authenticated actor is the review authority (reviewed_by is
    server-owned). Writes the Ch.3 record (producer='strike') and the
    immutable link row in ONE transaction; replays identically."""
    with get_db_connection() as conn:
        result = strike_evidence.promote_evidence(
            conn, auth.tenant_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify({
            "link": _render(result["link"]),
            "evidence_record_id": result["evidence_record_id"],
            "evidence_kind": result["evidence_kind"],
            "outcome": result["ch3_outcome"],
        })


@router.get(
    "/engagements/{engagement_id}/evidence",
    status_code=status.HTTP_200_OK,
    summary="Evidence links for the engagement (immutable history)",
)
@_endpoint
def list_evidence(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        rows = strike_evidence.list_evidence_links(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


# ---------------------------------------------------------------------------
# Discovery (Flow C)
# ---------------------------------------------------------------------------


@router.post(
    "/discoveries",
    status_code=status.HTTP_201_CREATED,
    summary="Report a discovery (routes a Ch.6 STRIKE_DISCOVERY intake record — never a finding)",
)
@_endpoint
def report_discovery(
    payload: DiscoveryReport,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        result = strike_operations.report_discovery(
            conn, auth.tenant_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(result)


# ---------------------------------------------------------------------------
# Relays
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/relays",
    status_code=status.HTTP_201_CREATED,
    summary="Deploy a relay (admin+; engagement event; one-time pairing secret)",
)
@_endpoint
def create_relay(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        relay = strike_relays.create_relay(
            conn, auth.tenant_id, engagement_id,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(relay))


@router.post(
    "/relays/{relay_id}/pair",
    status_code=status.HTTP_200_OK,
    summary="Pair the relay with its one-time secret (pending_pairing → active)",
)
@_endpoint
def pair_relay(
    relay_id: uuid.UUID,
    payload: PairRelayIn,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        relay = strike_relays.pair_relay(
            conn, auth.tenant_id, relay_id, payload.pairing_secret,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(relay))


@router.post(
    "/relays/{relay_id}/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke the relay (admin+; TERMINAL — never reusable)",
)
@_endpoint
def revoke_relay(
    relay_id: uuid.UUID,
    payload: RelayRevoke,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        relay = strike_relays.revoke_relay(
            conn, auth.tenant_id, relay_id, payload.reason,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(relay))


@router.get(
    "/engagements/{engagement_id}/relays",
    status_code=status.HTTP_200_OK,
    summary="Relays for the engagement",
)
@_endpoint
def list_relays(
    engagement_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        rows = strike_relays.list_relays(conn, auth.tenant_id, engagement_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


# ---------------------------------------------------------------------------
# Rendering (server-owned derived fields; raw rows never leak BYTEA)
# ---------------------------------------------------------------------------


def _render(row: dict) -> dict:
    out = dict(row)
    out.pop("content", None)  # artifact bytes travel via /artifacts/{id} only
    return out
