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

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
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
from app.collector_registry import collector_registry
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
from app.strike import runs as strike_runs
from app.strike import scopes as strike_scopes
from app.strike import service as strike_service
from app.strike import workspaces as strike_workspaces
from app.strike.server_runner import execute_server_run

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
from app.strike.runs import (
    CollectorInvalidError,
    CollectorNotReadyError,
    DEFAULT_MAX_TIME_SECONDS,
    RunCreate,
)
from app.strike.scopes import (
    ScopeEntryCreate,
    ScopeEntryNotFoundError,
    ScopeEntryRevoke,
    ScopeEntryStateError,
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


def _refuse_legacy_mutation() -> None:
    """The v1.12 toolbox model supersedes the engagement-scoped chain: no
    NEW legacy engagement/target/workspace/operation/relay state may be
    created — there is no opt-back. Reads, history, and safety actions on
    existing rows stay available; historical data is never deleted."""
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
    ScopeEntryStateError,
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
                        ScopeEntryNotFoundError,
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
    propagates (500s are never masked). Sync bodies keep threadpool
    execution; async bodies use _endpoint_async."""
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


def _endpoint_async(fn: Callable) -> Callable:
    """The same error mapping for async route bodies (the run-dispatch
    endpoint awaits the collector over WSS)."""
    import functools

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except (StrikeDomainError, ApprovalStateError, ApprovalSubjectError,
                EvidencePolicyError, ExposureConflictError,
                ExposureNotFoundError, ExposureDomainError,
                TenantMismatchError) as exc:
            raise _map_domain_errors(exc) from exc
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
    _refuse_legacy_mutation()
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
    _refuse_legacy_mutation()
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
    _refuse_legacy_mutation()
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
    _refuse_legacy_mutation()
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
    _refuse_legacy_mutation()
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
# Tenant testing-scope registry (amended PRD Ch.4 — /strike/scopes)
# ---------------------------------------------------------------------------


@router.post(
    "/scopes",
    status_code=status.HTTP_201_CREATED,
    summary="Create a testing-scope entry (Tenant Admin/Superadmin; exact hostname/IP/CIDR, required expiry, audited)",
)
@_endpoint
def create_scope_entry(
    payload: ScopeEntryCreate,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        row = strike_scopes.create_scope_entry(
            conn, auth.tenant_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
    summary="List the tenant's testing-scope registry (permanent history, expiry/revocation derived at read)",
)
@_endpoint
def list_scope_entries(auth: AuthContext = Depends(_require_admin)):
    with get_db_connection() as conn:
        rows = strike_scopes.list_scope_entries(conn, auth.tenant_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


@router.post(
    "/scopes/{scope_entry_id}/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke a testing-scope entry (Tenant Admin/Superadmin; enforcement-immediate, audited)",
)
@_endpoint
def revoke_scope_entry(
    scope_entry_id: uuid.UUID,
    payload: ScopeEntryRevoke,
    auth: AuthContext = Depends(_require_admin),
):
    with get_db_connection() as conn:
        row = strike_scopes.revoke_scope_entry(
            conn, auth.tenant_id, scope_entry_id, payload.reason,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        conn.commit()
        return _jsonify(_render(row))


# ---------------------------------------------------------------------------
# Toolbox runs (amended PRD Ch.4: catalogue → target/config → run →
# progress → results → history; the curl Phase-1 slice)
# ---------------------------------------------------------------------------


@router.get(
    "/catalogue",
    status_code=status.HTTP_200_OK,
    summary="The capability catalogue (only wired, reviewed capabilities appear)",
)
@_endpoint
def get_catalogue(auth: AuthContext = Depends(_require_analyst)):
    return strike_runs.CATALOGUE


@router.post(
    "/runs",
    status_code=status.HTTP_201_CREATED,
    summary=(
        "Create a run (analyst+; scope-checked, DNS pinned, then executed on "
        "the selected vantage: the platform server sandbox, or the explicitly "
        "selected tenant collector over its authenticated WSS)"
    ),
)
@_endpoint_async
async def create_run(
    payload: RunCreate,
    background: BackgroundTasks,
    auth: AuthContext = Depends(_require_analyst),
):
    # catalogue truth first: an unknown capability is refused before any
    # collector-dependent check
    from app.strike.runs import CATALOGUE, CapabilityNotFoundError, TOOL_ENVELOPE_SECONDS

    if payload.capability not in {c["capability"] for c in CATALOGUE}:
        raise CapabilityNotFoundError("Capability is not in the catalogue")

    # ---------------------------------------------------------------------
    # SERVER VANTAGE: the platform's own hardened sandbox, in-process.
    #
    # No collector is selected or contacted on this plane — runs.create_run
    # already refused a server-vantage run carrying a collector_id and
    # refused a capability whose tool is not installed here. Scope
    # validation happened inside create_run, BEFORE this execution path, and
    # activate_run re-checks the pinned snapshot's liveness at claim time.
    # ---------------------------------------------------------------------
    if payload.execution_plane == "server":
        with get_db_connection() as conn:
            row = strike_runs.create_run(
                conn, auth.tenant_id, payload,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()

        # The payload — not a pre-built spec — is handed to the task: the
        # script text is piped to the interpreter on stdin and the request
        # body is recorded only as a byte count, so both must travel in
        # memory. server_runner merges them with the durable policy_snapshot
        # and neither value outlives the task.
        background.add_task(execute_server_run, row["id"], auth.tenant_id, payload)

        # the run is returned durable and queued; the console follows it
        # through the chunk cursor rather than blocking on execution
        with get_db_connection() as conn:
            queued = strike_runs.get_run(conn, auth.tenant_id, row["id"])
            conn.commit()
        return _jsonify(_render(queued))

    # ---------------------------------------------------------------------
    # COLLECTOR VANTAGE (unchanged semantics): dispatch over authenticated
    # WSS to exactly the collector the user selected.
    # ---------------------------------------------------------------------

    # DB truth first: the selection must be an enrolled collector of THIS
    # tenant (an unregistered or cross-tenant id is collector_invalid)
    with get_db_connection() as conn:
        strike_runs.validate_run_collector(conn, auth.tenant_id, payload.collector_id)
        conn.commit()

    # then the fail-closed preflight on the USER-SELECTED collector: offline,
    # paused, or not-ready capability all refuse the run visibly — never a
    # redirect to another collector.
    session = collector_registry.get_session(payload.collector_id)
    if (
        session is None
        or session.tenant_id != auth.tenant_id
        or not collector_registry.is_connected(payload.collector_id)
        or session.operator_status != "active"
    ):
        raise CollectorNotReadyError(
            "The selected collector is not connected or not active; the run "
            "was not dispatched to any other collector"
        )
    if not collector_registry.strike_capability_ready(
        payload.collector_id, payload.capability
    ):
        raise CollectorNotReadyError(
            "The selected collector has not reported this capability as "
            "available; the run was refused (fail closed)"
        )

    with get_db_connection() as conn:
        row = strike_runs.create_run(
            conn, auth.tenant_id, payload,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
        claimed = strike_runs.activate_run(
            conn, row, f"collector:{payload.collector_id}"
        )
        conn.commit()

    snapshot = row["policy_snapshot"]
    capability = payload.capability
    dispatch_url = row["target_url"]
    if dispatch_url is None and capability in ("curl", "nuclei"):
        dispatch_url = "http://%s:%s" % (
            f"[{row['target_host']}]" if ":" in row["target_host"] else row["target_host"],
            row["target_port"],
        )
    result = await collector_registry.dispatch_strike_job(
        payload.collector_id,
        auth.tenant_id,
        row["id"],
        method=payload.method if capability == "curl" else None,
        url=dispatch_url,
        pinned_ips=snapshot.get("pinned_ips") or [],
        pinned_targets=snapshot.get("pinned_targets") or [],
        record_type=snapshot.get("record_type"),
        capability=capability,
        timeout_seconds=TOOL_ENVELOPE_SECONDS.get(capability, DEFAULT_MAX_TIME_SECONDS),
    )

    with get_db_connection() as conn:
        try:
            res_status = result.get("status")
            exit_code = result.get("exit_code")
            if res_status in ("completed", "success") and isinstance(exit_code, int):
                strike_runs.complete_run(
                    conn, claimed,
                    exit_code=exit_code,
                    output=result.get("stdout", ""),
                    error_code=None,
                )
            else:
                detail = (
                    result.get("stderr")
                    or result.get("error_message")
                    or "the collector reported no detail"
                )
                strike_runs.complete_run(
                    conn, claimed,
                    exit_code=exit_code if isinstance(exit_code, int) else -1,
                    output=detail[:2000],
                    error_code=result.get("error_code", "collector_run_failed"),
                )
        except strike_runs.RunStateError:
            # the run left 'running' while executing (analyst cancellation).
            # The collector process has verifiably returned — a confirmed stop.
            conn.rollback()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT state FROM strike_runs WHERE id = %s;",
                    (str(row["id"]),),
                )
                current = cur.fetchone()
            if current is not None and current["state"] == "cancel_requested":
                strike_runs.confirm_cancel(conn, claimed, confirmed=True)
        conn.commit()

    with get_db_connection() as conn:
        final = strike_runs.get_run(conn, auth.tenant_id, row["id"])
        conn.commit()
        return _jsonify(_render(final))


@router.get(
    "/runs",
    status_code=status.HTTP_200_OK,
    summary="Run history (permanent run metadata, newest first)",
)
@_endpoint
def list_runs(auth: AuthContext = Depends(_require_analyst)):
    with get_db_connection() as conn:
        rows = strike_runs.list_runs(conn, auth.tenant_id)
        conn.commit()
        return [_jsonify(_render(r)) for r in rows]


@router.get(
    "/runs/{run_id}",
    status_code=status.HTTP_200_OK,
    summary="Run progress and bounded inline result (64 KiB bound; truncation flagged)",
)
@_endpoint
def get_run(
    run_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_runs.get_run(conn, auth.tenant_id, run_id)
        conn.commit()
        return _jsonify(_render(row))


@router.get(
    "/runs/{run_id}/chunks",
    status_code=status.HTTP_200_OK,
    summary=(
        "Run output after a cursor (ordered, bounded chunks; the terminal "
        "inline result rides along so one poll serves a live and a finished run)"
    ),
)
@_endpoint
def read_run_chunks(
    run_id: uuid.UUID,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        payload = strike_runs.read_output_chunks(
            conn, auth.tenant_id, run_id, after=after, limit=limit
        )
        conn.commit()
        return _jsonify(payload)


@router.post(
    "/runs/{run_id}/cancel",
    status_code=status.HTTP_200_OK,
    summary="Cancel a pending run (before dispatch; running runs are not fake-cancellable)",
)
@_endpoint
def cancel_run(
    run_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        row = strike_runs.cancel_run(conn, auth.tenant_id, run_id)
        conn.commit()
        return _jsonify(_render(row))


# ---------------------------------------------------------------------------
# Rendering (server-owned derived fields; raw rows never leak BYTEA)
# ---------------------------------------------------------------------------


def _render(row: dict) -> dict:
    out = dict(row)
    out.pop("content", None)  # artifact bytes travel via /artifacts/{id} only
    return out
