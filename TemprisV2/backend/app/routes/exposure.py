# backend/app/routes/exposure.py
"""
Exposure Domain REST API Routes.
Provides tenant-isolated endpoints for Findings, Applicability Reviews, Exposure Confirmation,
Exposure Resolution, and Canonical Current Exposure queries.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from psycopg.errors import ForeignKeyViolation, SerializationFailure
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.audit import record_audit_event
from app.auth import AuthContext, require_roles
from app.config import PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.exposure.exceptions import (
    AssetNotFoundError,
    EntityNotFoundError,
    EvidencePolicyError,
    ExposureConflictError,
    ExposureNotFoundError,
    FindingNotFoundError,
    InvalidAssetStatusError,
    InvalidEvidenceError,
    ReviewBindingError,
    TenantMismatchError,
)
from app.exposure.models import (
    ApplicabilityReview,
    AssetExposure,
    CanonicalExposureItem,
    ExposureConfirm,
    Finding,
    FindingClose,
    FindingCreate,
    ReviewCreate,
    SssProposalIn,
)
from app.exposure.sss import (
    SssClassificationError,
    SssNotFoundError,
    create_sss_proposal,
)
from app.exposure.scoring_inputs import (
    BusinessImpactIn,
    BusinessImpactRecord,
    EvidenceRevokeIn,
    ExploitationEvidence,
    ExploitationEvidenceIn,
    ReachabilityEvidence,
    ReachabilityEvidenceIn,
    RecordResult,
    get_scoring_inputs,
    record_exploitation_evidence,
    record_reachability_evidence,
    revoke_evidence,
    set_business_impact,
)
from app.exposure.tes_read_model import (
    _jsonify,
    get_exposure_tes,
    get_finding_tes_summary,
)
from app.exposure.service import (
    allocate_finding_for_cve,
    close_finding,
    confirm_exposure,
    create_finding,
    get_canonical_current_exposures,
    get_finding,
    list_applicability_reviews,
    record_applicability_review,
)

logger = logging.getLogger(__name__)


def require_exposure_auth(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    """
    Enforces role authorization (analyst, admin, superadmin) and isolates
    the platform tenant session from accessing tenant exposure modules.
    """
    if auth.tenant_id == PLATFORM_TENANT_ID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform sessions cannot access tenant modules.",
        )
    return auth


router = APIRouter(
    prefix="/api/exposure",
    tags=["Exposure"],
    dependencies=[Depends(require_exposure_auth)],
)


# ---------------------------------------------------------------------------
# Findings Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/findings",
    response_model=Finding,
    status_code=status.HTTP_201_CREATED,
    summary="Create tenant finding",
)
def create_tenant_finding(
    payload: FindingCreate,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Create a finding within the authenticated tenant scope.

    Finding identity (PRD §3.3.1): the same vulnerability concept is the same
    finding — a non-null canonical_cve_id is allocated through the shared,
    serialized CVE allocator, so an existing finding for the CVE is reused
    (regardless of status) instead of duplicating the concept. Non-CVE
    findings are created directly (their identity rules are Chapter 6 scope).
    Emits finding.created audit event.
    """
    try:
        with get_db_connection() as conn:
            if payload.canonical_cve_id is not None:
                # The serialized allocator emits finding.created itself, on
                # actual insert only — reuse is not falsely audited.
                finding_id = allocate_finding_for_cve(
                    conn,
                    auth.tenant_id,
                    payload.canonical_cve_id,
                    default_title=payload.title,
                    default_severity=payload.severity,
                    default_description=payload.description,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                )
                finding = get_finding(conn, auth.tenant_id, finding_id)
            else:
                finding = create_finding(conn, auth.tenant_id, payload)
                record_audit_event(
                    conn=conn,
                    tenant_id=auth.tenant_id,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                    event_name="finding.created",
                    asset_id=None,
                    details={
                        "finding_id": str(finding.id),
                        "title": finding.title,
                        "canonical_cve_id": finding.canonical_cve_id,
                        "severity": finding.severity,
                    },
                )
            conn.commit()
            return finding
    except ForeignKeyViolation:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Canonical CVE ID '{payload.canonical_cve_id}' not found in vulnerability intelligence library.",
        )


@router.get(
    "/findings/{finding_id}",
    response_model=Finding,
    status_code=status.HTTP_200_OK,
    summary="Get tenant finding by ID",
)
def get_tenant_finding(
    finding_id: uuid.UUID,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Retrieve a finding by ID strictly within the authenticated tenant scope.
    """
    with get_db_connection() as conn:
        finding = get_finding(conn, auth.tenant_id, finding_id)
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )
        return finding


@router.post(
    "/findings/{finding_id}/close",
    response_model=Finding,
    status_code=status.HTTP_200_OK,
    summary="Close tenant finding",
)
def close_tenant_finding(
    finding_id: uuid.UUID,
    payload: Optional[FindingClose] = None,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Close a finding within the tenant. Roll-up consistency: a finding holding
    current confirmed exposures cannot be closed (409) — its derived state
    must stay open while exposure truth says current.
    Idempotent: closing an already closed finding returns 200 OK.
    Emits finding.closed audit event.
    """
    reason = payload.reason if payload else None
    try:
        with get_db_connection() as conn:
            finding = close_finding(
                conn=conn,
                tenant_id=auth.tenant_id,
                finding_id=finding_id,
                closed_by=auth.actor_id,
                reason=reason,
            )
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="finding.closed",
                asset_id=None,
                details={
                    "finding_id": str(finding.id),
                    "reason": reason,
                },
            )
            conn.commit()
            return finding
    except (FindingNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": ExposureConflictError.code, "message": str(e)},
        )


# ---------------------------------------------------------------------------
# Applicability Review Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/reviews",
    response_model=ApplicabilityReview,
    status_code=status.HTTP_201_CREATED,
    summary="Record applicability review",
)
def record_tenant_applicability_review(
    payload: ReviewCreate,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Record an append-only applicability review decision for a finding and asset.
    reviewed_by is server-owned: populated from the authenticated actor; client
    actor values are rejected by the request model.
    Emits exposure.review_recorded audit event.
    """
    try:
        with get_db_connection() as conn:
            review = record_applicability_review(
                conn, auth.tenant_id, payload, actor_id=auth.actor_id
            )
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="exposure.review_recorded",
                asset_id=review.asset_id,
                details={
                    "finding_id": str(review.finding_id),
                    "applicability": review.applicability,
                    "reason": review.reason,
                },
            )
            conn.commit()
            return review
    except (FindingNotFoundError, AssetNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding or asset not found",
        )


@router.get(
    "/reviews",
    response_model=List[ApplicabilityReview],
    status_code=status.HTTP_200_OK,
    summary="List tenant applicability reviews",
)
def list_tenant_applicability_reviews(
    finding_id: Optional[uuid.UUID] = Query(None, description="Filter by finding ID"),
    asset_id: Optional[uuid.UUID] = Query(None, description="Filter by asset ID"),
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    List applicability reviews within the tenant, optionally filtered by finding_id or asset_id.
    """
    with get_db_connection() as conn:
        return list_applicability_reviews(
            conn,
            auth.tenant_id,
            finding_id=finding_id,
            asset_id=asset_id,
        )


# ---------------------------------------------------------------------------
# Exposure Confirmation & Resolution Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/resolve/{exposure_id}",
    include_in_schema=False,
)
def resolve_tenant_exposure_removed(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Phase 0 fail-closed (P0-01 audit round 2): the public terminal-transition
    route is REMOVED. Both terminal triggers are owner-module decisions —
    'resolved' requires the Chapter 8 EDIP verified-closure intent and
    'false_positive' requires a Chapter 6/7 applicability-decision request —
    and neither owner exists yet. The exposure service retains the internal
    transitions for that future integration. Any request here fails closed.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Exposure terminal transitions are not publicly requestable in Phase 0.",
    )


@router.post(
    "/confirm",
    response_model=AssetExposure,
    status_code=status.HTTP_200_OK,
    summary="Explicitly confirm asset exposure",
)
def confirm_tenant_exposure(
    payload: ExposureConfirm,
    response: Response,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Explicitly confirm exposure with structured evidence via the one shared
    service-owned confirmation command. Actor identity (confirmed_by) and
    tenant are server-owned from the authenticated context; client values are
    rejected. The audit event AND the analyst's APPLICABLE applicability
    review commit atomically with the exposure row (the manual disposition is
    review-backed by construction; SCOUT confirmation stays reviewless).
    X-Exposure-Outcome distinguishes 'created' (committed success) from
    'replay' (idempotent return of the existing current episode).
    """
    try:
        with get_db_connection() as conn:
            result = confirm_exposure(
                conn,
                auth.tenant_id,
                payload,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                review=ReviewCreate(
                    finding_id=payload.finding_id,
                    asset_id=payload.asset_id,
                    applicability="APPLICABLE",
                ),
            )
            conn.commit()
            response.headers["X-Exposure-Outcome"] = result.outcome
            return result.exposure
    except InvalidEvidenceError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except ReviewBindingError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except (FindingNotFoundError, AssetNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding or asset not found",
        )
    except InvalidAssetStatusError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ---------------------------------------------------------------------------
# Scoring Input Ledgers (P0-02, PRD-000 §§3.3.2–3.3.4)
# ---------------------------------------------------------------------------


def _require_admin(auth: AuthContext) -> None:
    if auth.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required for evidence revocation.",
        )


def _record_response(response: Response, result: RecordResult):
    response.headers["X-Record-Outcome"] = result.outcome
    return result.record


@router.post(
    "/{exposure_id}/reachability",
    response_model=ReachabilityEvidence,
    status_code=status.HTTP_201_CREATED,
    summary="Record exact-exposure reachability evidence",
)
def record_exposure_reachability(
    exposure_id: uuid.UUID,
    payload: ReachabilityEvidenceIn,
    response: Response,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Record per-exposure reachability evidence (external vantage = 10 / internal
    = 8; absent = unknown). Reachability is producer-agnostic (§3.3.2): the
    producer is SERVER-ASSIGNED ('analyst' on this public route), never
    client-provided, and stays non-empty; actor and tenant are server-owned
    too. The evidence binds to the exact current confirmed episode. Audit
    commits atomically. X-Record-Outcome distinguishes 'created' from
    'replay' (idempotent duplicate callback via stable source identity).
    """
    try:
        with get_db_connection() as conn:
            result = record_reachability_evidence(
                conn,
                auth.tenant_id,
                exposure_id,
                payload,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                producer="analyst",
            )
            conn.commit()
            return _record_response(response, result)
    except EvidencePolicyError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": EvidencePolicyError.code, "message": str(e)},
        )
    except (ExposureNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": ExposureConflictError.code, "message": str(e)},
        )


@router.post(
    "/{exposure_id}/reachability/{record_id}/revoke",
    status_code=status.HTTP_201_CREATED,
    summary="Revoke reachability evidence (append-only correction)",
)
def revoke_exposure_reachability(
    exposure_id: uuid.UUID,
    record_id: uuid.UUID,
    payload: EvidenceRevokeIn,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """Append a revocation record; the original row is never mutated."""
    _require_admin(auth)
    try:
        with get_db_connection() as conn:
            result = revoke_evidence(
                conn, auth.tenant_id, exposure_id, record_id, "reachability",
                payload.reason, actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return {"revocation_id": result.record["id"], "revoked_record_id": record_id}
    except (ExposureNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")
    except EvidencePolicyError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": EvidencePolicyError.code, "message": str(e)},
        )


@router.post(
    "/{exposure_id}/business-impact",
    response_model=BusinessImpactRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Assess Business Impact for the exposure",
)
def assess_exposure_business_impact(
    exposure_id: uuid.UUID,
    payload: BusinessImpactIn,
    response: Response,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Per-exposure Business Impact (0–10) with actor, timestamp, and optional
    reason. Versioned: each assessment appends; the latest is current. An
    update affects only this exposure — never a sibling or the finding.
    """
    try:
        with get_db_connection() as conn:
            result = set_business_impact(
                conn,
                auth.tenant_id,
                exposure_id,
                payload,
                actor_id=auth.actor_id,
                actor_role=auth.role,
            )
            conn.commit()
            response.headers["X-Record-Outcome"] = result.outcome
            return result.record
    except (ExposureNotFoundError, TenantMismatchError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": ExposureConflictError.code, "message": str(e)},
        )


@router.post(
    "/{exposure_id}/exploitation-evidence",
    response_model=ExploitationEvidence,
    status_code=status.HTTP_201_CREATED,
    summary="Record analyst exploitation evidence",
)
def record_exposure_exploitation_evidence(
    exposure_id: uuid.UUID,
    payload: ExploitationEvidenceIn,
    response: Response,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Analyst-recorded exploitation evidence. The evidence kind is a server-side
    write-time classification of the basis ('observed' ⇒
    observed_exploitation / 365d, 'validated' ⇒ controlled_validation / 180d);
    producer is server-assigned ('analyst_review') and reviewed_by is forced
    to the authenticated actor (the analyst IS the review authority on this
    route); only successful observations/validations are recordable — failed,
    prevented, cancelled, unconfirmed, or artifact-only attempts are rejected
    and create no rung. TTL expiry affects eligibility only; rows persist.
    """
    try:
        with get_db_connection() as conn:
            result = record_exploitation_evidence(
                conn,
                auth.tenant_id,
                exposure_id,
                payload,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                reviewed_by=auth.actor_id,
            )
            conn.commit()
            response.headers["X-Record-Outcome"] = result.outcome
            return result.record
    except EvidencePolicyError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": EvidencePolicyError.code, "message": str(e)},
        )
    except (ExposureNotFoundError, TenantMismatchError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": ExposureConflictError.code, "message": str(e)},
        )


@router.post(
    "/{exposure_id}/exploitation-evidence/{record_id}/revoke",
    status_code=status.HTTP_201_CREATED,
    summary="Revoke exploitation evidence (append-only correction)",
)
def revoke_exposure_exploitation_evidence(
    exposure_id: uuid.UUID,
    record_id: uuid.UUID,
    payload: EvidenceRevokeIn,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """Append a revocation record; the original row is never mutated."""
    _require_admin(auth)
    try:
        with get_db_connection() as conn:
            result = revoke_evidence(
                conn, auth.tenant_id, exposure_id, record_id, "exploitation",
                payload.reason, actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return {"revocation_id": result.record["id"], "revoked_record_id": record_id}
    except (ExposureNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence record not found")
    except EvidencePolicyError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": EvidencePolicyError.code, "message": str(e)},
        )


@router.get(
    "/{exposure_id}/scoring-inputs",
    status_code=status.HTTP_200_OK,
    summary="Snapshot the exposure's scoring inputs (audited evidence download)",
)
def get_exposure_scoring_inputs(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    One snapshot of the exposure's scoring-input ledgers: current reachability
    (value + provenance), current Business Impact, exploitation evidence with
    TTL eligibility flags, and reserved attestations. Returns evidence
    payloads, so the read is audited as an evidence download (Appendix C Q12).

    This route OWNS the transaction boundary: REPEATABLE READ is established
    before the service's first query, so the response is one coherent
    snapshot; on success this boundary commits, on any failure it rolls back
    (including the in-transaction audit event). The service command itself
    never commits or rolls back the connection.
    """
    try:
        for attempt in range(2):
            try:
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
                    snapshot = get_scoring_inputs(
                        conn, auth.tenant_id, exposure_id,
                        actor_id=auth.actor_id, actor_role=auth.role,
                    )
                    conn.commit()
                    return snapshot
            except SerializationFailure:
                if attempt:
                    raise
    except (ExposureNotFoundError, TenantMismatchError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found")
    except SerializationFailure:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "snapshot_retry_exhausted", "retry": True},
        )


# ---------------------------------------------------------------------------
# Canonical Current Exposure Query Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/current",
    response_model=List[CanonicalExposureItem],
    status_code=status.HTTP_200_OK,
    summary="Query canonical current exposures",
)
def get_current_exposures(
    finding_id: Optional[uuid.UUID] = Query(None, description="Filter by finding ID"),
    asset_id: Optional[uuid.UUID] = Query(None, description="Filter by asset ID"),
    cve_id: Optional[str] = Query(None, description="Filter by canonical CVE ID"),
    severity: Optional[str] = Query(None, description="Filter by finding severity"),
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Query canonical current active exposures.
    Current = exposure status 'confirmed' on an active asset. Finding status is
    never a filter — the finding is a derived roll-up object.
    Deterministically ordered by confirmed_at DESC, id ASC.
    """
    with get_db_connection() as conn:
        return get_canonical_current_exposures(
            conn,
            auth.tenant_id,
            finding_id=finding_id,
            asset_id=asset_id,
            cve_id=cve_id,
            severity=severity,
        )


# ---------------------------------------------------------------------------
# P0-05 — Current TES read model (recompute-on-read; PRD-000 v1.11 §3.3.6)
# ---------------------------------------------------------------------------


@router.get(
    "/{exposure_id}/tes",
    status_code=status.HTTP_200_OK,
    summary="One exposure's current TES (recomputed at read)",
)
def get_exposure_current_tes(
    exposure_id: uuid.UUID,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    The authorized current-score read (P0-05; PRD-000 v1.11 §3.3.6). The
    current score is recomputed from current authoritative inputs inside ONE
    caller-owned REPEATABLE READ transaction established before the first
    query, bound to one captured ``as_of`` — never read from a stored score.

    Side-effect free (§3.3.6): no score persistence, no score snapshots, no
    audit rows, no refresh — snapshots are written only when a decision
    consumes a score. Atomic payload: value (full precision), display_value
    (two decimals), state, formula_version, coverage, missing reasons, full
    decomposition, and the PATCH-13 source-view identities the read is bound
    to. Full-precision Decimals are serialized losslessly as
    ``{"__decimal__": "<exact decimal string>"}``.

    Fail closed (§3.3.1): an unknown id, a cross-tenant id, a non-current
    episode (resolved / false_positive / superseded), or an inactive asset
    yields 404 with no TES value — the same response for all of them, so
    nothing is disclosed.
    """
    try:
        with get_db_connection() as conn:
            # ONE transaction boundary owned here: the isolation level is set
            # BEFORE the service's first query; as_of is captured at/inside
            # the same boundary; commit on success, rollback on any failure.
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
            as_of = datetime.now(timezone.utc)
            payload = get_exposure_tes(
                conn, auth.tenant_id, exposure_id, as_of=as_of
            )
            conn.commit()
            return _jsonify(payload)
    except (ExposureNotFoundError, TenantMismatchError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Exposure not found"
        )
    except ExposureConflictError as e:
        # A supersession that raced the snapshot boundary (rare: it must have
        # grabbed the row lock before our snapshot was established). The read
        # never claims a mixed result — the client retries against the new
        # current state.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.post(
    "/findings/{finding_id}/sss-proposals",
    status_code=status.HTTP_201_CREATED,
    summary="Propose a manual SSS for a non-CVE finding (pending; never scores)",
)
def create_tenant_sss_proposal(
    finding_id: uuid.UUID,
    payload: SssProposalIn,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Manual SSS proposal (P0-06; PRD-000 v1.11 §3.6.2 path 3, §3.6.6 #6).

    The request body may carry ONLY client-owned fields — proposed value,
    reason, evidence, optional valid taxonomy — and rejects anything else
    with 422 (tenant, actor, role, revision, status, validation state,
    version, approval state, and the derived comparison are server-owned).

    Tenant, proposer actor, and proposer role come from the AuthContext; the
    finding lookup is tenant-scoped in SQL, so unknown and cross-tenant
    findings are the same 404 (no disclosure). CVE findings reject (no CVE
    linkage is invented). The proposal is born 'pending' and can never score
    in this build — dual-control approval is reserved (§3.6.6 #6); there is
    no approve/apply endpoint. Proposal-only findings stay score-ineligible
    (no effective SSS ⇒ UNSCOREABLE). Emits sss.proposal_created, committed
    atomically with the proposal row.
    """
    try:
        with get_db_connection() as conn:
            result = create_sss_proposal(
                conn,
                auth.tenant_id,
                finding_id,
                proposed_value=payload.proposed_value,
                reason=payload.reason,
                evidence=payload.evidence,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                taxonomy=(payload.taxonomy.model_dump() if payload.taxonomy else None),
            )
            conn.commit()
            # lossless Decimal tagging (same wire contract as the TES reads)
            return _jsonify(result)
    except (SssNotFoundError, ExposureNotFoundError, TenantMismatchError, EntityNotFoundError):
        # unknown and cross-tenant findings are the same fail-closed 404
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )
    except SssClassificationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )


@router.get(
    "/findings/{finding_id}/tes-summary",
    status_code=status.HTTP_200_OK,
    summary="A finding's six-field TES summary over its current exposures",
)
def get_finding_current_tes_summary(
    finding_id: uuid.UUID,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    The locked six-field finding summary (P0-05; PRD-000 v1.11 §3.5 #6):
    exactly six flat fields — max FINAL TES, max PROVISIONAL TES, FINAL
    count, PROVISIONAL count, UNSCOREABLE count, total confirmed current
    exposures — computed over
    current, non-superseded confirmed exposures on active assets only.
    Max, never mean; the FINAL and PROVISIONAL maxima never combine;
    UNSCOREABLE is counted so a finding cannot look clean by hiding one.
    Finding status is never an input (§3.3.1). Recurrence history (resolved
    episodes) never enters — a recurrence episode that is itself current is
    a normal current episode.

    Every per-exposure read shares the same REPEATABLE READ snapshot as the
    episode enumeration, so the summary is one coherent source view bound to
    one ``as_of``; a concurrent supersession committed after the snapshot is
    simply not part of this view.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
            as_of = datetime.now(timezone.utc)
            payload = get_finding_tes_summary(
                conn, auth.tenant_id, finding_id, as_of=as_of
            )
            conn.commit()
            return _jsonify(payload)
    except (ExposureNotFoundError, TenantMismatchError):
        # Includes the read model's FindingNotFoundError (unknown and
        # cross-tenant findings are indistinguishable — no disclosure).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )
