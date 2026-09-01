# backend/app/routes/exposure.py
"""
Exposure Domain REST API Routes.
Provides tenant-isolated endpoints for Findings, Applicability Reviews, Exposure Confirmation,
Exposure Resolution, and Canonical Current Exposure queries.
"""
from __future__ import annotations

import logging
import uuid
from typing import List, Optional
from psycopg.errors import ForeignKeyViolation
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.audit import record_audit_event
from app.auth import AuthContext, require_roles
from app.config import PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.exposure.exceptions import (
    AssetNotFoundError,
    EntityNotFoundError,
    ExposureNotFoundError,
    FindingNotFoundError,
    InvalidAssetStatusError,
    InvalidEvidenceError,
    InvalidFindingStatusError,
    TenantMismatchError,
)
from app.exposure.models import (
    ApplicabilityReview,
    AssetExposure,
    CanonicalExposureItem,
    ExposureConfirm,
    ExposureResolve,
    Finding,
    FindingClose,
    FindingCreate,
    ReviewCreate,
)
from app.exposure.service import (
    close_finding,
    confirm_exposure,
    create_finding,
    get_canonical_current_exposures,
    get_finding,
    list_applicability_reviews,
    record_applicability_review,
    resolve_exposure,
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
    Create a new finding within the authenticated tenant scope.
    Emits finding.created audit event.
    """
    try:
        with get_db_connection() as conn:
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
    Close an open finding within the tenant.
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
    Defaults reviewed_by to auth.actor_id if omitted.
    Emits exposure.review_recorded audit event.
    """
    if not payload.reviewed_by:
        payload.reviewed_by = auth.actor_id

    try:
        with get_db_connection() as conn:
            review = record_applicability_review(conn, auth.tenant_id, payload)
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
    "/confirm",
    response_model=AssetExposure,
    status_code=status.HTTP_200_OK,
    summary="Explicitly confirm asset exposure",
)
def confirm_tenant_exposure(
    payload: ExposureConfirm,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Explicitly confirm exposure with structured evidence.
    Defaults confirmed_by to auth.actor_id if omitted.
    Emits exposure.confirmed audit event.
    """
    if not payload.confirmed_by:
        payload.confirmed_by = auth.actor_id

    try:
        with get_db_connection() as conn:
            exposure = confirm_exposure(conn, auth.tenant_id, payload)
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="exposure.confirmed",
                asset_id=exposure.asset_id,
                details={
                    "finding_id": str(exposure.finding_id),
                    "exposure_id": str(exposure.id),
                },
            )
            conn.commit()
            return exposure
    except InvalidEvidenceError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except (FindingNotFoundError, AssetNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding or asset not found",
        )
    except (InvalidAssetStatusError, InvalidFindingStatusError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/resolve/{exposure_id}",
    response_model=AssetExposure,
    status_code=status.HTTP_200_OK,
    summary="Resolve asset exposure",
)
def resolve_tenant_exposure(
    exposure_id: uuid.UUID,
    payload: Optional[ExposureResolve] = None,
    auth: AuthContext = Depends(require_exposure_auth),
):
    """
    Resolve an existing asset exposure.
    Defaults resolved_by to auth.actor_id if omitted.
    Emits exposure.resolved audit event.
    """
    if payload is None:
        payload = ExposureResolve()
    if not payload.resolved_by:
        payload.resolved_by = auth.actor_id

    try:
        with get_db_connection() as conn:
            exposure = resolve_exposure(conn, auth.tenant_id, exposure_id, payload)
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="exposure.resolved",
                asset_id=exposure.asset_id,
                details={
                    "finding_id": str(exposure.finding_id),
                    "exposure_id": str(exposure.id),
                    "status": exposure.status,
                    "reason": exposure.resolution_reason,
                },
            )
            conn.commit()
            return exposure
    except (ExposureNotFoundError, TenantMismatchError, EntityNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exposure not found",
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
    Enforces active asset and open finding joined filtering.
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
