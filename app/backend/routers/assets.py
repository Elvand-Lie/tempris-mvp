"""
Asset Inventory API Router — L5-02/03/08
Full CRUD for asset management with audit trail integration.
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional, Any
from services.database import get_db
from models import Asset, AssetScanAuthorization
from services.target_policy import classify_asset_target, validate_and_resolve_target
from services.operational_events import record_operational_event
from datetime import timedelta
from routers.audit import append_to_audit_log_db, AuditEntry
from routers.auth import get_auth_context, get_current_user, require_role
from datetime import datetime, timezone
from uuid import uuid4

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("ASSETS"))])


def _verified_tenant_id(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    return tenant_id

# ── Request Models ────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name: str = Field(..., max_length=255)
    asset_type: str = Field("server", max_length=50)
    ip_address: Optional[str] = Field(None, max_length=50)
    hostname: Optional[str] = Field(None, max_length=255)
    criticality: str = Field("medium", pattern="^(critical|high|medium|low)$")
    owner: Optional[str] = Field(None, max_length=255)
    environment: Optional[str] = Field(None, max_length=50)
    tags: list[str] = []
    notes: Optional[str] = None

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    asset_type: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, max_length=50)
    hostname: Optional[str] = Field(None, max_length=255)
    criticality: Optional[str] = Field(None, pattern="^(critical|high|medium|low)$")
    owner: Optional[str] = Field(None, max_length=255)
    environment: Optional[str] = Field(None, max_length=50)
    tags: Optional[list[str]] = None
    notes: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|decommissioned|maintenance)$")

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_assets(
    search: Optional[str] = None,
    criticality: Optional[str] = None,
    asset_type: Optional[str] = None,
    status: Optional[str] = Query("active"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """List all assets with optional filters and pagination."""
    query = db.query(Asset).filter(Asset.tenant_id == _verified_tenant_id(user))
    
    if status:
        query = query.filter(Asset.status == status)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Asset.name.ilike(search_term)) |
            (Asset.ip_address.ilike(search_term)) |
            (Asset.hostname.ilike(search_term)) |
            (Asset.owner.ilike(search_term))
        )
    
    total = query.count()
    assets = query.order_by(Asset.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
    
    return {
        "data": [_serialize_asset(a, db) for a in assets],
        "meta": {"total": total, "page": page, "limit": limit}
    }

@router.get("/stats")
def get_asset_stats(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Summary counts by criticality and type."""
    all_assets = db.query(Asset).filter(
        Asset.tenant_id == _verified_tenant_id(user),
        Asset.status != "decommissioned",
    ).all()

    by_criticality = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_type = {}
    for a in all_assets:
        crit = a.criticality or "medium"
        by_criticality[crit] = by_criticality.get(crit, 0) + 1
        atype = a.asset_type or "other"
        by_type[atype] = by_type.get(atype, 0) + 1

    return {
        "total": len(all_assets),
        "by_criticality": by_criticality,
        "by_type": by_type,
    }

@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Get a single asset by ID."""
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == _verified_tenant_id(user),
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _serialize_asset(asset, db)

@router.post("")
def create_asset(
    req: AssetCreate,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Create a new asset. Requires Analyst+ role."""
    tenant_id = _verified_tenant_id(user)
    asset_id = f"ASSET-{uuid4().hex[:12].upper()}"

    asset = Asset(
        id=asset_id,
        tenant_id=tenant_id,
        name=req.name,
        asset_type=req.asset_type,
        ip_address=req.ip_address,
        hostname=req.hostname,
        criticality=req.criticality,
        owner=req.owner,
        environment=req.environment,
        tags=req.tags,
        notes=req.notes,
    )
    try:
        db.add(asset)
        db.flush()
        append_to_audit_log_db(db, AuditEntry(
            user=user.get("sub", "unknown"),
            action="ASSET_CREATED",
            module="ASSETS",
            detail=f"Created asset {asset_id}: {req.name} ({req.criticality} criticality)"
        ), commit=False)
        db.commit()
        db.refresh(asset)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Asset creation failed")

    return _serialize_asset(asset, db)

@router.put("/{asset_id}")
def update_asset(
    asset_id: str,
    req: AssetUpdate,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Update an existing asset. Requires Analyst+ role."""
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == _verified_tenant_id(user),
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    changes = []
    for field, value in req.dict(exclude_unset=True).items():
        old_val = getattr(asset, field)
        if old_val != value:
            changes.append(f"{field}: {old_val} → {value}")
            setattr(asset, field, value)
    
    if changes:
        try:
            asset.updated_at = datetime.now(timezone.utc)
            db.flush()

            # If target identifiers changed, invalidate active scan authorizations
            if {"hostname", "ip_address"} & set(req.model_fields_set):
                now = datetime.now(timezone.utc)
                active_auths = db.query(AssetScanAuthorization).filter(
                    AssetScanAuthorization.tenant_id == asset.tenant_id,
                    AssetScanAuthorization.asset_id == asset.id,
                    AssetScanAuthorization.status.in_(["approved", "pending"]),
                ).all()
                for auth in active_auths:
                    auth.status = "revoked"
                    auth.revoked_by = "system"
                    auth.revoked_at = now
                    auth.revocation_reason = "Asset target modified; re-authorization required"
                    record_operational_event(
                        db,
                        tenant_id=asset.tenant_id,
                        event_type="scan_auth.revoked",
                        resource_type="asset_scan_authorization",
                        resource_id=auth.id,
                        source_module="ASSETS",
                        actor_id=user.get("sub", "unknown"),
                        correlation_id=asset.id,
                        metadata={"reason": auth.revocation_reason},
                    )

            recalculated = []
            if {"criticality", "status"} & set(req.model_fields_set):
                from services.tes_engine import recalculate_open_cve_findings
                recalculated = recalculate_open_cve_findings(
                    db, asset.tenant_id, actor_id=user.get("sub", "unknown"), reason="asset_context_updated",
                )
            append_to_audit_log_db(db, AuditEntry(
                user=user.get("sub", "unknown"),
                action="ASSET_UPDATED",
                module="ASSETS",
                detail=f"Updated {asset_id}: {'; '.join(changes[:5])}"
            ), commit=False)
            db.commit()
            if recalculated:
                from routers.edip import _publish_sss_event
                for finding_id in recalculated:
                    _publish_sss_event(asset.tenant_id, {"type": "finding.refresh", "finding_id": finding_id})
        except Exception:
            db.rollback()
            raise HTTPException(status_code=500, detail="Asset update failed")

    return _serialize_asset(asset, db)

@router.delete("/{asset_id}")
def decommission_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin")),
):
    """Soft-delete (decommission) an asset. Requires Admin+ role."""
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == _verified_tenant_id(user),
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    try:
        asset.status = "decommissioned"
        asset.updated_at = datetime.now(timezone.utc)
        db.flush()
        from services.tes_engine import recalculate_open_cve_findings
        recalculated = recalculate_open_cve_findings(
            db, asset.tenant_id, actor_id=user.get("sub", "unknown"), reason="asset_decommissioned",
        )
        append_to_audit_log_db(db, AuditEntry(
            user=user.get("sub", "unknown"),
            action="ASSET_DECOMMISSIONED",
            module="ASSETS",
            detail=f"Decommissioned asset {asset_id}: {asset.name}"
        ), commit=False)
        db.commit()
        if recalculated:
            from routers.edip import _publish_sss_event
            for finding_id in recalculated:
                _publish_sss_event(asset.tenant_id, {"type": "finding.refresh", "finding_id": finding_id})
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Asset decommission failed")
    
    return {"status": "decommissioned", "asset_id": asset_id}


# ── Asset Scan Authorization Endpoints ─────────────────────────────────────────

class ScanAuthRequestModel(BaseModel):
    evidence: Optional[str] = Field(None, max_length=1000)


class ScanAuthRevokeModel(BaseModel):
    reason: str = Field(..., min_length=3, max_length=1000)


class ScanAuthApproveModel(BaseModel):
    expires_in_days: int = Field(90, ge=1, le=365)


@router.post("/{asset_id}/scan-authorization/request")
def request_scan_authorization(
    asset_id: str,
    req: Optional[ScanAuthRequestModel] = None,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Request platform scan authorization for an asset. Requires Analyst+ role."""
    tenant_id = _verified_tenant_id(user)
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset.status != "active":
        raise HTTPException(status_code=400, detail="Cannot request scan authorization for inactive or decommissioned asset")

    # Validate target against network policy
    classification = classify_asset_target(asset.ip_address, asset.hostname, asset.name)
    if not classification["is_public_scannable"]:
        raise HTTPException(
            status_code=400,
            detail=f"Asset target is not publicly scannable: {classification['reason']}",
        )

    target_str = classification["target"]
    target_kind = classification["target_kind"]
    now = datetime.now(timezone.utc)
    user_email = user.get("sub", "unknown")

    # Check if existing pending or approved authorization already active
    existing = db.query(AssetScanAuthorization).filter(
        AssetScanAuthorization.tenant_id == tenant_id,
        AssetScanAuthorization.asset_id == asset_id,
        AssetScanAuthorization.status == "approved",
    ).first()
    if existing and existing.expires_at and existing.expires_at > now:
        return _serialize_auth(existing)

    auth_id = f"AUTH-{uuid4().hex[:16].upper()}"
    evidence_text = req.evidence if req and req.evidence else f"Analyst {user_email} requested authorization for {target_str}"
    auth = AssetScanAuthorization(
        id=auth_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        authorized_target=target_str,
        target_kind=target_kind,
        status="pending",
        approval_method="manual_platform_approval",
        evidence=evidence_text,
        requested_by=user_email,
        requested_at=now,
    )
    db.add(auth)
    record_operational_event(
        db,
        tenant_id=tenant_id,
        event_type="scan_auth.requested",
        resource_type="asset_scan_authorization",
        resource_id=auth_id,
        source_module="ASSETS",
        actor_id=user_email,
        correlation_id=asset_id,
        metadata={"target": target_str, "target_kind": target_kind},
    )
    append_to_audit_log_db(
        db,
        AuditEntry(
            user=user_email,
            action="ASSET_SCAN_AUTHORIZATION_REQUESTED",
            module="ASSETS",
            detail=f"Requested scan authorization for asset {asset_id} targeting {target_str} ({target_kind})",
        ),
        commit=False,
    )
    db.commit()
    db.refresh(auth)
    return _serialize_auth(auth)


@router.post("/{asset_id}/scan-authorization/approve")
def approve_scan_authorization(
    asset_id: str,
    req: Optional[ScanAuthApproveModel] = None,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin")),
):
    """Approve scan authorization for an asset. Requires platform Superadmin role."""
    tenant_id = _verified_tenant_id(user)
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    user_email = user.get("sub", "unknown")
    pending = db.query(AssetScanAuthorization).filter(
        AssetScanAuthorization.tenant_id == tenant_id,
        AssetScanAuthorization.asset_id == asset_id,
        AssetScanAuthorization.status == "pending",
    ).order_by(AssetScanAuthorization.requested_at.desc()).first()

    # Re-validate target policy at approval time
    classification = classify_asset_target(asset.ip_address, asset.hostname, asset.name)
    if not classification["is_public_scannable"]:
        raise HTTPException(
            status_code=400,
            detail=f"Asset target is not publicly scannable: {classification['reason']}",
        )

    now = datetime.now(timezone.utc)
    days = req.expires_in_days if req else 90
    expires_at = now + timedelta(days=days)

    if not pending:
        # Create direct approved authorization
        auth_id = f"AUTH-{uuid4().hex[:16].upper()}"
        pending = AssetScanAuthorization(
            id=auth_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            authorized_target=classification["target"],
            target_kind=classification["target_kind"],
            status="approved",
            approval_method="manual_platform_approval",
            evidence=f"Superadmin {user_email} directly approved scan authorization",
            requested_by=user_email,
            requested_at=now,
            approved_by=user_email,
            approved_at=now,
            expires_at=expires_at,
        )
        db.add(pending)
    else:
        pending.status = "approved"
        pending.approved_by = user_email
        pending.approved_at = now
        pending.expires_at = expires_at
        pending.authorized_target = classification["target"]
        pending.target_kind = classification["target_kind"]

    record_operational_event(
        db,
        tenant_id=tenant_id,
        event_type="scan_auth.approved",
        resource_type="asset_scan_authorization",
        resource_id=pending.id,
        source_module="ASSETS",
        actor_id=user_email,
        correlation_id=asset_id,
        metadata={"target": pending.authorized_target, "expires_at": expires_at.isoformat()},
    )
    append_to_audit_log_db(
        db,
        AuditEntry(
            user=user_email,
            action="ASSET_SCAN_AUTHORIZATION_APPROVED",
            module="ASSETS",
            detail=f"Approved scan authorization for asset {asset_id} targeting {pending.authorized_target} until {expires_at.date()}",
        ),
        commit=False,
    )
    db.commit()
    db.refresh(pending)
    return _serialize_auth(pending)


@router.post("/{asset_id}/scan-authorization/revoke")
def revoke_scan_authorization(
    asset_id: str,
    req: ScanAuthRevokeModel,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin")),
):
    """Revoke active or pending scan authorization for an asset."""
    tenant_id = _verified_tenant_id(user)
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    user_email = user.get("sub", "unknown")
    now = datetime.now(timezone.utc)
    active_auths = db.query(AssetScanAuthorization).filter(
        AssetScanAuthorization.tenant_id == tenant_id,
        AssetScanAuthorization.asset_id == asset_id,
        AssetScanAuthorization.status.in_(["approved", "pending"]),
    ).all()

    if not active_auths:
        raise HTTPException(status_code=404, detail="No active or pending scan authorization found to revoke")

    for auth in active_auths:
        auth.status = "revoked"
        auth.revoked_by = user_email
        auth.revoked_at = now
        auth.revocation_reason = req.reason
        record_operational_event(
            db,
            tenant_id=tenant_id,
            event_type="scan_auth.revoked",
            resource_type="asset_scan_authorization",
            resource_id=auth.id,
            source_module="ASSETS",
            actor_id=user_email,
            correlation_id=asset_id,
            metadata={"reason": req.reason},
        )

    append_to_audit_log_db(
        db,
        AuditEntry(
            user=user_email,
            action="ASSET_SCAN_AUTHORIZATION_REVOKED",
            module="ASSETS",
            detail=f"Revoked scan authorization for asset {asset_id}: {req.reason}",
        ),
        commit=False,
    )
    db.commit()
    return {"status": "success", "message": "Scan authorization revoked", "asset_id": asset_id}


@router.get("/{asset_id}/scan-authorization")
def get_scan_authorization(
    asset_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Get active scan authorization and historical authorizations for an asset."""
    tenant_id = _verified_tenant_id(user)
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    auths = db.query(AssetScanAuthorization).filter(
        AssetScanAuthorization.tenant_id == tenant_id,
        AssetScanAuthorization.asset_id == asset_id,
    ).order_by(AssetScanAuthorization.created_at.desc()).all()

    classification = classify_asset_target(asset.ip_address, asset.hostname, asset.name)
    now = datetime.now(timezone.utc)
    current = next((a for a in auths if a.status == "approved" and (not a.expires_at or _ensure_utc(a.expires_at) > now)), None)
    if not current:
        current = next((a for a in auths if a.status == "pending"), None)

    return {
        "asset_id": asset_id,
        "classification": classification,
        "current_authorization": _serialize_auth(current) if current else None,
        "history": [_serialize_auth(a) for a in auths],
    }


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _serialize_auth(a: Optional[AssetScanAuthorization]) -> Optional[dict]:
    if not a:
        return None
    now = datetime.now(timezone.utc)
    is_expired = bool(a.expires_at and _ensure_utc(a.expires_at) < now)
    return {
        "id": a.id,
        "tenant_id": a.tenant_id,
        "asset_id": a.asset_id,
        "authorized_target": a.authorized_target,
        "target_kind": a.target_kind,
        "status": "expired" if is_expired and a.status == "approved" else a.status,
        "approval_method": a.approval_method,
        "evidence": a.evidence,
        "requested_by": a.requested_by,
        "requested_at": a.requested_at.isoformat() if a.requested_at else None,
        "approved_by": a.approved_by,
        "approved_at": a.approved_at.isoformat() if a.approved_at else None,
        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
        "is_expired": is_expired,
        "revoked_by": a.revoked_by,
        "revoked_at": a.revoked_at.isoformat() if a.revoked_at else None,
        "revocation_reason": a.revocation_reason,
    }


def _derive_scan_eligibility(asset: Asset, auth: Optional[dict], classification: dict) -> dict[str, Any]:
    """Authoritative server derivation of asset scan eligibility."""
    if asset.status != "active":
        return {
            "eligible": False,
            "reason_code": "ASSET_INACTIVE",
            "reason": f"Asset {asset.id} is {asset.status} (only active assets can be scanned).",
        }
    if not classification.get("is_public_scannable"):
        return {
            "eligible": False,
            "reason_code": "TARGET_NOT_PUBLIC_SCANNABLE",
            "reason": "Asset target resolves to private, loopback, or non-globally-routable RFC 1918 address.",
        }
    if not auth:
        return {
            "eligible": False,
            "reason_code": "NO_AUTHORIZATION",
            "reason": f"Asset {asset.id} does not have a scan authorization. Request approval first.",
        }
    status = auth.get("status")
    if status == "revoked":
        return {
            "eligible": False,
            "reason_code": "AUTHORIZATION_REVOKED",
            "reason": f"Scan authorization was revoked: {auth.get('revocation_reason') or 'No reason provided'}.",
        }
    if status == "expired" or auth.get("is_expired"):
        expires_at = auth.get("expires_at") or "unknown"
        return {
            "eligible": False,
            "reason_code": "AUTHORIZATION_EXPIRED",
            "reason": f"Scan authorization expired at {expires_at}. Re-authorization required.",
        }
    if status == "pending":
        return {
            "eligible": False,
            "reason_code": "AUTHORIZATION_PENDING",
            "reason": "Scan authorization is pending Superadmin approval.",
        }
    if status != "approved":
        return {
            "eligible": False,
            "reason_code": f"AUTHORIZATION_{str(status).upper()}",
            "reason": f"Scan authorization status is {status}.",
        }

    # Target consistency check
    current_target = classification.get("target") or asset.hostname or asset.ip_address or ""
    authorized_target = auth.get("authorized_target") or ""
    from services.target_policy import clean_target_input
    if clean_target_input(current_target) != clean_target_input(authorized_target):
        return {
            "eligible": False,
            "reason_code": "TARGET_MISMATCH",
            "reason": f"Asset target '{current_target}' has changed and does not match authorized target '{authorized_target}'. Re-authorization required.",
        }

    return {
        "eligible": True,
        "reason_code": "ELIGIBLE",
        "reason": f"Asset is validly authorized for external scanning ({authorized_target}).",
    }


def _serialize_asset(a: Asset, db: Optional[Session] = None) -> dict:
    classification = classify_asset_target(a.ip_address, a.hostname, a.name)
    scan_auth = None
    if db is not None:
        now = datetime.now(timezone.utc)
        latest_auth = db.query(AssetScanAuthorization).filter(
            AssetScanAuthorization.tenant_id == a.tenant_id,
            AssetScanAuthorization.asset_id == a.id,
        ).order_by(AssetScanAuthorization.created_at.desc()).first()
        if latest_auth:
            scan_auth = _serialize_auth(latest_auth)

    scan_eligibility = _derive_scan_eligibility(a, scan_auth, classification)

    return {
        "id": a.id,
        "name": a.name,
        "asset_type": a.asset_type,
        "ip_address": a.ip_address,
        "hostname": a.hostname,
        "criticality": a.criticality,
        "owner": a.owner,
        "environment": a.environment,
        "tags": a.tags or [],
        "status": a.status,
        "notes": a.notes,
        "target_classification": classification,
        "scan_authorization": scan_auth,
        "scan_eligibility": scan_eligibility,
        "scan_eligible": scan_eligibility["eligible"],
        "scan_ineligible_reason": scan_eligibility["reason"] if not scan_eligibility["eligible"] else None,
        "created_at": a.created_at.isoformat() if a.created_at else "",
        "updated_at": a.updated_at.isoformat() if a.updated_at else "",
    }
