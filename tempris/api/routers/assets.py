"""
Asset Inventory API Router — L5-02/03/08
Full CRUD for asset management with audit trail integration.
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional
from services.database import get_db
from models import Asset
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
from datetime import datetime, timezone

router = APIRouter()

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
    query = db.query(Asset)
    
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
        "data": [_serialize_asset(a) for a in assets],
        "meta": {"total": total, "page": page, "limit": limit}
    }

@router.get("/stats")
def get_asset_stats(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Summary counts by criticality and type."""
    all_assets = db.query(Asset).filter(Asset.status != "decommissioned").all()
    
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
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _serialize_asset(asset)

@router.post("")
def create_asset(
    req: AssetCreate,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Create a new asset. Requires Analyst+ role."""
    # Auto-generate ID
    count = db.query(Asset).count()
    asset_id = f"ASSET-{count + 1:04d}"
    
    asset = Asset(
        id=asset_id,
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
    db.add(asset)
    db.commit()
    db.refresh(asset)
    
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="ASSET_CREATED",
        module="ASSETS",
        detail=f"Created asset {asset_id}: {req.name} ({req.criticality} criticality)"
    ))
    
    return _serialize_asset(asset)

@router.put("/{asset_id}")
def update_asset(
    asset_id: str,
    req: AssetUpdate,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Update an existing asset. Requires Analyst+ role."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    changes = []
    for field, value in req.dict(exclude_unset=True).items():
        old_val = getattr(asset, field)
        if old_val != value:
            changes.append(f"{field}: {old_val} → {value}")
            setattr(asset, field, value)
    
    if changes:
        asset.updated_at = datetime.now(timezone.utc)
        db.commit()
        
        append_to_audit_log(AuditEntry(
            user=user.get("sub", "unknown"),
            action="ASSET_UPDATED",
            module="ASSETS",
            detail=f"Updated {asset_id}: {'; '.join(changes[:5])}"
        ))
    
    return _serialize_asset(asset)

@router.delete("/{asset_id}")
def decommission_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin")),
):
    """Soft-delete (decommission) an asset. Requires Admin+ role."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    asset.status = "decommissioned"
    asset.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="ASSET_DECOMMISSIONED",
        module="ASSETS",
        detail=f"Decommissioned asset {asset_id}: {asset.name}"
    ))
    
    return {"status": "decommissioned", "asset_id": asset_id}


def _serialize_asset(a: Asset) -> dict:
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
        "created_at": a.created_at.isoformat() if a.created_at else "",
        "updated_at": a.updated_at.isoformat() if a.updated_at else "",
    }
