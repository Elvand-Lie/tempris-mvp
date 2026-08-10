"""Platform-only tenant entitlement administration."""

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import Asset, Finding, Tenant, TenantPackage
from routers import auth as auth_router
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_platform_superadmin
from services.database import get_db
from services.entitlements import (
    DEFAULT_PACKAGE,
    MODULES,
    effective_modules,
    entitlement_response,
    normalize_overrides,
    normalize_package_code,
)


router = APIRouter()
SAFE_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$")


class TenantEntitlementUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package_code: str = Field(..., max_length=20)
    module_overrides: dict[str, bool] = Field(default_factory=dict)
    expected_version: int = Field(..., ge=0)


def _validate_tenant_id(tenant_id: str) -> str:
    if not SAFE_TENANT_ID.fullmatch(tenant_id or ""):
        raise HTTPException(status_code=404, detail="Tenant not found.")
    return tenant_id


def _tenant_or_404(db: Session, tenant_id: str) -> Tenant:
    _validate_tenant_id(tenant_id)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    return tenant


def _account_count(tenant_id: str) -> int:
    return sum(1 for record in auth_router.USERS.values() if record.get("tenant_id") == tenant_id)


def _constraints(tenant_id: str) -> list[dict]:
    constraints = [{
        "code": "ADMIN_TARGET_ONLY",
        "message": "Selecting this tenant does not switch the current login or permit customer-data access.",
    }]
    if tenant_id == "bug-bounty":
        constraints.append({
            "code": "RESEARCHER_ROLE_ISOLATION",
            "message": "Researcher accounts remain limited to isolated SSS testing regardless of package modules.",
        })
    return constraints


def _detail(db: Session, tenant: Tenant) -> dict:
    payload = entitlement_response(db, tenant.id, can_manage=True)
    payload.update({
        "display_name": tenant.display_name,
        "tenant_type": tenant.tenant_type,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
        "tenant_updated_at": tenant.updated_at.isoformat() if tenant.updated_at else None,
        "asset_count": db.query(Asset).filter(Asset.tenant_id == tenant.id).count(),
        "finding_count": db.query(Finding).filter(Finding.tenant_id == tenant.id).count(),
        "account_count": _account_count(tenant.id),
        "constraints": _constraints(tenant.id),
        "selection_changes_session": False,
    })
    return payload


@router.get("")
def list_tenants(
    q: str = Query("", max_length=100),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user=Depends(require_platform_superadmin()),
):
    query = db.query(Tenant)
    search = q.strip()
    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(Tenant.id.ilike(pattern), Tenant.display_name.ilike(pattern)))
    total = query.count()
    tenants = query.order_by(Tenant.display_name.asc(), Tenant.id.asc()).offset(offset).limit(limit).all()
    ids = [tenant.id for tenant in tenants]

    packages = {
        row.tenant_id: row for row in db.query(TenantPackage).filter(TenantPackage.tenant_id.in_(ids)).all()
    } if ids else {}
    asset_counts = dict(
        db.query(Asset.tenant_id, func.count(Asset.id))
        .filter(Asset.tenant_id.in_(ids)).group_by(Asset.tenant_id).all()
    ) if ids else {}
    finding_counts = dict(
        db.query(Finding.tenant_id, func.count(Finding.id))
        .filter(Finding.tenant_id.in_(ids)).group_by(Finding.tenant_id).all()
    ) if ids else {}

    items = []
    for tenant in tenants:
        assignment = packages.get(tenant.id)
        package_code = assignment.package_code if assignment else DEFAULT_PACKAGE
        overrides = dict(assignment.module_overrides or {}) if assignment else {}
        items.append({
            "tenant_id": tenant.id,
            "display_name": tenant.display_name,
            "tenant_type": tenant.tenant_type,
            "package_code": package_code,
            "configured": assignment is not None,
            "enabled_module_count": len(effective_modules(package_code, overrides)),
            "asset_count": int(asset_counts.get(tenant.id, 0)),
            "finding_count": int(finding_counts.get(tenant.id, 0)),
            "account_count": _account_count(tenant.id),
            "updated_at": assignment.updated_at.isoformat() if assignment and assignment.updated_at else None,
            "version": assignment.version if assignment else 0,
        })
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{tenant_id}")
def tenant_detail(
    tenant_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_platform_superadmin()),
):
    return _detail(db, _tenant_or_404(db, tenant_id))


@router.put("/{tenant_id}/entitlements")
def update_tenant_entitlements(
    tenant_id: str,
    req: TenantEntitlementUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_platform_superadmin()),
):
    tenant = _tenant_or_404(db, tenant_id)
    auth = get_auth_context(user)
    try:
        package_code = normalize_package_code(req.package_code)
        overrides = normalize_overrides(req.module_overrides)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = db.query(TenantPackage).filter(TenantPackage.tenant_id == tenant.id).first()
    before = {
        "configured": row is not None,
        "package_code": row.package_code if row else DEFAULT_PACKAGE,
        "module_overrides": dict(row.module_overrides or {}) if row else {},
        "version": row.version if row else 0,
    }
    if before["version"] != req.expected_version:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "STALE_TENANT_CONFIGURATION",
                "current_version": before["version"],
                "message": "This tenant configuration changed after it was loaded.",
            },
        )

    try:
        if row is None:
            row = TenantPackage(
                tenant_id=tenant.id,
                package_code=package_code,
                module_overrides=overrides,
                version=1,
                updated_by=auth.user_id,
            )
            db.add(row)
            db.flush()
            new_version = 1
        else:
            new_version = req.expected_version + 1
            changed = db.query(TenantPackage).filter(
                TenantPackage.tenant_id == tenant.id,
                TenantPackage.version == req.expected_version,
            ).update({
                TenantPackage.package_code: package_code,
                TenantPackage.module_overrides: overrides,
                TenantPackage.version: new_version,
                TenantPackage.updated_by: auth.user_id,
                TenantPackage.updated_at: func.now(),
            }, synchronize_session=False)
            if changed != 1:
                db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "STALE_TENANT_CONFIGURATION",
                        "message": "This tenant configuration changed while it was being saved.",
                    },
                )
            db.flush()

        after = {
            "configured": True,
            "package_code": package_code,
            "module_overrides": overrides,
            "version": new_version,
        }
        append_to_audit_log_db(
            db,
            AuditEntry(
                user=auth.user_id,
                action="TENANT_ENTITLEMENTS_UPDATED",
                module="TENANT_ADMIN",
                detail=f"Updated entitlements for tenant {tenant.id}",
                ip_address=request.client.host if request.client else None,
                metadata={
                    "target_tenant_id": tenant.id,
                    "before": before,
                    "after": after,
                },
            ),
            commit=False,
        )
        db.commit()
    except HTTPException:
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={"code": "STALE_TENANT_CONFIGURATION", "message": "Tenant configuration changed."},
        ) from exc
    except Exception:
        db.rollback()
        raise

    db.expire_all()
    return _detail(db, tenant)
