from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import TenantPackage
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import PLATFORM_TENANT_ID, get_auth_context, require_role
from services.database import get_db
from services.entitlements import entitlement_response, normalize_overrides, normalize_package_code

router = APIRouter()


class PackageUpdate(BaseModel):
    package_code: str = Field(..., max_length=20)
    module_overrides: dict[str, bool] = Field(default_factory=dict)


def _response(db: Session, user: dict) -> dict:
    auth = get_auth_context(user)
    return entitlement_response(
        db,
        auth.tenant_id,
        role=auth.role,
        can_manage=auth.role == "Superadmin" and auth.tenant_id == PLATFORM_TENANT_ID,
    )


@router.get("/current")
def current_package(
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Researcher")),
):
    return _response(db, user)


@router.put("/current")
def update_package(
    req: PackageUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin")),
):
    auth = get_auth_context(user)
    try:
        package_code = normalize_package_code(req.package_code)
        overrides = normalize_overrides(req.module_overrides)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = db.query(TenantPackage).filter(TenantPackage.tenant_id == auth.tenant_id).first()
    if row is None:
        row = TenantPackage(tenant_id=auth.tenant_id, package_code=package_code,
                            module_overrides=overrides, updated_by=auth.user_id)
        db.add(row)
    else:
        row.package_code = package_code
        row.module_overrides = overrides
        row.version = (row.version or 0) + 1
        row.updated_by = auth.user_id

    append_to_audit_log_db(
        db,
        AuditEntry(
            user=auth.user_id, action="TENANT_PACKAGE_UPDATED", module="PACKAGES",
            detail=f"Tenant package changed to {package_code}",
            ip_address=request.client.host if request.client else None,
            metadata={"tenant_id": auth.tenant_id, "package_code": package_code,
                      "module_overrides": overrides},
        ),
        commit=False,
    )
    db.commit()
    return _response(db, user)
