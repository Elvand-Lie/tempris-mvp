from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import TenantPackage
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_role
from services.database import get_db
from services.entitlements import (
    MODULES, PACKAGE_DESCRIPTIONS, PACKAGE_MODULES, get_tenant_package,
    normalize_overrides, normalize_package_code,
)

router = APIRouter()


class PackageUpdate(BaseModel):
    package_code: str = Field(..., max_length=20)
    module_overrides: dict[str, bool] = Field(default_factory=dict)


def _catalog() -> list[dict]:
    return [
        {"code": code, "name": code.title(), "description": PACKAGE_DESCRIPTIONS[code],
         "included_modules": [module for module in MODULES if module in included]}
        for code, included in PACKAGE_MODULES.items()
    ]


def _response(db: Session, user: dict) -> dict:
    auth = get_auth_context(user)
    assignment = get_tenant_package(db, auth.tenant_id)
    if auth.role == "Researcher":
        assignment["effective_modules"] = []
    assignment.update({
        "catalog": _catalog(), "modules": list(MODULES), "role": auth.role,
        "can_manage": auth.role == "Superadmin",
        "can_submit_sss": auth.role in {"Superadmin", "Admin", "Analyst", "Researcher"},
        "can_manage_sss": auth.role in {"Superadmin", "Admin", "Analyst"},
    })
    return assignment


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
