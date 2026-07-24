"""Server-authoritative tenant package and module entitlement policy."""

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from models import TenantPackage
from routers.auth import get_auth_context, get_current_user
from services.database import get_db


MODULES = (
    "SYNTHESIS", "SPECTRUM", "SCOUT", "STRIKE", "STANDARD",
    "GRC", "ASSETS", "SPOTLIGHT", "CISO",
)

PACKAGE_MODULES = {
    "DETECT": frozenset({"SYNTHESIS", "SPECTRUM", "SCOUT", "ASSETS"}),
    "DEFEND": frozenset(
        {"SYNTHESIS", "SPECTRUM", "SCOUT", "STRIKE", "STANDARD", "GRC", "ASSETS"}
    ),
    "RESPOND": frozenset(
        {"SYNTHESIS", "SPECTRUM", "SCOUT", "STRIKE", "STANDARD", "GRC",
         "ASSETS", "SPOTLIGHT", "CISO"}
    ),
    "DOMINATE": frozenset(MODULES),
}

PACKAGE_DESCRIPTIONS = {
    "DETECT": "Continuous discovery, exposure intelligence, validation, and asset context.",
    "DEFEND": "Detect capabilities plus testing, control assurance, and compliance operations.",
    "RESPOND": "Full operational response, executive reporting, and CISO decision support.",
    "DOMINATE": "Complete Wave 1 platform access with every production module enabled.",
}
DEFAULT_PACKAGE = "DOMINATE"


def normalize_package_code(value: str) -> str:
    code = str(value or "").strip().upper()
    if code not in PACKAGE_MODULES:
        raise ValueError(f"Unknown package code: {code}")
    return code


def normalize_overrides(overrides: dict | None) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for raw_name, enabled in (overrides or {}).items():
        name = str(raw_name).strip().upper()
        if name not in MODULES:
            raise ValueError(f"Unknown module: {name}")
        if not isinstance(enabled, bool):
            raise ValueError(f"Module override for {name} must be boolean")
        result[name] = enabled
    return result


def effective_modules(package_code: str, overrides: dict | None = None) -> list[str]:
    enabled = set(PACKAGE_MODULES[normalize_package_code(package_code)])
    for module, state in normalize_overrides(overrides).items():
        if state:
            enabled.add(module)
        else:
            enabled.discard(module)
    return [module for module in MODULES if module in enabled]


def get_tenant_package(db: Session, tenant_id: str) -> dict:
    row = db.query(TenantPackage).filter(TenantPackage.tenant_id == tenant_id).first()
    package_code = row.package_code if row else DEFAULT_PACKAGE
    overrides = dict(row.module_overrides or {}) if row else {}
    return {
        "tenant_id": tenant_id,
        "package_code": package_code,
        "module_overrides": overrides,
        "effective_modules": effective_modules(package_code, overrides),
        "configured": row is not None,
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
    }


def ensure_default_tenant_packages(db: Session, tenant_ids) -> int:
    """Persist the safe full-access default for known tenants without overwriting choices."""
    created = 0
    for tenant_id in sorted({str(value).strip() for value in tenant_ids if value}):
        exists = db.query(TenantPackage).filter(TenantPackage.tenant_id == tenant_id).first()
        if exists:
            continue
        db.add(TenantPackage(
            tenant_id=tenant_id,
            package_code=DEFAULT_PACKAGE,
            module_overrides={},
            updated_by="system:default-package",
        ))
        created += 1
    if created:
        db.commit()
    return created


def require_module(module_name: str):
    module = str(module_name).upper()
    if module not in MODULES:
        raise ValueError(f"Unknown entitlement module: {module}")

    async def checker(user=Depends(get_current_user), db: Session = Depends(get_db)):
        tenant_id = get_auth_context(user).tenant_id
        if not tenant_id:
            raise HTTPException(status_code=400, detail="Missing tenant context")
        assignment = get_tenant_package(db, tenant_id)
        if module not in assignment["effective_modules"]:
            raise HTTPException(
                status_code=403,
                detail={"code": "MODULE_NOT_ENTITLED", "module": module,
                        "package": assignment["package_code"]},
            )
        return user

    return checker
