"""Authoritative tenant registry helpers."""

from models import Tenant
from sqlalchemy.orm import Session


def tenant_display_name(tenant_id: str) -> str:
    value = str(tenant_id or "").strip()
    if value == "tempris":
        return "Tempris Platform"
    if value == "bug-bounty":
        return "Bug Bounty Research"
    return value.replace("-", " ").replace("_", " ").title()


def tenant_type_for(tenant_id: str) -> str:
    if tenant_id == "tempris":
        return "platform"
    if tenant_id == "bug-bounty":
        return "research"
    return "customer"


def ensure_tenant_registry(db: Session, tenant_ids) -> int:
    created = 0
    values = {"tempris", "bug-bounty"}
    values.update(str(value).strip() for value in tenant_ids if value and str(value).strip())
    existing = {
        row[0] for row in db.query(Tenant.id).filter(Tenant.id.in_(sorted(values))).all()
    }
    for tenant_id in sorted(values - existing):
        db.add(Tenant(
            id=tenant_id,
            display_name=tenant_display_name(tenant_id),
            tenant_type=tenant_type_for(tenant_id),
        ))
        created += 1
    if created:
        db.commit()
    return created
