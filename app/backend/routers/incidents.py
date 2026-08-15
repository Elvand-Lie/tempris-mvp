"""Tenant-scoped incident intake compatibility API (not a SIEM)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from models import Asset, Finding, Incident
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, get_current_user, require_role
from services.database import get_db
from services.operational_events import record_operational_event


router = APIRouter()
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
STATUSES = {"open", "investigating", "contained", "resolved", "closed"}


class IncidentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_event_id: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=100)
    discovered_at: datetime
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(min_length=1, max_length=10000)
    severity: str
    status: str = "open"
    affected_asset_ids: list[str] = Field(default_factory=list, max_length=1000)
    related_finding_ids: list[str] = Field(default_factory=list, max_length=1000)
    evidence_references: list[str] = Field(default_factory=list, max_length=1000)
    observed_impact: str | None = Field(default=None, max_length=10000)
    response_actions: list[str] = Field(default_factory=list, max_length=1000)


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=500)
    summary: str | None = Field(default=None, min_length=1, max_length=10000)
    severity: str | None = None
    status: str | None = None
    affected_asset_ids: list[str] | None = Field(default=None, max_length=1000)
    related_finding_ids: list[str] | None = Field(default=None, max_length=1000)
    evidence_references: list[str] | None = Field(default=None, max_length=1000)
    observed_impact: str | None = Field(default=None, max_length=10000)
    response_actions: list[str] | None = Field(default=None, max_length=1000)


def _tenant(user: dict) -> str:
    return get_auth_context(user).tenant_id


def _validate_enum(value: str, allowed: set[str], name: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized not in allowed:
        raise HTTPException(status_code=422, detail=f"Invalid {name}: {value}")
    return normalized


def _validate_links(db: Session, tenant_id: str, asset_ids: list[str], finding_ids: list[str]) -> None:
    unique_assets = set(asset_ids)
    unique_findings = set(finding_ids)
    matched_assets = {
        row.id for row in db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.id.in_(unique_assets),
        ).all()
    } if unique_assets else set()
    matched_findings = {
        row.id for row in db.query(Finding).filter(
            Finding.tenant_id == tenant_id,
            Finding.id.in_(unique_findings),
        ).all()
    } if unique_findings else set()
    if matched_assets != unique_assets:
        raise HTTPException(status_code=422, detail="One or more assets do not belong to the current tenant")
    if matched_findings != unique_findings:
        raise HTTPException(status_code=422, detail="One or more findings do not belong to the current tenant")


def _serialize(row: Incident) -> dict:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "external_event_id": row.external_event_id,
        "source": row.source,
        "discovered_at": row.discovered_at.isoformat() if row.discovered_at else None,
        "title": row.title,
        "summary": row.summary,
        "severity": row.severity,
        "status": row.status,
        "affected_asset_ids": row.affected_asset_ids or [],
        "related_finding_ids": row.related_finding_ids or [],
        "evidence_references": row.evidence_references or [],
        "observed_impact": row.observed_impact,
        "response_actions": row.response_actions or [],
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.post("")
def create_incident(
    payload: IncidentInput,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    tenant_id = _tenant(user)
    severity = _validate_enum(payload.severity, SEVERITIES, "severity")
    status = _validate_enum(payload.status, STATUSES, "status")
    _validate_links(db, tenant_id, payload.affected_asset_ids, payload.related_finding_ids)
    existing = db.query(Incident).filter(
        Incident.tenant_id == tenant_id,
        Incident.source == payload.source,
        Incident.external_event_id == payload.external_event_id,
    ).first()
    if existing:
        return {"created": False, "incident": _serialize(existing)}
    row = Incident(
        id=f"INC-{uuid4().hex[:20].upper()}",
        tenant_id=tenant_id,
        external_event_id=payload.external_event_id,
        source=payload.source,
        discovered_at=payload.discovered_at.astimezone(timezone.utc),
        title=payload.title,
        summary=payload.summary,
        severity=severity,
        status=status,
        affected_asset_ids=list(dict.fromkeys(payload.affected_asset_ids)),
        related_finding_ids=list(dict.fromkeys(payload.related_finding_ids)),
        evidence_references=list(dict.fromkeys(payload.evidence_references)),
        observed_impact=payload.observed_impact,
        response_actions=payload.response_actions,
        created_by=user.get("sub", "unknown"),
    )
    db.add(row)
    record_operational_event(
        db, tenant_id=tenant_id, event_type="incident.created",
        resource_type="incident", resource_id=row.id, source_module="STANDARD",
        actor_id=user.get("sub", "unknown"), metadata={"source": row.source},
    )
    append_to_audit_log_db(db, AuditEntry(
        user=user.get("sub", "unknown"), action="INCIDENT_CREATED", module="STANDARD",
        detail=f"Created incident {row.id} from {row.source}",
    ), commit=False)
    db.commit()
    db.refresh(row)
    return {"created": True, "incident": _serialize(row)}


@router.get("")
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    query = db.query(Incident).filter(Incident.tenant_id == _tenant(user))
    return {
        "total": query.count(),
        "items": [_serialize(row) for row in query.order_by(Incident.discovered_at.desc()).offset(offset).limit(limit).all()],
    }


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    row = db.query(Incident).filter(Incident.id == incident_id, Incident.tenant_id == _tenant(user)).first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize(row)


@router.patch("/{incident_id}")
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    tenant_id = _tenant(user)
    row = db.query(Incident).filter(Incident.id == incident_id, Incident.tenant_id == tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    values = payload.model_dump(exclude_unset=True)
    asset_ids = values.get("affected_asset_ids", row.affected_asset_ids or [])
    finding_ids = values.get("related_finding_ids", row.related_finding_ids or [])
    _validate_links(db, tenant_id, asset_ids, finding_ids)
    if "severity" in values:
        values["severity"] = _validate_enum(values["severity"], SEVERITIES, "severity")
    if "status" in values:
        values["status"] = _validate_enum(values["status"], STATUSES, "status")
    for key, value in values.items():
        setattr(row, key, value)
    record_operational_event(
        db, tenant_id=tenant_id, event_type="incident.updated",
        resource_type="incident", resource_id=row.id, source_module="STANDARD",
        actor_id=user.get("sub", "unknown"), metadata={"changed_fields": sorted(values)},
    )
    append_to_audit_log_db(db, AuditEntry(
        user=user.get("sub", "unknown"), action="INCIDENT_UPDATED", module="STANDARD",
        detail=f"Updated incident {row.id}: {', '.join(sorted(values))}",
    ), commit=False)
    db.commit()
    db.refresh(row)
    return _serialize(row)
