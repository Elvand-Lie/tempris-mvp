"""Explicit, provenance-preserving cross-module workflow API."""

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import or_

from models import Asset, AuditLog, Finding, FindingStatusHistory
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_role
from services.database import get_db
from services.entitlements import require_module
from services.workflow_connections import build_workflow_overview
from services.exposure_links import (
    active_asset_map,
    candidate_assets,
    confirmed_asset_ids_by_finding,
    confirm_finding_assets,
    is_catalog_finding,
    set_finding_assets,
)
from services.operational_events import record_operational_event


router = APIRouter(dependencies=[Depends(require_module("SYNTHESIS"))])

EXPOSURE_CLASSIFICATION_STATUSES = {"reference_only", "not_applicable"}
# ``ignore`` is a false-positive EDIP disposition. It stays in history but is
# not open posture; analysts can reopen it when new evidence arrives.
RESOLVED_FINDING_STATUSES = {"resolved", "mitigated", "closed", "ignore", "false_positive", "false-positive"}


class FindingWorkflowUpdate(BaseModel):
    asset_id: str | None = Field(default=None, max_length=50)
    sla_days: int | None = Field(default=None, ge=1, le=3650)
    required_action: str | None = Field(default=None, max_length=4000)
    business_impact: str | None = Field(default=None, max_length=2000)
    effort: str | None = Field(default=None, max_length=500)
    revalidate_by: str | None = None
    remediation_verification: str | None = Field(default=None, max_length=2000)


    @field_validator("revalidate_by")
    @classmethod
    def validate_revalidation_date(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        try:
            return date.fromisoformat(value).isoformat()
        except ValueError as exc:
            raise ValueError("revalidate_by must be an ISO date (YYYY-MM-DD)") from exc

    @field_validator(
        "asset_id", "required_action", "business_impact", "effort", "remediation_verification"
    )
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        return value.strip() if isinstance(value, str) and value.strip() else None


class FindingAssetConfirmation(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=100)
    evidence: str | None = Field(default=None, max_length=2000)

    @field_validator("asset_ids")
    @classmethod
    def normalize_asset_ids(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not normalized:
            raise ValueError("At least one asset is required")
        return normalized


class FindingAssetReplacement(BaseModel):
    asset_ids: list[str] = Field(default_factory=list, max_length=100)
    evidence: str | None = Field(default=None, max_length=2000)

    @field_validator("asset_ids")
    @classmethod
    def normalize_asset_ids(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class FindingExposureClassification(BaseModel):
    classification: str = Field(pattern="^(needs_review|reference_intelligence|not_applicable)$")
    rationale: str = Field(min_length=10, max_length=2000)

    @field_validator("rationale")
    @classmethod
    def normalize_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 10:
            raise ValueError("Rationale must contain at least 10 non-whitespace characters")
        return normalized


class FindingLifecycleRequest(BaseModel):
    rationale: str = Field(min_length=10, max_length=2000)



@router.get("/overview")
def workflow_overview(
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Read-only")),
):
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    return build_workflow_overview(db, auth.tenant_id)

def _asset_summary(asset: Asset) -> dict:
    return {
        "id": asset.id,
        "name": asset.name,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "environment": asset.environment,
        "owner": asset.owner,
    }


def _mapping_reason(finding: Finding, asset_ids: list[str], candidates: list[dict], assets: dict[str, Asset]) -> str:
    status = (finding.status or "").strip().lower()
    if status == "reference_only":
        return "reference_intelligence"
    if status == "not_applicable":
        return "not_applicable"
    if status in RESOLVED_FINDING_STATUSES:
        return "closed"
    if asset_ids:
        return "asset_linked"
    if finding.asset_id and finding.asset_id not in assets:
        return "invalid_asset_link"
    if candidates:
        return "candidate_match"
    if is_catalog_finding(finding):
        return "catalogue_reference"
    return "unclassified_intake"


def _restore_exposure_review_status(db: Session, finding: Finding, changed_by: str, note: str) -> None:
    old_status = (finding.status or "").strip().lower()
    if old_status not in EXPOSURE_CLASSIFICATION_STATUSES:
        return
    finding.status = "unmitigated"
    db.add(FindingStatusHistory(
        finding_id=finding.id,
        old_status=old_status,
        new_status="unmitigated",
        changed_by=changed_by,
        notes=note,
    ))


@router.get("/exposures")
def list_exposure_records(
    q: str = Query(default="", max_length=200),
    assignment: str = Query(default="all", pattern="^(all|confirmed|unassigned)$"),
    view: str = Query(
        default="all",
        pattern="^(all|needs_review|suggested|unclassified|reference|asset_linked|not_applicable)$",
    ),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Read-only")),
):
    """Search tenant findings and manage confirmed asset occurrences at PoC scale."""
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")

    query = db.query(Finding).filter(Finding.tenant_id == auth.tenant_id)
    normalized = q.strip()
    if normalized:
        pattern = f"%{normalized}%"
        query = query.filter(or_(
            Finding.id.ilike(pattern),
            Finding.cve.ilike(pattern),
            Finding.cve_id.ilike(pattern),
            Finding.title.ilike(pattern),
            Finding.vendor.ilike(pattern),
            Finding.product.ilike(pattern),
        ))

    assets = active_asset_map(db, auth.tenant_id)
    links = confirmed_asset_ids_by_finding(db, auth.tenant_id, assets)
    rows = query.all()
    classified_rows = []
    for row in rows:
        asset_ids = sorted(links.get(row.id, set()))
        candidates = candidate_assets(row, assets)
        reason = _mapping_reason(row, asset_ids, candidates, assets)
        classified_rows.append((row, asset_ids, candidates, reason))

    if assignment == "confirmed":
        classified_rows = [item for item in classified_rows if item[1]]
    elif assignment == "unassigned":
        classified_rows = [item for item in classified_rows if not item[1]]

    view_reasons = {
        "needs_review": {"invalid_asset_link", "candidate_match", "unclassified_intake"},
        "suggested": {"candidate_match"},
        "unclassified": {"invalid_asset_link", "unclassified_intake"},
        "reference": {"catalogue_reference", "reference_intelligence"},
        "asset_linked": {"asset_linked"},
        "not_applicable": {"not_applicable"},
    }
    if view != "all":
        classified_rows = [item for item in classified_rows if item[3] in view_reasons[view]]

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    classified_rows.sort(key=lambda item: (
        priority_order.get((item[0].priority or "").upper(), 4),
        (item[0].cve or item[0].cve_id or item[0].id).lower(),
        item[0].id,
    ))
    total = len(classified_rows)
    page = classified_rows[offset:offset + limit]
    data = []
    for finding, asset_ids, candidates, mapping_reason in page:
        data.append({
            "finding_id": finding.id,
            "cve": finding.cve or finding.cve_id,
            "title": finding.title,
            "vendor": finding.vendor,
            "product": finding.product,
            "source": finding.source or "unknown",
            "priority": finding.priority,
            "status": finding.status,
            "mapping_reason": mapping_reason,
            "is_catalog": is_catalog_finding(finding),
            "confirmed_asset_ids": asset_ids,
            "confirmed_assets": [_asset_summary(assets[asset_id]) for asset_id in asset_ids],
            "candidate_assets": candidates,
        })
    return {"data": data, "total": total, "limit": limit, "offset": offset, "view": view}


@router.put("/findings/{finding_id}/exposure-classification")
def classify_finding_exposure(
    finding_id: str,
    req: FindingExposureClassification,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Record an analyst decision for an unlinked finding without inventing exposure."""
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    assets = active_asset_map(db, auth.tenant_id)
    if confirmed_asset_ids_by_finding(db, auth.tenant_id, assets).get(finding.id):
        raise HTTPException(
            status_code=409,
            detail="Clear the affected asset assignment before classifying this record as reference or not applicable",
        )

    target_status = {
        "needs_review": "unmitigated",
        "reference_intelligence": "reference_only",
        "not_applicable": "not_applicable",
    }[req.classification]
    old_status = (finding.status or "unmitigated").strip().lower()
    if old_status in RESOLVED_FINDING_STATUSES:
        raise HTTPException(
            status_code=409,
            detail="Closed or resolved findings must be reopened through their finding workflow before exposure classification",
        )
    if req.classification == "needs_review" and old_status not in EXPOSURE_CLASSIFICATION_STATUSES:
        return {
            "status": "unchanged",
            "finding_id": finding.id,
            "classification": "needs_review",
        }
    if old_status == target_status:
        return {
            "status": "unchanged",
            "finding_id": finding.id,
            "classification": req.classification,
        }

    finding.status = target_status
    db.add(FindingStatusHistory(
        finding_id=finding.id,
        old_status=old_status,
        new_status=target_status,
        changed_by=auth.user_id,
        notes=req.rationale,
    ))
    record_operational_event(
        db,
        tenant_id=auth.tenant_id,
        event_type=("finding.reference_only" if target_status == "reference_only" else "finding.not_applicable" if target_status == "not_applicable" else "finding.reopened"),
        resource_type="finding",
        resource_id=finding.id,
        source_module="INTAKE_TRIAGE",
        actor_id=auth.user_id,
        metadata={"previous_status": old_status, "new_status": target_status},
    )
    append_to_audit_log_db(db, AuditEntry(
        user=auth.user_id,
        action="FINDING_EXPOSURE_CLASSIFIED",
        module="SPECTRUM",
        detail=f"Classified {finding.id} as {req.classification}",
        metadata={
            "finding_id": finding.id,
            "previous_status": old_status,
            "new_status": target_status,
            "classification": req.classification,
            "rationale_recorded": True,
        },
    ), commit=False)
    db.commit()
    _publish_finding_refresh(auth.tenant_id, finding.id, target_status)
    return {
        "status": "updated",
        "finding_id": finding.id,
        "classification": req.classification,
    }


@router.get("/exposure-activity")
def list_exposure_activity(
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=5, ge=1, le=25),
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Read-only")),
):
    """Return recent tamper-evident finding-to-asset assignment changes."""
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")

    rows = db.query(AuditLog).filter(
        AuditLog.tenant_id == auth.tenant_id,
        AuditLog.action.in_((
            "FINDING_ASSETS_CONFIRMED",
            "FINDING_ASSET_ASSIGNMENT_UPDATED",
            "FINDING_EXPOSURE_CLASSIFIED",
        )),
    ).order_by(AuditLog.id.desc()).limit(250).all()
    finding_ids = {
        str((row.metadata_ or {}).get("finding_id"))
        for row in rows if (row.metadata_ or {}).get("finding_id")
    }
    findings = {
        row.id: row
        for row in db.query(Finding).filter(
            Finding.tenant_id == auth.tenant_id,
            Finding.id.in_(finding_ids),
        ).all()
    } if finding_ids else {}
    assets = active_asset_map(db, auth.tenant_id)
    normalized = q.strip().lower()
    data = []
    for row in rows:
        metadata = dict(row.metadata_ or {})
        finding_id = str(metadata.get("finding_id") or "")
        finding = findings.get(finding_id)
        after_ids = list(metadata.get("after_asset_ids") or metadata.get("asset_ids") or [])
        before_ids = list(metadata.get("before_asset_ids") or [])
        added_ids = list(metadata.get("added_asset_ids") or after_ids)
        removed_ids = list(metadata.get("removed_asset_ids") or [])
        if row.action == "FINDING_EXPOSURE_CLASSIFIED":
            classification = str(metadata.get("classification") or "reviewed").replace("_", " ")
            change = f"Classified: {classification}"
        elif added_ids and removed_ids:
            change = "Reassigned"
        elif removed_ids and not after_ids:
            change = "Cleared"
        elif removed_ids:
            change = "Removed asset"
        elif before_ids:
            change = "Updated"
        else:
            change = "Assigned"
        asset_names = [
            assets[asset_id].name if asset_id in assets else asset_id
            for asset_id in after_ids
        ]
        item = {
            "audit_id": row.id,
            "finding_id": finding_id,
            "cve": (finding.cve or finding.cve_id) if finding else None,
            "title": finding.title if finding else finding_id,
            "change": change,
            "asset_ids": after_ids,
            "asset_names": asset_names,
            "added_asset_ids": added_ids,
            "removed_asset_ids": removed_ids,
            "recorded_by": row.user_email,
            "recorded_at": row.timestamp.isoformat() if row.timestamp else None,
            "evidence_recorded": bool(metadata.get("evidence_recorded")),
        }
        searchable = " ".join([
            finding_id,
            item["cve"] or "",
            item["title"] or "",
            item["recorded_by"] or "",
            *asset_names,
        ]).lower()
        if normalized and normalized not in searchable:
            continue
        data.append(item)
        if len(data) >= limit:
            break
    return {"data": data}



@router.post("/findings/{finding_id}/assets")
def confirm_finding_asset_links(
    finding_id: str,
    req: FindingAssetConfirmation,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Confirm one vulnerability occurrence on one or more tenant assets."""
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if is_catalog_finding(finding) and len((req.evidence or '').strip()) < 10:
        raise HTTPException(
            status_code=422,
            detail="Catalogue vulnerability links require at least 10 characters explaining why the selected asset is affected",
        )
    rows = db.query(Asset).filter(
        Asset.tenant_id == auth.tenant_id,
        Asset.id.in_(req.asset_ids),
        Asset.status != "decommissioned",
    ).all()
    by_id = {asset.id: asset for asset in rows}
    missing = [asset_id for asset_id in req.asset_ids if asset_id not in by_id]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Assets are not active in this tenant: {', '.join(missing)}",
        )
    ordered_assets = [by_id[asset_id] for asset_id in req.asset_ids]
    _restore_exposure_review_status(
        db,
        finding,
        auth.user_id,
        "Returned to active review because an analyst recorded an affected asset",
    )
    confirm_finding_assets(
        db, finding, ordered_assets, auth.user_id, req.evidence,
    )
    record_operational_event(
        db, tenant_id=auth.tenant_id, event_type="finding.asset_confirmed",
        resource_type="finding", resource_id=finding.id, source_module="INTAKE_TRIAGE",
        actor_id=auth.user_id, metadata={"asset_ids": req.asset_ids},
    )
    append_to_audit_log_db(
        db,
        AuditEntry(
            user=auth.user_id,
            action="FINDING_ASSETS_CONFIRMED",
            module="SPECTRUM",
            detail=f"Confirmed {finding.id} on {len(ordered_assets)} tenant asset(s)",
            metadata={
                "finding_id": finding.id,
                "asset_ids": req.asset_ids,
                "evidence_recorded": bool(req.evidence),
            },
        ),
        commit=False,
    )
    db.commit()
    _publish_finding_refresh(auth.tenant_id, finding.id, finding.status or "unmitigated")
    active_ids = sorted(
        confirmed_asset_ids_by_finding(db, auth.tenant_id).get(finding.id, set())
    )
    return {
        "status": "confirmed",
        "finding_id": finding.id,
        "confirmed_asset_ids": active_ids,
        "confirmed_exposure_count": len(active_ids),
    }

@router.put("/findings/{finding_id}/assets")
def replace_finding_asset_links(
    finding_id: str,
    req: FindingAssetReplacement,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Replace, expand, or clear the full active asset assignment for a finding."""
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    rows = []
    if req.asset_ids:
        rows = db.query(Asset).filter(
            Asset.tenant_id == auth.tenant_id,
            Asset.id.in_(req.asset_ids),
            Asset.status != "decommissioned",
        ).all()
    by_id = {asset.id: asset for asset in rows}
    missing = [asset_id for asset_id in req.asset_ids if asset_id not in by_id]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Assets are not active in this tenant: {', '.join(missing)}",
        )

    assets_map = active_asset_map(db, auth.tenant_id)
    current_ids = set(
        confirmed_asset_ids_by_finding(db, auth.tenant_id, assets_map).get(finding.id, set())
    )
    requested_ids = set(req.asset_ids)
    added_ids = requested_ids - current_ids
    evidence = (req.evidence or "").strip()
    if added_ids and is_catalog_finding(finding) and len(evidence) < 10:
        raise HTTPException(
            status_code=422,
            detail="New catalogue vulnerability links require at least 10 characters explaining why the selected asset is affected",
        )

    ordered_assets = [by_id[asset_id] for asset_id in req.asset_ids]
    if ordered_assets:
        _restore_exposure_review_status(
            db,
            finding,
            auth.user_id,
            "Returned to active review because an analyst recorded an affected asset",
        )
    before, after, added, removed = set_finding_assets(
        db, finding, ordered_assets, auth.user_id, evidence or None,
    )
    if before == after:
        db.rollback()
        return {
            "status": "unchanged",
            "finding_id": finding.id,
            "confirmed_asset_ids": after,
            "added_asset_ids": [],
            "removed_asset_ids": [],
        }

    append_to_audit_log_db(
        db,
        AuditEntry(
            user=auth.user_id,
            action="FINDING_ASSET_ASSIGNMENT_UPDATED",
            module="SPECTRUM",
            detail=(
                f"Updated {finding.id} asset assignment: "
                f"{len(added)} added, {len(removed)} removed, {len(after)} active"
            ),
            metadata={
                "finding_id": finding.id,
                "before_asset_ids": before,
                "after_asset_ids": after,
                "added_asset_ids": added,
                "removed_asset_ids": removed,
                "evidence_recorded": bool(evidence),
            },
        ),
        commit=False,
    )
    if added:
        record_operational_event(
            db, tenant_id=auth.tenant_id, event_type="finding.asset_confirmed",
            resource_type="finding", resource_id=finding.id, source_module="INTAKE_TRIAGE",
            actor_id=auth.user_id, metadata={"asset_ids": added},
        )
    db.commit()
    _publish_finding_refresh(auth.tenant_id, finding.id, finding.status or "unmitigated")
    return {
        "status": "updated",
        "finding_id": finding.id,
        "confirmed_asset_ids": after,
        "added_asset_ids": added,
        "removed_asset_ids": removed,
    }


def _publish_finding_refresh(tenant_id: str, finding_id: str, status: str) -> None:
    try:
        from routers.edip import _publish_sss_event
        _publish_sss_event(tenant_id, {
            "type": "finding.refresh",
            "finding_id": finding_id,
            "status": status,
        })
    except Exception:
        pass


@router.post("/findings/{finding_id}/resolve")
def resolve_finding(
    finding_id: str,
    req: FindingLifecycleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin")),
):
    auth = get_auth_context(user)
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    old_status = (finding.status or "unmitigated").strip().lower()
    if old_status in RESOLVED_FINDING_STATUSES:
        raise HTTPException(status_code=409, detail="Finding is already resolved")
    finding.status = "resolved"
    db.add(FindingStatusHistory(
        finding_id=finding.id, old_status=old_status, new_status="resolved",
        changed_by=auth.user_id, notes=req.rationale.strip(),
    ))
    record_operational_event(
        db, tenant_id=auth.tenant_id, event_type="finding.resolved",
        resource_type="finding", resource_id=finding.id, source_module="INTAKE_TRIAGE",
        actor_id=auth.user_id, metadata={"previous_status": old_status},
    )
    append_to_audit_log_db(db, AuditEntry(
        user=auth.user_id, action="FINDING_RESOLVED", module="SPECTRUM",
        detail=f"Resolved finding {finding.id}", metadata={"finding_id": finding.id},
    ), commit=False)
    db.commit()
    _publish_finding_refresh(auth.tenant_id, finding.id, "resolved")
    return {"status": "resolved", "finding_id": finding.id}


@router.post("/findings/{finding_id}/reopen")
def reopen_finding(
    finding_id: str,
    req: FindingLifecycleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin")),
):
    auth = get_auth_context(user)
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    old_status = (finding.status or "").strip().lower()
    if old_status not in RESOLVED_FINDING_STATUSES:
        raise HTTPException(status_code=409, detail="Only a resolved, closed, or false-positive finding can be reopened")
    finding.status = "unmitigated"
    db.add(FindingStatusHistory(
        finding_id=finding.id, old_status=old_status, new_status="unmitigated",
        changed_by=auth.user_id, notes=req.rationale.strip(),
    ))
    record_operational_event(
        db, tenant_id=auth.tenant_id, event_type="finding.reopened",
        resource_type="finding", resource_id=finding.id, source_module="INTAKE_TRIAGE",
        actor_id=auth.user_id, metadata={"previous_status": old_status},
    )
    append_to_audit_log_db(db, AuditEntry(
        user=auth.user_id, action="FINDING_REOPENED", module="SPECTRUM",
        detail=f"Reopened finding {finding.id}", metadata={"finding_id": finding.id},
    ), commit=False)
    db.commit()
    _publish_finding_refresh(auth.tenant_id, finding.id, "unmitigated")
    return {"status": "reopened", "finding_id": finding.id}



@router.patch("/findings/{finding_id}")
def update_finding_workflow(
    finding_id: str,
    req: FindingWorkflowUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Record analyst-supplied workflow facts; no values are inferred or defaulted."""
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    supplied = set(req.model_fields_set)
    if not supplied:
        raise HTTPException(status_code=422, detail="At least one workflow field is required")

    changes: dict[str, object] = {}
    if "asset_id" in supplied:
        if req.asset_id and is_catalog_finding(finding):
            raise HTTPException(
                status_code=422,
                detail="Use the evidence-backed asset confirmation endpoint for catalogue vulnerabilities",
            )
        if req.asset_id:
            asset = db.query(Asset).filter(
                Asset.id == req.asset_id,
                Asset.tenant_id == auth.tenant_id,
                Asset.status != "decommissioned",
            ).first()
            if not asset:
                raise HTTPException(status_code=422, detail="Asset is not an active asset in this tenant")
            set_finding_assets(db, finding, [asset], auth.user_id)
        else:
            set_finding_assets(db, finding, [], auth.user_id)
        changes["asset_id"] = req.asset_id
    if "sla_days" in supplied:
        finding.sla = req.sla_days
        changes["sla_days"] = req.sla_days
    if "required_action" in supplied:
        finding.required_action = req.required_action
        changes["required_action"] = bool(req.required_action)

    sss = dict(finding.sss_data or {})
    sss_fields = {
        "business_impact": req.business_impact,
        "effort": req.effort,
        "revalidate_by": req.revalidate_by,
        "remediation_verification": req.remediation_verification,
    }
    for field, value in sss_fields.items():
        if field not in supplied:
            continue
        if value is None:
            sss.pop(field, None)
        else:
            sss[field] = value
        changes[field] = bool(value) if isinstance(value, str) else value

    provenance = dict(sss.get("workflow_provenance") or {})
    recorded_at = datetime.now(timezone.utc).isoformat()
    for field in supplied:
        provenance[field] = {
            "source": "explicit_analyst_update",
            "recorded_by": auth.user_id,
            "recorded_at": recorded_at,
        }
    if provenance:
        sss["workflow_provenance"] = provenance
    finding.sss_data = sss

    append_to_audit_log_db(
        db,
        AuditEntry(
            user=auth.user_id,
            action="FINDING_WORKFLOW_UPDATED",
            module="SPECTRUM",
            detail=f"Recorded explicit workflow fields for {finding.id}: {', '.join(sorted(supplied))}",
            metadata={"finding_id": finding.id, "fields": sorted(supplied), "changes": changes},
        ),
        commit=False,
    )
    db.commit()
    if "asset_id" in supplied:
        _publish_finding_refresh(auth.tenant_id, finding.id, finding.status or "unmitigated")
    return {
        "status": "updated",
        "finding_id": finding.id,
        "recorded_fields": sorted(supplied),
        "provenance": "explicit_analyst_update",
    }
