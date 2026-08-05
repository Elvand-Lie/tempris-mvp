"""Explicit, provenance-preserving cross-module workflow API."""

from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from models import Asset, AssetExposure, Finding
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_role
from services.database import get_db
from services.entitlements import require_module
from services.workflow_connections import build_workflow_overview
from services.exposure_links import (
    confirm_finding_assets,
    exposure_rows_for_finding,
    is_catalog_finding,
)


router = APIRouter(dependencies=[Depends(require_module("SYNTHESIS"))])


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


@router.get("/overview")
def workflow_overview(
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Read-only")),
):
    auth = get_auth_context(user)
    if not auth.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    return build_workflow_overview(db, auth.tenant_id)


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
            detail="Catalogue vulnerability links require recorded scanner, inventory, SBOM, or analyst evidence",
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
    links = confirm_finding_assets(
        db, finding, ordered_assets, auth.user_id, req.evidence,
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
    return {
        "status": "confirmed",
        "finding_id": finding.id,
        "confirmed_asset_ids": [row.asset_id for row in links],
        "confirmed_exposure_count": len(exposure_rows_for_finding(db, auth.tenant_id, finding.id)),
    }


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
            confirm_finding_assets(db, finding, [asset], auth.user_id)
        else:
            db.query(AssetExposure).filter(
                AssetExposure.tenant_id == auth.tenant_id,
                AssetExposure.finding_id == finding.id,
            ).delete(synchronize_session=False)
            finding.asset_id = None
            finding.asset_data = None
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
    return {
        "status": "updated",
        "finding_id": finding.id,
        "recorded_fields": sorted(supplied),
        "provenance": "explicit_analyst_update",
    }
