from fastapi import APIRouter, HTTPException, Depends, Request, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from services.tes_engine import calculate_tes, TESInputs, calculate_finding_tes, decision_from_tes, priority_from_tes, public_severity, public_decision_for_finding, public_cve_context, recalculate_open_cve_findings
from services.sss_contract import public_sss_output
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
from services.kev_loader import get_findings_paginated, get_finding_by_id, _finding_to_dict
from services.database import get_db
from models import EdipDecision, FindingEvidence
from services.edip_engine import auto_classify
from middleware.rate_limit import detect_probe_attempt
from typing import Any
from pathlib import Path
from uuid import uuid4

from services.entitlements import require_module
from services.customer_posture import build_customer_posture, canonical_exposure_rows

router = APIRouter(dependencies=[Depends(require_module("SPECTRUM"))])

VALID_EDIP_DECISIONS = {"mitigate", "accept", "transfer", "ignore"}

class EDIPRequest(BaseModel):
    decision: str  # mitigate, accept, transfer, ignore
    rationale: str | None = None  # Business justification for the decision


class PublicTESResponse(BaseModel):
    tes_score: float
    decision: str


class BusinessImpactUpdate(BaseModel):
    value: float = Field(ge=0, le=10)
    justification: str = Field(min_length=10, max_length=2000)

def _load_edip_decisions(db: Session, user_tenant_id: str | None, is_superadmin: bool) -> dict:
    """Load all EDIP decisions from DB into a lookup dict, filtered by tenant."""
    if not user_tenant_id:
        return {}
    decisions = db.query(EdipDecision).filter(
        EdipDecision.tenant_id == user_tenant_id
    ).all()
    return {
        d.finding_id: {
            "decision": d.decision,
            "rationale": d.rationale,
            "decided_by": d.decided_by,
        }
        for d in decisions
    }



def _public_tes_score(f: dict, db: Session, tenant_id: str) -> float:
    """Use live server-side GRC context for non-CVE findings."""
    return calculate_finding_tes(f, db=db, tenant_id=tenant_id)


def _strip_internal_fields(f: dict) -> dict:
    sss = f.get("sss_data") or {}
    f.update(public_sss_output(sss))
    if sss.get("fim_bypass"):
        f["fim_bypass"] = True
        f["fim_bypass_note"] = sss.get("fim_bypass_note")
    if sss.get("type"):
        f["finding_type"] = sss.get("type")
    if sss.get("sub_class"):
        f["sub_class"] = sss.get("sub_class")
    if sss.get("source"):
        f["source_detail"] = sss.get("source")
    for public_key, private_key in (
        ("patch_available", "patch_available"),
        ("compensating_controls", "compensating_controls"),
        ("source_references", "references"),
        ("attack_vectors", "attack_vectors"),
        ("mas_trm_mapping", "mas_trm_mapping"),
    ):
        value = sss.get(private_key)
        if value not in (None, [], ""):
            f[public_key] = value
    for field in ("raw_inputs", "sss_data", "tes_breakdown"):
        f.pop(field, None)
    return f

PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


@router.get("/findings")
def get_findings(
    page: int = 1,
    limit: int = 50,
    priority: str | None = None,
    search: str | None = None,
    decision: str | None = None,
    scope: str = "all",
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Returns findings with TES scores and canonical intelligence.

    Dedicated SPECTRUM pipeline:
    1. Loads tenant Finding records.
    2. Classifies scope (confirmed exposure, intake, suggested match, etc.).
    3. Hydrates canonical CVE intelligence (CVSS, KEV, Ransomware).
    4. Computes live TES scores, decisions, and priorities.
    5. Filters by scope, decision, and live TES priority.
    6. Stably sorts by live TES priority -> TES score desc -> CVSS desc -> stable ID.
    7. Paginates the exact sorted and filtered results.
    """
    from models import Finding
    from routers.auth import get_auth_context
    from sqlalchemy import or_

    auth_ctx = get_auth_context(user)
    edip_map = _load_edip_decisions(db, auth_ctx.tenant_id, auth_ctx.is_superadmin)
    posture = build_customer_posture(db, auth_ctx.tenant_id)
    confirmed_ids = set(posture["confirmed_finding_ids"])
    legacy_ids = set(posture["legacy_unverified_finding_ids"])
    confirmed_assets: dict[str, list[dict[str, Any]]] = {}

    for finding, asset, link in canonical_exposure_rows(db, auth_ctx.tenant_id, open_only=False):
        confirmed_assets.setdefault(finding.id, []).append({
            "id": asset.id,
            "name": asset.name,
            "ip_address": asset.ip_address,
            "asset_id": asset.id,
            "asset_name": asset.name,
            "asset_ip": asset.ip_address,
            "hostname": asset.hostname,
            "criticality": asset.criticality,
            "environment": asset.environment,
            "evidence": link.evidence,
            "source": link.match_method,
        })

    allowed_scopes = {
        "all", "confirmed_exposure", "unmapped_intake", "suggested_match",
        "reference_intelligence", "not_applicable", "resolved", "catalogue_record",
        "legacy_unverified",
    }
    if scope not in allowed_scopes:
        raise HTTPException(status_code=422, detail="Unknown finding scope")

    query = db.query(Finding).filter(Finding.tenant_id == auth_ctx.tenant_id)
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Finding.cve.ilike(search_pattern),
                Finding.cve_id.ilike(search_pattern),
                Finding.title.ilike(search_pattern),
                Finding.vendor.ilike(search_pattern),
                Finding.id.ilike(search_pattern),
            )
        )

    all_tenant_findings = query.all()

    # Pre-fetch evidence files for all candidate findings
    candidate_ids = [f.id for f in all_tenant_findings]
    evidence_by_finding: dict[str, list[dict[str, Any]]] = {}
    if candidate_ids:
        for evidence in db.query(FindingEvidence).filter(FindingEvidence.finding_id.in_(candidate_ids)).all():
            evidence_by_finding.setdefault(evidence.finding_id, []).append({
                "id": evidence.id,
                "filename": evidence.filename,
                "uploaded_by": evidence.uploaded_by,
                "uploaded_at": evidence.uploaded_at.isoformat() if evidence.uploaded_at else None,
                "verification_state": evidence.verification_state,
            })

    def record_scope(record: dict) -> str:
        status = str(record.get("status") or "").lower()
        record_id = record.get("id")
        if record_id in confirmed_ids:
            return "confirmed_exposure"
        if status in {"resolved", "closed", "mitigated", "ignore", "false_positive", "false-positive"}:
            return "resolved"
        if status in {"not_applicable", "not-applicable"}:
            return "not_applicable"
        if status in {"reference", "reference_only"}:
            return "reference_intelligence"
        if record_id in legacy_ids:
            return "legacy_unverified"
        queue = next((row for row in posture["mapping_queue"] if row["finding_id"] == record_id), None)
        if queue and queue["mapping_reason"] == "suggested_match":
            return "suggested_match"
        if queue:
            return "unmapped_intake"
        if record.get("cisa") or record.get("cisa_kev") or str(record.get("source") or "").lower() in {"kev", "cisa", "nvd", "catalog"}:
            return "catalogue_record"
        return "unmapped_intake"

    processed: list[dict[str, Any]] = []

    for f_orm in all_tenant_findings:
        f = _finding_to_dict(f_orm)
        scope_label = record_scope(f)
        if scope != "all" and scope_label != scope:
            continue

        f_copy = f.copy()
        f_copy["record_scope"] = scope_label
        f_copy["record_scope_label"] = scope_label.replace("_", " ").title()

        # Authoritative canonical intelligence resolution
        is_cve = str(f.get("cve") or f.get("cve_id") or "").upper().startswith("CVE-")
        intel = None
        if is_cve:
            from services.cve_intelligence import resolve_vulnerability_intelligence
            intel = resolve_vulnerability_intelligence(f, db)
            f_copy["vulnerability_intelligence"] = intel.to_dict()
            if intel.cvss_score is not None:
                f_copy["cvss"] = intel.cvss_score
            f_copy["cisa_kev"] = intel.is_cisa_kev
            f_copy["cisa"] = intel.is_cisa_kev
            f_copy["ransomware"] = intel.is_ransomware

        # Live TES resolution
        has_cve_score = is_cve and f_copy.get("cvss") is not None
        has_sss_score = (not is_cve) and bool(
            (f.get("sss_data") or {}).get("scoring")
            or ((f.get("sss_data") or {}).get("base_severity") is not None)
            or (f.get("cvss") is not None and f.get("cvss") > 0)
        )

        if has_cve_score or has_sss_score:
            try:
                tes_val = _public_tes_score(f, db, auth_ctx.tenant_id)
                f_copy["tes_score"] = tes_val
                f_copy["tes_decision"] = public_decision_for_finding(f, tes_val)
                f_copy["tes_priority"] = priority_from_tes(tes_val)
            except (KeyError, TypeError, ValueError):
                f_copy["tes_score"] = None
                f_copy["tes_decision"] = None
                f_copy["tes_priority"] = None
        else:
            f_copy["tes_score"] = None
            f_copy["tes_decision"] = None
            f_copy["tes_priority"] = None

        f_copy["severity"] = public_severity(f, db=db)
        if is_cve and f_copy["tes_score"] is not None:
            f_copy["business_impact"] = public_cve_context(f, db=db, tenant_id=auth_ctx.tenant_id)["business_impact"]

        # Native SPECTRUM receives canonical confirmed assets
        assets = confirmed_assets.get(f["id"], [])
        f_copy["assets"] = assets
        f_copy["asset"] = assets[0] if assets else None
        f_copy["evidence_files"] = evidence_by_finding.get(f["id"], [])
        asset_data = assets[0] if assets else None
        asset_ctx = None
        if asset_data:
            asset_ctx = {
                "asset_name": asset_data.get("asset_name", ""),
                "asset_ip": asset_data.get("asset_ip", ""),
                "asset_id": asset_data.get("asset_id", ""),
            }

        # Automated EDIP classification
        cisa_flag = intel.is_cisa_kev if intel else bool(f.get("cisa", False))
        ransomware_flag = intel.is_ransomware if intel else bool(f.get("ransomware", False))
        f_copy["auto_classification"] = auto_classify(
            cvss=f_copy["severity"]["score"],
            asset_criticality=(asset_data or {}).get("criticality", "high"),
            cisa_kev=cisa_flag,
            ransomware_linked=ransomware_flag,
            asset_context=asset_ctx,
            severity_source=f_copy["severity"]["source"],
        )

        # Overlay persisted EDIP decision + rationale
        if f["id"] in edip_map:
            edip_data = edip_map[f["id"]]
            f_copy["edip_decision"] = edip_data["decision"]
            f_copy["edip_rationale"] = edip_data.get("rationale")
            f_copy["edip_decided_by"] = edip_data.get("decided_by")

        # Filter by decision
        if decision:
            has_decision = f_copy.get("edip_decision") is not None
            if decision == "pending" and has_decision:
                continue
            if decision == "decided" and not has_decision:
                continue
            if decision in VALID_EDIP_DECISIONS and f_copy.get("edip_decision") != decision:
                continue

        # Filter by live TES priority
        if priority:
            if f_copy.get("tes_priority") != priority and f_copy.get("priority") != priority:
                continue

        processed.append(_strip_internal_fields(f_copy))

    # Stable sort: TES Priority -> TES score desc -> CVSS desc -> created_at / ID
    def _spectrum_sort_key(item: dict) -> tuple:
        p = item.get("tes_priority") or item.get("priority")
        p_rank = PRIORITY_RANK.get(p, 99) if p else 99
        tes = item.get("tes_score")
        tes_val = float(tes) if tes is not None else -1.0
        cvss = item.get("cvss")
        cvss_val = float(cvss) if cvss is not None else -1.0
        fid = str(item.get("id") or "")
        return (p_rank, -tes_val, -cvss_val, fid)

    processed.sort(key=_spectrum_sort_key)

    total = len(processed)
    start = max(0, (page - 1) * limit)
    paged = processed[start : start + limit]

    return {
        "data": paged,
        "meta": {"total": total, "page": page, "limit": limit, "scope": scope}
    }


@router.patch("/findings/{finding_id}/business-impact")
def update_business_impact(
    finding_id: str,
    req: BusinessImpactUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Record explicit analyst impact for a confirmed CVE exposure."""
    from datetime import datetime, timezone
    from models import Finding
    from routers.audit import append_to_audit_log_db, AuditEntry
    from routers.auth import get_auth_context

    auth = get_auth_context(user)
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not str(finding.cve or finding.cve_id or "").upper().startswith("CVE-"):
        raise HTTPException(status_code=422, detail="Business impact assessment is available for CVE findings")
    if not any(row[0].id == finding.id for row in canonical_exposure_rows(db, auth.tenant_id)):
        raise HTTPException(status_code=409, detail="Business impact requires a confirmed active customer exposure")

    context = dict(finding.cve_context or {})
    context["business_impact"] = {
        "value": req.value,
        "justification": req.justification.strip(),
        "source": "analyst_assessment",
        "assessed_by": auth.user_id,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }
    finding.cve_context = context
    recalculated = recalculate_open_cve_findings(
        db, auth.tenant_id, actor_id=auth.user_id, reason="business_impact_updated",
    )
    from services.operational_events import record_operational_event
    record_operational_event(
        db, tenant_id=auth.tenant_id, event_type="finding.business_impact_assessed",
        resource_type="finding", resource_id=finding.id, source_module="SPECTRUM",
        actor_id=auth.user_id, metadata={"assessed": True},
    )
    append_to_audit_log_db(db, AuditEntry(
        user=auth.user_id, action="FINDING_BUSINESS_IMPACT_UPDATED", module="SPECTRUM",
        detail=f"Recorded business impact for {finding.id}",
        metadata={"finding_id": finding.id, "business_impact": req.value},
    ), commit=False)
    db.commit()
    try:
        from routers.edip import _publish_sss_event
        for refreshed_id in set(recalculated) | {finding.id}:
            _publish_sss_event(auth.tenant_id, {"type": "finding.refresh", "finding_id": refreshed_id})
    except Exception:
        pass
    return {"finding_id": finding.id, "business_impact": req.value, "recalculated_finding_ids": recalculated}

@router.post("/findings/{finding_id}/edip")
async def record_edip_decision(
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Records an EDIP decision for a finding — persisted to PostgreSQL.
    Requires Superadmin, Admin, or Analyst role.
    """
    from routers.auth import get_auth_context
    from services.edip_validator import EDIPDecision, validate_edip_transition
    from routers.audit import append_to_audit_log_db, AuditEntry
    from models import AuditLog, Finding
    from sqlalchemy.sql import func
    from fastapi.responses import JSONResponse

    auth_ctx = get_auth_context(user)
    if not auth_ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    user_email = auth_ctx.user_id

    # 1. Parse request body manually
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    # 2. Strict type check on body
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    # Reject unexpected fields
    allowed_keys = {"decision", "rationale"}
    if not set(body.keys()).issubset(allowed_keys):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    # Validate decision
    if "decision" not in body:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    raw_decision = body.get("decision")
    if raw_decision is None or not isinstance(raw_decision, str):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    # Empty and whitespace-only values must return 422
    if not raw_decision.strip():
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    # Case normalization may be used to preserve already documented contract (.strip().lower())
    cleaned_decision = raw_decision.strip().lower()

    if len(cleaned_decision) > 20:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    if cleaned_decision not in {d.value for d in EDIPDecision}:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_EDIP_DECISION",
                    "message": "The supplied decision is not supported."
                }
            }
        )

    # Validate rationale
    rationale = body.get("rationale")
    if "rationale" in body and rationale is not None:
        if not isinstance(rationale, str):
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "code": "INVALID_EDIP_DECISION",
                        "message": "The supplied decision is not supported."
                    }
                }
            )
        if len(rationale) > 2000:
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "code": "INVALID_EDIP_DECISION",
                        "message": "The supplied decision is not supported."
                    }
                }
            )

    # 3. Target resource lookup (tenant scoped check for existing decision)
    # Check if finding exists
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    existing = db.query(EdipDecision).filter(
        EdipDecision.finding_id == finding_id,
        EdipDecision.tenant_id == auth_ctx.tenant_id,
    ).first()

    # 4. An analyst may revise any decision. The prior decision is retained
    # in the decision row, audit record, and operational event.
    current_decision = existing.decision if existing else None

    # 5. Idempotency Check
    if existing and existing.decision == cleaned_decision and existing.rationale == rationale:
        return {
            "status": "success",
            "message": f"Recorded decision '{cleaned_decision}' for {finding_id}",
            "finding_id": finding_id,
            "decision": cleaned_decision,
            "decided_by": existing.decided_by,
            "rationale": existing.rationale
        }

    # 6. Database mutation & transaction boundary
    try:
        # Sync finding status workflow state
        finding.status = cleaned_decision

        event_type = (
            "decision.overridden"
            if existing and existing.decision != cleaned_decision
            else "decision.updated" if existing else "decision.created"
        )
        if existing:
            if existing.decision != cleaned_decision:
                existing.original_decision = existing.decision
                existing.override_reason = rationale
            existing.decision = cleaned_decision
            existing.rationale = rationale
            existing.decided_by = user_email
            existing.decided_at = func.now()
        else:
            db.add(EdipDecision(
                tenant_id=auth_ctx.tenant_id,
                finding_id=finding_id,
                cve=finding.cve or "",
                decision=cleaned_decision,
                rationale=rationale,
                decided_by=user_email
            ))
        db.flush()

        # Audit entry inside same transaction
        append_to_audit_log_db(db, AuditEntry(
            user=user_email,
            action="EDIP_DECISION",
            module="SPECTRUM",
            detail=f"Applied '{cleaned_decision}' to {finding_id} ({finding.cve or ''}). Rationale: {rationale or 'None provided'}",
            metadata={"finding_id": finding_id, "previous_decision": current_decision, "decision": cleaned_decision},
        ), commit=False)
        from services.operational_events import record_operational_event
        record_operational_event(
            db,
            tenant_id=auth_ctx.tenant_id,
            event_type=event_type,
            resource_type="finding",
            resource_id=finding_id,
            source_module="SPECTRUM",
            actor_id=user_email,
            metadata={"previous_decision": current_decision, "decision": cleaned_decision},
        )

        db.commit()
    except Exception as e:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "TRANSACTION_FAILED",
                    "message": "Failed to record EDIP decision due to internal storage error."
                }
            }
        )

    try:
        from routers.edip import _publish_sss_event
        _publish_sss_event(auth_ctx.tenant_id, {"type": "finding.refresh", "finding_id": finding_id, "status": cleaned_decision})
    except Exception:
        pass

    return {
        "status": "success",
        "message": f"Recorded decision '{cleaned_decision}' for {finding_id}",
        "finding_id": finding_id,
        "decision": cleaned_decision,
        "decided_by": user_email,
        "rationale": rationale
    }

@router.post("/calculate-tes", response_model=PublicTESResponse)
def calculate_custom_tes(
    inputs: TESInputs,
    request: Request,
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Return public TES output without exposing scoring components."""
    if detect_probe_attempt(user.get("sub", "unknown"), request.url.path, inputs.model_dump()):
        append_to_audit_log(AuditEntry(
            user=user.get("sub", "unknown"),
            action="TES_PROBE_DETECTED",
            module="SPECTRUM",
            detail="Repeated near-variant TES scoring requests blocked.",
            ip_address=request.client.host if request.client else None,
        ))
        raise HTTPException(status_code=429, detail="PROBE_PATTERN_DETECTED")
    score = calculate_tes(inputs).total_score
    return PublicTESResponse(tes_score=score, decision=decision_from_tes(score))


from models import FindingRelationship, FindingSource, FindingDisputedClaim, FindingControl, FindingStatusHistory, Finding


def _tenant_finding(db: Session, finding_id: str, user: dict) -> Finding:
    from routers.auth import get_auth_context
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

# ── Finding Relationships (CORE-C06) ─────────────────────────────────────────

class FindingRelationshipReq(BaseModel):
    source_id: str
    target_id: str
    relationship_type: str
    metadata_: Any = {}

@router.post("/findings/relationships")
def create_relationship(
    req: FindingRelationshipReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    _tenant_finding(db, req.source_id, user)
    _tenant_finding(db, req.target_id, user)
            
    rel = FindingRelationship(
        source_id=req.source_id,
        target_id=req.target_id,
        relationship_type=req.relationship_type,
        metadata_=req.metadata_
    )
    db.add(rel)
    db.commit()
    db.refresh(rel)
    return rel

@router.get("/findings/{finding_id}/relationships")
def get_relationships(
    finding_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    _tenant_finding(db, finding_id, user)
        
    # Get all relationships where finding is source or target
    from sqlalchemy import or_
    rels = db.query(FindingRelationship).filter(
        or_(FindingRelationship.source_id == finding_id, FindingRelationship.target_id == finding_id)
    ).all()
    return rels

# ── Finding Sources (THREAT-T02) ─────────────────────────────────────────────

class FindingSourceReq(BaseModel):
    source_id: str
    publisher: str
    retrieved_at: str
    last_verified_at: str
    verification_state: str = "CONFIRMED"
    expiry_date: str | None = None
    analyst_notes: str | None = None

@router.post("/findings/{finding_id}/sources")
def add_finding_source(
    finding_id: str,
    req: FindingSourceReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    from datetime import datetime
    _tenant_finding(db, finding_id, user)
        
    src = FindingSource(
        finding_id=finding_id,
        source_id=req.source_id,
        publisher=req.publisher,
        retrieved_at=datetime.fromisoformat(req.retrieved_at),
        last_verified_at=datetime.fromisoformat(req.last_verified_at),
        verification_state=req.verification_state,
        expiry_date=datetime.fromisoformat(req.expiry_date) if req.expiry_date else None,
        analyst_notes=req.analyst_notes
    )
    db.add(src)
    db.commit()
    db.refresh(src)
    return src

@router.get("/findings/{finding_id}/sources")
def get_finding_sources(
    finding_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    _tenant_finding(db, finding_id, user)
        
    return db.query(FindingSource).filter(FindingSource.finding_id == finding_id).all()

# ── Finding Disputed Claims (CORE-C02) ────────────────────────────────────────

class DisputedClaimReq(BaseModel):
    source: str
    claim_details: str
    disagreement_text: str | None = None
    verification_state: str  # DISPUTED or SINGLE_SOURCE

@router.post("/findings/{finding_id}/disputed-claims")
def add_disputed_claim(
    finding_id: str,
    req: DisputedClaimReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    finding = _tenant_finding(db, finding_id, user)
        
    claim = FindingDisputedClaim(
        finding_id=finding_id,
        source=req.source,
        claim_details=req.claim_details,
        disagreement_text=req.disagreement_text
    )
    db.add(claim)
    
    # Enforce evidence verification state on the finding
    finding.verification = req.verification_state
    db.commit()
    db.refresh(claim)
    return claim

@router.get("/findings/{finding_id}/disputed-claims")
def get_disputed_claims(
    finding_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    _tenant_finding(db, finding_id, user)
        
    return db.query(FindingDisputedClaim).filter(FindingDisputedClaim.finding_id == finding_id).all()

# ── Finding Controls / Remediation (CORE-C07) ───────────────────────────────

class FindingControlReq(BaseModel):
    title: str
    description: str | None = None
    layer_type: str  # build, identity, network, detection, response, governance, awareness, patch, compensating
    priority: str = "P1"
    status: str = "not_assessed"

@router.post("/findings/{finding_id}/controls")
def add_finding_control(
    finding_id: str,
    req: FindingControlReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    _tenant_finding(db, finding_id, user)
        
    ctrl = FindingControl(
        finding_id=finding_id,
        title=req.title,
        description=req.description,
        layer_type=req.layer_type,
        priority=req.priority,
        status=req.status
    )
    db.add(ctrl)
    db.commit()
    db.refresh(ctrl)
    return ctrl

@router.get("/findings/{finding_id}/controls")
def get_finding_controls(
    finding_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    _tenant_finding(db, finding_id, user)
        
    return db.query(FindingControl).filter(FindingControl.finding_id == finding_id).all()

# ── Finding Status History & Audit (CORE-C05) ────────────────────────────────

@router.get("/findings/{finding_id}/history")
def get_finding_history(
    finding_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    _tenant_finding(db, finding_id, user)
        
    return db.query(FindingStatusHistory).filter(FindingStatusHistory.finding_id == finding_id).all()


_FINDING_EVIDENCE_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".md"}
_FINDING_EVIDENCE_MAX_BYTES = 10 * 1024 * 1024


def _finding_evidence_payload(evidence: FindingEvidence) -> dict:
    return {
        "id": evidence.id,
        "filename": evidence.filename,
        "uploaded_by": evidence.uploaded_by,
        "uploaded_at": evidence.uploaded_at.isoformat() if evidence.uploaded_at else None,
        "verification_state": evidence.verification_state,
    }


@router.get("/findings/{finding_id}/evidence")
def list_finding_evidence(
    finding_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    _tenant_finding(db, finding_id, user)
    return [_finding_evidence_payload(row) for row in db.query(FindingEvidence).filter(
        FindingEvidence.finding_id == finding_id
    ).order_by(FindingEvidence.id.desc()).all()]


@router.post("/findings/{finding_id}/evidence")
async def upload_finding_evidence(
    finding_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Attach analyst-supplied evidence to a tenant finding without inventing proof."""
    from routers.auth import get_auth_context
    from routers.audit import append_to_audit_log_db, AuditEntry
    from routers.standard import get_evidence_storage_root, sanitize_filename, validate_storage_path
    from services.operational_events import record_operational_event

    finding = _tenant_finding(db, finding_id, user)
    auth = get_auth_context(user)
    clean_name = sanitize_filename(file.filename or "evidence_file.dat")
    suffix = Path(clean_name).suffix.lower()
    if suffix not in _FINDING_EVIDENCE_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported evidence file type")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Evidence file is empty")
    if len(content) > _FINDING_EVIDENCE_MAX_BYTES:
        raise HTTPException(status_code=400, detail="Evidence file exceeds 10 MB")

    root = Path(get_evidence_storage_root()).resolve()
    destination_dir = root / "spectrum" / auth.tenant_id / finding.id
    if any(part.is_symlink() for part in (root / "spectrum", root / "spectrum" / auth.tenant_id, destination_dir) if part.exists()):
        raise HTTPException(status_code=400, detail="Invalid evidence storage path")
    try:
        destination_dir.resolve(strict=False).relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid evidence storage path")
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{uuid4().hex}{suffix}"
    validate_storage_path(str(destination), strict=False)
    try:
        destination.write_bytes(content)
        evidence = FindingEvidence(
            finding_id=finding.id,
            filename=clean_name,
            file_path=str(destination),
            uploaded_by=auth.user_id,
        )
        db.add(evidence)
        db.flush()
        record_operational_event(
            db, tenant_id=auth.tenant_id, event_type="finding.evidence_attached",
            resource_type="finding", resource_id=finding.id, source_module="INTAKE_TRIAGE",
            actor_id=auth.user_id, metadata={"evidence_id": evidence.id, "filename": clean_name},
        )
        append_to_audit_log_db(db, AuditEntry(
            user=auth.user_id, action="FINDING_EVIDENCE_UPLOADED", module="SPECTRUM",
            detail=f"Attached evidence to {finding.id}",
            metadata={"finding_id": finding.id, "evidence_id": evidence.id, "filename": clean_name},
        ), commit=False)
        db.commit()
        db.refresh(evidence)
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        if destination.exists():
            destination.unlink()
        raise HTTPException(status_code=500, detail="Evidence upload could not be stored")
    return {"status": "uploaded", "evidence": _finding_evidence_payload(evidence)}


@router.get("/findings/{finding_id}/evidence/{evidence_id}/download")
def download_finding_evidence(
    finding_id: str,
    evidence_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from routers.standard import sanitize_filename, validate_storage_path

    _tenant_finding(db, finding_id, user)
    evidence = db.query(FindingEvidence).filter(
        FindingEvidence.id == evidence_id,
        FindingEvidence.finding_id == finding_id,
    ).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    validate_storage_path(evidence.file_path)
    return FileResponse(evidence.file_path, filename=sanitize_filename(evidence.filename))


