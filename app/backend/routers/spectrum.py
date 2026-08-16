from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.tes_engine import calculate_tes, TESInputs, calculate_finding_tes, decision_from_tes, priority_from_tes, public_severity, public_decision_for_finding
from services.sss_contract import public_sss_output
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
from services.kev_loader import get_findings_paginated, get_finding_by_id
from services.database import get_db
from models import EdipDecision
from services.edip_engine import auto_classify
from middleware.rate_limit import detect_probe_attempt
from typing import Any

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



def _public_tes_score(f: dict) -> float:
    return calculate_finding_tes(f)


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
    """Returns findings with TES scores. DB-level pagination, search, and filtering."""
    from routers.auth import get_auth_context
    auth_ctx = get_auth_context(user)
    edip_map = _load_edip_decisions(db, auth_ctx.tenant_id, auth_ctx.is_superadmin)
    posture = build_customer_posture(db, auth_ctx.tenant_id)
    confirmed_ids = set(posture["confirmed_finding_ids"])
    legacy_ids = set(posture["legacy_unverified_finding_ids"])
    confirmed_assets: dict[str, list[dict[str, Any]]] = {}
    for finding, asset, link in canonical_exposure_rows(db, auth_ctx.tenant_id):
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

    # DB-level filtered + paginated query
    fetch_page = 1 if scope != "all" else page
    fetch_limit = 100000 if scope != "all" else limit
    page_findings, total = get_findings_paginated(
        db, page=fetch_page, limit=fetch_limit,
        priority=priority, search=search,
        decision_filter=decision,
        user_tenant_id=auth_ctx.tenant_id,
        is_superadmin=auth_ctx.is_superadmin,
    )

    def record_scope(record: dict) -> str:
        status = str(record.get("status") or "").lower()
        record_id = record.get("id")
        if record_id in confirmed_ids:
            return "confirmed_exposure"
        if status in {"resolved", "closed", "mitigated"}:
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

    scoped = [(row, record_scope(row)) for row in page_findings]
    if scope != "all":
        scoped = [pair for pair in scoped if pair[1] == scope]
        total = len(scoped)
        start = max(0, (page - 1) * limit)
        scoped = scoped[start:start + limit]

    result = []
    for f, scope_label in scoped:
        f_copy = f.copy()
        f_copy["record_scope"] = scope_label
        f_copy["record_scope_label"] = scope_label.replace("_", " ").title()
        f_copy["tes_score"] = _public_tes_score(f)
        f_copy["tes_decision"] = public_decision_for_finding(f, f_copy["tes_score"])
        f_copy["tes_priority"] = priority_from_tes(f_copy["tes_score"])
        f_copy["severity"] = public_severity(f)
        
        # Native SPECTRUM receives canonical confirmed assets, never the legacy
        # Finding.asset_id convenience field.
        assets = confirmed_assets.get(f["id"], [])
        f_copy["assets"] = assets
        f_copy["asset"] = assets[0] if assets else None
        asset_data = assets[0] if assets else None
        asset_ctx = None
        if asset_data:
            asset_ctx = {
                "asset_name": asset_data.get("asset_name", ""),
                "asset_ip": asset_data.get("asset_ip", ""),
                "asset_id": asset_data.get("asset_id", ""),
            }

        # Run automated EDIP classification with context binding
        f_copy["auto_classification"] = auto_classify(
            cvss=f_copy["severity"]["score"],
            asset_criticality=(asset_data or {}).get("criticality", "high"),
            cisa_kev=f.get("cisa", False),
            ransomware_linked=f.get("ransomware", False),
            asset_context=asset_ctx,
            severity_source=f_copy["severity"]["source"],
        )
        
        # Overlay persisted EDIP decision + rationale
        if f["id"] in edip_map:
            edip_data = edip_map[f["id"]]
            f_copy["edip_decision"] = edip_data["decision"]
            f_copy["edip_rationale"] = edip_data.get("rationale")
            f_copy["edip_decided_by"] = edip_data.get("decided_by")
        result.append(_strip_internal_fields(f_copy))

    return {
        "data": result,
        "meta": {"total": total, "page": page, "limit": limit, "scope": scope}
    }

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

    # 4. Transition legality check
    current_decision = existing.decision if existing else None
    if current_decision == "ignore" and cleaned_decision != "ignore":
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "INVALID_STATE_TRANSITION",
                    "message": "Cannot transition out of terminal state 'ignore'."
                }
            }
        )

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
            detail=f"Applied '{cleaned_decision}' to {finding_id} ({finding.cve or ''}). Rationale: {rationale or 'None provided'}"
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
            metadata={"decision": cleaned_decision},
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


from models import FindingRelationship, FindingSource, FindingDisputedClaim, FindingControl, FindingEvidence, FindingStatusHistory, Finding


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


