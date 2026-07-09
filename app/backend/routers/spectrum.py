from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.tes_engine import calculate_tes, TESInputs, calculate_finding_tes, decision_from_tes, priority_from_tes, public_severity, public_decision_for_finding
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
from services.kev_loader import get_findings_paginated, get_finding_by_id
from services.database import get_db
from models import EdipDecision
from services.edip_engine import auto_classify
from middleware.rate_limit import detect_probe_attempt

router = APIRouter()

VALID_EDIP_DECISIONS = {"mitigate", "accept", "transfer", "ignore"}

class EDIPRequest(BaseModel):
    decision: str  # mitigate, accept, transfer, ignore
    rationale: str | None = None  # Business justification for the decision


class PublicTESResponse(BaseModel):
    tes_score: float
    decision: str

def _load_edip_decisions(db: Session) -> dict:
    """Load all EDIP decisions from DB into a lookup dict."""
    decisions = db.query(EdipDecision).all()
    return {d.finding_id: {"decision": d.decision, "rationale": d.rationale, "decided_by": d.decided_by} for d in decisions}



def _public_tes_score(f: dict) -> float:
    return calculate_finding_tes(f)


def _strip_internal_fields(f: dict) -> dict:
    sss = f.get("sss_data") or {}
    if sss.get("fim_bypass"):
        f["fim_bypass"] = True
        f["fim_bypass_note"] = sss.get("fim_bypass_note")
    if sss.get("type"):
        f["finding_type"] = sss.get("type")
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
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Returns findings with TES scores. DB-level pagination, search, and filtering."""
    edip_map = _load_edip_decisions(db)

    # DB-level filtered + paginated query
    page_findings, total = get_findings_paginated(
        db, page=page, limit=limit,
        priority=priority, search=search,
        decision_filter=decision,
    )

    result = []
    for f in page_findings:
        f_copy = f.copy()
        f_copy["tes_score"] = _public_tes_score(f)
        f_copy["tes_decision"] = public_decision_for_finding(f, f_copy["tes_score"])
        f_copy["tes_priority"] = priority_from_tes(f_copy["tes_score"])
        f_copy["severity"] = public_severity(f)
        
        # Build asset context for context-bound output
        asset_data = f.get("asset")
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
            asset_criticality="high",
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
        "meta": {"total": total, "page": page, "limit": limit}
    }

@router.post("/findings/{finding_id}/edip")
def record_edip_decision(
    finding_id: str,
    req: EDIPRequest,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Records an EDIP decision for a finding â€” persisted to PostgreSQL.
    Requires Superadmin, Admin, or Analyst role.
    """
    user_email = user.get("sub", "unknown")
    user_role = user.get("role", "unknown")
    decision = req.decision.strip().lower()
    if decision not in VALID_EDIP_DECISIONS:
        raise HTTPException(status_code=400, detail=f"Invalid EDIP decision. Must be one of: {sorted(VALID_EDIP_DECISIONS)}")

    # DB lookup instead of iterating in-memory list
    target = get_finding_by_id(db, finding_id)
    if not target:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Persist to DB (upsert)
    existing = db.query(EdipDecision).filter(EdipDecision.finding_id == finding_id).first()
    if existing:
        existing.decision = decision
        existing.rationale = req.rationale
        existing.decided_by = user_email
    else:
        db.add(EdipDecision(
            finding_id=finding_id, cve=target.get("cve", ""),
            decision=decision, rationale=req.rationale,
            decided_by=user_email
        ))
    db.commit()
    
    client_ip = request.client.host if request.client else None
    append_to_audit_log(AuditEntry(
        user=user_email,
        action="EDIP_DECISION",
        module="SPECTRUM",
        detail=f"Applied '{decision}' to {finding_id} ({target.get('cve', '')}). Rationale: {req.rationale or 'None provided'}",
        ip_address=client_ip
    ))
    
    return {
        "status": "success",
        "message": f"Recorded decision '{decision}' for {finding_id}",
        "finding_id": finding_id,
        "decision": decision,
        "decided_by": user_email,
        "rationale": req.rationale
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


