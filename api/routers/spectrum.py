from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.tes_engine import calculate_tes, TESInputs, TESBreakdown
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
from services.kev_loader import get_all_findings
from services.database import get_db
from models import EdipDecision
from services.edip_engine import auto_classify

router = APIRouter()

class EDIPRequest(BaseModel):
    decision: str  # mitigate, accept, transfer, ignore
    rationale: str | None = None  # Business justification for the decision

def _load_edip_decisions(db: Session) -> dict:
    """Load all EDIP decisions from DB into a lookup dict."""
    decisions = db.query(EdipDecision).all()
    return {d.finding_id: {"decision": d.decision, "rationale": d.rationale, "decided_by": d.decided_by} for d in decisions}

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
    """Returns findings with TES scores. Supports pagination, search, and filtering."""
    edip_map = _load_edip_decisions(db)
    all_findings = get_all_findings()

    # Sort by priority
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    sorted_all = sorted(all_findings, key=lambda f: priority_order.get(f.get("priority", "P3"), 4))

    # Apply filters
    filtered = sorted_all
    if priority:
        filtered = [f for f in filtered if f.get("priority") == priority]
    if search:
        search_lower = search.lower()
        filtered = [f for f in filtered if search_lower in f.get("cve", "").lower() or search_lower in f.get("title", "").lower() or search_lower in f.get("vendor", "").lower()]
    if decision == "pending":
        filtered = [f for f in filtered if f["id"] not in edip_map]
    elif decision == "decided":
        filtered = [f for f in filtered if f["id"] in edip_map]

    total = len(filtered)

    # Paginate
    start = (page - 1) * limit
    page_findings = filtered[start:start + limit]

    result = []
    for f in page_findings:
        inputs = TESInputs(**f["raw_inputs"])
        tes_breakdown = calculate_tes(inputs)
        
        f_copy = f.copy()
        f_copy["tes_score"] = tes_breakdown.total_score
        f_copy["tes_breakdown"] = tes_breakdown.dict()
        
        # Run automated EDIP classification
        f_copy["auto_classification"] = auto_classify(
            cvss=f.get("cvss", 0.0),
            asset_criticality="high",
            cisa_kev=f.get("cisa", False),
            ransomware_linked=f.get("ransomware", False)
        )
        
        # Overlay persisted EDIP decision + rationale
        if f["id"] in edip_map:
            edip_data = edip_map[f["id"]]
            f_copy["edip_decision"] = edip_data["decision"]
            f_copy["edip_rationale"] = edip_data.get("rationale")
            f_copy["edip_decided_by"] = edip_data.get("decided_by")
        result.append(f_copy)

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
    """Records an EDIP decision for a finding — persisted to PostgreSQL.
    Requires Superadmin, Admin, or Analyst role.
    """
    user_email = user.get("sub", "unknown")
    user_role = user.get("role", "unknown")

    target = None
    for f in get_all_findings():
        if f["id"] == finding_id:
            target = f
            break
    if not target:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Update in-memory (for current session perf)
    target["edip_decision"] = req.decision
    target["edip_rationale"] = req.rationale
    target["edip_decided_by"] = user_email
    
    # Persist to DB (upsert)
    existing = db.query(EdipDecision).filter(EdipDecision.finding_id == finding_id).first()
    if existing:
        existing.decision = req.decision
        existing.rationale = req.rationale
        existing.decided_by = user_email
    else:
        db.add(EdipDecision(
            finding_id=finding_id, cve=target.get("cve", ""),
            decision=req.decision, rationale=req.rationale,
            decided_by=user_email
        ))
    db.commit()
    
    client_ip = request.headers.get("X-Real-IP", request.client.host if request.client else None)
    append_to_audit_log(AuditEntry(
        user=user_email,
        action="EDIP_DECISION",
        module="SPECTRUM",
        detail=f"Applied '{req.decision}' to {finding_id} ({target.get('cve', '')}). Rationale: {req.rationale or 'None provided'}",
        ip_address=client_ip
    ))
    
    return {
        "status": "success",
        "message": f"Recorded decision '{req.decision}' for {finding_id}",
        "finding_id": finding_id,
        "decision": req.decision,
        "decided_by": user_email,
        "rationale": req.rationale
    }

@router.post("/calculate-tes", response_model=TESBreakdown)
def calculate_custom_tes(inputs: TESInputs, user=Depends(get_current_user)):
    """Exposes the raw TES engine for calculations. Requires authentication."""
    return calculate_tes(inputs)
