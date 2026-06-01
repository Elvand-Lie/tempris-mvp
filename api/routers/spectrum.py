from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.tes_engine import calculate_tes, TESInputs, TESBreakdown
from routers.audit import append_to_audit_log, AuditEntry
from services.kev_loader import get_all_findings
from services.database import get_db
from models import EdipDecision

router = APIRouter()

class EDIPRequest(BaseModel):
    decision: str  # mitigate, accept, transfer, ignore

def _load_edip_decisions(db: Session) -> dict:
    """Load all EDIP decisions from DB into a lookup dict."""
    decisions = db.query(EdipDecision).all()
    return {d.finding_id: d.decision for d in decisions}

@router.get("/findings")
def get_findings(db: Session = Depends(get_db)):
    """Returns all findings with their real-time calculated TES scores."""
    edip_map = _load_edip_decisions(db)
    result = []
    all_findings = get_all_findings()
    critical_findings = [f for f in all_findings if f.get("priority") == "P0"][:50]
    
    for f in critical_findings:
        inputs = TESInputs(**f["raw_inputs"])
        tes_breakdown = calculate_tes(inputs)
        
        f_copy = f.copy()
        f_copy["tes_score"] = tes_breakdown.total_score
        f_copy["tes_breakdown"] = tes_breakdown.dict()
        # Overlay persisted EDIP decision
        if f["id"] in edip_map:
            f_copy["edip_decision"] = edip_map[f["id"]]
        result.append(f_copy)
    return result

@router.post("/findings/{finding_id}/edip")
def record_edip_decision(finding_id: str, req: EDIPRequest, db: Session = Depends(get_db)):
    """Records an EDIP decision for a finding — persisted to PostgreSQL."""
    target = None
    for f in get_all_findings():
        if f["id"] == finding_id:
            target = f
            break
    if not target:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Update in-memory (for current session perf)
    target["edip_decision"] = req.decision
    
    # Persist to DB (upsert)
    existing = db.query(EdipDecision).filter(EdipDecision.finding_id == finding_id).first()
    if existing:
        existing.decision = req.decision
    else:
        db.add(EdipDecision(
            finding_id=finding_id, cve=target.get("cve", ""),
            decision=req.decision, decided_by="Current User"
        ))
    db.commit()
    
    append_to_audit_log(AuditEntry(
        user="Current User",
        action="EDIP_DECISION",
        module="SPECTRUM",
        detail=f"Applied '{req.decision}' decision to finding {finding_id} ({target.get('cve', '')})"
    ))
    
    return {"status": "success", "message": f"Recorded decision '{req.decision}' for {finding_id}"}

@router.post("/calculate-tes", response_model=TESBreakdown)
def calculate_custom_tes(inputs: TESInputs):
    """Exposes the raw TES engine for arbitrary calculations."""
    return calculate_tes(inputs)
