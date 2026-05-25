from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.tes_engine import calculate_tes, TESInputs, TESBreakdown
from routers.audit import append_to_audit_log, AuditEntry
from services.kev_loader import get_all_findings

router = APIRouter()

class EDIPRequest(BaseModel):
    decision: str  # mitigate, accept, transfer, ignore

@router.get("/findings")
def get_findings():
    """Returns all findings with their real-time calculated TES scores."""
    result = []
    # For demo, just return the top 50 critical findings to keep payload reasonable
    all_findings = get_all_findings()
    critical_findings = [f for f in all_findings if f.get("priority") == "P0"][:50]
    
    for f in critical_findings:
        inputs = TESInputs(**f["raw_inputs"])
        tes_breakdown = calculate_tes(inputs)
        
        # Merge data for frontend
        f_copy = f.copy()
        f_copy["tes_score"] = tes_breakdown.total_score
        f_copy["tes_breakdown"] = tes_breakdown.dict()
        result.append(f_copy)
    return result

@router.post("/findings/{finding_id}/edip")
def record_edip_decision(finding_id: str, req: EDIPRequest):
    """Records an EDIP decision for a finding."""
    for f in get_all_findings():
        if f["id"] == finding_id:
            f["edip_decision"] = req.decision
            
            append_to_audit_log(AuditEntry(
                user="Current User", # In real app, get from token
                action="EDIP_DECISION",
                module="SPECTRUM",
                detail=f"Applied '{req.decision}' decision to finding {finding_id} ({f.get('cve', '')})"
            ))
            
            return {"status": "success", "message": f"Recorded decision '{req.decision}' for {finding_id}"}
    
    raise HTTPException(status_code=404, detail="Finding not found")

@router.post("/calculate-tes", response_model=TESBreakdown)
def calculate_custom_tes(inputs: TESInputs):
    """Exposes the raw TES engine for arbitrary calculations."""
    return calculate_tes(inputs)
