from fastapi import APIRouter, HTTPException, Depends, Request
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
    rationale: str | None = None  # Business justification for the decision

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
def record_edip_decision(
    finding_id: str,
    req: EDIPRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Records an EDIP decision for a finding — persisted to PostgreSQL.
    Requires Superadmin, Admin, or Analyst role.
    """
    # Get user info from auth header (or default for demo)
    from routers.auth import get_current_user
    try:
        from fastapi.security import HTTPAuthorizationCredentials
        auth_header = request.headers.get("authorization", "")
        user_email = "demo@tempris.com"
        user_role = "Superadmin"
        if auth_header.startswith("Bearer "):
            import jwt as pyjwt
            from routers.auth import SECRET_KEY, ALGORITHM
            token = auth_header.split(" ")[1]
            payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_email = payload.get("sub", user_email)
            user_role = payload.get("role", user_role)
    except Exception:
        user_email = "demo@tempris.com"
        user_role = "Superadmin"

    # RBAC check — only authorized roles can make EDIP decisions
    allowed_roles = ["Superadmin", "Admin", "Analyst"]
    if user_role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions. EDIP decisions require: {', '.join(allowed_roles)}"
        )

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
        "decided_by": user_email,
        "rationale": req.rationale
    }

@router.post("/calculate-tes", response_model=TESBreakdown)
def calculate_custom_tes(inputs: TESInputs):
    """Exposes the raw TES engine for arbitrary calculations."""
    return calculate_tes(inputs)
