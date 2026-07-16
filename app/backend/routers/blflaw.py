from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database import get_db
from models import Finding, FindingStatusHistory, FindingControl
from routers.auth import get_current_user, require_role, get_auth_context
from routers.audit import append_to_audit_log_db, AuditEntry
import uuid

router = APIRouter()

APPROVED_FLAW_TYPES = {"IDOR", "ACCESS_CONTROL", "PRIVILEGE_ESCALATION", "WORKFLOW_BYPASS", "MULTI_STEP_FLAW"}

class CompensatingControlReq(BaseModel):
    title: str
    description: str | None = None

class BLFlawIntakeReq(BaseModel):
    title: str
    description: str
    flaw_type: str  # IDOR, ACCESS_CONTROL, PRIVILEGE_ESCALATION, WORKFLOW_BYPASS, MULTI_STEP_FLAW
    severity: str  # Low, Medium, High, Critical
    asset_id: str
    flow_steps: list[str] = []
    compensating_controls: list[CompensatingControlReq] = []

class BLFlawTransitionReq(BaseModel):
    new_status: str  # OPEN, TRIAGED, MITIGATION_PLANNED, RESOLVED, VERIFIED
    notes: str | None = None

VALID_STATUSES = ["OPEN", "TRIAGED", "MITIGATION_PLANNED", "RESOLVED", "VERIFIED"]

# Enforce clean linear transitions
ALLOWED_TRANSITIONS = {
    "OPEN": {"TRIAGED"},
    "TRIAGED": {"MITIGATION_PLANNED", "OPEN"},
    "MITIGATION_PLANNED": {"RESOLVED", "TRIAGED"},
    "RESOLVED": {"VERIFIED", "MITIGATION_PLANNED"},
    "VERIFIED": {"RESOLVED"}  # allow rolling back verification if needed
}

@router.post("/intake")
def intake_blflaw(
    req: BLFlawIntakeReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    tenant_id = auth_ctx.tenant_id
    
    # Enforce approved flaw types
    if req.flaw_type.upper() not in APPROVED_FLAW_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid flaw_type '{req.flaw_type}'. Must be one of: {list(APPROVED_FLAW_TYPES)}"
        )
        
    # Calculate base CVSS value from severity string
    severity_map = {"low": 3.0, "medium": 5.0, "high": 7.5, "critical": 9.8}
    cvss = severity_map.get(req.severity.strip().lower(), 5.0)
    priority = "P0" if cvss >= 9.0 else "P1" if cvss >= 7.0 else "P2" if cvss >= 4.0 else "P3"
    
    finding_id = f"F-BL-{uuid.uuid4().hex[:6].upper()}"
    
    # Create the Finding representation
    finding = Finding(
        id=finding_id,
        tenant_id=tenant_id,
        finding_type="business_logic",
        subtype=req.flaw_type.upper(),
        pipeline="SYNTHETIC",
        verification="CONFIRMED",
        score=cvss,
        status="OPEN",
        cve=f"BL-{finding_id}",
        title=req.title,
        vendor="Internal",
        product="Business Logic",
        cvss=cvss,
        priority=priority,
        short_description=req.description,
        asset_id=req.asset_id,
        sss_data={
            "type": req.flaw_type.upper(),
            "flow_steps": req.flow_steps,
            "scoring": {
                "base_severity": cvss,
                "agm": 1.0,
                "drf": 1.0,
                "tef": 1.0
            }
        },
        source="sss"
    )
    
    db.add(finding)
    
    # Add compensating controls
    for cc in req.compensating_controls:
        ctrl = FindingControl(
            finding_id=finding_id,
            title=cc.title,
            description=cc.description,
            layer_type="compensating",
            priority=priority,
            status="not_assessed"
        )
        db.add(ctrl)
        
    # Add initial history
    history = FindingStatusHistory(
        finding_id=finding_id,
        old_status="NONE",
        new_status="OPEN",
        changed_by=user_email,
        notes="Initial intake submission."
    )
    db.add(history)
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="BLFLAW_INTAKE",
        module="SURGE",
        detail=f"Intake business logic flaw {finding_id} scoped to tenant {tenant_id}."
    ))
    
    db.commit()
    db.refresh(finding)
    return finding

@router.get("")
def list_blflaws(
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    auth_ctx = get_auth_context(user)
    
    query = db.query(Finding).filter(Finding.finding_type == "business_logic")
    if not auth_ctx.is_superadmin:
        query = query.filter(Finding.tenant_id == auth_ctx.tenant_id)
        
    return query.all()

@router.post("/{finding_id}/transition")
def transition_blflaw(
    finding_id: str,
    req: BLFlawTransitionReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.finding_type == "business_logic").first()
    if not finding:
        raise HTTPException(status_code=404, detail="Business logic flaw not found")
        
    if not auth_ctx.is_superadmin and finding.tenant_id != auth_ctx.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    current_status = finding.status or "OPEN"
    target_status = req.new_status.upper()
    
    if target_status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid target status. Must be one of: {VALID_STATUSES}")
        
    # Enforce transition rules
    allowed = ALLOWED_TRANSITIONS.get(current_status, set())
    if target_status != current_status and target_status not in allowed:
        raise HTTPException(
            status_code=409, 
            detail=f"Illegal transition: {current_status} -> {target_status}. Allowed transitions: {allowed}"
        )
        
    if target_status != current_status:
        finding.status = target_status
        history = FindingStatusHistory(
            finding_id=finding_id,
            old_status=current_status,
            new_status=target_status,
            changed_by=user_email,
            notes=req.notes
        )
        db.add(history)
        
        append_to_audit_log_db(db, AuditEntry(
            user=user_email,
            action="BLFLAW_TRANSITION",
            module="SURGE",
            detail=f"Transitioned {finding_id} status from {current_status} to {target_status}."
        ))
        
        db.commit()
        
    return {"status": "success", "current_status": finding.status}
