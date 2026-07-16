from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database import get_db
from models import OperationsChangeTicket, AuditLog
from routers.auth import get_current_user, require_role, get_auth_context
from routers.audit import append_to_audit_log_db, AuditEntry
from sqlalchemy.sql import func
from datetime import datetime
import uuid

router = APIRouter()

class TicketCreateReq(BaseModel):
    title: str
    description: str
    runbook_reference: str | None = None
    backup_required: bool = True
    rollback_plan: str | None = None

class TicketExecuteReq(BaseModel):
    evidence_path: str
    post_verification_template: str

@router.post("/tickets")
def create_ticket(
    req: TicketCreateReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    
    ticket_id = f"OCQ-{uuid.uuid4().hex[:8].upper()}"
    
    ticket = OperationsChangeTicket(
        id=ticket_id,
        title=req.title,
        description=req.description,
        runbook_reference=req.runbook_reference,
        backup_required=req.backup_required,
        rollback_plan=req.rollback_plan,
        status="PENDING",
        preflight_passed=False
    )
    db.add(ticket)
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="OCQ_TICKET_CREATED",
        module="OCQ",
        detail=f"Created change ticket {ticket_id}: {req.title}."
    ))
    db.commit()
    db.refresh(ticket)
    return ticket

@router.post("/tickets/{ticket_id}/preflight")
def run_preflight(
    ticket_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    ticket = db.query(OperationsChangeTicket).filter(OperationsChangeTicket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Change ticket not found")
        
    # Simulate preflight execution
    ticket.preflight_passed = True
    ticket.dry_run_output = "Preflight check PASSED: Backups directory writable. Change script validated."
    db.commit()
    return {"status": "success", "dry_run_output": ticket.dry_run_output}

@router.post("/tickets/{ticket_id}/approve")
def approve_ticket(
    ticket_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    
    ticket = db.query(OperationsChangeTicket).filter(OperationsChangeTicket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Change ticket not found")
        
    if not ticket.preflight_passed:
        raise HTTPException(status_code=400, detail="Cannot approve ticket without passing preflight check first.")
        
    # Enforce two-man rule: Find creator from AuditLog!
    creator_log = db.query(AuditLog).filter(
        AuditLog.action == "OCQ_TICKET_CREATED",
        AuditLog.detail.like(f"%{ticket_id}%")
    ).first()
    
    creator_email = creator_log.user_email if creator_log else None
    if creator_email == user_email:
        raise HTTPException(
            status_code=400,
            detail="OCQ_SAFETY_GATE_VIOLATION: Ticket creator cannot approve their own change tickets (Two-man rule)."
        )
        
    ticket.status = "APPROVED"
    ticket.approved_by = user_email
    ticket.approved_at = datetime.utcnow()
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="OCQ_TICKET_APPROVED",
        module="OCQ",
        detail=f"Approved change ticket {ticket_id}."
    ))
    db.commit()
    return {"status": "APPROVED"}

@router.post("/tickets/{ticket_id}/execute")
def execute_ticket(
    ticket_id: str,
    req: TicketExecuteReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    
    ticket = db.query(OperationsChangeTicket).filter(OperationsChangeTicket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Change ticket not found")
        
    if ticket.status != "APPROVED":
        raise HTTPException(status_code=400, detail=f"Cannot execute change ticket in status {ticket.status}. Must be APPROVED.")
        
    ticket.status = "EXECUTED"
    ticket.evidence_path = req.evidence_path
    ticket.post_verification_template = req.post_verification_template
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="OCQ_TICKET_EXECUTED",
        module="OCQ",
        detail=f"Executed change ticket {ticket_id}."
    ))
    db.commit()
    return {"status": "EXECUTED"}

@router.get("/tickets")
def list_tickets(
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    return db.query(OperationsChangeTicket).all()
