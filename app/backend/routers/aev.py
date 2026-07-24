from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database import get_db
from models import AevModule, AevRun
from routers.auth import get_current_user, require_role, get_auth_context
from routers.audit import append_to_audit_log_db, AuditEntry
from datetime import datetime
import os
import uuid

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("SCOUT"))])

class AevModuleRegisterReq(BaseModel):
    id: str
    name: str
    enabled: bool = False
    contract_approved: bool = False

class AevRunCreateReq(BaseModel):
    module_id: str
    target_input: dict = {}

class AevRunAuthorizeReq(BaseModel):
    notes: str | None = None

@router.post("/modules")
def register_module(
    req: AevModuleRegisterReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    
    existing = db.query(AevModule).filter(AevModule.id == req.id).first()
    if existing:
        existing.name = req.name
        existing.enabled = req.enabled
        existing.contract_approved = req.contract_approved
        existing.owner = user_email
    else:
        existing = AevModule(
            id=req.id,
            name=req.name,
            enabled=req.enabled,
            contract_approved=req.contract_approved,
            owner=user_email
        )
        db.add(existing)
        
    db.commit()
    db.refresh(existing)
    return existing

@router.post("/runs")
def create_run(
    req: AevRunCreateReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    raise HTTPException(
        status_code=400,
        detail="AEV_DISABLED: AEV execution endpoints are globally disabled pending approved contracts."
    )

@router.post("/runs/{run_id}/authorize")
def authorize_run(
    run_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    raise HTTPException(
        status_code=400,
        detail="AEV_DISABLED: AEV execution endpoints are globally disabled pending approved contracts."
    )

@router.post("/runs/{run_id}/execute")
def execute_run(
    run_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    raise HTTPException(
        status_code=400,
        detail="AEV_DISABLED: AEV execution endpoints are globally disabled pending approved contracts."
    )

@router.post("/runs/{run_id}/pause")
def pause_run(
    run_id: str,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    raise HTTPException(
        status_code=400,
        detail="AEV_DISABLED: AEV execution endpoints are globally disabled pending approved contracts."
    )
