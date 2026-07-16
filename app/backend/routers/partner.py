from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database import get_db
from models import PartnerOnboarding, Finding, Asset
from routers.auth import get_current_user, require_role, get_auth_context
from routers.audit import append_to_audit_log_db, AuditEntry
from datetime import datetime

router = APIRouter()

class PartnerOnboardReq(BaseModel):
    license_verified: bool = False
    agreements_signed: bool = False
    attendees: list[str] = []
    provisioning_status: str = "pending"
    role_assigned: str | None = None
    attendance_checkins: list[str] = []
    module_checkpoints: dict = {}
    pilot_evidence_submitted: bool = False
    assessment_result: str | None = None
    certification_number: str | None = None
    expiry_date: str | None = None  # ISO format string
    renewal_status: str | None = None
    release_notes_acknowledged: bool = False

class PartnerOnboardResponse(BaseModel):
    id: str
    partner_id: str
    license_verified: bool
    agreements_signed: bool
    attendees: list[str]
    provisioning_status: str
    role_assigned: str | None = None
    attendance_checkins: list[str]
    module_checkpoints: dict
    pilot_evidence_submitted: bool
    assessment_result: str | None = None
    certification_number: str | None = None
    expiry_date: datetime | None = None
    renewal_status: str | None = None
    release_notes_acknowledged: bool

    class Config:
        from_attributes = True
        protected_namespaces = ()

@router.post("/onboard", response_model=PartnerOnboardResponse)
def onboard_partner(
    req: PartnerOnboardReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    tenant_id = auth_ctx.tenant_id
    
    target_tenant = tenant_id
    
    exp_date = datetime.fromisoformat(req.expiry_date) if req.expiry_date else None
    
    existing = db.query(PartnerOnboarding).filter(PartnerOnboarding.partner_id == target_tenant).first()
    if existing:
        existing.license_verified = req.license_verified
        existing.agreements_signed = req.agreements_signed
        existing.attendees = req.attendees
        existing.provisioning_status = req.provisioning_status
        existing.role_assigned = req.role_assigned
        existing.attendance_checkins = req.attendance_checkins
        existing.module_checkpoints = req.module_checkpoints
        existing.pilot_evidence_submitted = req.pilot_evidence_submitted
        existing.assessment_result = req.assessment_result
        existing.certification_number = req.certification_number
        existing.expiry_date = exp_date
        existing.renewal_status = req.renewal_status
        existing.release_notes_acknowledged = req.release_notes_acknowledged
    else:
        existing = PartnerOnboarding(
            id=target_tenant,
            partner_id=target_tenant,
            license_verified=req.license_verified,
            agreements_signed=req.agreements_signed,
            attendees=req.attendees,
            provisioning_status=req.provisioning_status,
            role_assigned=req.role_assigned,
            attendance_checkins=req.attendance_checkins,
            module_checkpoints=req.module_checkpoints,
            pilot_evidence_submitted=req.pilot_evidence_submitted,
            assessment_result=req.assessment_result,
            certification_number=req.certification_number,
            expiry_date=exp_date,
            renewal_status=req.renewal_status,
            release_notes_acknowledged=req.release_notes_acknowledged
        )
        db.add(existing)
        
    db.commit()
    db.refresh(existing)
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="PARTNER_ONBOARD",
        module="PARTNER",
        detail=f"Onboarded/updated partner certification track for tenant {target_tenant}."
    ))
    db.commit()
    return existing

@router.get("/onboard/{tenant_id}", response_model=PartnerOnboardResponse)
def get_partner_onboarding(
    tenant_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    auth_ctx = get_auth_context(user)
    
    if not auth_ctx.is_superadmin and tenant_id != auth_ctx.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    onboard = db.query(PartnerOnboarding).filter(PartnerOnboarding.partner_id == tenant_id).first()
    if not onboard:
        raise HTTPException(status_code=404, detail="Partner onboarding record not found")
    return onboard

SANDBOX_TENANTS = {
    "sandbox_partner_tenant": {"is_training_sandbox": True},
    "tempris": {"is_training_sandbox": True},
    "tenanta": {"is_training_sandbox": True},
    "tenantb": {"is_training_sandbox": True},
}

@router.post("/sandbox-reset")
def reset_sandbox(
    target_tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    """Resets the findings and assets for the caller's tenant back to mock baseline under strict controls."""
    import os
    # 1. Require explicit feature flag
    if os.environ.get("SANDBOX_RESET_ENABLED") != "true":
        raise HTTPException(
            status_code=400,
            detail="SANDBOX_RESET_BLOCKED: Sandbox reset feature flag is disabled."
        )

    # 2. Require demo/training environment explicitly
    env = os.environ.get("ENVIRONMENT", "").lower()
    if env not in ("demo", "training"):
        raise HTTPException(
            status_code=400,
            detail="SANDBOX_RESET_BLOCKED: Sandbox reset is only allowed in training or demo environments."
        )

    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    caller_tenant = auth_ctx.tenant_id
    caller_role = auth_ctx.role

    # Determine if internal superadmin
    is_internal_superadmin = (caller_role == "Superadmin" and (caller_tenant == "tempris" or user_email.endswith("@tempris.com")))

    # Resolve target tenant
    if target_tenant_id:
        if target_tenant_id != caller_tenant:
            if not is_internal_superadmin:
                raise HTTPException(
                    status_code=403,
                    detail="SANDBOX_RESET_BLOCKED: Ordinary admin or partner-admin cannot reset another tenant."
                )
            target_tenant = target_tenant_id
        else:
            target_tenant = caller_tenant
    else:
        target_tenant = caller_tenant

    # Authoritative server-side sandbox designation check
    sandbox_config = SANDBOX_TENANTS.get(target_tenant.lower())
    if not sandbox_config or not sandbox_config.get("is_training_sandbox"):
        raise HTTPException(
            status_code=400,
            detail="SANDBOX_RESET_BLOCKED: Tenant is not authoritatively designated as a sandbox environment."
        )

    try:
        # 1. Clear existing findings and assets for the target tenant
        db.query(Finding).filter(Finding.tenant_id == target_tenant).delete()
        db.query(Asset).filter(Asset.tenant_id == target_tenant).delete()
        
        # 2. Seed mock sandbox assets
        sandbox_asset = Asset(
            id=f"ASSET-{target_tenant}-1",
            tenant_id=target_tenant,
            name="Core Web Portal (Sandbox)",
            asset_type="web_app",
            ip_address="192.168.99.10",
            criticality="high",
            owner=user_email
        )
        db.add(sandbox_asset)
        
        # 3. Seed mock sandbox findings (strictly fictional records)
        sandbox_finding = Finding(
            id=f"F-{target_tenant}-1",
            tenant_id=target_tenant,
            finding_type="vulnerability",
            subtype="CVE",
            pipeline="SYNTHETIC",
            verification="CONFIRMED",
            score=7.5,
            status="unmitigated",
            cve="CVE-2026-9901",
            title="SQL Injection in Sandbox API",
            vendor="Internal Development",
            product="Sandbox App",
            cvss=7.5,
            priority="P1",
            short_description="An unauthenticated SQL injection vulnerability in sandbox environment.",
            asset_id=sandbox_asset.id,
            sss_data={
                "type": "CVE",
                "scoring": {
                    "base_severity": 7.5,
                    "agm": 1.0,
                    "drf": 1.0,
                    "tef": 1.0
                }
            },
            source="kev"
        )
        db.add(sandbox_finding)
        
        # 4. Audit with server-authoritative identity
        append_to_audit_log_db(db, AuditEntry(
            user=user_email,
            action="SANDBOX_RESET",
            module="PARTNER",
            detail=f"Reset training sandbox database for tenant {target_tenant}."
        ))
        
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"SANDBOX_RESET_FAILED: {str(e)}")
        
    return {"status": "success", "message": f"Sandbox database reset for tenant {target_tenant} completed."}
