from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from services.database import get_db
from models import GeneratedReport, Finding, ControlEvidence
from routers.auth import get_current_user, require_role, get_auth_context
from routers.audit import append_to_audit_log_db, AuditEntry
from typing import Any

router = APIRouter()

class ReportRegisterReq(BaseModel):
    id: str
    engagement_id: str | None = None
    report_type: str  # risk, gap, evidence, combined, json
    generator_version: str
    approved_by: str | None = None
    source_finding_ids: list[str] = []
    source_evidence_ids: list[str] = []
    framework_configuration: dict = {}
    content_hash: str
    artifact_location: str

class ReportGenerateReq(BaseModel):
    report_type: str  # risk, gap, evidence, combined, json
    approved_by: str | None = None
    source_finding_ids: list[str] = []
    source_evidence_ids: list[str] = []
    framework_configuration: dict = {}

@router.post("/register")
def register_report(
    req: ReportRegisterReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    tenant_id = auth_ctx.tenant_id
    
    # --- Data Anomalies Check ---
    # 1. Validate source findings exist and belong to correct tenant
    for fid in req.source_finding_ids:
        finding = db.query(Finding).filter(Finding.id == fid).first()
        if not finding:
            raise HTTPException(
                status_code=400, 
                detail=f"ANOMALY_DETECTED: Reference finding {fid} does not exist in the database."
            )
        if finding.tenant_id != tenant_id:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference finding {fid} belongs to a different tenant."
            )
            
    # 2. Validate source evidence files exist and belong to correct tenant
    for eid in req.source_evidence_ids:
        try:
            eid_int = int(eid)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Invalid evidence ID {eid}."
            )
        evidence = db.query(ControlEvidence).filter(ControlEvidence.id == eid_int).first()
        if not evidence:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference evidence {eid} does not exist in the database."
            )
        if evidence.tenant_id != tenant_id:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference evidence {eid} belongs to a different tenant."
            )

    # Save to reporting registry
    report = GeneratedReport(
        id=req.id,
        tenant_id=tenant_id,
        engagement_id=req.engagement_id,
        report_type=req.report_type,
        generator_version=req.generator_version,
        requested_by=user_email,
        approved_by=req.approved_by,
        source_finding_ids=req.source_finding_ids,
        source_evidence_ids=req.source_evidence_ids,
        framework_configuration=req.framework_configuration,
        content_hash=req.content_hash,
        artifact_location=req.artifact_location
    )
    db.add(report)
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="REPORT_REGISTERED",
        module="SYNTHESIS",
        detail=f"Registered report {req.id} of type {req.report_type}. Hash: {req.content_hash}."
    ))
    
    db.commit()
    db.refresh(report)
    return report

@router.post("/generate")
def generate_report(
    req: ReportGenerateReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    tenant_id = auth_ctx.tenant_id
    
    from services.reporting_engine import generate_report_pipeline
    try:
        res = generate_report_pipeline(
            db,
            tenant_id=tenant_id,
            report_type=req.report_type,
            requested_by=user_email,
            approved_by=req.approved_by,
            source_finding_ids=req.source_finding_ids,
            source_evidence_ids=req.source_evidence_ids,
            framework_configuration=req.framework_configuration
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("")
def list_reports(
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    auth_ctx = get_auth_context(user)
    
    query = db.query(GeneratedReport)
    if not auth_ctx.is_superadmin:
        query = query.filter(GeneratedReport.tenant_id == auth_ctx.tenant_id)
        
    return query.all()

@router.get("/{report_id}/raw")
def get_raw_report(
    report_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    auth_ctx = get_auth_context(user)
    
    report = db.query(GeneratedReport).filter(GeneratedReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    if not auth_ctx.is_superadmin and report.tenant_id != auth_ctx.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Return as clean JSON (raw payload metadata)
    return {
        "id": report.id,
        "tenant_id": report.tenant_id,
        "engagement_id": report.engagement_id,
        "report_type": report.report_type,
        "generator_version": report.generator_version,
        "requested_by": report.requested_by,
        "approved_by": report.approved_by,
        "source_finding_ids": report.source_finding_ids,
        "source_evidence_ids": report.source_evidence_ids,
        "content_hash": report.content_hash,
        "artifact_location": report.artifact_location,
        "created_at": report.created_at.isoformat() if report.created_at else None
    }
