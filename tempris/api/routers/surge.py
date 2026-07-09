from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import Finding, SurgeResearcher, SurgeSubmission
from routers.audit import AuditEntry, append_to_audit_log
from routers.auth import get_current_user, require_role
from services.database import get_db
from services.tes_engine import calculate_sss_tes, priority_from_tes

router = APIRouter()

SEVERITY_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
VALID_STATUS = {"submitted", "triaged", "accepted", "duplicate", "rejected", "paid"}


class SurgeSubmit(BaseModel):
    title: str = Field(..., max_length=255)
    severity: str = "medium"
    description: str = Field(..., max_length=4000)
    poc_url: str | None = Field(default=None, max_length=500)
    attachments: list[str] = []
    handle: str | None = Field(default=None, max_length=100)


class SurgeStatus(BaseModel):
    status: str


class SurgeTriage(BaseModel):
    status: str = "accepted"
    edip_decision: str = "mitigate"
    bounty_amount: float | None = None


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:8]}"


def _severity_score(severity: str) -> float:
    return SEVERITY_SCORE.get((severity or "medium").lower(), 5.5)


def _researcher(db: Session, email: str, handle: str | None) -> SurgeResearcher:
    existing = db.query(SurgeResearcher).filter(SurgeResearcher.email == email).first()
    if existing:
        if handle:
            existing.handle = handle
        return existing
    row = SurgeResearcher(id=_id("R"), email=email, handle=handle or email.split("@")[0])
    db.add(row)
    db.flush()
    return row


def _submission_dict(s: SurgeSubmission) -> dict:
    return {
        "id": s.id,
        "title": s.title,
        "severity": s.severity,
        "description": s.description,
        "poc_url": s.poc_url,
        "attachments": s.attachments or [],
        "researcher_id": s.researcher_id,
        "status": s.status,
        "edip_decision": s.edip_decision,
        "bounty_amount": s.bounty_amount,
        "paid_at": s.paid_at.isoformat() if s.paid_at else None,
        "finding_id": s.finding_id,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


def _create_finding(db: Session, s: SurgeSubmission) -> str:
    if s.finding_id:
        return s.finding_id
    score = _severity_score(s.severity)
    scoring = {"base_severity": score, "AGM": 1.1, "DRF": 1.1, "TEF": 1.1}
    tes = calculate_sss_tes(scoring)
    finding = Finding(
        id=_id("FSG")[:20],
        cve=f"SURGE-{s.id}",
        title=s.title,
        vendor="SURGE Researcher Submission",
        product=s.poc_url or "Private VDP",
        cvss=score,
        priority=priority_from_tes(tes),
        status="unmitigated",
        cisa_kev=False,
        ransomware=False,
        date_added=datetime.now(timezone.utc).isoformat(),
        short_description=s.description,
        required_action="Validate and remediate accepted SURGE finding",
        raw_inputs={"cvss": score, "exploitability": 8.0, "business_impact": 7.0, "asset_criticality": 7.0, "threat_actor_activity": 6.0},
        sss_data={
            "type": "SURGE",
            "source": "SURGE",
            "scoring": scoring,
            "patch_available": True,
            "references": [s.poc_url] if s.poc_url else [],
            "attack_vectors": ["RESEARCHER_REPORT"],
        },
        source="surge",
    )
    db.add(finding)
    db.flush()
    s.finding_id = finding.id
    return finding.id


@router.post("/submit")
def submit(req: SurgeSubmit, request: Request, db: Session = Depends(get_db), user=Depends(get_current_user)):
    email = user.get("sub", "unknown")
    researcher = _researcher(db, email, req.handle)
    sub = SurgeSubmission(
        id=_id("S"), title=req.title, severity=req.severity.lower(), description=req.description,
        poc_url=req.poc_url, attachments=req.attachments, researcher_id=researcher.id, status="submitted",
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    append_to_audit_log(AuditEntry(
        user=email, action="SURGE_SUBMISSION_CREATED", module="SURGE",
        detail=f"SURGE submission {sub.id} created: {sub.title}", ip_address=request.client.host if request.client else None,
    ))
    return _submission_dict(sub)


@router.get("/submissions")
def submissions(db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    rows = db.query(SurgeSubmission).order_by(SurgeSubmission.created_at.desc()).limit(200).all()
    return {"data": [_submission_dict(s) for s in rows]}


@router.patch("/submissions/{submission_id}/status")
def update_status(submission_id: str, req: SurgeStatus, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    status = req.status.lower()
    if status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")
    s = db.query(SurgeSubmission).filter(SurgeSubmission.id == submission_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Submission not found")
    s.status = status
    db.commit()
    db.refresh(s)
    return _submission_dict(s)


@router.post("/submissions/{submission_id}/triage")
def triage(submission_id: str, req: SurgeTriage, request: Request, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    s = db.query(SurgeSubmission).filter(SurgeSubmission.id == submission_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Submission not found")
    status = req.status.lower()
    if status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")
    s.status = status
    s.edip_decision = req.edip_decision
    s.bounty_amount = req.bounty_amount
    if status == "accepted":
        _create_finding(db, s)
    if status == "paid":
        s.paid_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(s)
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"), action="SURGE_TRIAGE", module="SURGE",
        detail=f"SURGE submission {s.id} triaged as {s.status}; finding={s.finding_id or 'none'}",
        ip_address=request.client.host if request.client else None,
    ))
    return _submission_dict(s)


@router.get("/hall-of-fame")
def hall_of_fame(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(SurgeResearcher).order_by(SurgeResearcher.reputation_score.desc(), SurgeResearcher.created_at.asc()).limit(50).all()
    accepted = db.query(SurgeSubmission).filter(SurgeSubmission.status.in_(["accepted", "paid"])).all()
    counts = {}
    for s in accepted:
        counts[s.researcher_id] = counts.get(s.researcher_id, 0) + 1
    return {"data": [{"handle": r.handle, "accepted_findings": counts.get(r.id, 0), "reputation_score": r.reputation_score} for r in rows if counts.get(r.id, 0) > 0]}
