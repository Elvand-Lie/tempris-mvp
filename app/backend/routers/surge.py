import os
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import Finding, SurgeResearcher, SurgeSubmission
from routers.audit import AuditEntry, append_to_audit_log, get_client_ip
from routers.auth import get_auth_context, require_role
from services.database import get_db
from services.tes_engine import calculate_sss_tes, priority_from_tes

router = APIRouter()

SEVERITY_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
VALID_STATUS = {"submitted", "triaged", "accepted", "duplicate", "rejected", "paid"}
VALID_SEVERITY = frozenset(SEVERITY_SCORE)
VDP_TENANT_ID = os.environ.get("VDP_TENANT_ID", "tempris").strip() or "tempris"
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$")


class SurgeSubmit(BaseModel):
    title: str = Field(..., max_length=255)
    severity: str = "medium"
    description: str = Field(..., max_length=4000)
    poc_url: str | None = Field(default=None, max_length=500)
    attachments: list[str] = []
    handle: str | None = Field(default=None, max_length=100)


class PublicSurgeSubmit(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    recognition_name: str | None = Field(default=None, max_length=100)
    title: str = Field(..., min_length=5, max_length=255)
    severity: str = Field(default="medium", max_length=20)
    description: str = Field(..., min_length=20, max_length=8000)
    affected_url: str | None = Field(default=None, max_length=500)
    safe_harbor_ack: bool = False
    privacy_ack: bool = False
    website: str = Field(default="", max_length=200)


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


def _validated_severity(value: str) -> str:
    severity = str(value or "").strip().lower()
    if severity not in VALID_SEVERITY:
        raise HTTPException(status_code=400, detail="Invalid severity")
    return severity


def _validated_email(value: str) -> str:
    email = str(value or "").strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=400, detail="Enter a valid contact email")
    return email


def _validated_http_url(value: str | None) -> str | None:
    url = str(value or "").strip()
    if not url:
        return None
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Affected URL must be a public HTTP(S) URL")
    return url


def require_vdp_staff(user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    """Keep the Tempris-operated VDP queue out of customer tenant accounts."""
    if get_auth_context(user).tenant_id != VDP_TENANT_ID:
        raise HTTPException(status_code=403, detail="VDP operations require Tempris security staff")
    return user


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


def _create_submission(
    db: Session,
    *,
    email: str,
    handle: str | None,
    title: str,
    severity: str,
    description: str,
    poc_url: str | None,
) -> SurgeSubmission:
    researcher = _researcher(db, email, handle)
    submission = SurgeSubmission(
        id=_id("S"),
        title=title.strip(),
        severity=severity,
        description=description.strip(),
        poc_url=poc_url,
        attachments=[],
        researcher_id=researcher.id,
        status="submitted",
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    return submission


def _submission_dict(s: SurgeSubmission, researcher: SurgeResearcher | None = None) -> dict:
    payload = {
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
    if researcher is not None:
        payload["researcher"] = {"handle": researcher.handle, "email": researcher.email}
    return payload


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
        tenant_id=VDP_TENANT_ID,
    )
    db.add(finding)
    db.flush()
    s.finding_id = finding.id
    return finding.id


@router.post("/public/submit", status_code=status.HTTP_202_ACCEPTED)
def public_submit(req: PublicSurgeSubmit, request: Request, db: Session = Depends(get_db)):
    """Public VDP intake. It intentionally accepts no uploads or active content."""
    generic = {
        "status": "received",
        "message": "Your report has been received for confidential security triage.",
    }
    if req.website:
        return generic
    if not req.safe_harbor_ack or not req.privacy_ack:
        raise HTTPException(status_code=400, detail="Policy and privacy acknowledgements are required")

    email = _validated_email(req.email)
    severity = _validated_severity(req.severity)
    affected_url = _validated_http_url(req.affected_url)
    sub = _create_submission(
        db,
        email=email,
        handle=(req.recognition_name or "").strip() or None,
        title=req.title,
        severity=severity,
        description=req.description,
        poc_url=affected_url,
    )
    append_to_audit_log(AuditEntry(
        user="public-vdp", action="VDP_SUBMISSION_RECEIVED", module="SURGE",
        detail=f"Confidential VDP submission {sub.id} received",
        ip_address=get_client_ip(request),
        metadata={"submission_id": sub.id, "severity_claimed": severity},
    ))
    return {**generic, "tracking_id": sub.id}


@router.post("/submit")
def submit(
    req: SurgeSubmit,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_vdp_staff),
):
    email = _validated_email(user.get("sub", ""))
    severity = _validated_severity(req.severity)
    sub = _create_submission(
        db,
        email=email,
        handle=req.handle,
        title=req.title,
        severity=severity,
        description=req.description,
        poc_url=_validated_http_url(req.poc_url),
    )
    append_to_audit_log(AuditEntry(
        user=email, action="SURGE_SUBMISSION_CREATED", module="SURGE",
        detail=f"SURGE submission {sub.id} created",
        ip_address=get_client_ip(request),
        metadata={"submission_id": sub.id, "severity_claimed": severity},
    ))
    return _submission_dict(sub)


@router.get("/submissions")
def submissions(db: Session = Depends(get_db), user=Depends(require_vdp_staff)):
    rows = db.query(SurgeSubmission).order_by(SurgeSubmission.created_at.desc()).limit(200).all()
    researcher_ids = {row.researcher_id for row in rows if row.researcher_id}
    researchers = {
        row.id: row for row in db.query(SurgeResearcher).filter(SurgeResearcher.id.in_(researcher_ids)).all()
    } if researcher_ids else {}
    return {"data": [_submission_dict(row, researchers.get(row.researcher_id)) for row in rows]}


@router.patch("/submissions/{submission_id}/status")
def update_status(submission_id: str, req: SurgeStatus, db: Session = Depends(get_db), user=Depends(require_vdp_staff)):
    status_value = req.status.lower()
    if status_value not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")
    submission = db.query(SurgeSubmission).filter(SurgeSubmission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    submission.status = status_value
    db.commit()
    db.refresh(submission)
    return _submission_dict(submission)


@router.post("/submissions/{submission_id}/triage")
def triage(submission_id: str, req: SurgeTriage, request: Request, db: Session = Depends(get_db), user=Depends(require_vdp_staff)):
    submission = db.query(SurgeSubmission).filter(SurgeSubmission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    status_value = req.status.lower()
    if status_value not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")
    submission.status = status_value
    submission.edip_decision = req.edip_decision
    submission.bounty_amount = req.bounty_amount
    if status_value == "accepted":
        _create_finding(db, submission)
    if status_value == "paid":
        submission.paid_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(submission)
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"), action="SURGE_TRIAGE", module="SURGE",
        detail=f"SURGE submission {submission.id} triaged as {submission.status}; finding={submission.finding_id or 'none'}",
        ip_address=get_client_ip(request),
    ))
    return _submission_dict(submission)


@router.get("/hall-of-fame")
def hall_of_fame(db: Session = Depends(get_db), user=Depends(require_vdp_staff)):
    rows = db.query(SurgeResearcher).order_by(SurgeResearcher.reputation_score.desc(), SurgeResearcher.created_at.asc()).limit(50).all()
    accepted = db.query(SurgeSubmission).filter(SurgeSubmission.status.in_(["accepted", "paid"])).all()
    counts = {}
    for submission in accepted:
        counts[submission.researcher_id] = counts.get(submission.researcher_id, 0) + 1
    return {"data": [{"handle": researcher.handle, "accepted_findings": counts.get(researcher.id, 0), "reputation_score": researcher.reputation_score} for researcher in rows if counts.get(researcher.id, 0) > 0]}
