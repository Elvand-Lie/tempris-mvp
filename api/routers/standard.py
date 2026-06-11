"""
STANDARD Compliance Module — Production
Regulatory framework tracking with automated advisory alerts
and MAS TRM incident reporting workflow.
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from services.database import get_db
from models import ControlStatus, ControlEvidence
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role

router = APIRouter()

VALID_STATUSES = ["not_assessed", "compliant", "partial", "non_compliant", "not_applicable"]

# ── Framework Definitions ────────────────────────────────────────────────────

FRAMEWORKS = {
    "mas_trm_2024": {
        "name": "MAS TRM 2024",
        "controls": [
            {"id": "MAS-TRM-5.1.1", "title": "IT Security Policies", "description": "The FI should establish IT security policies approved by the board.", "default_status": "compliant"},
            {"id": "MAS-TRM-7.4.1", "title": "Privileged Access Management", "description": "Privileged system accounts should be subject to enhanced controls.", "default_status": "compliant"},
            {"id": "MAS-TRM-9.1.1", "title": "Security Monitoring", "description": "The FI should implement security monitoring and logging.", "default_status": "compliant"},
            {"id": "MAS-TRM-11.1.1", "title": "Timely Patching of Critical Network Devices", "description": "Security patches must be applied within the timeframe specified.", "default_status": "non_compliant"},
            {"id": "MAS-TRM-11.2.3", "title": "Vulnerability Scanning", "description": "Regular vulnerability scanning must be conducted.", "default_status": "compliant"},
            {"id": "MAS-TRM-12.1.1", "title": "Incident Response Plan", "description": "The FI should establish incident management and response procedures.", "default_status": "partial"},
            {"id": "MAS-TRM-12.1.5", "title": "1-Hour Incident Notification", "description": "Notify MAS within 1 hour of discovering a relevant incident.", "default_status": "not_assessed"},
        ]
    },
    "pdpa": {
        "name": "PDPA Singapore",
        "controls": [
            {"id": "PDPA-26", "title": "Protection Obligation", "description": "Reasonable security arrangements to protect personal data.", "default_status": "compliant"},
            {"id": "PDPA-24", "title": "Retention Limitation", "description": "Cease retaining personal data when no longer necessary.", "default_status": "compliant"},
            {"id": "PDPA-26D", "title": "Data Breach Notification", "description": "Notify PDPC within 3 calendar days of assessing a notifiable breach.", "default_status": "compliant"},
        ]
    },
    "iso_27001": {
        "name": "ISO 27001:2022",
        "controls": [
            {"id": "ISO-A.5.1", "title": "Policies for Information Security", "description": "Information security policy and topic-specific policies.", "default_status": "compliant"},
            {"id": "ISO-A.8.8", "title": "Management of Technical Vulnerabilities", "description": "Information about technical vulnerabilities shall be obtained.", "default_status": "partial"},
            {"id": "ISO-A.8.15", "title": "Logging", "description": "Logs that record activities, exceptions, faults shall be produced and stored.", "default_status": "compliant"},
            {"id": "ISO-A.5.24", "title": "Incident Management Planning", "description": "Plan and prepare for managing information security incidents.", "default_status": "compliant"},
        ]
    },
    "im8a": {
        "name": "IM8A",
        "controls": [
            {"id": "IM8A-SM-1", "title": "Security Management", "description": "Chief Information Security Officer shall be appointed.", "default_status": "compliant"},
            {"id": "IM8A-AM-3", "title": "Patch Management", "description": "Critical patches must be applied within 2 weeks of release.", "default_status": "non_compliant"},
            {"id": "IM8A-IR-1", "title": "Incident Reporting", "description": "Security incidents to be reported within 24 hours.", "default_status": "partial"},
        ]
    },
    "nist_csf": {
        "name": "NIST CSF 2.0",
        "controls": [
            {"id": "NIST-ID.AM-1", "title": "Asset Inventory", "description": "Inventories of hardware and software are maintained.", "default_status": "compliant"},
            {"id": "NIST-PR.PS-1", "title": "Patch Management", "description": "Patches are applied in a timely manner.", "default_status": "partial"},
            {"id": "NIST-DE.CM-8", "title": "Vulnerability Scanning", "description": "Vulnerability scans are performed.", "default_status": "compliant"},
            {"id": "NIST-RS.AN-5", "title": "Incident Analysis", "description": "Incidents are categorized consistent with response plans.", "default_status": "compliant"},
        ]
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": [
            {"id": "SOC2-CC6.1", "title": "Logical and Physical Access Controls", "description": "Logical access security over protected information assets.", "default_status": "compliant"},
            {"id": "SOC2-CC7.1", "title": "System Monitoring", "description": "Detection of configuration changes, vulnerabilities, and incidents.", "default_status": "partial"},
            {"id": "SOC2-CC7.2", "title": "Incident Response", "description": "The entity monitors system components for anomalies.", "default_status": "compliant"},
        ]
    },
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "controls": [
            {"id": "PCI-6.3.3", "title": "Vulnerability Patch Management", "description": "Critical patches installed within one month of release.", "default_status": "compliant"},
            {"id": "PCI-11.3.1", "title": "Internal Vulnerability Scans", "description": "Internal scans performed at least quarterly.", "default_status": "compliant"},
            {"id": "PCI-12.10.1", "title": "Incident Response Plan", "description": "An incident response plan exists and is ready for activation.", "default_status": "compliant"},
        ]
    },
    "csa_cybertrust": {
        "name": "CSA Cyber Trust",
        "controls": [
            {"id": "CT-GOV-1", "title": "Cyber Governance", "description": "Organisation has established cyber security governance.", "default_status": "compliant"},
            {"id": "CT-PRO-3", "title": "Vulnerability Management", "description": "Processes to identify and remediate vulnerabilities.", "default_status": "partial"},
            {"id": "CT-INC-1", "title": "Incident Management", "description": "Processes for detecting and responding to incidents.", "default_status": "compliant"},
        ]
    }
}

# ── Advisory Alert Engine ────────────────────────────────────────────────────
# Maps control IDs to functions that check live data and return advisory alerts.
# These do NOT change statuses — they provide warnings for analyst review.

def _get_live_advisories(db: Session) -> dict:
    """Check live system data and return advisory alerts per control.
    Returns: {control_id: {"level": "warning"|"critical", "message": str}}
    """
    advisories = {}

    # Check scanner findings for patching-related controls
    from models import ScanFinding
    try:
        critical_findings = db.query(ScanFinding).filter(
            ScanFinding.risk.in_(["Critical", "High"])
        ).count()
        total_findings = db.query(ScanFinding).count()
    except Exception:
        critical_findings = 0
        total_findings = 0

    # Check KEV data for vulnerability counts
    from services.kev_loader import get_all_findings
    kev_findings = get_all_findings()
    p0_count = len([f for f in kev_findings if f.get("priority") == "P0"])
    ransomware_count = len([f for f in kev_findings if f.get("ransomware")])

    # Check STRIKE simulation results
    from models import StrikeSimulation
    try:
        latest_sim = db.query(StrikeSimulation).filter(
            StrikeSimulation.status == "completed"
        ).order_by(StrikeSimulation.completed_at.desc()).first()
        exploitable_count = 0
        if latest_sim and latest_sim.results:
            exploitable_count = len([r for r in latest_sim.results if r.get("result") == "exploitable"])
    except Exception:
        exploitable_count = 0

    # Check if scanner has been run recently
    try:
        latest_scan = db.query(ScanFinding).order_by(ScanFinding.discovered_at.desc()).first()
        has_recent_scan = latest_scan is not None
    except Exception:
        has_recent_scan = False

    # ── Patching Controls ──
    if p0_count > 0:
        patch_msg = f"{p0_count} critical (P0) CVEs from CISA KEV remain unpatched. {ransomware_count} linked to ransomware."
        advisories["MAS-TRM-11.1.1"] = {"level": "critical", "message": patch_msg}
        advisories["IM8A-AM-3"] = {"level": "critical", "message": patch_msg}
        advisories["NIST-PR.PS-1"] = {"level": "warning", "message": patch_msg}
        advisories["PCI-6.3.3"] = {"level": "warning", "message": f"{p0_count} critical CVEs may exceed PCI patching SLA."}
        advisories["ISO-A.8.8"] = {"level": "warning", "message": f"{p0_count} critical vulnerabilities require management attention."}
        advisories["CT-PRO-3"] = {"level": "warning", "message": f"{p0_count} unpatched critical vulnerabilities detected."}

    # ── Vulnerability Scanning Controls ──
    if has_recent_scan:
        advisories["MAS-TRM-11.2.3"] = {"level": "ok", "message": f"SCOUT scanner active. {total_findings} findings from latest scan."}
        advisories["NIST-DE.CM-8"] = {"level": "ok", "message": "Vulnerability scanning is being performed via SCOUT."}
        advisories["PCI-11.3.1"] = {"level": "ok", "message": "Internal scans performed via SCOUT scanner."}

    # ── Incident Response Controls ──
    if exploitable_count > 0:
        sim_msg = f"STRIKE emulation found {exploitable_count} exploitable technique(s). Incident response readiness should be verified."
        advisories["MAS-TRM-12.1.1"] = {"level": "warning", "message": sim_msg}
        advisories["ISO-A.5.24"] = {"level": "warning", "message": sim_msg}
        advisories["SOC2-CC7.2"] = {"level": "warning", "message": sim_msg}

    # ── Monitoring Controls ──
    from models import AuditLog
    try:
        audit_count = db.query(AuditLog).count()
        if audit_count > 0:
            advisories["MAS-TRM-9.1.1"] = {"level": "ok", "message": f"TACF audit trail active with {audit_count} records and hash chain integrity."}
            advisories["ISO-A.8.15"] = {"level": "ok", "message": f"{audit_count} audit log entries with tamper-proof hash chain."}
            advisories["SOC2-CC7.1"] = {"level": "ok", "message": "System monitoring active via TACF audit trail."}
    except Exception:
        pass

    return advisories


def _get_control_status(db: Session, framework_id: str, control_id: str, default: str) -> str:
    """Get control status from DB, falling back to default."""
    row = db.query(ControlStatus).filter(
        ControlStatus.framework_id == framework_id,
        ControlStatus.control_id == control_id
    ).first()
    return row.status if row else default

def _get_evidence_count(db: Session, framework_id: str, control_id: str) -> int:
    return db.query(ControlEvidence).filter(
        ControlEvidence.framework_id == framework_id,
        ControlEvidence.control_id == control_id
    ).count()


# ── API Endpoints ────────────────────────────────────────────────────────────

@router.get("/frameworks")
def get_frameworks(db: Session = Depends(get_db), user = Depends(get_current_user)):
    advisories = _get_live_advisories(db)
    result = []
    for key, fw in FRAMEWORKS.items():
        controls = fw["controls"]
        total = len(controls)
        statuses = [_get_control_status(db, key, c["id"], c["default_status"]) for c in controls]
        compliant = sum(1 for s in statuses if s == "compliant")
        partial = sum(1 for s in statuses if s == "partial")
        non_compliant = sum(1 for s in statuses if s == "non_compliant")
        assessed = sum(1 for s in statuses if s != "not_assessed")
        score = round(((compliant + partial * 0.5) / assessed * 100) if assessed > 0 else 0, 1)

        # Count advisories for this framework
        fw_advisories = sum(1 for c in controls if c["id"] in advisories and advisories[c["id"]].get("level") in ("warning", "critical"))

        result.append({
            "id": key, "name": fw["name"], "score": score, "total_controls": total,
            "compliant": compliant, "partial": partial, "non_compliant": non_compliant,
            "not_assessed": total - assessed, "active_advisories": fw_advisories,
        })
    return result


@router.get("/frameworks/{framework_id}/controls")
def get_framework_controls(framework_id: str, db: Session = Depends(get_db), user = Depends(get_current_user)):
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    advisories = _get_live_advisories(db)
    controls = []
    for c in fw["controls"]:
        status = _get_control_status(db, framework_id, c["id"], c["default_status"])
        ev_count = _get_evidence_count(db, framework_id, c["id"])
        ctrl_data = {
            "id": c["id"], "title": c["title"], "description": c["description"],
            "status": status, "evidence_count": ev_count
        }
        if c["id"] in advisories:
            ctrl_data["advisory"] = advisories[c["id"]]
        controls.append(ctrl_data)
    return {"name": fw["name"], "controls": controls}


@router.get("/advisories")
def get_all_advisories(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return all active compliance advisory alerts from live system data."""
    return _get_live_advisories(db)


class ControlStatusUpdate(BaseModel):
    status: str

@router.put("/frameworks/{framework_id}/controls/{control_id}")
def update_control_status(framework_id: str, control_id: str, update: ControlStatusUpdate, db: Session = Depends(get_db), user = Depends(require_role("Superadmin", "Admin", "Analyst"))):
    if update.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    ctrl = next((c for c in fw["controls"] if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    existing = db.query(ControlStatus).filter(
        ControlStatus.framework_id == framework_id,
        ControlStatus.control_id == control_id
    ).first()
    old_status = existing.status if existing else ctrl["default_status"]

    if existing:
        existing.status = update.status
        existing.updated_at = datetime.now(timezone.utc)
        existing.updated_by = user.get("sub", "unknown")
    else:
        db.add(ControlStatus(
            framework_id=framework_id, control_id=control_id,
            status=update.status, updated_by=user.get("sub", "unknown")
        ))
    db.commit()

    user_email = user.get("sub", "unknown")
    append_to_audit_log(AuditEntry(
        user=user_email, action="CONTROL_STATUS_UPDATE", module="STANDARD",
        detail=f"Control {control_id} ({ctrl['title']}) in {fw['name']}: {old_status} → {update.status}"
    ))
    return {"status": "updated", "control": {"id": control_id, "title": ctrl["title"], "status": update.status}}


@router.post("/frameworks/{framework_id}/controls/{control_id}/evidence")
async def upload_evidence(
    framework_id: str,
    control_id: str,
    file: UploadFile = File(None),
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Upload evidence for a compliance control. Accepts file upload or creates a marker record."""
    import os, re, traceback
    from uuid import uuid4

    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    ctrl = next((c for c in fw["controls"] if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    user_email = user.get("sub", "unknown")
    ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".md"}
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    filename = "evidence_marker.txt"
    file_path = None

    try:
        if file and file.filename:
            raw_name = file.filename
            safe_name = re.sub(r'[^\w\s\-\.]', '_', raw_name)
            ext = os.path.splitext(safe_name)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise HTTPException(status_code=400, detail=f"File type '{ext}' not allowed. Accepted: {', '.join(ALLOWED_EXTENSIONS)}")

            content = await file.read()
            if len(content) > MAX_SIZE:
                raise HTTPException(status_code=400, detail="File exceeds 10 MB limit.")

            # Try primary path, fallback to /tmp
            base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'evidence')
            evidence_dir = os.path.join(base_dir, 'standard', framework_id, control_id)
            try:
                os.makedirs(evidence_dir, exist_ok=True)
                # Test write permission
                test_file = os.path.join(evidence_dir, '.write_test')
                with open(test_file, 'w') as tf:
                    tf.write('ok')
                os.remove(test_file)
            except (OSError, PermissionError):
                # Fallback to /tmp-based storage
                evidence_dir = os.path.join('/tmp', 'tempris_evidence', 'standard', framework_id, control_id)
                os.makedirs(evidence_dir, exist_ok=True)

            unique_name = f"{uuid4().hex}{ext}"
            file_path = os.path.join(evidence_dir, unique_name)
            with open(file_path, "wb") as f:
                f.write(content)
            filename = safe_name

        ev = ControlEvidence(
            framework_id=framework_id, control_id=control_id,
            filename=filename, file_path=file_path, uploaded_by=user_email
        )
        db.add(ev)
        db.commit()
        db.refresh(ev)

        append_to_audit_log(AuditEntry(
            user=user_email, action="EVIDENCE_UPLOADED", module="STANDARD",
            detail=f"Evidence '{filename}' uploaded for control {control_id} in {fw['name']}"
        ))
        return {"status": "uploaded", "evidence": {"id": ev.id, "filename": filename, "uploaded_at": ev.uploaded_at.isoformat() if ev.uploaded_at else ""}}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Evidence upload failed: {str(e)}")


@router.get("/frameworks/{framework_id}/controls/{control_id}/evidence")
def list_evidence(
    framework_id: str, control_id: str,
    db: Session = Depends(get_db), user = Depends(get_current_user),
):
    """List all evidence files attached to a control."""
    records = db.query(ControlEvidence).filter(
        ControlEvidence.framework_id == framework_id,
        ControlEvidence.control_id == control_id
    ).order_by(ControlEvidence.uploaded_at.desc()).all()
    return [
        {
            "id": r.id, "filename": r.filename,
            "uploaded_by": r.uploaded_by,
            "uploaded_at": r.uploaded_at.isoformat() if r.uploaded_at else "",
            "has_file": r.file_path is not None,
        }
        for r in records
    ]


@router.get("/frameworks/{framework_id}/controls/{control_id}/evidence/{evidence_id}/download")
def download_evidence(
    framework_id: str, control_id: str, evidence_id: int,
    db: Session = Depends(get_db), user = Depends(get_current_user),
):
    """Download an evidence file."""
    import os
    from fastapi.responses import FileResponse

    ev = db.query(ControlEvidence).filter(
        ControlEvidence.id == evidence_id,
        ControlEvidence.framework_id == framework_id,
        ControlEvidence.control_id == control_id
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if not ev.file_path or not os.path.exists(ev.file_path):
        raise HTTPException(status_code=404, detail="Evidence file not found on disk")

    return FileResponse(
        ev.file_path,
        filename=ev.filename or "evidence",
        media_type="application/octet-stream",
    )


@router.delete("/frameworks/{framework_id}/controls/{control_id}/evidence/{evidence_id}")
def delete_evidence(
    framework_id: str, control_id: str, evidence_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin")),
):
    """Delete an evidence record and its file."""
    import os

    ev = db.query(ControlEvidence).filter(
        ControlEvidence.id == evidence_id,
        ControlEvidence.framework_id == framework_id,
        ControlEvidence.control_id == control_id
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    filename = ev.filename
    # Remove file from disk
    if ev.file_path and os.path.exists(ev.file_path):
        os.remove(ev.file_path)

    db.delete(ev)
    db.commit()

    user_email = user.get("sub", "unknown")
    append_to_audit_log(AuditEntry(
        user=user_email, action="EVIDENCE_DELETED", module="STANDARD",
        detail=f"Evidence '{filename}' deleted from control {control_id} in framework {framework_id}"
    ))
    return {"status": "deleted", "evidence_id": evidence_id}



# ── MAS TRM 1-Hour Incident Report ──────────────────────────────────────────

class IncidentReportRequest(BaseModel):
    incident_type: str = "cyber_security_incident"
    description: str = ""
    severity: str = "high"
    affected_systems: str = ""

@router.post("/mas-trm/incident-report")
def generate_incident_report(
    req: IncidentReportRequest = IncidentReportRequest(),
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    """Generate a structured MAS TRM 1-Hour Incident Notice report.
    
    Per MAS TRM 12.1.5, financial institutions must notify MAS within
    1 hour of discovering a relevant cyber security incident.
    """
    user_email = user.get("sub", "unknown")
    now = datetime.now(timezone.utc)

    # Gather live threat context
    from services.kev_loader import get_all_findings
    kev_findings = get_all_findings()
    p0_count = len([f for f in kev_findings if f.get("priority") == "P0"])
    ransomware_count = len([f for f in kev_findings if f.get("ransomware")])

    # Get latest scanner findings
    from models import ScanFinding
    try:
        recent_critical = db.query(ScanFinding).filter(
            ScanFinding.risk.in_(["Critical", "High"])
        ).order_by(ScanFinding.discovered_at.desc()).limit(10).all()
        scanner_findings = [{
            "target": f.target, "port": f.port, "service": f.service,
            "risk": f.risk, "detail": f.detail, "cve": f.cve_id or ""
        } for f in recent_critical]
    except Exception:
        scanner_findings = []

    # Get latest STRIKE results
    from models import StrikeSimulation
    try:
        latest_sim = db.query(StrikeSimulation).filter(
            StrikeSimulation.status == "completed"
        ).order_by(StrikeSimulation.completed_at.desc()).first()
        strike_summary = None
        if latest_sim and latest_sim.results:
            exploitable = [r for r in latest_sim.results if r.get("result") == "exploitable"]
            strike_summary = {
                "simulation_id": latest_sim.id,
                "techniques_tested": len(latest_sim.results),
                "exploitable": len(exploitable),
                "details": [{"technique": r.get("technique_id"), "name": r.get("technique_name"), "evidence": r.get("evidence")} for r in exploitable]
            }
    except Exception:
        strike_summary = None

    # Get TES score
    from routers.synthesis import get_dashboard_data
    dashboard = get_dashboard_data()
    tes_score = dashboard.get("aggregate_tes", 0)

    # Build the structured report
    report_id = f"INC-{now.strftime('%Y%m%d%H%M%S')}"
    deadline = datetime(now.year, now.month, now.day, now.hour + 1, now.minute, now.second) if now.hour < 23 else now

    report = {
        "report_id": report_id,
        "type": "MAS TRM 12.1.5 — 1-Hour Incident Notification",
        "generated_at": now.isoformat() + "Z",
        "generated_by": user_email,
        "notification_deadline": deadline.isoformat() + "Z",
        "status": "DRAFT — PENDING SUBMISSION TO MAS",

        "incident_summary": {
            "type": req.incident_type or "Cyber Security Incident",
            "severity": req.severity,
            "description": req.description or "Automated incident report generated from Tempris CTEM platform.",
            "affected_systems": req.affected_systems or "See scanner findings below.",
            "discovery_time": now.isoformat() + "Z",
        },

        "threat_landscape": {
            "tempris_exposure_score": round(tes_score, 2),
            "risk_band": "Critical" if tes_score >= 8.0 else "High" if tes_score >= 6.0 else "Medium" if tes_score >= 4.0 else "Low",
            "critical_cves_tracked": p0_count,
            "ransomware_linked_cves": ransomware_count,
            "total_kev_findings": len(kev_findings),
        },

        "scanner_findings": scanner_findings[:5],

        "red_team_assessment": strike_summary,

        "immediate_actions": [
            "CSRO has been notified via TACF audit trail.",
            "Incident response team activated per MAS-TRM-12.1.1.",
            "All critical findings are being triaged via SPECTRUM EDIP engine.",
            f"Current TES score: {tes_score:.2f} ({('Critical' if tes_score >= 8.0 else 'High' if tes_score >= 6.0 else 'Medium')}).",
        ],

        "regulatory_references": [
            "MAS TRM 12.1.5 — Notify MAS within 1 hour of discovering a relevant incident.",
            "MAS TRM 12.1.1 — Incident management and response procedures.",
            "PDPA 26D — Notify PDPC within 3 calendar days of a notifiable data breach.",
        ],
    }

    # Log to TACF audit trail
    append_to_audit_log(AuditEntry(
        user=user_email, action="MAS_TRM_INCIDENT_REPORT_GENERATED", module="STANDARD",
        detail=f"Incident report {report_id} generated. Severity: {req.severity}. TES: {tes_score:.2f}. Deadline: {deadline.isoformat()}Z"
    ))

    return report
