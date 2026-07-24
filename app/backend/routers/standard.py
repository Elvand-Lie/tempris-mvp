"""
STANDARD Compliance Module — Production
Regulatory framework tracking with automated advisory alerts
and MAS TRM incident reporting workflow.
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from services.database import get_db
from models import ControlStatus, ControlEvidence, IncidentReport
from routers.audit import (
    append_to_audit_log,
    append_to_audit_log_db,
    verify_audit_chain,
    AuditEntry,
)
from routers.auth import get_current_user, require_role, get_auth_context, scoped_evidence_query, EvidencePermission
from typing import Optional
import os
import re
import uuid
import unicodedata
import urllib.parse
from pathlib import Path

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("STANDARD"))])
VALID_STATUSES = ["not_assessed", "compliant", "partial", "non_compliant", "not_applicable"]

def get_evidence_storage_root() -> str:
    root = os.environ.get("EVIDENCE_STORAGE_ROOT", "").strip()
    if not root:
        backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        root = os.path.join(backend_dir, "data", "evidence")
    os.makedirs(root, exist_ok=True)
    return os.path.realpath(root)

def validate_storage_path(file_path: str, strict: bool = True):
    if not file_path:
        raise HTTPException(status_code=404, detail="Evidence not found")
    try:
        root = Path(get_evidence_storage_root()).resolve(strict=True)
        candidate = Path(file_path).resolve(strict=strict)
        
        # Confinement check
        candidate.relative_to(root)
        
        if os.name == 'nt':
            if root.drive.lower() != candidate.drive.lower():
                raise ValueError("Different drives")
    except (ValueError, FileNotFoundError):
        raise HTTPException(status_code=404, detail="Evidence not found")

def sanitize_filename(filename: str) -> str:
    if not filename:
        return "evidence_file.dat"
    # Normalize Unicode
    filename = unicodedata.normalize("NFKC", filename)
    # Remove CR, LF, NUL and other control characters
    filename = re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', filename)
    # Remove path separators
    filename = re.sub(r'[\\/]', '', filename)
    # Remove header delimiters
    filename = re.sub(r'[";*=]', '', filename)
    
    base, ext = os.path.splitext(filename)
    base = base[:100]
    ext = ext[:10]
    filename = base + ext
    
    if filename in (".", "..", ""):
        return "evidence_file.dat"
    return filename

def log_evidence_action(
    user_ctx,
    evidence_id: int,
    action: str,
    module: str,
    outcome: str,
    reason_code: str,
    owning_tenant: Optional[str] = None,
    db: Optional[Session] = None,
    commit: bool = True,
):
    detail = f"User {user_ctx.user_id} ({user_ctx.role}) performed {action} on evidence {evidence_id}. Outcome: {outcome}. Reason: {reason_code}."
    metadata = {
        "actor_user_id": user_ctx.user_id,
        "actor_role": user_ctx.role,
        "action": action,
        "evidence_id": evidence_id,
        "owning_tenant": owning_tenant or "not_found_or_out_of_scope",
        "outcome": outcome,
        "reason_code": reason_code,
        "request_id": uuid.uuid4().hex
    }
    entry = AuditEntry(
        user=user_ctx.user_id,
        action=action,
        module=module,
        detail=detail,
        metadata=metadata,
    )
    if db is None:
        append_to_audit_log(entry)
    else:
        append_to_audit_log_db(db, entry, commit=commit)


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

# An absent assessment record cannot truthfully imply compliance.
for _framework in FRAMEWORKS.values():
    for _control in _framework["controls"]:
        _control["default_status"] = "not_assessed"

# ── Advisory Alert Engine ────────────────────────────────────────────────────
# Maps control IDs to functions that check live data and return advisory alerts.
# These do NOT change statuses — they provide warnings for analyst review.

def _get_live_advisories(db: Session, tenant_id: str) -> dict:
    """Check live system data and return advisory alerts per control.
    Returns: {control_id: {"level": "warning"|"critical", "message": str}}
    """
    advisories = {}

    # Check scanner findings for patching-related controls
    from models import ScanFinding
    try:
        critical_findings = db.query(ScanFinding).filter(
            ScanFinding.tenant_id == tenant_id,
            ScanFinding.risk.in_(["Critical", "High"])
        ).count()
        total_findings = db.query(ScanFinding).filter(
            ScanFinding.tenant_id == tenant_id
        ).count()
    except Exception:
        critical_findings = 0
        total_findings = 0

    # Check KEV data for vulnerability counts
    from services.kev_loader import get_finding_stats
    kev_stats = get_finding_stats(db, tenant_id=tenant_id)
    p0_count = kev_stats["critical_count"]
    ransomware_count = kev_stats["ransomware_linked"]

    # Check STRIKE simulation results
    from models import StrikeAuthorization, StrikeSimulation
    try:
        latest_sim = db.query(StrikeSimulation).join(
            StrikeAuthorization,
            StrikeSimulation.authorization_id == StrikeAuthorization.id,
        ).filter(
            StrikeSimulation.status == "completed",
            StrikeAuthorization.tenant_id == tenant_id,
        ).order_by(StrikeSimulation.completed_at.desc()).first()
        exploitable_count = 0
        if latest_sim and latest_sim.results:
            exploitable_count = len([r for r in latest_sim.results if r.get("result") == "exploitable"])
    except Exception:
        exploitable_count = 0

    # Check if scanner has been run recently
    try:
        latest_scan = db.query(ScanFinding).filter(
            ScanFinding.tenant_id == tenant_id
        ).order_by(ScanFinding.discovered_at.desc()).first()
        has_recent_scan = latest_scan is not None
    except Exception:
        has_recent_scan = False

    # ── Patching Controls ──
    if p0_count > 0:
        patch_msg = (
            f"{p0_count} tracked P0 findings require applicability and remediation review. "
            f"{ransomware_count} are ransomware-linked."
        )
        advisories["MAS-TRM-11.1.1"] = {"level": "critical", "message": patch_msg}
        advisories["IM8A-AM-3"] = {"level": "critical", "message": patch_msg}
        advisories["NIST-PR.PS-1"] = {"level": "warning", "message": patch_msg}
        advisories["PCI-6.3.3"] = {"level": "warning", "message": f"{p0_count} critical CVEs may exceed PCI patching SLA."}
        advisories["ISO-A.8.8"] = {"level": "warning", "message": f"{p0_count} critical vulnerabilities require management attention."}
        advisories["CT-PRO-3"] = {"level": "warning", "message": f"{p0_count} tracked P0 findings require review."}

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
        audit_count = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).count()
        if audit_count > 0:
            verification = verify_audit_chain(db, tenant_id)
            if verification["intact"]:
                message = f"TACF audit trail has {audit_count} records with a verified tamper-evident chain."
                advisories["MAS-TRM-9.1.1"] = {"level": "ok", "message": message}
                advisories["ISO-A.8.15"] = {"level": "ok", "message": message}
                advisories["SOC2-CC7.1"] = {"level": "ok", "message": "TACF audit-chain verification passed."}
            else:
                message = "TACF audit-chain verification failed for this tenant."
                advisories["MAS-TRM-9.1.1"] = {"level": "critical", "message": message}
                advisories["ISO-A.8.15"] = {"level": "critical", "message": message}
                advisories["SOC2-CC7.1"] = {"level": "critical", "message": message}
    except Exception:
        pass

    return advisories


def _get_control_status(db: Session, tenant_id: str, framework_id: str, control_id: str, default: str) -> str:
    """Get control status from DB, falling back to default."""
    row = db.query(ControlStatus).filter(
        ControlStatus.tenant_id == tenant_id,
        ControlStatus.framework_id == framework_id,
        ControlStatus.control_id == control_id
    ).first()
    return row.status if row else default

def _get_evidence_count(db: Session, tenant_id: str, framework_id: str, control_id: str) -> int:
    return db.query(ControlEvidence).filter(
        ControlEvidence.tenant_id == tenant_id,
        ControlEvidence.framework_id == framework_id,
        ControlEvidence.control_id == control_id
    ).count()


def _principal_tenant(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    return tenant_id


# ── API Endpoints ────────────────────────────────────────────────────────────

@router.get("/frameworks")
def get_frameworks(db: Session = Depends(get_db), user = Depends(get_current_user)):
    tenant_id = _principal_tenant(user)
    advisories = _get_live_advisories(db, tenant_id)
    result = []
    for key, fw in FRAMEWORKS.items():
        controls = fw["controls"]
        total = len(controls)
        statuses = [_get_control_status(db, tenant_id, key, c["id"], c["default_status"]) for c in controls]
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
    tenant_id = _principal_tenant(user)
    advisories = _get_live_advisories(db, tenant_id)
    controls = []
    for c in fw["controls"]:
        status = _get_control_status(db, tenant_id, framework_id, c["id"], c["default_status"])
        ev_count = _get_evidence_count(db, tenant_id, framework_id, c["id"])
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
    return _get_live_advisories(db, _principal_tenant(user))


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

    tenant_id = _principal_tenant(user)
    existing = db.query(ControlStatus).filter(
        ControlStatus.tenant_id == tenant_id,
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
            tenant_id=tenant_id,
            framework_id=framework_id, control_id=control_id,
            status=update.status, updated_by=user.get("sub", "unknown")
        ))
    user_email = user.get("sub", "unknown")
    try:
        append_to_audit_log_db(db, AuditEntry(
            user=user_email, action="CONTROL_STATUS_UPDATE", module="STANDARD",
            detail=f"Control {control_id} ({ctrl['title']}) in {fw['name']}: {old_status} to {update.status}",
        ), commit=False)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Control status update failed")
    return {"status": "updated", "control": {"id": control_id, "title": ctrl["title"], "status": update.status}}


@router.post("/frameworks/{framework_id}/controls/{control_id}/evidence")
async def upload_evidence(
    framework_id: str,
    control_id: str,
    target_tenant_id: Optional[str] = None,
    file: UploadFile = File(None),
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Upload evidence for a compliance control. Accepts file upload or creates a marker record."""
    import os
    from uuid import uuid4

    if ".." in framework_id or "/" in framework_id or "\\" in framework_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    ctrl = next((c for c in fw["controls"] if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    auth_ctx = get_auth_context(user)
    if auth_ctx.role not in ("Superadmin", "Admin", "Analyst"):
        raise HTTPException(status_code=403, detail="Permission denied")

    # Enforce no implicit/fallback defaults and target tenant checks
    if auth_ctx.is_superadmin:
        if not target_tenant_id:
            raise HTTPException(status_code=400, detail="Superadmin upload must explicitly specify a valid target_tenant_id")
        from routers.auth import USERS
        valid_tenants = {u.get("tenant_id") for u in USERS.values() if u.get("tenant_id")}
        if target_tenant_id not in valid_tenants:
            raise HTTPException(status_code=400, detail="Invalid target tenant ID")
        assigned_tenant_id = target_tenant_id
    else:
        if target_tenant_id is not None:
            raise HTTPException(status_code=400, detail="Caller-supplied tenant ID is not permitted")
        if not auth_ctx.tenant_id:
            raise HTTPException(status_code=400, detail="Missing tenant context")
        assigned_tenant_id = auth_ctx.tenant_id

    ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".md"}
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    filename = "evidence_marker.txt"
    file_path = None

    try:
        if file and file.filename:
            raw_name = file.filename
            clean_name = sanitize_filename(raw_name)
            ext = os.path.splitext(clean_name)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise HTTPException(status_code=400, detail=f"File type '{ext}' not allowed. Accepted: {', '.join(ALLOWED_EXTENSIONS)}")

            content = await file.read()
            if len(content) > MAX_SIZE:
                raise HTTPException(status_code=400, detail="File exceeds 10 MB limit.")

            root_dir = get_evidence_storage_root()
            evidence_dir = os.path.join(
                root_dir, "standard", assigned_tenant_id, framework_id, control_id
            )
            
            if os.path.islink(evidence_dir):
                raise HTTPException(status_code=400, detail="Symlinks not allowed in storage directory path")
                
            os.makedirs(evidence_dir, exist_ok=True)
            
            resolved_evidence_dir = os.path.realpath(evidence_dir)
            try:
                Path(resolved_evidence_dir).relative_to(Path(root_dir))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid destination path")

            unique_name = f"{uuid4().hex}{ext}"
            file_path = os.path.join(evidence_dir, unique_name)
            validate_storage_path(file_path, strict=False)

            with open(file_path, "wb") as f:
                f.write(content)
            filename = clean_name

        ev = ControlEvidence(
            tenant_id=assigned_tenant_id,
            framework_id=framework_id,
            control_id=control_id,
            filename=filename,
            file_path=file_path,
            uploaded_by=auth_ctx.user_id
        )
        db.add(ev)
        db.flush()

        log_evidence_action(
            auth_ctx, ev.id, "EVIDENCE_UPLOADED", "STANDARD",
            "success", "authorized", assigned_tenant_id,
            db=db, commit=False,
        )
        db.commit()
        db.refresh(ev)
        return {"status": "uploaded", "evidence": {"id": ev.id, "filename": filename, "uploaded_at": ev.uploaded_at.isoformat() if ev.uploaded_at else ""}}
    except HTTPException:
        db.rollback()
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        raise
    except Exception:
        db.rollback()
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
        raise HTTPException(status_code=500, detail="Evidence upload failed")


@router.get("/frameworks/{framework_id}/controls/{control_id}/evidence")
def list_evidence(
    framework_id: str, control_id: str,
    db: Session = Depends(get_db), user = Depends(get_current_user),
):
    """List all evidence files attached to a control."""
    if ".." in framework_id or "/" in framework_id or "\\" in framework_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    if auth_ctx.role not in ("Superadmin", "Admin", "Analyst"):
        raise HTTPException(status_code=403, detail="Permission denied")

    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        framework_id=framework_id,
        control_id=control_id,
        required_permission=EvidencePermission.LIST
    )
    records = query.order_by(ControlEvidence.uploaded_at.desc()).all()
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
    from fastapi.responses import FileResponse

    if ".." in framework_id or "/" in framework_id or "\\" in framework_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        evidence_id=evidence_id,
        framework_id=framework_id,
        control_id=control_id,
        required_permission=EvidencePermission.DOWNLOAD
    )
    ev = query.first()

    if not ev:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD_DENIED", "STANDARD",
            "denied", "not_found_or_out_of_scope"
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    if not ev.file_path or not os.path.exists(ev.file_path):
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD_DENIED", "STANDARD",
            "denied", "file_not_found", ev.tenant_id
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    validate_storage_path(ev.file_path)

    if auth_ctx.is_superadmin:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD", "STANDARD",
            "success", "superadmin_bypass", ev.tenant_id
        )
    else:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD", "STANDARD",
            "success", "authorized", ev.tenant_id
        )

    clean_filename = sanitize_filename(ev.filename)
    ascii_filename = "".join(c for c in clean_filename if ord(c) < 128)
    if not ascii_filename:
        ascii_filename = "evidence_file.dat"
    encoded_filename = urllib.parse.quote(clean_filename)
    content_disposition = f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}'

    headers = {
        "Content-Disposition": content_disposition,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "Content-Length": str(os.path.getsize(ev.file_path))
    }
    return FileResponse(
        path=ev.file_path,
        media_type="application/octet-stream",
        headers=headers
    )


@router.get("/frameworks/{framework_id}/controls/{control_id}/evidence/{evidence_id}/preview")
def preview_evidence(
    framework_id: str, control_id: str, evidence_id: int,
    db: Session = Depends(get_db), user = Depends(get_current_user),
):
    from fastapi.responses import FileResponse

    if ".." in framework_id or "/" in framework_id or "\\" in framework_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        evidence_id=evidence_id,
        framework_id=framework_id,
        control_id=control_id,
        required_permission=EvidencePermission.PREVIEW
    )
    ev = query.first()

    if not ev:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW_DENIED", "STANDARD",
            "denied", "not_found_or_out_of_scope"
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    if not ev.file_path or not os.path.exists(ev.file_path):
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW_DENIED", "STANDARD",
            "denied", "file_not_found", ev.tenant_id
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    validate_storage_path(ev.file_path)

    if auth_ctx.is_superadmin:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW", "STANDARD",
            "success", "superadmin_bypass", ev.tenant_id
        )
    else:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW", "STANDARD",
            "success", "authorized", ev.tenant_id
        )

    clean_filename = sanitize_filename(ev.filename)
    ext = os.path.splitext(clean_filename)[1].lower()

    inline_preview_allowed = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".txt": "text/plain",
        ".md": "text/plain"
    }

    if ext in inline_preview_allowed:
        media_type = inline_preview_allowed[ext]
        disposition = f'inline; filename="{clean_filename}"'
    else:
        media_type = "application/octet-stream"
        ascii_filename = "".join(c for c in clean_filename if ord(c) < 128)
        if not ascii_filename:
            ascii_filename = "evidence_file.dat"
        encoded_filename = urllib.parse.quote(clean_filename)
        disposition = f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}'

    headers = {
        "Content-Disposition": disposition,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "Content-Length": str(os.path.getsize(ev.file_path))
    }
    return FileResponse(
        path=ev.file_path,
        media_type=media_type,
        headers=headers
    )


@router.delete("/frameworks/{framework_id}/controls/{control_id}/evidence/{evidence_id}")
def delete_evidence(
    framework_id: str, control_id: str, evidence_id: int,
    db: Session = Depends(get_db), user = Depends(get_current_user),
):
    """Delete an evidence record and its file."""
    if ".." in framework_id or "/" in framework_id or "\\" in framework_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        evidence_id=evidence_id,
        framework_id=framework_id,
        control_id=control_id,
        required_permission=EvidencePermission.DELETE
    )
    ev = query.first()

    if not ev:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DELETE_DENIED", "STANDARD",
            "denied", "not_found_or_out_of_scope"
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    file_path = ev.file_path
    if file_path:
        validate_storage_path(file_path)

    tenant_id = ev.tenant_id

    # 1. Initiated log
    log_evidence_action(
        auth_ctx, evidence_id, "EVIDENCE_DELETE_REQUESTED", "STANDARD",
        "success", "initiated", tenant_id
    )

    # 2. Compensating rollback quarantine setup
    quarantine_dir = os.path.join(get_evidence_storage_root(), ".quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    
    quarantine_filename = os.path.basename(file_path) + ".quarantine" if file_path else None
    quarantine_path = os.path.join(quarantine_dir, quarantine_filename) if quarantine_filename else None

    moved_to_quarantine = False
    if file_path and os.path.exists(file_path):
        try:
            os.replace(file_path, quarantine_path)
            moved_to_quarantine = True
        except Exception as e:
            log_evidence_action(
                auth_ctx, evidence_id, "EVIDENCE_DELETE_FAILED", "STANDARD",
                "error", f"filesystem_quarantine_failed: {str(e)}", tenant_id
            )
            raise HTTPException(status_code=500, detail="Evidence deletion failed: filesystem error")

    filename = ev.filename

    # 3. Database deletion and transaction commit
    try:
        db.delete(ev)
        db.commit()
    except Exception as e:
        db.rollback()
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DELETE_FAILED", "STANDARD",
            "error", f"database_transaction_failed: {str(e)}", tenant_id
        )
        if moved_to_quarantine:
            try:
                os.replace(quarantine_path, file_path)
                log_evidence_action(
                    auth_ctx, evidence_id, "EVIDENCE_DELETE_RECOVERED", "STANDARD",
                    "success", "restored_from_quarantine", tenant_id
                )
            except Exception as re:
                log_evidence_action(
                    auth_ctx, evidence_id, "EVIDENCE_DELETE_RECOVERY_FAILED", "STANDARD",
                    "error", f"failed_to_restore_quarantine: {str(re)}", tenant_id
                )
        raise HTTPException(status_code=500, detail="Evidence deletion failed: database error")

    # 4. Complete filesystem removal
    if moved_to_quarantine:
        try:
            os.remove(quarantine_path)
        except Exception:
            pass

    log_evidence_action(
        auth_ctx, evidence_id, "EVIDENCE_DELETED", "STANDARD",
        "success", "authorized", tenant_id
    )

    return {"status": "deleted", "evidence_id": evidence_id}




# ── MAS TRM 1-Hour Incident Report ──────────────────────────────────────────

class IncidentReportRequest(BaseModel):
    incident_type: str = "cyber_security_incident"
    description: str = ""
    severity: str = "high"
    affected_systems: str = ""


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/mas-trm/incident-reports/latest")
def get_latest_incident_report(db: Session = Depends(get_db), user = Depends(get_current_user)):
    tenant_id = _principal_tenant(user)
    latest = db.query(IncidentReport).filter(
        IncidentReport.tenant_id == tenant_id
    ).order_by(IncidentReport.generated_at.desc()).first()
    return latest.payload if latest else None


@router.get("/mas-trm/incident-reports")
def list_incident_reports(
    limit: int = 20,
    offset: int = 0,
    order: str = "desc",
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    sort_expr = IncidentReport.generated_at.asc() if order.lower() == "asc" else IncidentReport.generated_at.desc()
    query = db.query(IncidentReport).filter(
        IncidentReport.tenant_id == _principal_tenant(user)
    )
    total = query.count()
    rows = query.order_by(sort_expr).offset(offset).limit(limit).all()
    return {
        "data": [row.payload for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


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
    tenant_id = _principal_tenant(user)
    now = datetime.now(timezone.utc)

    # Gather live threat context
    from services.kev_loader import get_finding_stats
    kev_stats = get_finding_stats(db, tenant_id=tenant_id)
    p0_count = kev_stats["critical_count"]
    ransomware_count = kev_stats["ransomware_linked"]

    # Get latest scanner findings
    from models import ScanFinding
    try:
        recent_critical = db.query(ScanFinding).filter(
            ScanFinding.tenant_id == tenant_id,
            ScanFinding.risk.in_(["Critical", "High"])
        ).order_by(ScanFinding.discovered_at.desc()).limit(10).all()
        scanner_findings = [{
            "target": f.target, "port": f.port, "service": f.service,
            "risk": f.risk, "detail": f.detail, "cve": getattr(f, "cve_id", None) or ""
        } for f in recent_critical]
    except Exception:
        scanner_findings = []

    # Get latest STRIKE results
    from models import StrikeAuthorization, StrikeSimulation
    try:
        latest_sim = db.query(StrikeSimulation).join(
            StrikeAuthorization,
            StrikeSimulation.authorization_id == StrikeAuthorization.id,
        ).filter(
            StrikeSimulation.status == "completed",
            StrikeAuthorization.tenant_id == tenant_id,
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
    dashboard = get_dashboard_data(db, tenant_id=tenant_id)
    tes_score = dashboard.get("aggregate_tes", 0)

    # Build the structured report
    report_id = f"INC-{now.strftime('%Y%m%d%H%M%S%f')}"
    deadline = now + timedelta(hours=1)

    report = {
        "report_id": report_id,
        "type": "MAS TRM 12.1.5 — 1-Hour Incident Notification",
        "generated_at": _iso_z(now),
        "generated_by": user_email,
        "notification_deadline": _iso_z(deadline),
        "status": "DRAFT — PENDING SUBMISSION TO MAS",

        "incident_summary": {
            "type": req.incident_type or "Cyber Security Incident",
            "severity": req.severity,
            "description": req.description or "Automated incident report generated from Tempris CTEM platform.",
            "affected_systems": req.affected_systems or "See scanner findings below.",
            "discovery_time": _iso_z(now),
        },

        "threat_landscape": {
            "tempris_exposure_score": round(tes_score, 2),
            "risk_band": "Critical" if tes_score >= 8.0 else "High" if tes_score >= 6.0 else "Medium" if tes_score >= 4.0 else "Low",
            "critical_cves_tracked": p0_count,
            "ransomware_linked_cves": ransomware_count,
            "total_kev_findings": kev_stats["total_findings"],
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

    db.add(IncidentReport(
        report_id=report_id,
        tenant_id=tenant_id,
        report_type=report["type"],
        status=report["status"],
        severity=req.severity,
        generated_by=user_email,
        generated_at=now,
        notification_deadline=deadline,
        payload=report,
    ))
    try:
        append_to_audit_log_db(db, AuditEntry(
            user=user_email, action="MAS_TRM_INCIDENT_REPORT_GENERATED", module="STANDARD",
            detail=f"Incident report {report_id} generated and stored. Severity: {req.severity}. TES: {tes_score:.2f}. Deadline: {_iso_z(deadline)}",
        ), commit=False)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Incident report generation failed")

    return report
