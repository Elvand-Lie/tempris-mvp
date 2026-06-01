from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session
from services.database import get_db
from models import ControlStatus, ControlEvidence
from routers.audit import append_to_audit_log, AuditEntry

router = APIRouter()

VALID_STATUSES = ["not_assessed", "compliant", "partial", "non_compliant", "not_applicable"]

# Framework definitions (reference data — stays in code)
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

@router.get("/frameworks")
def get_frameworks(db: Session = Depends(get_db)):
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
        result.append({
            "id": key, "name": fw["name"], "score": score, "total_controls": total,
            "compliant": compliant, "partial": partial, "non_compliant": non_compliant,
            "not_assessed": total - assessed,
        })
    return result

@router.get("/frameworks/{framework_id}/controls")
def get_framework_controls(framework_id: str, db: Session = Depends(get_db)):
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    controls = []
    for c in fw["controls"]:
        status = _get_control_status(db, framework_id, c["id"], c["default_status"])
        ev_count = _get_evidence_count(db, framework_id, c["id"])
        controls.append({
            "id": c["id"], "title": c["title"], "description": c["description"],
            "status": status, "evidence_count": ev_count
        })
    return {"name": fw["name"], "controls": controls}

class ControlStatusUpdate(BaseModel):
    status: str

@router.put("/frameworks/{framework_id}/controls/{control_id}")
def update_control_status(framework_id: str, control_id: str, update: ControlStatusUpdate, db: Session = Depends(get_db)):
    if update.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    ctrl = next((c for c in fw["controls"] if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    # Upsert
    existing = db.query(ControlStatus).filter(
        ControlStatus.framework_id == framework_id,
        ControlStatus.control_id == control_id
    ).first()
    old_status = existing.status if existing else ctrl["default_status"]
    
    if existing:
        existing.status = update.status
        existing.updated_at = datetime.utcnow()
    else:
        db.add(ControlStatus(
            framework_id=framework_id, control_id=control_id,
            status=update.status, updated_by="Current User"
        ))
    db.commit()

    append_to_audit_log(AuditEntry(
        user="Current User", action="CONTROL_STATUS_UPDATE", module="STANDARD",
        detail=f"Control {control_id} ({ctrl['title']}) in {fw['name']}: {old_status} → {update.status}"
    ))
    return {"status": "updated", "control": {"id": control_id, "title": ctrl["title"], "status": update.status}}

@router.post("/frameworks/{framework_id}/controls/{control_id}/evidence")
def upload_evidence(framework_id: str, control_id: str, db: Session = Depends(get_db)):
    fw = FRAMEWORKS.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    ctrl = next((c for c in fw["controls"] if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    ev = ControlEvidence(
        framework_id=framework_id, control_id=control_id,
        filename="evidence_uploaded.pdf", uploaded_by="Current User"
    )
    db.add(ev)
    db.commit()

    append_to_audit_log(AuditEntry(
        user="Current User", action="EVIDENCE_UPLOADED", module="STANDARD",
        detail=f"Evidence uploaded for control {control_id} in {fw['name']}"
    ))
    return {"status": "uploaded", "evidence": {"filename": ev.filename, "uploaded_at": ev.uploaded_at.isoformat() if ev.uploaded_at else ""}}
