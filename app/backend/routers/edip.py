from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models import Finding
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_role
from services.database import get_db
from services.tes_engine import calculate_sss_tes, priority_from_tes, public_decision_for_finding, public_severity

router = APIRouter()


class SssIntake(BaseModel):
    finding_id: str | None = None
    finding_type: str = Field(default="BLFLAW", max_length=50)
    title: str = Field(..., max_length=255)
    description: str = Field(..., max_length=2000)
    affected_ecosystem: str = Field(default="Application", max_length=255)
    attack_vectors: list[str] = []
    base_severity: float = Field(default=7.0, ge=0, le=10)
    agm: float = Field(default=1.0, ge=0, le=2)
    drf: float = Field(default=1.0, ge=0, le=2)
    tef: float = Field(default=1.0, ge=0, le=2)
    patch_available: bool = False
    recommended_action: str = "COMPENSATING_CONTROL"
    compensating_controls: list[str] = []
    references: list[str] = []
    asset_id: str | None = None


def _new_id(prefix: str) -> str:
    return f"F-{prefix}-{uuid4().hex[:8]}"


def _tacf_metadata(kind: str, evidence: str) -> dict:
    return {
        "agent_identity": "tempris-edip-intake",
        "authority_granted": f"create-{kind}-finding",
        "tool_used": "edip-intake-api",
        "evidence_generated": evidence,
        "revocation_path": "delete finding or supersede with EDIP decision",
        "under_policy_control": True,
    }


def _tenant_id(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    return tenant_id


def _create_finding(db: Session, req: SssIntake, kind: str, tenant_id: str) -> Finding:
    fid = req.finding_id or f"SSS-{datetime.now(timezone.utc).year}-{kind}-{uuid4().hex[:6].upper()}"
    if db.query(Finding).filter(Finding.cve == fid, Finding.tenant_id == tenant_id).first():
        raise HTTPException(status_code=409, detail="Finding already exists")

    scoring = {"base_severity": req.base_severity, "AGM": req.agm, "DRF": req.drf, "TEF": req.tef}
    tes = calculate_sss_tes(scoring)
    finding = Finding(
        id=_new_id("ED"),
        tenant_id=tenant_id,
        cve=fid,
        title=req.title,
        vendor=req.affected_ecosystem,
        product=", ".join(req.attack_vectors),
        cvss=req.base_severity,
        priority=priority_from_tes(tes),
        status="unmitigated",
        cisa_kev=False,
        ransomware=False,
        date_added=datetime.now(timezone.utc).isoformat(),
        short_description=req.description,
        required_action=req.recommended_action,
        raw_inputs={
            "cvss": req.base_severity,
            "exploitability": 10.0,
            "business_impact": min(10.0, req.base_severity * req.drf),
            "asset_criticality": min(10.0, 7.0 * req.tef),
            "threat_actor_activity": min(10.0, 7.0 * req.agm),
        },
        asset_id=req.asset_id,
        sss_data={
            "type": req.finding_type or kind,
            "source": kind,
            "scoring": scoring,
            "patch_available": req.patch_available,
            "compensating_controls": req.compensating_controls,
            "attack_vectors": req.attack_vectors,
            "references": req.references,
        },
        source="sss",
    )
    db.add(finding)
    db.flush()
    return finding


def _public(f: Finding) -> dict:
    data = {
        "id": f.id,
        "cve": f.cve,
        "title": f.title,
        "vendor": f.vendor,
        "product": f.product,
        "priority": f.priority,
        "status": f.status,
        "finding_type": (f.sss_data or {}).get("type"),
        "patch_available": (f.sss_data or {}).get("patch_available"),
        "compensating_controls": (f.sss_data or {}).get("compensating_controls", []),
        "source_references": (f.sss_data or {}).get("references", []),
    }
    score = calculate_sss_tes((f.sss_data or {}).get("scoring", {}))
    data["tes_score"] = score
    data["tes_decision"] = public_decision_for_finding({"sss_data": f.sss_data, "source": f.source}, score)
    data["severity"] = public_severity({"sss_data": f.sss_data, "source": f.source, "cve": f.cve, "cvss": f.cvss})
    return data


def _list_findings(db: Session, kind: str, tenant_id: str) -> list[dict]:
    rows = db.query(Finding).filter(
        Finding.source == "sss",
        Finding.tenant_id == tenant_id,
    ).order_by(Finding.created_at.desc()).limit(300).all()
    return [_public(f) for f in rows if ((f.sss_data or {}).get("source") == kind or (f.sss_data or {}).get("type") == kind)]


@router.post("/intake/blflaw")
def create_blflaw(req: SssIntake, request: Request, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    req.finding_type = req.finding_type or "BLFLAW"
    try:
        finding = _create_finding(db, req, "BLFLAW", _tenant_id(user))
        append_to_audit_log_db(db, AuditEntry(
            user=user.get("sub", "unknown"), action="AUTO_EDIP_INTAKE", module="EDIP",
            detail=f"BLFLAW intake created {finding.cve}", ip_address=request.client.host if request.client else None,
            metadata=_tacf_metadata("blflaw", finding.cve),
        ), commit=False)
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="EDIP intake failed")
    return _public(finding)


@router.get("/intake/blflaw")
def list_blflaw(db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer"))):
    return {"data": _list_findings(db, "BLFLAW", _tenant_id(user))}


@router.put("/intake/blflaw/{finding_id}")
def update_blflaw(finding_id: str, req: SssIntake, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    f = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == _tenant_id(user),
    ).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.title = req.title
    f.short_description = req.description
    f.vendor = req.affected_ecosystem
    f.product = ", ".join(req.attack_vectors)
    f.required_action = req.recommended_action
    scoring = {"base_severity": req.base_severity, "AGM": req.agm, "DRF": req.drf, "TEF": req.tef}
    f.cvss = req.base_severity
    f.priority = priority_from_tes(calculate_sss_tes(scoring))
    f.sss_data = {**(f.sss_data or {}), "type": req.finding_type or "BLFLAW", "source": "BLFLAW", "scoring": scoring, "patch_available": req.patch_available, "compensating_controls": req.compensating_controls, "attack_vectors": req.attack_vectors, "references": req.references}
    db.commit()
    db.refresh(f)
    return _public(f)


@router.post("/intake/nhi")
def create_nhi(req: SssIntake, request: Request, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    req.finding_type = req.finding_type if req.finding_type.startswith("NHI") else "NHI_AUTHORITY"
    try:
        finding = _create_finding(db, req, "NHI", _tenant_id(user))
        append_to_audit_log_db(db, AuditEntry(
            user=user.get("sub", "unknown"), action="AUTO_EDIP_INTAKE", module="EDIP",
            detail=f"NHI intake created {finding.cve}", ip_address=request.client.host if request.client else None,
            metadata=_tacf_metadata("nhi", finding.cve),
        ), commit=False)
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="EDIP intake failed")
    return _public(finding)


@router.get("/intake/nhi")
def list_nhi(db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer"))):
    rows = db.query(Finding).filter(
        Finding.source == "sss",
        Finding.tenant_id == _tenant_id(user),
    ).order_by(Finding.created_at.desc()).limit(300).all()
    return {"data": [_public(f) for f in rows if str((f.sss_data or {}).get("type", "")).startswith("NHI") or (f.sss_data or {}).get("source") == "NHI"]}
