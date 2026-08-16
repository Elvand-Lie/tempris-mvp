"""
GRC Router - ISO/IEC 42001:2023 AI Management System
Handles GRC state persistence, TES composite scoring, and SOP sign-offs.

References:
  - ISO/IEC 42001:2023 Clauses 6.1.2, 6.1.4, 9.2, 10.2
  - Annex A.2.2, A.3.2, A.5.2, A.6.2.2, A.7.4, A.9.2, A.10.3
  - Singapore alignment: PDPA, MAS TRM, MAS FEAT, IMDA AI Governance Framework v2
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from pathlib import Path
from typing import Optional
from uuid import uuid4
from services.database import get_db
from services.entitlements import require_module
from models import (
    GrcState, GrcSignoff, GrcPolicyDocument, ControlEvidence, GeneratedReport,
    ControlAssessment, FrameworkControl, PolicyControlLink,
)
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role, get_auth_context, scoped_evidence_query, EvidencePermission
from services.operational_events import record_operational_event
from services.grc_framework import (
    CONTROL_CATALOG, ISO_42001_ID, ISO_42001_NAME, ISO_42001_VERSION,
    assessment_rows, assessment_state, ensure_framework_catalog,
    ensure_tenant_assessments, framework_controls, get_live_grc_modifiers,
    qualitative_drivers, recalculate_open_sss_findings,
)
import os
import json
import re
from datetime import datetime, timezone
import uuid
import unicodedata
import urllib.parse
from fastapi.responses import FileResponse

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
    owning_tenant: Optional[str] = None
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
    append_to_audit_log(AuditEntry(
        user=user_ctx.user_id,
        action=action,
        module=module,
        detail=detail,
        metadata=metadata
    ))



router = APIRouter(dependencies=[Depends(require_module("GRC"))])


def _verified_tenant_id(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    return tenant_id

# Ã¢â€â‚¬Ã¢â€â‚¬ ISO 42001 Control definitions Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

GRC_CONTROLS = [
    {"id": control_id, "domain": domain, "title": requirement, "description": description,
     "tes_modifier": modifier_group}
    for control_id, domain, requirement, description, modifier_group in CONTROL_CATALOG
]

def _legacy_toggle_snapshot(toggles) -> dict:
    """Retain legacy native-client input without allowing it to drive risk."""
    return toggles if isinstance(toggles, dict) else {}


DEFAULT_SOP_STATE = [
    {"id": c["id"], "status": "pending", "pic": "", "notes": "", "endUserAgreed": False, "picAgreed": False}
    for c in GRC_CONTROLS
]

SOP_SIGNOFF_FIELDS = {
    "end_user": "endUserAgreed",
    "pic": "picAgreed",
}


def _clone_default_sop_state() -> list[dict]:
    return [dict(item) for item in DEFAULT_SOP_STATE]


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _normalize_sop_state(sop_state, fallback=None) -> list[dict]:
    base_state = fallback if isinstance(fallback, list) and len(fallback) == len(GRC_CONTROLS) else _clone_default_sop_state()
    source_state = sop_state if isinstance(sop_state, list) and len(sop_state) == len(GRC_CONTROLS) else None

    normalized = []
    for idx, ctrl in enumerate(GRC_CONTROLS):
        base_item = base_state[idx] if idx < len(base_state) and isinstance(base_state[idx], dict) else {}
        source_item = source_state[idx] if source_state and isinstance(source_state[idx], dict) else {}
        normalized.append({
            "id": ctrl["id"],
            "status": str(source_item.get("status", base_item.get("status", "pending"))).strip().lower().replace(" ", "_") if str(source_item.get("status", base_item.get("status", "pending"))).strip().lower().replace(" ", "_") in {"pending", "in_review", "completed"} else "pending",
            "pic": source_item.get("pic", base_item.get("pic", "")) if isinstance(source_item.get("pic", base_item.get("pic", "")), str) else base_item.get("pic", ""),
            "notes": source_item.get("notes", base_item.get("notes", "")) if isinstance(source_item.get("notes", base_item.get("notes", "")), str) else base_item.get("notes", ""),
            "endUserAgreed": _coerce_bool(source_item.get("endUserAgreed", base_item.get("endUserAgreed", False))),
            "picAgreed": _coerce_bool(source_item.get("picAgreed", base_item.get("picAgreed", False))),
        })
    return normalized


def _latest_sop_state_from_db(db: Session, tenant_id: str) -> list[dict]:
    state = (
        db.query(GrcState)
        .filter(GrcState.tenant_id == tenant_id)
        .order_by(GrcState.id.desc())
        .first()
    )
    if state and isinstance(state.sop_state, list) and len(state.sop_state) == len(GRC_CONTROLS):
        return _normalize_sop_state(state.sop_state)
    return _clone_default_sop_state()


def _signoff_state_from_db(db: Session, tenant_id: str) -> dict[str, set[str]]:
    signoffs: dict[str, set[str]] = {}
    rows = (
        db.query(GrcSignoff)
        .filter(GrcSignoff.tenant_id == tenant_id)
        .order_by(GrcSignoff.id.asc())
        .all()
    )
    for row in rows:
        if row.signoff_type not in SOP_SIGNOFF_FIELDS:
            continue
        signoffs.setdefault(row.control_id, set()).add(row.signoff_type)
    return signoffs


def _effective_sop_state(db: Session, tenant_id: str) -> list[dict]:
    return [
        {
            "id": control.control_id,
            "pic": assessment.pic or "",
            "notes": assessment.notes or "",
            "status": status,
            "endUserAgreed": bool(assessment.end_user_agreed),
            "picAgreed": bool(assessment.pic_signed_off),
        }
        for control, assessment, status, _ in assessment_rows(db, tenant_id)
    ]


def _sync_signoff_record(
    db: Session,
    tenant_id: str,
    control_id: str,
    signoff_type: str,
    signed: bool,
    signed_by: str,
    notes: Optional[str] = None,
) -> str:
    rows = db.query(GrcSignoff).filter(
        GrcSignoff.tenant_id == tenant_id,
        GrcSignoff.control_id == control_id,
        GrcSignoff.signoff_type == signoff_type,
    ).order_by(GrcSignoff.id.asc()).all()

    if signed:
        if not rows:
            db.add(GrcSignoff(
                tenant_id=tenant_id,
                control_id=control_id,
                signoff_type=signoff_type,
                signed_by=signed_by,
                notes=notes,
            ))
        elif len(rows) > 1:
            for extra in rows[1:]:
                db.delete(extra)
    else:
        for row in rows:
            db.delete(row)

    return "signed" if signed else "revoked"


def _sync_signoffs_from_sop_state(
    db: Session,
    tenant_id: str,
    sop_state: list[dict],
    signed_by: str,
) -> None:
    normalized = _normalize_sop_state(sop_state)
    for entry in normalized:
        for signoff_type, field in SOP_SIGNOFF_FIELDS.items():
            _sync_signoff_record(
                db=db,
                tenant_id=tenant_id,
                control_id=entry["id"],
                signoff_type=signoff_type,
                signed=_coerce_bool(entry.get(field, False)),
                signed_by=signed_by,
                notes=entry.get("notes") or None,
            )

# Ã¢â€â‚¬Ã¢â€â‚¬ TES Composite Calculation (matches client's panel formula) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

BASE_VULN = 8.5
BASE_EXPOSURE = 0.7
BASE_LIKELIHOOD = 0.6


def _public_ai_system_risk(db: Session, tenant_id: str) -> dict:
    """Customer-safe presentation contract; never expose scoring internals."""
    modifiers = get_live_grc_modifiers(db, tenant_id)
    score = round(BASE_VULN * BASE_EXPOSURE * BASE_LIKELIHOOD * modifiers["AGM"] * modifiers["DRF"] * modifiers["TEF"], 3)
    if score >= 7:
        band = "CRITICAL"
    elif score >= 5:
        band = "HIGH"
    elif score >= 3:
        band = "MEDIUM"
    else:
        band = "LOW"
    return {
        "score": round(float(score), 1),
        "band": band,
        "direction": None,
        "drivers": qualitative_drivers(db, tenant_id),
        "scope": "AI_SYSTEM",
        "subject": "AI-powered credit-scoring system",
        "as_of": datetime.now(timezone.utc).isoformat(),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Request Models Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

class GrcStateRequest(BaseModel):
    # Legacy native clients still send this field. It is retained only for compatibility.
    toggles: dict = Field(default_factory=dict)
    sop_state: list[dict]

class SignoffRequest(BaseModel):
    signoff_type: str  # 'end_user' or 'pic'
    signed: bool = True
    notes: Optional[str] = None


def _save_assessments_from_sop_state(db: Session, tenant_id: str, sop_state: list[dict], actor: str) -> None:
    supplied = {entry.get("id"): entry for entry in _normalize_sop_state(sop_state)}
    for control, assessment, _, _ in assessment_rows(db, tenant_id):
        entry = supplied[control.control_id]
        requested = str(entry.get("status") or "").strip().lower().replace(" ", "_")
        end_user = _coerce_bool(entry.get("endUserAgreed", False))
        pic_signed = _coerce_bool(entry.get("picAgreed", False))
        if requested not in {"pending", "in_review", "completed"}:
            requested = "completed" if end_user and pic_signed else "in_review" if end_user or pic_signed else "pending"
        assessment.status = requested
        assessment.pic = entry.get("pic", "")
        assessment.notes = entry.get("notes", "")
        assessment.end_user_agreed = end_user
        assessment.pic_signed_off = pic_signed
        assessment.updated_by = actor

# Ã¢â€â‚¬Ã¢â€â‚¬ Endpoints Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.get("/state")
def get_grc_state(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Load the most recent GRC state. Returns defaults if none saved."""
    tenant_id = _verified_tenant_id(user)
    state = (
        db.query(GrcState)
        .filter(GrcState.tenant_id == tenant_id)
        .order_by(GrcState.id.desc())
        .first()
    )
    sop_state = _effective_sop_state(db, tenant_id)
    if state:
        return {
            "governance_flags_recorded": bool(state.toggles),
            "sop_state": sop_state,
            "updated_by": state.updated_by,
            "updated_at": state.updated_at.isoformat() if state.updated_at else None,
        }
    return {
        "governance_flags_recorded": False,
        "sop_state": sop_state,
        "updated_by": None,
        "updated_at": None,
    }

@router.post("/state")
def save_grc_state(
    req: GrcStateRequest,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Save canonical SOP state; legacy toggle input has no scoring effect."""
    # Ã¢â€â‚¬Ã¢â€â‚¬ Validate toggle structure Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    tenant_id = _verified_tenant_id(user)
    actor = user.get("sub", "unknown")
    validated_sop_state = _normalize_sop_state(req.sop_state)
    _save_assessments_from_sop_state(db, tenant_id, validated_sop_state, actor)
    _sync_signoffs_from_sop_state(db, tenant_id, validated_sop_state, actor)

    # Keep an immutable compatibility snapshot for the existing native client.
    state = GrcState(
        tenant_id=tenant_id,
        toggles=_legacy_toggle_snapshot(req.toggles),
        sop_state=validated_sop_state,
        updated_by=actor,
    )
    db.add(state)
    recalculated = recalculate_open_sss_findings(db, tenant_id, actor)
    db.commit()
    db.refresh(state)
    risk_score = _public_ai_system_risk(db, tenant_id)
    
    append_to_audit_log(AuditEntry(
        user=actor,
        action="GRC_STATE_UPDATED",
        module="GRC",
        detail=f"GRC state saved. AI-system risk score: {risk_score['score']} ({risk_score['band']})."
    ))
    
    for finding_id in recalculated:
        try:
            from routers.edip import _publish_sss_event
            _publish_sss_event(tenant_id, {"type": "finding.refresh", "finding_id": finding_id, "reason": "grc_assessment_changed"})
        except Exception:
            pass
    return {"status": "saved", "id": state.id, "risk_score": risk_score}

@router.get("/tes-score")
def get_tes_score(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Compatibility route returning the safe AI-system risk presentation."""
    tenant_id = _verified_tenant_id(user)
    return _public_ai_system_risk(db, tenant_id)

@router.get("/controls")
def get_grc_controls(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return the ISO 42001 control definitions."""
    _verified_tenant_id(user)
    return [{
        "id": control.control_id,
        "framework_id": control.framework_id,
        "framework_version": control.framework_version,
        "control_id": control.control_id,
        "domain": control.domain,
        "requirement": control.requirement,
        "title": control.requirement,
        "sg_ref": ISO_42001_NAME,
        "description": control.description,
        "modifier_group": control.modifier_group,
        "display_order": control.display_order,
    } for control in framework_controls(db)]


@router.get("/assessments")
def list_control_assessments(
    q: str = "",
    status: str = "",
    modifier_group: str = "",
    page: int = 1,
    page_size: int = 25,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Canonical SOP assessment list used by both SOP Builder and Gap Analysis."""
    tenant_id = _verified_tenant_id(user)
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    query = q.strip().lower()
    wanted_status = status.strip().lower().replace(" ", "_")
    wanted_group = modifier_group.strip().upper()
    rows = []
    for control, assessment, label, completion in assessment_rows(db, tenant_id):
        normalized_status = label.lower().replace(" ", "_")
        searchable = " ".join((control.control_id, control.domain, control.requirement)).lower()
        if query and query not in searchable:
            continue
        if wanted_status and wanted_status != normalized_status:
            continue
        if wanted_group and wanted_group != control.modifier_group:
            continue
        rows.append({
            "framework_id": control.framework_id,
            "framework_version": control.framework_version,
            "control_id": control.control_id,
            "domain": control.domain,
            "requirement": control.requirement,
            "description": control.description,
            "modifier_group": control.modifier_group,
            "status": label,
            "pic": assessment.pic or "",
            "notes": assessment.notes or "",
            "end_user_agreed": bool(assessment.end_user_agreed),
            "pic_signed_off": bool(assessment.pic_signed_off),
            "evidence_count": db.query(ControlEvidence).filter(
                ControlEvidence.tenant_id == tenant_id,
                ControlEvidence.framework_id == ISO_42001_ID,
                ControlEvidence.control_id == control.control_id,
            ).count(),
            "updated_at": assessment.updated_at.isoformat() if assessment.updated_at else None,
        })
    total = len(rows)
    start = (page - 1) * page_size
    return {"framework": ISO_42001_NAME, "items": rows[start:start + page_size], "total": total, "page": page, "page_size": page_size}

@router.post("/signoff/{control_id}")
def record_signoff(
    control_id: str,
    req: SignoffRequest,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Record a PIC or end-user sign-off for an ISO 42001 control."""
    ctrl = next((c for c in GRC_CONTROLS if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    
    if req.signoff_type not in ("end_user", "pic"):
        raise HTTPException(status_code=400, detail="signoff_type must be 'end_user' or 'pic'")

    tenant_id = _verified_tenant_id(user)
    action = _sync_signoff_record(
        db=db,
        tenant_id=tenant_id,
        control_id=control_id,
        signoff_type=req.signoff_type,
        signed=req.signed,
        signed_by=user.get("sub", "unknown"),
        notes=req.notes,
    )
    assessment = next(row for control, row, _, _ in assessment_rows(db, tenant_id) if control.control_id == control_id)
    if req.signoff_type == "end_user":
        assessment.end_user_agreed = req.signed
    else:
        assessment.pic_signed_off = req.signed
    if assessment.status == "pending" and req.signed:
        assessment.status = "in_review"
    assessment.updated_by = user.get("sub", "unknown")
    recalculated = recalculate_open_sss_findings(db, tenant_id, user.get("sub", "unknown"))
    db.commit()
    
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="GRC_SIGNOFF",
        module="GRC",
        detail=f"ISO 42001 {control_id} ({ctrl['title']}): {req.signoff_type} sign-off {action}"
    ))
    
    for finding_id in recalculated:
        from routers.edip import _publish_sss_event
        _publish_sss_event(tenant_id, {"type": "finding.refresh", "finding_id": finding_id, "reason": "grc_signoff_changed"})
    return {"status": action, "control_id": control_id, "signoff_type": req.signoff_type}

@router.get("/gap-analysis")
def get_gap_analysis(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Return the read-only derived view of canonical SOP assessments."""
    tenant_id = _verified_tenant_id(user)
    results = []
    completed = 0
    in_review = 0
    pending = 0
    
    for ctrl, assessment, status, _ in assessment_rows(db, tenant_id):
        if status == "Completed":
            completed += 1
        elif status == "In Review":
            in_review += 1
        else:
            pending += 1
        
        results.append({
            "framework_id": ctrl.framework_id,
            "control_id": ctrl.control_id,
            "domain": ctrl.domain,
            "title": ctrl.requirement,
            "sg_ref": ISO_42001_NAME,
            "modifier_group": ctrl.modifier_group,
            "pic": assessment.pic or "",
            "status": status,
        })
    
    return {
        "controls": results,
        "summary": {
            "total": len(GRC_CONTROLS),
            "completed": completed,
            "in_review": in_review,
            "pending": pending,
            "completion_pct": round((completed / len(GRC_CONTROLS)) * 100),
        }
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ ISO 42001 AI System Inventory & Policy Status Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

AI_SYSTEMS = [
    {
        "id": "AI-SPEAK",
        "name": "SPEAK AI Security Assistant",
        "purpose": "Interactive chatbot for security posture Q&A, CVE lookup, TES interpretation",
        "ai_type": "Generative LLM (GPT-based via FreeLLMAPI)",
        "data_inputs": ["CISA KEV catalog", "TES scores", "TACF audit logs", "GRC state", "User queries"],
        "data_outputs": ["Natural language responses", "Security recommendations"],
        "risk_level": "Medium",
        "owner": "CSRO",
        "human_oversight": "Advisory only; no automated actions triggered by AI output",
        "pii_processed": False,
        "audit_logged": True,
        "fallback": "Regex-based mock response engine when LLM unavailable",
        "iso_controls": ["A.2.2", "A.6.2.2", "A.7.4", "A.9.2", "A.10.3"],
    },
    {
        "id": "AI-SPOTLIGHT",
        "name": "SPOTLIGHT Executive Report Generator",
        "purpose": "AI-generated board-level, CISO, compliance, and insurance risk narratives",
        "ai_type": "Generative LLM (GPT-based via FreeLLMAPI)",
        "data_inputs": ["TES scores", "CISA KEV findings", "TACF audit logs", "Module health status"],
        "data_outputs": ["Executive summary reports", "CISO technical briefs", "Compliance gap reports"],
        "risk_level": "Medium",
        "owner": "CSRO",
        "human_oversight": "Reports are generated on-demand and reviewed by humans before distribution",
        "pii_processed": False,
        "audit_logged": True,
        "fallback": "Template-based offline report generation",
        "iso_controls": ["A.2.2", "A.5.2", "A.6.2.2", "A.9.2", "A.10.3"],
    },
]

AI_RISK_REGISTER = [
    {"risk_id": "AIR-001", "category": "Prompt Injection", "description": "Adversarial input to manipulate AI output",
     "likelihood": "Medium", "impact": "High", "mitigation": "System prompt isolation, input sanitization, output review",
     "residual_risk": "Low", "controls": ["A.7.4", "A.9.2"]},
    {"risk_id": "AIR-002", "category": "Hallucination", "description": "AI generates inaccurate security recommendations",
     "likelihood": "Medium", "impact": "High", "mitigation": "RAG with real-time CISA KEV data, human oversight requirement",
     "residual_risk": "Medium", "controls": ["A.9.2", "A.7.4"]},
    {"risk_id": "AIR-003", "category": "Data Leakage", "description": "Sensitive data exposed through AI responses",
     "likelihood": "Low", "impact": "Critical", "mitigation": "No PII in AI context, system prompt restrictions, audit logging",
     "residual_risk": "Low", "controls": ["A.7.4", "A.2.2"]},
    {"risk_id": "AIR-004", "category": "Third-party Dependency", "description": "FreeLLMAPI outage or policy change",
     "likelihood": "Medium", "impact": "Medium", "mitigation": "Offline fallback engine, no training data shared",
     "residual_risk": "Low", "controls": ["A.10.3"]},
    {"risk_id": "AIR-005", "category": "Bias", "description": "AI produces biased vulnerability assessments",
     "likelihood": "Low", "impact": "Medium", "mitigation": "Documented data-quality controls and human review",
     "residual_risk": "Low", "controls": ["A.5.2", "A.7.4"]},
]


@router.get("/ai-inventory")
def get_ai_inventory(user=Depends(get_current_user)):
    """ISO 42001 A.6.2.2: Return the documented AI system inventory."""
    return {
        "ai_systems": AI_SYSTEMS,
        "total_systems": len(AI_SYSTEMS),
        "last_review": "2026-06-03",
        "next_review": "2026-09-03",
        "review_cycle": "Quarterly",
    }


@router.get("/ai-risk-register")
def get_ai_risk_register(user=Depends(get_current_user)):
    """ISO 42001 Clause 6.1.2: Return AI-specific risk register."""
    return {
        "risks": AI_RISK_REGISTER,
        "total_risks": len(AI_RISK_REGISTER),
        "high_residual": len([r for r in AI_RISK_REGISTER if r["residual_risk"] in ("High", "Critical")]),
        "last_assessment": "2026-06-03",
    }


@router.get("/ai-policy-status")
def get_ai_policy_status(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """ISO 42001 compliance dashboard: returns overall AI governance posture."""
    tenant_id = _verified_tenant_id(user)
    tes = _public_ai_system_risk(db, tenant_id)
    ai_controls = assessment_rows(db, tenant_id)
    ai_compliance = []
    for ctrl, assessment, status, _ in ai_controls:
        has_signoff = status == "Completed"
        ai_compliance.append({
            "control_id": ctrl.control_id,
            "domain": ctrl.domain,
            "title": ctrl.requirement,
            "signed_off": has_signoff,
            "status": "Implemented" if has_signoff else status,
        })

    implemented = len([c for c in ai_compliance if c["signed_off"]])
    total = len(ai_compliance)

    return {
        "policy_version": "1.0",
        "policy_date": "2026-06-03",
        "framework": "ISO/IEC 42001:2023",
        "jurisdiction": "Singapore (PDPA, MAS TRM, MAS FEAT, IMDA AI Gov v2)",
        "composite_tes": tes,
        "ai_systems_count": len(AI_SYSTEMS),
        "ai_risks_count": len(AI_RISK_REGISTER),
        "controls": ai_compliance,
        "compliance_summary": {
            "total_controls": total,
            "implemented": implemented,
            "in_progress": total - implemented,
            "completion_pct": round((implemented / total) * 100) if total > 0 else 0,
        },
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Policy Document Serving Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

import os
import re

POLICY_REGISTRY = {
    "iso42001": {
        "filename": "iso42001_ai_policy.md",
        "title": "ISO/IEC 42001:2023 - AI Management System Policy",
        "category": "AI Governance",
        "version": "1.0",
        "status": "Active",
        "owner": "CSRO",
        "review_cycle": "Annual",
    },
    "bug_bounty": {
        "filename": "bug_bounty_framework.md",
        "title": "Private Bug Bounty & Security Testing Framework",
        "category": "Security Operations",
        "version": "1.0",
        "status": "Active",
        "owner": "Security Engineering",
        "review_cycle": "Quarterly",
    },
    "air_gapped": {
        "filename": "air_gapped_readiness.md",
        "title": "Air-Gapped Deployment Readiness Guide",
        "category": "Infrastructure",
        "version": "1.0",
        "status": "Active",
        "owner": "DevOps / SRE",
        "review_cycle": "Semi-Annual",
    },
}


def _policy_docs_dir() -> Path:
    router_path = Path(__file__).resolve()
    candidates = [
        router_path.parents[2] / "docs",
        router_path.parents[1] / "docs",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _policy_path(meta: dict) -> Path:
    return _policy_docs_dir() / meta["filename"]


def _slugify_policy_id(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.strip().lower()).strip("-")
    return slug[:70] or f"policy-{uuid4().hex[:8]}"


def _policy_links(db: Session, tenant_id: str, policy_id: str) -> list[dict]:
    return [{"framework_id": row.framework_id, "control_id": row.control_id, "relation_type": row.relation_type}
            for row in db.query(PolicyControlLink).filter(
                PolicyControlLink.tenant_id == tenant_id,
                PolicyControlLink.policy_id == policy_id,
            ).order_by(PolicyControlLink.framework_id, PolicyControlLink.control_id).all()]


def _replace_policy_links(
    db: Session, tenant_id: str, policy_id: str, framework_id: str | None,
    control_ids: list[str], unmapped: bool, actor: str,
) -> None:
    if control_ids:
        if framework_id != ISO_42001_ID:
            raise HTTPException(status_code=422, detail="Policies may link only to ISO/IEC 42001:2023 controls")
        valid = {control.control_id for control in framework_controls(db)}
        invalid = sorted(set(control_ids) - valid)
        if invalid:
            raise HTTPException(status_code=422, detail=f"Unknown framework controls: {', '.join(invalid)}")
    elif not unmapped:
        raise HTTPException(status_code=422, detail="Select one or more controls or explicitly mark the policy unmapped")
    db.query(PolicyControlLink).filter(
        PolicyControlLink.tenant_id == tenant_id,
        PolicyControlLink.policy_id == policy_id,
    ).delete(synchronize_session=False)
    for control_id in sorted(set(control_ids)):
        db.add(PolicyControlLink(
            tenant_id=tenant_id, policy_id=policy_id, framework_id=framework_id,
            control_id=control_id, relation_type="supporting_evidence", created_by=actor,
        ))


def _policy_row_to_dict(row: GrcPolicyDocument, db: Session | None = None) -> dict:
    links = _policy_links(db, row.tenant_id, row.id) if db is not None else []
    return {
        "id": row.id,
        "title": row.title,
        "category": row.category,
        "version": row.version,
        "status": row.status,
        "owner": row.owner,
        "review_cycle": row.review_cycle,
        "available": True,
        "source": "custom",
        "archived": row.archived_at is not None,
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,
        "supersedes_id": row.supersedes_id,
        "superseded_by_id": row.superseded_by_id,
        "size_bytes": len((row.content or "").encode("utf-8")),
        "framework_id": links[0]["framework_id"] if links else None,
        "linked_controls": links,
        "unmapped": not links,
        "scoring_effect": "None directly — supporting evidence only",
    }


@router.get("/policies")
def list_policies(
    q: str = "", framework_id: str = "", control_id: str = "", source: str = "",
    lifecycle: str = "", page: int = 1, page_size: int = 25,
    db: Session = Depends(get_db), user=Depends(get_current_user),
):
    """List all available policy documents with metadata."""
    tenant_id = _verified_tenant_id(user)
    policies = []
    for key, meta in POLICY_REGISTRY.items():
        filepath = _policy_path(meta)
        exists = filepath.exists()
        size = filepath.stat().st_size if exists else 0
        links = _policy_links(db, tenant_id, key)
        policies.append({
            "id": key,
            "title": meta["title"],
            "category": meta["category"],
            "version": meta["version"],
            "status": meta["status"],
            "owner": meta["owner"],
            "review_cycle": meta["review_cycle"],
            "available": exists,
            "source": "bundled",
            "size_bytes": size,
            "framework_id": links[0]["framework_id"] if links else None,
            "linked_controls": links,
            "unmapped": not links,
            "scoring_effect": "None directly — supporting evidence only",
        })
    custom_rows = (
        db.query(GrcPolicyDocument)
        .filter(GrcPolicyDocument.tenant_id == tenant_id)
        .order_by(GrcPolicyDocument.created_at.desc())
        .all()
    )
    policies.extend(_policy_row_to_dict(row, db) for row in custom_rows)
    q = q.strip().lower()
    source = source.strip().lower()
    lifecycle = lifecycle.strip().lower()
    control_id = control_id.strip()
    framework_id = framework_id.strip()
    policies = [item for item in policies if (
        (not q or q in item["title"].lower())
        and (not source or item["source"] == source)
        and (not framework_id or item.get("framework_id") == framework_id)
        and (not control_id or any(link["control_id"] == control_id for link in item["linked_controls"]))
        and (not lifecycle or ("archived" if item.get("archived") else "active") == lifecycle)
    )]
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    total = len(policies)
    start = (page - 1) * page_size
    return {"policies": policies[start:start + page_size], "total": total, "page": page, "page_size": page_size}


class PolicyCreate(BaseModel):
    title: str
    category: str = "Custom"
    version: str = "1.0"
    status: str = "Active"
    owner: str = "CSRO"
    review_cycle: str = "Annual"
    content: str = ""
    framework_id: str | None = None
    control_ids: list[str] = Field(default_factory=list)
    # The caller must deliberately choose an unmapped supporting document when
    # it does not link to an ISO control.
    unmapped: bool


class PolicyArchiveRequest(BaseModel):
    archived: bool = True


class PolicySupersedeRequest(BaseModel):
    version: str
    content: str
    title: str | None = None


class PolicyControlLinksUpdate(BaseModel):
    framework_id: str | None = None
    control_ids: list[str] = Field(default_factory=list)
    unmapped: bool = False


@router.post("/policies")
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin"))):
    """Create a custom policy document in the GRC library."""
    tenant_id = _verified_tenant_id(user)
    title = payload.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Policy title is required")
    if len(payload.content) > MAX_POLICY_SIZE:
        raise HTTPException(status_code=400, detail=f"Policy content too large. Maximum {MAX_POLICY_SIZE // 1024}KB.")

    base_id = _slugify_policy_id(title)
    policy_id = base_id
    i = 2
    while POLICY_REGISTRY.get(policy_id) or db.query(GrcPolicyDocument).filter(GrcPolicyDocument.id == policy_id).first():
        policy_id = f"{base_id[:64]}-{i}"
        i += 1

    row = GrcPolicyDocument(
        id=policy_id,
        tenant_id=tenant_id,
        title=title,
        category=payload.category.strip() or "Custom",
        version=payload.version.strip() or "1.0",
        status=payload.status.strip() or "Active",
        owner=payload.owner.strip() or "CSRO",
        review_cycle=payload.review_cycle.strip() or "Annual",
        content=payload.content or f"# {title}\n\n",
        created_by=user.get("sub", "unknown"),
    )
    db.add(row)
    db.flush()
    _replace_policy_links(
        db, tenant_id, row.id, payload.framework_id, payload.control_ids,
        payload.unmapped, user.get("sub", "unknown"),
    )
    record_operational_event(
        db, tenant_id=tenant_id, event_type="policy.created",
        resource_type="grc_policy", resource_id=row.id, source_module="GRC",
        actor_id=user.get("sub", "unknown"), metadata={"version": row.version},
    )
    db.commit()
    db.refresh(row)

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="POLICY_CREATED",
        module="GRC",
        detail=f"Created custom policy document: {row.title}"
    ))
    return _policy_row_to_dict(row, db)


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Serve a policy document's markdown content."""
    tenant_id = _verified_tenant_id(user)
    meta = POLICY_REGISTRY.get(policy_id)
    if not meta:
        row = db.query(GrcPolicyDocument).filter(
            GrcPolicyDocument.id == policy_id,
            GrcPolicyDocument.tenant_id == tenant_id,
        ).first()
        if not row:
            raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found")
        append_to_audit_log(AuditEntry(
            user=user.get("sub", "unknown"),
            action="POLICY_VIEWED",
            module="GRC",
            detail=f"Viewed custom policy: {row.title}"
        ))
        data = _policy_row_to_dict(row, db)
        data["content"] = row.content
        return data

    filepath = _policy_path(meta)

    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Policy file not found on server")

    content = filepath.read_text(encoding='utf-8')

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="POLICY_VIEWED",
        module="GRC",
        detail=f"Viewed policy: {meta['title']}"
    ))

    links = _policy_links(db, tenant_id, policy_id)
    return {
        "id": policy_id,
        "title": meta["title"],
        "category": meta["category"],
        "version": meta["version"],
        "status": meta["status"],
        "owner": meta["owner"],
        "content": content,
        "framework_id": links[0]["framework_id"] if links else None,
        "linked_controls": links,
        "unmapped": not links,
        "scoring_effect": "None directly — supporting evidence only",
    }


MAX_POLICY_SIZE = 200 * 1024  # C-04: 200KB limit for policy content

class PolicyUpdate(BaseModel):
    content: str


@router.put("/policies/{policy_id}")
def update_policy(policy_id: str, payload: PolicyUpdate, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin"))):
    """Update a policy document's content."""
    tenant_id = _verified_tenant_id(user)
    meta = POLICY_REGISTRY.get(policy_id)
    if meta:
        raise HTTPException(
            status_code=409,
            detail='Bundled policies are read-only; create a tenant policy to customize content',
        )
    if not meta:
        row = db.query(GrcPolicyDocument).filter(
            GrcPolicyDocument.id == policy_id,
            GrcPolicyDocument.tenant_id == tenant_id,
        ).first()
        if not row:
            raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found")
        if len(payload.content) > MAX_POLICY_SIZE:
            raise HTTPException(status_code=400, detail=f"Policy content too large. Maximum {MAX_POLICY_SIZE // 1024}KB.")
        row.content = payload.content
        db.commit()
        append_to_audit_log(AuditEntry(
            user=user.get("sub", "unknown"),
            action="POLICY_UPDATED",
            module="GRC",
            detail=f"Updated custom policy document: {row.title}"
        ))
        return {"message": "Policy updated successfully"}

    # C-04: Enforce content size limit
    if len(payload.content) > MAX_POLICY_SIZE:
        raise HTTPException(status_code=400, detail=f"Policy content too large. Maximum {MAX_POLICY_SIZE // 1024}KB.")

    filepath = _policy_path(meta)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    filepath.write_text(payload.content, encoding='utf-8')

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="POLICY_UPDATED",
        module="GRC",
        detail=f"Updated policy document: {meta['title']}"
    ))

    return {"message": "Policy updated successfully"}


@router.put("/policies/{policy_id}/links")
def update_policy_links(
    policy_id: str,
    payload: PolicyControlLinksUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin")),
):
    tenant_id = _verified_tenant_id(user)
    if policy_id not in POLICY_REGISTRY:
        _custom_policy_or_404(db, tenant_id, policy_id)
    _replace_policy_links(
        db, tenant_id, policy_id, payload.framework_id, payload.control_ids,
        payload.unmapped, user.get("sub", "unknown"),
    )
    db.commit()
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"), action="POLICY_CONTROL_LINKS_UPDATED", module="GRC",
        detail=f"Updated explicit control links for policy {policy_id}",
    ))
    return {"policy_id": policy_id, "linked_controls": _policy_links(db, tenant_id, policy_id), "scoring_effect": "None directly — supporting evidence only"}


def _custom_policy_or_404(db: Session, tenant_id: str, policy_id: str) -> GrcPolicyDocument:
    if policy_id in POLICY_REGISTRY:
        raise HTTPException(status_code=409, detail="Bundled policies are immutable and cannot be deleted")
    row = db.query(GrcPolicyDocument).filter(
        GrcPolicyDocument.id == policy_id,
        GrcPolicyDocument.tenant_id == tenant_id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return row


def _policy_is_referenced(db: Session, row: GrcPolicyDocument) -> bool:
    if db.query(PolicyControlLink).filter(
        PolicyControlLink.tenant_id == row.tenant_id,
        PolicyControlLink.policy_id == row.id,
    ).first():
        return True
    if db.query(GrcPolicyDocument).filter(
        GrcPolicyDocument.tenant_id == row.tenant_id,
        GrcPolicyDocument.id != row.id,
        ((GrcPolicyDocument.supersedes_id == row.id) | (GrcPolicyDocument.superseded_by_id == row.id)),
    ).first():
        return True
    reports = db.query(GeneratedReport).filter(GeneratedReport.tenant_id == row.tenant_id).all()
    return any(row.id in json.dumps(report.framework_configuration or {}, sort_keys=True) for report in reports)


@router.patch("/policies/{policy_id}/archive")
def set_policy_archive(
    policy_id: str,
    payload: PolicyArchiveRequest,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin")),
):
    tenant_id = _verified_tenant_id(user)
    row = _custom_policy_or_404(db, tenant_id, policy_id)
    actor = user.get("sub", "unknown")
    row.archived_at = datetime.now(timezone.utc) if payload.archived else None
    row.archived_by = actor if payload.archived else None
    row.status = "Archived" if payload.archived else "Active"
    event_type = "policy.archived" if payload.archived else "policy.restored"
    record_operational_event(
        db, tenant_id=tenant_id, event_type=event_type,
        resource_type="grc_policy", resource_id=row.id, source_module="GRC", actor_id=actor,
    )
    db.commit()
    append_to_audit_log(AuditEntry(
        user=actor, action="POLICY_ARCHIVED" if payload.archived else "POLICY_RESTORED",
        module="GRC", detail=f"{'Archived' if payload.archived else 'Restored'} custom policy {row.id}",
    ))
    return _policy_row_to_dict(row, db)


@router.post("/policies/{policy_id}/supersede")
def supersede_policy(
    policy_id: str,
    payload: PolicySupersedeRequest,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin")),
):
    tenant_id = _verified_tenant_id(user)
    old = _custom_policy_or_404(db, tenant_id, policy_id)
    if old.superseded_by_id:
        raise HTTPException(status_code=409, detail="Policy has already been superseded")
    if not payload.version.strip() or len(payload.content) > MAX_POLICY_SIZE:
        raise HTTPException(status_code=422, detail="A version and valid policy content are required")
    new_id = f"{old.id[:60]}-v-{uuid4().hex[:8]}"
    actor = user.get("sub", "unknown")
    new = GrcPolicyDocument(
        id=new_id, tenant_id=tenant_id, title=(payload.title or old.title).strip(),
        category=old.category, version=payload.version.strip(), status="Active",
        owner=old.owner, review_cycle=old.review_cycle, content=payload.content,
        created_by=actor, supersedes_id=old.id,
    )
    old.status = "Superseded"
    old.superseded_by_id = new.id
    old.archived_at = datetime.now(timezone.utc)
    old.archived_by = actor
    db.add(new)
    db.flush()
    for link in _policy_links(db, tenant_id, old.id):
        db.add(PolicyControlLink(
            tenant_id=tenant_id, policy_id=new.id, framework_id=link["framework_id"],
            control_id=link["control_id"], relation_type=link["relation_type"], created_by=actor,
        ))
    record_operational_event(
        db, tenant_id=tenant_id, event_type="policy.superseded",
        resource_type="grc_policy", resource_id=old.id, source_module="GRC", actor_id=actor,
        metadata={"replacement_policy_id": new.id, "version": new.version},
    )
    db.commit()
    append_to_audit_log(AuditEntry(
        user=actor, action="POLICY_SUPERSEDED", module="GRC",
        detail=f"Superseded custom policy {old.id} with {new.id}",
    ))
    return {"superseded": _policy_row_to_dict(old, db), "replacement": _policy_row_to_dict(new, db)}


@router.delete("/policies/{policy_id}")
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin")),
):
    tenant_id = _verified_tenant_id(user)
    row = _custom_policy_or_404(db, tenant_id, policy_id)
    actor = user.get("sub", "unknown")
    if _policy_is_referenced(db, row):
        row.archived_at = datetime.now(timezone.utc)
        row.archived_by = actor
        row.status = "Archived"
        record_operational_event(
            db, tenant_id=tenant_id, event_type="policy.archived",
            resource_type="grc_policy", resource_id=row.id, source_module="GRC", actor_id=actor,
            metadata={"reason": "referenced_policy_delete_requested"},
        )
        db.commit()
        append_to_audit_log(AuditEntry(
            user=actor, action="POLICY_ARCHIVED", module="GRC",
            detail=f"Archived referenced custom policy {row.id}; hard deletion was prevented",
        ))
        return {"status": "archived", "reason": "Policy is referenced and cannot be hard-deleted"}
    deleted_id = row.id
    record_operational_event(
        db, tenant_id=tenant_id, event_type="policy.deleted",
        resource_type="grc_policy", resource_id=row.id, source_module="GRC", actor_id=actor,
    )
    db.delete(row)
    db.commit()
    append_to_audit_log(AuditEntry(
        user=actor, action="POLICY_DELETED", module="GRC",
        detail=f"Deleted unreferenced custom policy {deleted_id}",
    ))
    return {"status": "deleted", "policy_id": deleted_id}


# Ã¢â€â‚¬Ã¢â€â‚¬ Evidence Upload / Download / Delete Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

ALLOWED_EVIDENCE_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".md"}
MAX_EVIDENCE_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/evidence/{control_id}")
async def upload_evidence(
    control_id: str,
    target_tenant_id: Optional[str] = None,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Upload a file as evidence for an ISO 42001 control."""
    import os, traceback
    from uuid import uuid4

    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # Validate control exists
    ctrl = next((c for c in GRC_CONTROLS if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")

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

    try:
        raw_name = file.filename or "untitled"
        clean_name = sanitize_filename(raw_name)
        ext = os.path.splitext(clean_name)[1].lower()
        if ext not in ALLOWED_EVIDENCE_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"File type '{ext}' not allowed. Accepted: {', '.join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))}",
            )

        content = await file.read()
        if len(content) > MAX_EVIDENCE_SIZE:
            raise HTTPException(status_code=400, detail="File exceeds maximum size of 10 MB")

        root_dir = get_evidence_storage_root()
        save_dir = os.path.join(root_dir, "ISO42001", control_id)
        
        if os.path.islink(save_dir):
            raise HTTPException(status_code=400, detail="Symlinks not allowed in storage directory path")
            
        os.makedirs(save_dir, exist_ok=True)
        
        resolved_save_dir = os.path.realpath(save_dir)
        try:
            Path(resolved_save_dir).relative_to(Path(root_dir))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid destination path")

        unique_name = f"{uuid4().hex}{ext}"
        save_path = os.path.join(save_dir, unique_name)
        validate_storage_path(save_path, strict=False)

        with open(save_path, "wb") as f:
            f.write(content)

        evidence = ControlEvidence(
            tenant_id=assigned_tenant_id,
            framework_id="ISO42001",
            control_id=control_id,
            filename=clean_name,
            file_path=save_path,
            uploaded_by=auth_ctx.user_id,
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        log_evidence_action(
            auth_ctx, evidence.id, "EVIDENCE_UPLOADED", "GRC",
            "success", "authorized", assigned_tenant_id
        )

        return {
            "id": evidence.id,
            "control_id": evidence.control_id,
            "framework_id": evidence.framework_id,
            "filename": evidence.filename,
            "uploaded_by": evidence.uploaded_by,
            "uploaded_at": evidence.uploaded_at.isoformat() if evidence.uploaded_at else None,
        }
    except HTTPException:
        raise
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail='Evidence upload failed')


@router.get("/evidence/{control_id}")
def list_evidence(
    control_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """List all evidence files for a given control."""
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    if auth_ctx.role not in ("Superadmin", "Admin", "Analyst"):
        raise HTTPException(status_code=403, detail="Permission denied")

    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        framework_id="ISO42001",
        control_id=control_id,
        required_permission=EvidencePermission.LIST
    )
    records = query.order_by(ControlEvidence.uploaded_at.desc()).all()
    results = []
    for rec in records:
        file_size = None
        if rec.file_path and os.path.exists(rec.file_path):
            file_size = os.path.getsize(rec.file_path)
        results.append({
            "id": rec.id,
            "control_id": rec.control_id,
            "framework_id": rec.framework_id,
            "filename": rec.filename,
            "uploaded_by": rec.uploaded_by,
            "uploaded_at": rec.uploaded_at.isoformat() if rec.uploaded_at else None,
            "file_size": file_size,
        })
    return {"evidence": results, "total": len(results)}


@router.get("/evidence/{control_id}/{evidence_id}/download")
def download_evidence(
    control_id: str,
    evidence_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Download an evidence file."""
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        evidence_id=evidence_id,
        framework_id="ISO42001",
        control_id=control_id,
        required_permission=EvidencePermission.DOWNLOAD
    )
    record = query.first()

    if not record:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD_DENIED", "GRC",
            "denied", "not_found_or_out_of_scope"
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    if not record.file_path or not os.path.exists(record.file_path):
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD_DENIED", "GRC",
            "denied", "file_not_found", record.tenant_id
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    validate_storage_path(record.file_path)

    if auth_ctx.is_superadmin:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD", "GRC",
            "success", "superadmin_bypass", record.tenant_id
        )
    else:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DOWNLOAD", "GRC",
            "success", "authorized", record.tenant_id
        )

    clean_filename = sanitize_filename(record.filename)
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
        "Content-Length": str(os.path.getsize(record.file_path))
    }
    return FileResponse(
        path=record.file_path,
        media_type="application/octet-stream",
        headers=headers
    )


@router.get("/evidence/{control_id}/{evidence_id}/preview")
def preview_evidence(
    control_id: str,
    evidence_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        evidence_id=evidence_id,
        framework_id="ISO42001",
        control_id=control_id,
        required_permission=EvidencePermission.PREVIEW
    )
    record = query.first()

    if not record:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW_DENIED", "GRC",
            "denied", "not_found_or_out_of_scope"
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    if not record.file_path or not os.path.exists(record.file_path):
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW_DENIED", "GRC",
            "denied", "file_not_found", record.tenant_id
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    validate_storage_path(record.file_path)

    if auth_ctx.is_superadmin:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW", "GRC",
            "success", "superadmin_bypass", record.tenant_id
        )
    else:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_PREVIEW", "GRC",
            "success", "authorized", record.tenant_id
        )

    clean_filename = sanitize_filename(record.filename)
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
        "Content-Length": str(os.path.getsize(record.file_path))
    }
    return FileResponse(
        path=record.file_path,
        media_type=media_type,
        headers=headers
    )


@router.delete("/evidence/{control_id}/{evidence_id}")
def delete_evidence(
    control_id: str,
    evidence_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Delete an evidence record and its file from disk. Requires Superadmin or Admin."""
    if ".." in control_id or "/" in control_id or "\\" in control_id:
        raise HTTPException(status_code=404, detail="Evidence not found")

    auth_ctx = get_auth_context(user)
    query = scoped_evidence_query(
        db,
        user=auth_ctx,
        evidence_id=evidence_id,
        framework_id="ISO42001",
        control_id=control_id,
        required_permission=EvidencePermission.DELETE
    )
    record = query.first()

    if not record:
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DELETE_DENIED", "GRC",
            "denied", "not_found_or_out_of_scope"
        )
        raise HTTPException(status_code=404, detail="Evidence not found")

    file_path = record.file_path
    if file_path:
        validate_storage_path(file_path)

    tenant_id = record.tenant_id

    # 1. Initiated log
    log_evidence_action(
        auth_ctx, evidence_id, "EVIDENCE_DELETE_REQUESTED", "GRC",
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
                auth_ctx, evidence_id, "EVIDENCE_DELETE_FAILED", "GRC",
                "error", f"filesystem_quarantine_failed: {str(e)}", tenant_id
            )
            raise HTTPException(status_code=500, detail="Evidence deletion failed: filesystem error")

    filename = record.filename

    # 3. Database deletion and transaction commit
    try:
        db.delete(record)
        db.commit()
    except Exception as e:
        db.rollback()
        log_evidence_action(
            auth_ctx, evidence_id, "EVIDENCE_DELETE_FAILED", "GRC",
            "error", f"database_transaction_failed: {str(e)}", tenant_id
        )
        if moved_to_quarantine:
            try:
                os.replace(quarantine_path, file_path)
                log_evidence_action(
                    auth_ctx, evidence_id, "EVIDENCE_DELETE_RECOVERED", "GRC",
                    "success", "restored_from_quarantine", tenant_id
                )
            except Exception as re:
                log_evidence_action(
                    auth_ctx, evidence_id, "EVIDENCE_DELETE_RECOVERY_FAILED", "GRC",
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
        auth_ctx, evidence_id, "EVIDENCE_DELETED", "GRC",
        "success", "authorized", tenant_id
    )

    return {"status": "deleted", "evidence_id": evidence_id, "control_id": control_id}
