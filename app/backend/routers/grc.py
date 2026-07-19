"""
GRC Router - ISO/IEC 42001:2023 AI Management System
Handles GRC state persistence, TES composite scoring, and SOP sign-offs.

References:
  - ISO/IEC 42001:2023 Clauses 6.1.2, 6.1.4, 9.2, 10.2
  - Annex A.2.2, A.3.2, A.5.2, A.6.2.2, A.7.4, A.9.2, A.10.3
  - Singapore alignment: PDPA, MAS TRM, MAS FEAT, IMDA AI Governance Framework v2
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session
from pathlib import Path
from typing import Optional
from uuid import uuid4
from services.database import get_db
from models import GrcState, GrcSignoff, GrcPolicyDocument, ControlEvidence
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role, get_auth_context, scoped_evidence_query, EvidencePermission
import os
import re
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



router = APIRouter()


def _verified_tenant_id(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    return tenant_id

# Ã¢â€â‚¬Ã¢â€â‚¬ ISO 42001 Control definitions Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

GRC_CONTROLS = [
    {"id": "A.2.2", "domain": "AI Policy", "title": "Document AI Policy for Development / Use",
     "sg_ref": "PDPA / MAS FEAT Principles", "tes_modifier": "AGM"},
    {"id": "A.3.2", "domain": "Internal Org", "title": "Define & Allocate AI Roles and Responsibilities",
     "sg_ref": "MAS TRM Guidelines Section 4", "tes_modifier": "AGM"},
    {"id": "A.5.2", "domain": "Impact Assessment", "title": "Establish AI System Impact Assessment Process",
     "sg_ref": "PDPA DPIA / MAS FEAT", "tes_modifier": "AGM"},
    {"id": "A.6.2.2", "domain": "AI Lifecycle", "title": "Specify & Document AI System Requirements",
     "sg_ref": "IMDA AI Governance Framework v2", "tes_modifier": "AGM"},
    {"id": "A.7.4", "domain": "Data Quality", "title": "Define Data Quality Requirements for AI Systems",
     "sg_ref": "MAS Notice 655 / ISO/IEC 25024", "tes_modifier": "DRF"},
    {"id": "A.9.2", "domain": "Responsible Use", "title": "Define Processes for Responsible AI Use",
     "sg_ref": "IMDA Model AI Governance Framework", "tes_modifier": "AGM"},
    {"id": "A.10.3", "domain": "Third-party", "title": "Ensure Supplier AI Alignment with Org Policy",
     "sg_ref": "MAS TRM Guidelines Section 9", "tes_modifier": "TEF"},
]

# Default toggle states
DEFAULT_TOGGLES = {
    "agm": [True, False, True, False, False],
    "drf": [True, False, True],
    "tef": [True, False],
}


TOGGLE_GROUP_LENGTHS = {"agm": 5, "drf": 3, "tef": 2}


def _normalize_toggles(toggles) -> dict:
    """Return the complete, typed toggle contract for legacy or malformed rows."""
    source = toggles if isinstance(toggles, dict) else {}
    normalized = {}
    for key, default_values in DEFAULT_TOGGLES.items():
        values = source.get(key)
        if (
            isinstance(values, list)
            and len(values) == TOGGLE_GROUP_LENGTHS[key]
            and all(isinstance(value, bool) for value in values)
        ):
            normalized[key] = list(values)
        else:
            normalized[key] = list(default_values)
    return normalized


DEFAULT_SOP_STATE = [
    {"id": c["id"], "pic": "", "notes": "", "endUserAgreed": False, "picAgreed": False}
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
    base_state = _latest_sop_state_from_db(db, tenant_id)
    signoff_state = _signoff_state_from_db(db, tenant_id)
    merged = []
    for entry in base_state:
        control_signoffs = signoff_state.get(entry["id"], set())
        merged.append({
            **entry,
            "endUserAgreed": "end_user" in control_signoffs,
            "picAgreed": "pic" in control_signoffs,
        })
    return merged


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


def _calc_agm(toggles: dict) -> float:
    agm_list = toggles.get("agm", [True, False, True, False, False])
    ratio = sum(1 for x in agm_list if x) / max(len(agm_list), 1)
    return round(1.5 - 0.5 * ratio, 3)


def _calc_drf(toggles: dict) -> float:
    drf_list = toggles.get("drf", [True, False, True])
    pts = 0
    if len(drf_list) > 0 and not drf_list[0]:
        pts += 1
    if len(drf_list) > 1 and not drf_list[1]:
        pts += 1
    if len(drf_list) > 2 and drf_list[2]:  # bias exists = risk
        pts += 1
    return round(1.0 + pts * 0.1, 3)


def _calc_tef(toggles: dict) -> float:
    tef_list = toggles.get("tef", [True, False])
    p = tef_list[0] if len(tef_list) > 0 else True
    a = tef_list[1] if len(tef_list) > 1 else False
    if p and a:
        return 1.0
    if p or a:
        return 1.1
    return 1.2


def _calc_composite_tes(toggles: dict) -> dict:
    toggles = _normalize_toggles(toggles)
    agm = _calc_agm(toggles)
    drf = _calc_drf(toggles)
    tef = _calc_tef(toggles)
    base = round(BASE_VULN * BASE_EXPOSURE * BASE_LIKELIHOOD, 3)
    final = round(base * agm * drf * tef, 3)
    
    if final >= 7:
        band = "CRITICAL"
        sla = "24 hours"
    elif final >= 5:
        band = "HIGH"
        sla = "72 hours"
    elif final >= 3:
        band = "MEDIUM"
        sla = "7 days"
    else:
        band = "LOW"
        sla = "30 days"
    
    return {
        "score": final,
        "band": band,
        "sla": sla,
        "base": base,
        "agm": agm,
        "drf": drf,
        "tef": tef,
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Request Models Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

class GrcStateRequest(BaseModel):
    toggles: dict
    sop_state: list[dict]

class SignoffRequest(BaseModel):
    signoff_type: str  # 'end_user' or 'pic'
    signed: bool = True
    notes: Optional[str] = None

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
            "toggles": _normalize_toggles(state.toggles),
            "sop_state": sop_state,
            "updated_by": state.updated_by,
            "updated_at": state.updated_at.isoformat() if state.updated_at else None,
        }
    return {
        "toggles": _normalize_toggles(None),
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
    """Save GRC toggles + SOP state. Logged in audit trail.
    
    Server-side validation: toggles must have correct structure and boolean values.
    TES is always recalculated server-side to prevent score manipulation.
    """
    # Ã¢â€â‚¬Ã¢â€â‚¬ Validate toggle structure Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    tenant_id = _verified_tenant_id(user)
    toggles = req.toggles
    EXPECTED_LENGTHS = {"agm": 5, "drf": 3, "tef": 2}
    
    for key, expected_len in EXPECTED_LENGTHS.items():
        arr = toggles.get(key)
        if arr is None:
            raise HTTPException(status_code=400, detail=f"Missing toggle group: {key}")
        if not isinstance(arr, list):
            raise HTTPException(status_code=400, detail=f"Toggle group '{key}' must be an array")
        if len(arr) != expected_len:
            raise HTTPException(status_code=400, detail=f"Toggle group '{key}' must have exactly {expected_len} items, got {len(arr)}")
        if not all(isinstance(v, bool) for v in arr):
            raise HTTPException(status_code=400, detail=f"All values in toggle group '{key}' must be boolean")
    
    # Sanitize: only keep known keys
    validated_toggles = {k: toggles[k] for k in EXPECTED_LENGTHS}
    validated_sop_state = _normalize_sop_state(req.sop_state)

    _sync_signoffs_from_sop_state(
        db=db,
        tenant_id=tenant_id,
        sop_state=validated_sop_state,
        signed_by=user.get("sub", "unknown"),
    )
    
    state = GrcState(
        tenant_id=tenant_id,
        toggles=validated_toggles,
        sop_state=validated_sop_state,
        updated_by=user.get("sub", "unknown"),
    )
    db.add(state)
    db.commit()
    db.refresh(state)
    
    # Calculate TES server-side from validated toggles
    tes = _calc_composite_tes(validated_toggles)
    
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="GRC_STATE_UPDATED",
        module="GRC",
        detail=f"GRC state saved. Composite TES: {tes['score']} ({tes['band']}). AGM={tes['agm']} DRF={tes['drf']} TEF={tes['tef']}"
    ))
    
    return {"status": "saved", "id": state.id, "tes": tes}

@router.get("/tes-score")
def get_tes_score(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Calculate composite TES from saved toggles."""
    tenant_id = _verified_tenant_id(user)
    state = (
        db.query(GrcState)
        .filter(GrcState.tenant_id == tenant_id)
        .order_by(GrcState.id.desc())
        .first()
    )
    toggles = _normalize_toggles(state.toggles if state else None)
    return _calc_composite_tes(toggles)

@router.get("/controls")
def get_grc_controls(user = Depends(get_current_user)):
    """Return the ISO 42001 control definitions."""
    return GRC_CONTROLS

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
    db.commit()
    
    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="GRC_SIGNOFF",
        module="GRC",
        detail=f"ISO 42001 {control_id} ({ctrl['title']}): {req.signoff_type} sign-off {action}"
    ))
    
    return {"status": action, "control_id": control_id, "signoff_type": req.signoff_type}

@router.get("/gap-analysis")
def get_gap_analysis(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Return gap analysis derived from SOP state."""
    sop_state = _effective_sop_state(db, _verified_tenant_id(user))
    
    results = []
    completed = 0
    in_review = 0
    pending = 0
    
    for i, ctrl in enumerate(GRC_CONTROLS):
        s = sop_state[i] if i < len(sop_state) else {"endUserAgreed": False, "picAgreed": False, "pic": ""}
        if s.get("endUserAgreed") and s.get("picAgreed"):
            status = "Completed"
            completed += 1
        elif s.get("endUserAgreed") or s.get("picAgreed"):
            status = "In Review"
            in_review += 1
        else:
            status = "Pending"
            pending += 1
        
        results.append({
            "control_id": ctrl["id"],
            "domain": ctrl["domain"],
            "title": ctrl["title"],
            "sg_ref": ctrl["sg_ref"],
            "tes_modifier": ctrl["tes_modifier"],
            "pic": s.get("pic", ""),
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
     "likelihood": "Low", "impact": "Medium", "mitigation": "CISA KEV data is objective/factual, DRF modifier tracks bias",
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
    # Get current GRC state for toggle-based scoring
    tenant_id = _verified_tenant_id(user)
    state = (
        db.query(GrcState)
        .filter(GrcState.tenant_id == tenant_id)
        .order_by(GrcState.id.desc())
        .first()
    )
    toggles = _normalize_toggles(state.toggles if state else None)
    tes = _calc_composite_tes(toggles)

    # Get signoff progress
    signoff_state = _signoff_state_from_db(db, tenant_id)

    ai_controls = [c for c in GRC_CONTROLS]
    ai_compliance = []
    for ctrl in ai_controls:
        control_signoffs = signoff_state.get(ctrl["id"], set())
        has_signoff = "end_user" in control_signoffs and "pic" in control_signoffs
        ai_compliance.append({
            "control_id": ctrl["id"],
            "domain": ctrl["domain"],
            "title": ctrl["title"],
            "sg_ref": ctrl["sg_ref"],
            "signed_off": has_signoff,
            "status": "Implemented" if has_signoff else "In Progress",
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


def _policy_row_to_dict(row: GrcPolicyDocument) -> dict:
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
        "size_bytes": len((row.content or "").encode("utf-8")),
    }


@router.get("/policies")
def list_policies(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """List all available policy documents with metadata."""
    tenant_id = _verified_tenant_id(user)
    policies = []
    for key, meta in POLICY_REGISTRY.items():
        filepath = _policy_path(meta)
        exists = filepath.exists()
        size = filepath.stat().st_size if exists else 0
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
        })
    custom_rows = (
        db.query(GrcPolicyDocument)
        .filter(GrcPolicyDocument.tenant_id == tenant_id)
        .order_by(GrcPolicyDocument.created_at.desc())
        .all()
    )
    policies.extend(_policy_row_to_dict(row) for row in custom_rows)
    return {"policies": policies, "total": len(policies)}


class PolicyCreate(BaseModel):
    title: str
    category: str = "Custom"
    version: str = "1.0"
    status: str = "Active"
    owner: str = "CSRO"
    review_cycle: str = "Annual"
    content: str = ""


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
    db.commit()
    db.refresh(row)

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="POLICY_CREATED",
        module="GRC",
        detail=f"Created custom policy document: {row.title}"
    ))
    return _policy_row_to_dict(row)


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
        data = _policy_row_to_dict(row)
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

    return {
        "id": policy_id,
        "title": meta["title"],
        "category": meta["category"],
        "version": meta["version"],
        "status": meta["status"],
        "owner": meta["owner"],
        "content": content,
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
