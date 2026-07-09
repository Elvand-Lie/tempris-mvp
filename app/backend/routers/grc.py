"""
GRC Router — ISO/IEC 42001:2023 AI Management System
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
from routers.auth import get_current_user, require_role

router = APIRouter()

# ── ISO 42001 Control definitions ─────────────────────────────────────────────

GRC_CONTROLS = [
    {"id": "A.2.2", "domain": "AI Policy", "title": "Document AI Policy for Development / Use",
     "sg_ref": "PDPA · MAS FEAT Principles", "tes_modifier": "AGM"},
    {"id": "A.3.2", "domain": "Internal Org", "title": "Define & Allocate AI Roles and Responsibilities",
     "sg_ref": "MAS TRM Guidelines Section 4", "tes_modifier": "AGM"},
    {"id": "A.5.2", "domain": "Impact Assessment", "title": "Establish AI System Impact Assessment Process",
     "sg_ref": "PDPA DPIA · MAS FEAT", "tes_modifier": "AGM"},
    {"id": "A.6.2.2", "domain": "AI Lifecycle", "title": "Specify & Document AI System Requirements",
     "sg_ref": "IMDA AI Governance Framework v2", "tes_modifier": "AGM"},
    {"id": "A.7.4", "domain": "Data Quality", "title": "Define Data Quality Requirements for AI Systems",
     "sg_ref": "MAS Notice 655 · ISO/IEC 25024", "tes_modifier": "DRF"},
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


def _latest_sop_state_from_db(db: Session) -> list[dict]:
    state = db.query(GrcState).order_by(GrcState.id.desc()).first()
    if state and isinstance(state.sop_state, list) and len(state.sop_state) == len(GRC_CONTROLS):
        return _normalize_sop_state(state.sop_state)
    return _clone_default_sop_state()


def _signoff_state_from_db(db: Session) -> dict[str, set[str]]:
    signoffs: dict[str, set[str]] = {}
    rows = db.query(GrcSignoff).order_by(GrcSignoff.id.asc()).all()
    for row in rows:
        if row.signoff_type not in SOP_SIGNOFF_FIELDS:
            continue
        signoffs.setdefault(row.control_id, set()).add(row.signoff_type)
    return signoffs


def _effective_sop_state(db: Session) -> list[dict]:
    base_state = _latest_sop_state_from_db(db)
    signoff_state = _signoff_state_from_db(db)
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
    control_id: str,
    signoff_type: str,
    signed: bool,
    signed_by: str,
    notes: Optional[str] = None,
) -> str:
    rows = db.query(GrcSignoff).filter(
        GrcSignoff.control_id == control_id,
        GrcSignoff.signoff_type == signoff_type,
    ).order_by(GrcSignoff.id.asc()).all()

    if signed:
        if not rows:
            db.add(GrcSignoff(
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


def _sync_signoffs_from_sop_state(db: Session, sop_state: list[dict], signed_by: str) -> None:
    normalized = _normalize_sop_state(sop_state)
    for entry in normalized:
        for signoff_type, field in SOP_SIGNOFF_FIELDS.items():
            _sync_signoff_record(
                db=db,
                control_id=entry["id"],
                signoff_type=signoff_type,
                signed=_coerce_bool(entry.get(field, False)),
                signed_by=signed_by,
                notes=entry.get("notes") or None,
            )

# ── TES Composite Calculation (matches client's panel formula) ────────────────

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


# ── Request Models ────────────────────────────────────────────────────────────

class GrcStateRequest(BaseModel):
    toggles: dict
    sop_state: list[dict]

class SignoffRequest(BaseModel):
    signoff_type: str  # 'end_user' or 'pic'
    signed: bool = True
    notes: Optional[str] = None

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/state")
def get_grc_state(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Load the most recent GRC state. Returns defaults if none saved."""
    state = db.query(GrcState).order_by(GrcState.id.desc()).first()
    sop_state = _effective_sop_state(db)
    if state:
        return {
            "toggles": state.toggles or DEFAULT_TOGGLES,
            "sop_state": sop_state,
            "updated_by": state.updated_by,
            "updated_at": state.updated_at.isoformat() if state.updated_at else None,
        }
    return {
        "toggles": DEFAULT_TOGGLES,
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
    # ── Validate toggle structure ─────────────────────────────────────────
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
        sop_state=validated_sop_state,
        signed_by=user.get("sub", "unknown"),
    )
    
    state = GrcState(
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
    state = db.query(GrcState).order_by(GrcState.id.desc()).first()
    toggles = state.toggles if state else DEFAULT_TOGGLES
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

    action = _sync_signoff_record(
        db=db,
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
    sop_state = _effective_sop_state(db)
    
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


# ── ISO 42001 AI System Inventory & Policy Status ─────────────────────────────

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
        "human_oversight": "Advisory only — no automated actions triggered by AI output",
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
    state = db.query(GrcState).order_by(GrcState.id.desc()).first()
    toggles = state.toggles if state else DEFAULT_TOGGLES
    tes = _calc_composite_tes(toggles)

    # Get signoff progress
    signoff_state = _signoff_state_from_db(db)

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


# ── Policy Document Serving ───────────────────────────────────────────────────

import os
import re

POLICY_REGISTRY = {
    "iso42001": {
        "filename": "iso42001_ai_policy.md",
        "title": "ISO/IEC 42001:2023 — AI Management System Policy",
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
    policies.extend(_policy_row_to_dict(row) for row in db.query(GrcPolicyDocument).order_by(GrcPolicyDocument.created_at.desc()).all())
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
    meta = POLICY_REGISTRY.get(policy_id)
    if not meta:
        row = db.query(GrcPolicyDocument).filter(GrcPolicyDocument.id == policy_id).first()
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
    meta = POLICY_REGISTRY.get(policy_id)
    if not meta:
        row = db.query(GrcPolicyDocument).filter(GrcPolicyDocument.id == policy_id).first()
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


# ── Evidence Upload / Download / Delete ────────────────────────────────────────

from fastapi.responses import FileResponse

ALLOWED_EVIDENCE_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".md"}
MAX_EVIDENCE_SIZE = 10 * 1024 * 1024  # 10 MB
EVIDENCE_BASE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'evidence')


@router.post("/evidence/{control_id}")
async def upload_evidence(
    control_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Upload a file as evidence for an ISO 42001 control."""
    # Validate control exists
    ctrl = next((c for c in GRC_CONTROLS if c["id"] == control_id), None)
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")

    # C-03: Sanitize filename to prevent path traversal
    import re
    raw_name = file.filename or "untitled"
    original_name = re.sub(r'[^\w\s\-\.]', '_', raw_name)
    ext = os.path.splitext(original_name)[1].lower()
    if ext not in ALLOWED_EVIDENCE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' not allowed. Accepted: {', '.join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))}",
        )

    # Read file content and enforce size limit
    content = await file.read()
    if len(content) > MAX_EVIDENCE_SIZE:
        raise HTTPException(status_code=400, detail=f"File exceeds maximum size of 10 MB")

    # Save to disk with a unique name to prevent collisions
    save_dir = os.path.join(EVIDENCE_BASE_DIR, control_id)
    try:
        os.makedirs(save_dir, exist_ok=True)
    except PermissionError:
        # Fallback: use /tmp-based evidence directory
        save_dir = os.path.join('/tmp', 'tempris_evidence', control_id)
        os.makedirs(save_dir, exist_ok=True)
    unique_name = f"{uuid4().hex}{ext}"
    save_path = os.path.join(save_dir, unique_name)

    with open(save_path, "wb") as f:
        f.write(content)

    # Persist metadata
    evidence = ControlEvidence(
        framework_id="ISO42001",
        control_id=control_id,
        filename=original_name,
        file_path=save_path,
        uploaded_by=user.get("sub", "unknown"),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="EVIDENCE_UPLOADED",
        module="GRC",
        detail=f"Evidence '{original_name}' uploaded for control {control_id} (id={evidence.id})",
    ))

    return {
        "id": evidence.id,
        "control_id": evidence.control_id,
        "framework_id": evidence.framework_id,
        "filename": evidence.filename,
        "uploaded_by": evidence.uploaded_by,
        "uploaded_at": evidence.uploaded_at.isoformat() if evidence.uploaded_at else None,
    }


@router.get("/evidence/{control_id}")
def list_evidence(
    control_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """List all evidence files for a given control."""
    records = (
        db.query(ControlEvidence)
        .filter(ControlEvidence.control_id == control_id)
        .order_by(ControlEvidence.uploaded_at.desc())
        .all()
    )
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
    record = (
        db.query(ControlEvidence)
        .filter(ControlEvidence.id == evidence_id, ControlEvidence.control_id == control_id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    if not record.file_path or not os.path.exists(record.file_path):
        raise HTTPException(status_code=404, detail="Evidence file not found on disk")

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="EVIDENCE_DOWNLOADED",
        module="GRC",
        detail=f"Downloaded evidence '{record.filename}' (id={record.id}) for control {control_id}",
    ))

    return FileResponse(
        path=record.file_path,
        filename=record.filename,
        media_type="application/octet-stream",
    )


@router.delete("/evidence/{control_id}/{evidence_id}")
def delete_evidence(
    control_id: str,
    evidence_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin")),
):
    """Delete an evidence record and its file from disk. Requires Superadmin or Admin."""
    record = (
        db.query(ControlEvidence)
        .filter(ControlEvidence.id == evidence_id, ControlEvidence.control_id == control_id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    # Remove file from disk
    if record.file_path and os.path.exists(record.file_path):
        os.remove(record.file_path)

    filename = record.filename
    db.delete(record)
    db.commit()

    append_to_audit_log(AuditEntry(
        user=user.get("sub", "unknown"),
        action="EVIDENCE_DELETED",
        module="GRC",
        detail=f"Deleted evidence '{filename}' (id={evidence_id}) for control {control_id}",
    ))

    return {"status": "deleted", "evidence_id": evidence_id, "control_id": control_id}
