"""Canonical ISO/IEC 42001 control assessments and server-side GRC modifiers."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models import ControlAssessment, FrameworkControl, FrameworkDefinition, Finding, GrcSignoff


ISO_42001_ID = "iso-iec-42001-2023"
ISO_42001_VERSION = "2023"
ISO_42001_NAME = "ISO/IEC 42001:2023"

CONTROL_CATALOG = (
    ("A.2.2", "AI Policy", "Document AI Policy for Development / Use", "Establish and maintain an AI policy.", "AGM"),
    ("A.3.2", "Internal Organisation", "Define & Allocate AI Roles and Responsibilities", "Assign accountable AI roles.", "AGM"),
    ("A.5.2", "Impact Assessment", "Establish AI System Impact Assessment Process", "Maintain an AI impact assessment process.", "AGM"),
    ("A.6.2.2", "AI Lifecycle", "Specify & Document AI System Requirements", "Document AI lifecycle requirements.", "AGM"),
    ("A.7.4", "Data Quality", "Define Data Quality Requirements for AI Systems", "Define and maintain data-quality requirements.", "DRF"),
    ("A.9.2", "Responsible Use", "Define Processes for Responsible AI Use", "Define responsible-AI use processes.", "AGM"),
    ("A.10.3", "Third-Party", "Ensure Supplier AI Alignment with Organisation Policy", "Verify supplier AI alignment.", "TEF"),
)

_OPEN_STATUSES = {"unmitigated", "open", "active", "investigate", "in_progress"}
_ASSESSMENT_STATUSES = {"pending", "in_review", "completed"}


def ensure_framework_catalog(db: Session) -> None:
    """Idempotently seed the one server-managed GRC framework and controls."""
    framework = db.get(FrameworkDefinition, ISO_42001_ID)
    if not framework:
        db.add(FrameworkDefinition(
            id=ISO_42001_ID,
            version=ISO_42001_VERSION,
            name=ISO_42001_NAME,
            description="Authoritative Tempris GRC framework control catalogue.",
            server_managed=True,
            active=True,
        ))
    for order, (control_id, domain, requirement, description, modifier_group) in enumerate(CONTROL_CATALOG, start=1):
        existing = db.query(FrameworkControl).filter(
            FrameworkControl.framework_id == ISO_42001_ID,
            FrameworkControl.control_id == control_id,
        ).first()
        if not existing:
            db.add(FrameworkControl(
                framework_id=ISO_42001_ID,
                framework_version=ISO_42001_VERSION,
                control_id=control_id,
                domain=domain,
                requirement=requirement,
                description=description,
                modifier_group=modifier_group,
                display_order=order,
                active=True,
            ))
    db.flush()


def framework_controls(db: Session) -> list[FrameworkControl]:
    ensure_framework_catalog(db)
    return db.query(FrameworkControl).filter(
        FrameworkControl.framework_id == ISO_42001_ID,
        FrameworkControl.active.is_(True),
    ).order_by(FrameworkControl.display_order.asc()).all()


def _signoff_sets(db: Session, tenant_id: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for row in db.query(GrcSignoff).filter(GrcSignoff.tenant_id == tenant_id).all():
        if row.signoff_type in {"end_user", "pic"}:
            result.setdefault(row.control_id, set()).add(row.signoff_type)
    return result


def _legacy_sop_by_control(db: Session, tenant_id: str) -> dict[str, dict]:
    """Read-only bridge for pre-migration rows; canonical writes use assessments."""
    from models import GrcState

    row = db.query(GrcState).filter(GrcState.tenant_id == tenant_id).order_by(GrcState.id.desc()).first()
    values = row.sop_state if row and isinstance(row.sop_state, list) else []
    return {item.get("id"): item for item in values if isinstance(item, dict) and item.get("id")}


def _legacy_status(item: dict, signoffs: set[str]) -> str:
    requested = str(item.get("status") or "").strip().lower().replace(" ", "_")
    if requested in _ASSESSMENT_STATUSES:
        return requested
    if "end_user" in signoffs and "pic" in signoffs:
        return "completed"
    if "end_user" in signoffs or "pic" in signoffs:
        return "in_review"
    return "pending"


def ensure_tenant_assessments(db: Session, tenant_id: str, actor: str | None = None) -> list[ControlAssessment]:
    """Create missing assessment rows once, preserving legacy SOP/sign-off state."""
    controls = framework_controls(db)
    existing = {
        row.control_id: row
        for row in db.query(ControlAssessment).filter(
            ControlAssessment.tenant_id == tenant_id,
            ControlAssessment.framework_id == ISO_42001_ID,
        ).all()
    }
    legacy = _legacy_sop_by_control(db, tenant_id)
    signoffs = _signoff_sets(db, tenant_id)
    for control in controls:
        if control.control_id in existing:
            continue
        item = legacy.get(control.control_id, {})
        signed = signoffs.get(control.control_id, set())
        row = ControlAssessment(
            tenant_id=tenant_id,
            framework_id=ISO_42001_ID,
            control_id=control.control_id,
            status=_legacy_status(item, signed),
            pic=item.get("pic", "") if isinstance(item.get("pic", ""), str) else "",
            notes=item.get("notes", "") if isinstance(item.get("notes", ""), str) else "",
            end_user_agreed="end_user" in signed or bool(item.get("endUserAgreed")),
            pic_signed_off="pic" in signed or bool(item.get("picAgreed")),
            created_by=actor,
            updated_by=actor,
        )
        db.add(row)
        existing[control.control_id] = row
    db.flush()
    return [existing[control.control_id] for control in controls]


def assessment_state(row: ControlAssessment) -> tuple[str, float]:
    """Return customer-safe state and server-only effective completion."""
    status = (row.status or "pending").strip().lower()
    if status == "completed" and row.end_user_agreed and row.pic_signed_off:
        return "Completed", 1.0
    if status == "completed" or status == "in_review" or row.end_user_agreed or row.pic_signed_off:
        return "In Review", 0.5
    return "Pending", 0.0


def assessment_rows(db: Session, tenant_id: str) -> list[tuple[FrameworkControl, ControlAssessment, str, float]]:
    controls = framework_controls(db)
    rows = {row.control_id: row for row in ensure_tenant_assessments(db, tenant_id)}
    return [(control, rows[control.control_id], *assessment_state(rows[control.control_id])) for control in controls]


def get_live_grc_modifiers(db: Session, tenant_id: str) -> dict[str, float]:
    """Derive the live non-CVE GRC context from the canonical control assessments."""
    values = {control.control_id: completion for control, _, _, completion in assessment_rows(db, tenant_id)}
    agm_ids = ("A.2.2", "A.3.2", "A.5.2", "A.6.2.2", "A.9.2")
    agm_completion = sum(values[control_id] for control_id in agm_ids) / len(agm_ids)
    agm = round(1.5 - 0.5 * agm_completion, 3)
    drf = round(1.3 - 0.3 * values["A.7.4"], 3)
    tef = round(1.2 - 0.2 * values["A.10.3"], 3)
    return {"AGM": agm, "DRF": drf, "TEF": tef, "as_of": datetime.now(timezone.utc).isoformat()}


def qualitative_drivers(db: Session, tenant_id: str) -> list[str]:
    rows = assessment_rows(db, tenant_id)
    completion = {control.control_id: value for control, _, _, value in rows}
    drivers = []
    if any(completion[item] < 1.0 for item in ("A.2.2", "A.3.2", "A.5.2", "A.6.2.2", "A.9.2")):
        drivers.append("Governance controls incomplete")
    if completion["A.7.4"] < 1.0:
        drivers.append("Data-quality control pending")
    if completion["A.10.3"] < 1.0:
        drivers.append("Third-party governance incomplete")
    return drivers or ["Recorded governance controls are complete"]


def recalculate_open_sss_findings(db: Session, tenant_id: str, actor_id: str | None = None) -> list[str]:
    """Refresh live GRC context for open non-CVE findings while retaining provenance."""
    from services.operational_events import record_operational_event
    from services.tes_engine import calculate_sss_tes, priority_from_tes, public_decision_for_finding

    modifiers = get_live_grc_modifiers(db, tenant_id)
    finding_ids = []
    rows = db.query(Finding).filter(Finding.tenant_id == tenant_id, Finding.source == "sss").all()
    for finding in rows:
        if (finding.status or "unmitigated").lower() not in _OPEN_STATUSES:
            continue
        sss = dict(finding.sss_data or {})
        scoring = dict(sss.get("scoring") or {})
        if scoring.get("base_severity") is None:
            continue
        previous = {key: scoring.get(key) for key in ("AGM", "DRF", "TEF")}
        updated = {**scoring, "AGM": modifiers["AGM"], "DRF": modifiers["DRF"], "TEF": modifiers["TEF"]}
        if previous == {key: updated[key] for key in previous}:
            continue
        history = list(sss.get("scoring_history") or [])
        history.append({"at": datetime.now(timezone.utc).isoformat(), "reason": "grc_assessment_changed", "modifiers": previous})
        sss["scoring_history"] = history[-50:]
        sss["scoring"] = updated
        sss["live_grc_context_at"] = modifiers["as_of"]
        score = calculate_sss_tes(updated)
        # Re-evaluate automatic EDIP output from the new live score. A manual
        # analyst override is stored separately in EdipDecision and is untouched.
        decision_context = dict(sss)
        decision_context.pop("engine_decision", None)
        decision = public_decision_for_finding({"sss_data": decision_context, "source": "sss"}, score)
        sequence = list(sss.get("decision_sequence") or [])
        if not sequence or sequence[-1] != decision:
            sequence.append(decision)
        sss["decision_sequence"] = sequence
        sss["engine_decision"] = decision
        finding.sss_data = sss
        finding.score = score
        finding.priority = priority_from_tes(score)
        finding.decision = decision
        finding_ids.append(finding.id)
        record_operational_event(
            db, tenant_id=tenant_id, event_type="finding.grc_context_recalculated",
            resource_type="finding", resource_id=finding.id, source_module="GRC",
            actor_id=actor_id, metadata={"reason": "control_assessment_changed"},
        )
    return finding_ids
