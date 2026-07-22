"""Public SSS intake/output contract from the v62 third-party debrief.

This module deliberately contains categories, descriptive posture fields, and
presentation states only. Scoring weights and thresholds remain server-internal.
"""

from datetime import date, datetime, timezone
from enum import Enum


class FindingClass(str, Enum):
    BLFLAW = "BLFLAW"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    IDENTITY_POSTURE = "IDENTITY_POSTURE"
    AGENTIC_EXPOSURE = "AGENTIC_EXPOSURE"
    VALIDATION_EVIDENCE = "VALIDATION_EVIDENCE"
    NHI = "NHI"


class FindingSubclass(str, Enum):
    INJECTION_PATH = "INJECTION_PATH"
    MEMORY_RAG = "MEMORY_RAG"
    TOOL_MCP = "TOOL_MCP"
    TRAINING_SUPPLY = "TRAINING_SUPPLY"
    MFA_ENROLMENT = "MFA_ENROLMENT"
    SESSION_TOKEN = "SESSION_TOKEN"
    MACHINE_KEY = "MACHINE_KEY"
    CONDITIONAL_ACCESS = "CONDITIONAL_ACCESS"


SUBCLASSES_BY_CLASS = {
    FindingClass.AGENTIC_EXPOSURE.value: {
        FindingSubclass.INJECTION_PATH.value,
        FindingSubclass.MEMORY_RAG.value,
        FindingSubclass.TOOL_MCP.value,
        FindingSubclass.TRAINING_SUPPLY.value,
    },
    FindingClass.IDENTITY_POSTURE.value: {
        FindingSubclass.MFA_ENROLMENT.value,
        FindingSubclass.SESSION_TOKEN.value,
        FindingSubclass.MACHINE_KEY.value,
        FindingSubclass.CONDITIONAL_ACCESS.value,
    },
}


PUBLIC_SSS_FIELDS = (
    "agent_id",
    "credential_scope",
    "ingestion_paths",
    "egress_controlled",
    "token_lifetime_minutes",
    "cae_enabled",
    "conditional_access_coverage",
    "behavioural_detection",
    "itdr_source",
    "escalation_date",
    "escalated_severity",
    "kev_due",
    "required_control",
    "portable_asset_priority",
    "watch_flag",
    "conditional_decision",
    "validated",
    "path_id",
    "verdict",
    "evidence_ref",
    "revalidate_by",
)


def validate_subclass(finding_class: str, sub_class: str | None) -> str | None:
    """Validate a client-visible subclass without inferring one."""
    normalized_class = str(finding_class or "").upper()
    if not sub_class:
        return None
    normalized_subclass = str(sub_class).upper()
    allowed = SUBCLASSES_BY_CLASS.get(normalized_class)
    if allowed is None:
        raise ValueError(f"sub_class is not supported for class {normalized_class}")
    if normalized_subclass not in allowed:
        raise ValueError(
            f"Invalid sub_class {normalized_subclass} for class {normalized_class}"
        )
    return normalized_subclass


def deadline_state(value: str | date | datetime | None, *, today: date | None = None) -> str | None:
    """Return the server-authoritative >7d / <=7d / overdue presentation state."""
    if not value:
        return None
    if isinstance(value, datetime):
        due = value.date()
    elif isinstance(value, date):
        due = value
    else:
        try:
            due = datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
        except ValueError:
            due = date.fromisoformat(str(value))
    current = today or datetime.now(timezone.utc).date()
    days = (due - current).days
    if days < 0:
        return "overdue"
    if days <= 7:
        return "due_soon"
    return "scheduled"


def public_sss_output(sss_data: dict | None) -> dict:
    """Select only the existence/output fields approved for clients."""
    source = sss_data or {}
    output = {
        key: source[key]
        for key in PUBLIC_SSS_FIELDS
        if source.get(key) not in (None, "", [])
    }
    if source.get("sub_class"):
        output["sub_class"] = source["sub_class"]
    if source.get("kev_due"):
        output["kev_countdown_state"] = deadline_state(source["kev_due"])
    if source.get("revalidate_by"):
        output["revalidation_countdown_state"] = deadline_state(source["revalidate_by"])
    return output
