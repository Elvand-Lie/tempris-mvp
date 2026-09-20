"""Domain errors for STANDARD / GRC (PRD-000 v1.11 Ch.9)."""
from app.exposure.exceptions import ExposureDomainError


class StandardWorkflowError(ExposureDomainError):
    """A malformed STANDARD request (bad vocabulary, missing mandatory
    fields, an unreadable rule condition). Stable code 'standard_workflow' —
    the message names the specific refusal."""

    code = "standard_workflow"


class StandardNotFoundError(ExposureDomainError):
    """The object does not exist in the requesting tenant (unknown and
    cross-tenant ids are the identical not-found — no disclosure)."""

    code = "standard_not_found"


class StandardConflictError(ExposureDomainError):
    """A lifecycle conflict: duplicate live assessment, duplicate submission,
    a stale compare-and-set, resolution blocked by unfinished evaluations or
    obligations. Stable code 'standard_conflict'."""

    code = "standard_conflict"
