"""Domain errors for EDIP (PRD-000 v1.11 Ch.8)."""
from app.exposure.exceptions import ExposureDomainError


class EdipWorkflowError(ExposureDomainError):
    """A malformed EDIP request (bad state vocabulary, missing mandatory
    fields, an expired review consumed as active). Stable code:
    'edip_workflow' — the message names the specific refusal."""

    code = "edip_workflow"


class EdipDecisionNotFoundError(ExposureDomainError):
    """The decision does not exist in the requesting tenant (unknown and
    cross-tenant ids are the identical not-found — no disclosure)."""

    code = "edip_decision_not_found"


class EdipExposureNotFoundError(ExposureDomainError):
    """The exposure does not exist in the requesting tenant, is not a CURRENT
    confirmed episode, or sits on an inactive asset — the same fail-closed
    not-found as the Ch.3 TES reads and the Ch.7 workbench gate."""

    code = "exposure_not_found"


class EdipConflictError(ExposureDomainError):
    """A lifecycle conflict: an invalid state edge, a stale compare-and-set,
    a standing decision where only one may exist, closure refused for missing
    or invalidated verification, a replayed handoff. Stable code:
    'edip_conflict'."""

    code = "edip_conflict"
