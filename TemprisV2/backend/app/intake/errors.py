# backend/app/intake/errors.py
"""
Domain errors for Intake & Triage (PRD-000 v1.11 Ch.6).

Every conflict surface carries a stable ``code`` so retries can distinguish
committed outcomes from rejected attempts, mirroring the exposure-domain
convention.
"""
from app.exposure.exceptions import ExposureDomainError, EntityNotFoundError


class IntakeNotFoundError(EntityNotFoundError):
    """The intake record does not exist in the requesting tenant (unknown and
    cross-tenant ids are the same not-found — no disclosure)."""


class IntakeStateError(ExposureDomainError):
    """A lifecycle transition was rejected (wrong current state, missing
    classification, missing review action). Stable code: 'intake_state'."""

    code = "intake_state"


class IntakeDuplicateExposureError(ExposureDomainError):
    """Exact match against a CURRENT confirmed exposure: the record is
    terminal-duplicate with a stored duplicate_of_exposure_id reference, and
    the confirm request is a hard 409. Stable code: 'intake_duplicate'."""

    code = "intake_duplicate"

    def __init__(self, message: str, duplicate_of_exposure_id):
        super().__init__(message)
        self.duplicate_of_exposure_id = duplicate_of_exposure_id


class IntakeEventConflictError(ExposureDomainError):
    """The same (registration, event id) replayed with a DIFFERENT payload:
    rejected, never silently revised. Stable code: 'intake_event_conflict'."""

    code = "intake_event_conflict"


class IntakeAnchorRequiredError(ExposureDomainError):
    """Confirmation attempted without a resolvable anchor. Fail-closed: never
    confirmed without a valid anchor. Stable code: 'anchor_required'."""

    code = "anchor_required"


class IntakeAnchorlessClassError(ExposureDomainError):
    """An anchorless class (v1: NHI) cannot be confirmed — no anchor semantics
    exist yet (§3.6.6 #8); the record can be held (needs_info) but never
    confirmed. A named refusal, never a silent block.
    Stable code: 'anchorless_class'."""

    code = "anchorless_class"


class IntakePriorFalsePositiveError(ExposureDomainError):
    """Exact match against a false_positive exposure: fresh review required —
    the prior not-applicable judgment must be explicitly re-examined by an
    analyst; never auto-duplicated, never auto-recurred.
    Stable code: 'false_positive_re_review_required'."""

    code = "false_positive_re_review_required"


class IntakeAnchorSupersededError(ExposureDomainError):
    """History touching a superseded exposure: the current anchor must be
    explicitly re-resolved before any confirmation (e.g. the boundary was
    re-designated). Stable code: 'anchor_re_resolution_required'."""

    code = "anchor_re_resolution_required"


class IntakeAmbiguousIdentityError(ExposureDomainError):
    """Finding identity is ambiguous (multiple candidate findings match the
    v1 non-CVE signature): review, never auto-resolve (PATCH-06).
    Stable code: 'ambiguous_finding_identity'."""

    code = "ambiguous_finding_identity"


class IntakeConnectorRegistrationError(ExposureDomainError):
    """A CONNECTOR-source submission referenced an unknown, cross-tenant, or
    disabled registration. Stable code: 'connector_registration'."""

    code = "connector_registration"


class IntakeClassificationRationaleError(ExposureDomainError):
    """A classification/reclassification was attempted without a nonblank
    rationale. Fail-closed: no projection update and no history event — the
    append-only record would otherwise carry a decision with no stated reason
    (§6:1141/1149). Stable code: 'classification_rationale_required'."""

    code = "classification_rationale_required"
