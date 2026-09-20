# backend/app/strike/errors.py
"""Named, fail-closed errors for the STRIKE domain.

Every refusal carries a stable ``code`` the API maps to a specific HTTP
surface — refusal is never silent and never improvised. Unknown and
cross-tenant ids are the IDENTICAL not-found everywhere (no disclosure).
"""


class StrikeDomainError(Exception):
    """Base class for STRIKE domain errors."""

    code = "strike_error"


# ---------------------------------------------------------------------------
# Not found (unknown and cross-tenant ids are the identical not-found)
# ---------------------------------------------------------------------------


class StrikeNotFoundError(StrikeDomainError):
    code = "strike_not_found"


class EngagementNotFoundError(StrikeNotFoundError):
    code = "engagement_not_found"


class TargetNotFoundError(StrikeNotFoundError):
    code = "target_not_found"


class WorkspaceNotFoundError(StrikeNotFoundError):
    code = "workspace_not_found"


class OperationNotFoundError(StrikeNotFoundError):
    code = "operation_not_found"


class RelayNotFoundError(StrikeNotFoundError):
    code = "relay_not_found"


# ---------------------------------------------------------------------------
# Lifecycle / policy refusals
# ---------------------------------------------------------------------------


class EngagementStateError(StrikeDomainError):
    """The engagement is not in the state (or derived-expiry condition) the
    command requires."""

    code = "engagement_state"


class EngagementExpiredError(EngagementStateError):
    """The engagement's authorization window has closed (derived at read —
    the stored state is never rewritten)."""

    code = "engagement_expired"


class TargetStateError(StrikeDomainError):
    code = "target_state"


class TargetExpiredError(TargetStateError):
    """The target's authorization has expired (derived at read)."""

    code = "target_expired"


class WorkspaceStateError(StrikeDomainError):
    code = "workspace_state"


class WorkspaceCardinalityError(StrikeDomainError):
    """The cardinality lock: ONE live workspace per engagement. A second
    reservation while a generation is live is a conflict — the standing one
    must be reconciled/fenced first (PATCH-04)."""

    code = "workspace_generation_conflict"


class OperationStateError(StrikeDomainError):
    code = "operation_state"


class RelayStateError(StrikeDomainError):
    code = "relay_state"


class AbilityNotAllowlistedError(StrikeDomainError):
    """The requested ability is not on the approved allowlist (or is
    inactive). Nothing runs that is not on it."""

    code = "ability_not_allowlisted"


class OutcomeClassificationError(StrikeDomainError):
    """The classifier refused the outcome: EXPLOITABLE and PREVENTED are
    never auto-assigned (the POC A rule preserved from principle 8)."""

    code = "outcome_classification_refused"


class OutputBoundError(StrikeDomainError):
    """Engine output or artifact exceeds the bounded cap (principle 9:
    bounded, hashed artifacts)."""

    code = "output_bound_exceeded"


# ---------------------------------------------------------------------------
# Evidence promotion (PATCH-01)
# ---------------------------------------------------------------------------


class EvidencePromotionError(StrikeDomainError):
    """A promotion claim failed server-side validation: the operation, its
    outcome, the exact exposure episode, the occurrence time, or the
    constrained evidence_kind does not support the claim. Observed
    exploitation is never fabricated and a failed/absent operation is never
    promotable."""

    code = "evidence_promotion_refused"


# ---------------------------------------------------------------------------
# Provider / engine seams (fail-closed)
# ---------------------------------------------------------------------------


class WorkspaceProviderUnavailableError(StrikeDomainError):
    """No workspace provider is configured (frozen-open decision: provider
    choice, PRD Ch.4 open decision #1). The reservation is truthfully
    alarmed, never fabricated."""

    code = "workspace_provider_unavailable"


class EngineUnavailableError(StrikeDomainError):
    """No execution engine is integrated for the operation's ability. The
    operation records outcome ERROR — engine/transport failure never
    translates into PREVENTED or NOT_EXECUTED (failure modes)."""

    code = "engine_unavailable"
