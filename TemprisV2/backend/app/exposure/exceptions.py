# backend/app/exposure/exceptions.py
"""
Domain exceptions for the Exposure Domain.
"""

class ExposureDomainError(Exception):
    """Base exception for all exposure domain errors."""
    pass


class InvalidEvidenceError(ExposureDomainError, ValueError):
    """Raised when evidence is missing, empty, or not a valid JSON object."""
    pass


class EntityNotFoundError(ExposureDomainError):
    """Base exception for entities not found within tenant scope."""
    pass


class FindingNotFoundError(EntityNotFoundError):
    """Raised when a finding cannot be found for the specified tenant."""
    pass


class AssetNotFoundError(EntityNotFoundError):
    """Raised when an asset cannot be found for the specified tenant."""
    pass


class ExposureNotFoundError(EntityNotFoundError):
    """Raised when an asset exposure cannot be found for the specified tenant."""
    pass


class TenantMismatchError(ExposureDomainError):
    """Raised when an operation attempts to link or operate on entities across different tenants."""
    pass


class InvalidAssetStatusError(ExposureDomainError):
    """Raised when attempting to confirm exposure on an inactive/decommissioned asset."""
    pass


class ExposureConflictError(ExposureDomainError):
    """
    Raised when a lifecycle transition is rejected because the episode is in a
    stale or conflicting state. Stable conflict code: 'exposure_conflict' —
    retries can distinguish committed success / idempotent replay / rejected
    stale state.
    """

    code = "exposure_conflict"


class ReviewBindingError(ExposureDomainError, ValueError):
    """
    Raised when a review bound to a confirmation command does not reference
    the exact (finding, asset) tuple being confirmed. The review, the
    exposure, and the audit must commit as one atomic disposition.
    """


class EvidencePolicyError(ExposureDomainError):
    """
    Raised when a score-bearing record is rejected by server-side evidence
    policy: producer outside the closed allowlist, non-success attempt
    semantics, impossible occurrence time, wrong evidence class for the
    exposure path, or an unprovable provenance claim. Stable code:
    'evidence_policy_rejected' — the record is never written.
    """

    code = "evidence_policy_rejected"


class IdentityBoundaryStateError(ExposureDomainError):
    """
    Raised when a command violates the §3.6.6 #7 identity-boundary lifecycle
    contract: a precondition failure on the designated asset (not a domain
    target, not active), a confirmation without an active boundary for the
    anchor asset, or a create attempted while a different active binding
    exists. Stable conflict surface: 409 at the API boundary.
    """


class BoundAssetError(ExposureDomainError):
    """
    Raised when decommissioning an asset that is the tenant's active
    identity boundary (§3.6.6 #7: replace or clear the binding first).
    Stable code: 'identity_boundary_bound'.
    """

    code = "identity_boundary_bound"


class IdentityBoundaryNotFoundError(EntityNotFoundError):
    """No current identity boundary exists for the tenant (0..1 — absence
    is a normal state, this error is for commands that require one)."""
