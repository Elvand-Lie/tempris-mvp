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


class InvalidFindingStatusError(ExposureDomainError):
    """Raised when attempting to confirm exposure on a non-open finding."""
    pass
