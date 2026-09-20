# backend/app/ciso/errors.py
"""Error vocabulary for the SPOTLIGHT executive view (Ch.10)."""


class SpotlightError(Exception):
    """Base class: carries a stable machine code for the API envelope."""

    code = "spotlight_error"

    def __init__(self, message: str):
        super().__init__(message)


class SnapshotNotFoundError(SpotlightError):
    """Unknown or cross-tenant snapshot id (the same fail-closed 404 shape
    as the rest of the platform — nothing is disclosed)."""

    code = "snapshot_not_found"
