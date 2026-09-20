# backend/app/spectrum/errors.py
"""Domain errors for the SPECTRUM workbench (PRD-000 v1.11 Ch.7)."""
from app.exposure.exceptions import ExposureDomainError


class SpectrumWorkflowError(ExposureDomainError):
    """A workbench action was rejected. Stable code: 'spectrum_workflow' —
    the message names the specific refusal (a second open EDIP handoff,
    an invalid analysis_state, ...)."""

    code = "spectrum_workflow"


class SpectrumExposureNotFoundError(ExposureDomainError):
    """The exposure does not exist in the requesting tenant, is not current,
    or sits on an inactive asset — the same fail-closed not-found as the Ch.3
    TES reads (nothing is disclosed)."""

    code = "exposure_not_found"
