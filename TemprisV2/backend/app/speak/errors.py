# backend/app/speak/errors.py
"""Error vocabulary for SPEAK reports/deliverables (Ch.11)."""


class SpeakError(Exception):
    """Base class: carries a stable machine code for the API envelope."""

    code = "speak_error"

    def __init__(self, message: str):
        super().__init__(message)


class ReportNotFoundError(SpeakError):
    """Unknown or cross-tenant report id — the same fail-closed 404 shape as
    the rest of the platform."""

    code = "report_not_found"


class ReportStateError(SpeakError):
    """The lifecycle transition or action is not valid for the report's
    current state (unapproved regeneration, export of a draft, deletion of
    an approved report, ...)."""

    code = "report_state_error"


class ScopeValidationError(SpeakError):
    """The registered scope names an object that is not a current tenant
    exposure (register-time ownership validation — V1 posture kept)."""

    code = "scope_validation_error"


class ArtifactIntegrityError(SpeakError):
    """A stored artifact's bytes no longer match its sealed hash — download
    refuses and alarms."""

    code = "artifact_hash_mismatch"


class LlmUnavailableError(SpeakError):
    """The SPEAK AI surface has no configured model. It fails closed —
    'unavailable' — and never invents content (the V1 mock-LLM fallback that
    rendered seeded numbers is a named defect class and is retired)."""

    code = "llm_unavailable"


class PromptInjectionBlockedError(SpeakError):
    """The chat message matched the prompt-injection guardrail (the V1
    SPEAK input guardrail, kept per the Ch.11/Ch.12 boundary). Blocked
    BEFORE any provider call or state read — an instruction-override
    attempt is a rejected input, never prompt material."""

    code = "prompt_injection_blocked"
