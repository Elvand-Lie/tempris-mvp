# backend/app/strike/outcomes.py
"""Execution truth — the 7-state operation outcome enum and its classifier
(PRD-000 v1.11 Ch.4 principle 8; D-7; the POC A rule preserved).

Two truth layers, explicitly separated:

  * EXECUTION TRUTH (this module) — what the operation did, expressed in the
    7-state enum from the 2026-09-06 review:
        EXPLOITABLE / PREVENTED / INCONCLUSIVE / NOT_EXECUTED / UNSUPPORTED /
        ERROR / OBSERVED
  * SCORING TRUTH (Ch.3 §3.3.3) — ``evidence_kind``, recorded at write time
    on the Ch.3 evidence record, NEVER derived from the operation outcome
    (D-7). app/strike/evidence.py owns the constrained mapping; the enum
    below is never shown to Ch.3.

The POC A rule is binding: the classifier NEVER auto-assigns EXPLOITABLE or
PREVENTED —
  * EXPLOITABLE: a successful run alone does not establish exploitability;
    the scoring side handles proven exploitation through the constrained
    write-time classification (evidence.py), never through this enum;
  * PREVENTED: silence, timeout, or empty output cannot observe defensive
    controls; PREVENTED requires evidence linking the attempt to an actual
    control intervention, which nothing in the v1 control plane produces —
    so the value is refused wherever the control plane writes outcomes.

Failure/timeout/transport error is ERROR; a run whose result could not be
established is INCONCLUSIVE — never PREVENTED, never NOT_EXECUTED (target
truth remains unknown).
"""
from __future__ import annotations

from app.strike.errors import OutcomeClassificationError

EXPLOITABLE = "EXPLOITABLE"
PREVENTED = "PREVENTED"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_EXECUTED = "NOT_EXECUTED"
UNSUPPORTED = "UNSUPPORTED"
ERROR = "ERROR"
OBSERVED = "OBSERVED"

#: The full outcome enum (stored in strike_operations.outcome, migration 028).
ALL_OUTCOMES = (
    EXPLOITABLE, PREVENTED, INCONCLUSIVE, NOT_EXECUTED,
    UNSUPPORTED, ERROR, OBSERVED,
)

#: The POC A forbidden set — the classifier refuses to auto-assign either
#: value, no matter who (engine, adapter, operator) claims it.
FORBIDDEN_OUTCOMES = frozenset({EXPLOITABLE, PREVENTED})

#: Outcomes the control plane accepts when a result is recorded for a
#: dispatched/running operation. ERROR is set by the control plane itself on
#: engine/transport failure, not accepted from an engine claim.
REPORTABLE_OUTCOMES = (
    OBSERVED, INCONCLUSIVE, NOT_EXECUTED, UNSUPPORTED,
)


def classify_reported_outcome(reported: str) -> str:
    """Validate an engine/operator-reported outcome for a completing
    operation. Refuses anything outside the reportable set — EXPLOITABLE and
    PREVENTED above all (named, visible refusal, never silent remapping)."""
    if reported not in REPORTABLE_OUTCOMES:
        if reported in FORBIDDEN_OUTCOMES:
            raise OutcomeClassificationError(
                f"outcome {reported!r} is never auto-assigned (the classifier "
                "refuses EXPLOITABLE/PREVENTED); execution truth records what "
                "was observed — scoring truth is decided in the Ch.3 evidence "
                "contract with write-time classification"
            )
        raise OutcomeClassificationError(
            f"outcome {reported!r} is not a reportable execution outcome "
            f"(reportable: {', '.join(REPORTABLE_OUTCOMES)})"
        )
    return reported
