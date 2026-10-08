# backend/app/intake/classification_history.py
"""
Append-only classification history for Intake & Triage (PRD-000 v1.11 Ch.6).

PRD contract: every classification/reclassification must preserve the prior
class/subclass/subtype, the new values, the actor, the timestamp and the
rationale, as append-only history; `intake_records` stays the CURRENT
projection (`classification_reviews` append-only, §6:1141/1149).

This module is the pure half of that contract:

- ``normalize_rationale`` gates the mandatory rationale (§6 — the same
  mandatory-rationale rule the exposure-classification precedent carries,
  ``routers/workflow.py:87-97``). Blank/absent fails closed.
- ``build_transition_detail`` shapes the before/after payload written into the
  existing ``intake_record_events.detail`` JSONB on the SAME transaction as
  the projection update, so a decision can never be recorded without its
  history row — or vice versa.

Purity note: no database driver, no FastAPI and no ``app.exposure`` import
here — the unit suite's kernel purity guard asserts a clean ``sys.modules``
and must hold in any run order. The actor and timestamp are NOT duplicated in
``detail``: they are already first-class columns on the event row
(``actor``/``actor_role``/``created_at``), which is the existing machinery —
no second history store is invented.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

# The taxonomy fields the projection carries and the history must preserve.
TAXONOMY_FIELDS = ("taxonomy_class", "taxonomy_subclass", "taxonomy_subtype")


def normalize_rationale(rationale: Optional[str]) -> Optional[str]:
    """Return the trimmed rationale, or ``None`` when it carries no content.

    ``None`` is the fail-closed signal: a classification decision without a
    rationale is rejected before any row is touched.
    """
    if rationale is None:
        return None
    trimmed = rationale.strip()
    return trimmed or None


def _taxonomy_projection(row: Mapping[str, Any]) -> dict[str, Optional[str]]:
    return {field: row.get(field) for field in TAXONOMY_FIELDS}


def build_transition_detail(
    prior: Mapping[str, Any],
    *,
    taxonomy_class: str,
    taxonomy_subclass: Optional[str],
    taxonomy_subtype: Optional[str],
    rationale: str,
) -> dict[str, Any]:
    """The append-only before/after payload for one classification decision.

    Every element of the contract lands in one typed object: the prior
    class/subclass/subtype, the new values and the rationale. The actor and
    timestamp live on the event row itself.
    """
    prior_taxonomy = _taxonomy_projection(prior)
    new_taxonomy = {
        "taxonomy_class": taxonomy_class,
        "taxonomy_subclass": taxonomy_subclass,
        "taxonomy_subtype": taxonomy_subtype,
    }
    return {
        "prior": prior_taxonomy,
        "new": new_taxonomy,
        # TRUE for the first classification, FALSE for a reclassification —
        # an analyst can tell "classified for the first time" from "changed
        # the earlier decision" without reconstructing the event order.
        "prior_unclassified": prior_taxonomy["taxonomy_class"] is None,
        "rationale": rationale,
    }