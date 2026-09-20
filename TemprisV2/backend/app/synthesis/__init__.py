# backend/app/synthesis
"""SYNTHESIS — deterministic correlation (PRD-000 v1.11 Ch.12).

A correlation service with one binding hard rule: SYNTHESIS correlates
truth; it does not manufacture truth. v1 is read-time joins ONLY (the
frozen decision — materialized summaries wait for the scheduler decision);
every answer keeps links back to the authoritative rows it was computed
from, degrades LOUDLY when an input domain is missing, and never involves
an AI layer.
"""
