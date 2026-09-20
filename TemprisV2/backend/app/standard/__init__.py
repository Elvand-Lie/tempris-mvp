"""
Chapter 9 — STANDARD / GRC (Governance, Risk & Compliance) (PRD-000 v1.11).

Two separately-owned planes, one chapter:

  1. The governance SUBSTRATE — framework/control reference catalogs (the 8
     STANDARD frameworks carry over), control assessments (the end_user/PIC
     dual sign-off pattern), policies (registry + archive/supersede
     versioning), control evidence (typed inline store), exceptions. This is
     compliance STATE, never scoring input.
  2. Obligations & regulatory INCIDENTS — the MAS pattern generalized:
     deduped incident candidates, explicit rule objects
     (condition → obligation template + policy clock), durable rule
     evaluations (PATCH-11), immutable submission proof, human submission
     through the official channel (Tempris never submits to a regulator).

THE HARD BOUNDARY IS STRUCTURAL (frozen decision 1): no module outside
Chapter 3 may write score-bearing fields. No table in this module carries a
score column and no code here touches findings or asset_exposures. V1's
GRC modifier chain (AGM/DRF/TEF into SSS) is retired, not ported (§3.6.5,
D-3). The ``standard.py`` non-mutation precedent becomes the module-wide
rule. EDIP→compliance evidence integration is BY REFERENCE — mapped, never
re-scored (frozen decision 6).

Deadline state derives AT READ TIME (V1 workflow_connections precedent):
``overdue`` computes from ``due_at`` whenever read and breach is recorded
when first observed — the codebase's first background worker does not exist
(Ch.9 open decision #1) and no deadline correctness depends on one
(PATCH-12: due_at persists at creation; retries never restart the clock).
"""
