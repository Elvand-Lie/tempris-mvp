"""
Chapter 8 — EDIP (Remediation & Risk Decisions) (PRD-000 v1.11 Ch.8).

EDIP turns an exposure that requires action into an explicit remediation/
risk decision with ownership, deadlines, evidence, verification, and closure
— CONSUMING TES, never rewriting or multiplying it.

Structural boundaries this module enforces (mirrored by migration 030):

  * EDIP never writes scores, score states, or workflow status. The score a
    decision consumed is sealed as an immutable snapshot (§3.3.6 history-only
    writer; PATCH-13 one coherent ``as_of`` source view per consuming
    revision); the live score stays Ch.3's recompute-on-read truth.
  * EDIP never owns the exposure lifecycle. Verified closure emits the
    transition intent THROUGH the Ch.3 exposure service (``resolve_exposure``)
    inside ONE version-checked transaction (PATCH-09: compare-and-set on both
    states). Nobody else writes Ch.3 state.
  * Decision lifecycle (rule 2): Needs Decision → Planned → In Progress →
    Mitigated → Verification → Closed, with the active branch dispositions
    Accepted Risk / Deferred (mandatory review_due_at; the exposure stays
    current and visible) and the system-initiated Superseded. Closed and
    Superseded are the only terminals; VERIFIED precedes Closed.
  * Accepted Risk is dual-controlled (rule 8 — decided): the Ch.5 approval
    primitive (approver ≠ proposer, payload-bound, single-use) via
    ``app.edip.approval_consumers``.
  * History is a sequence of decision revisions; every score-consuming
    branch action seals its OWN fresh snapshot and replaces the prior
    revision. One CURRENT decision per exposure (Q7).
"""
