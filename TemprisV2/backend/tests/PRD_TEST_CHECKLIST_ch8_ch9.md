# PRD-derived test checklist — Chapters 8–9 (working checklist, wave-b)

Derived from TEMPRIS_V3_GLOBAL_PRD.md (v1.11) Ch.8, Ch.9, Ch.3 §3.3.1/§3.3.6,
Ch.7 rule 6, Appendix A Flows D–E, Appendix B D-16, Appendix C Q6–Q19,
Appendix D PATCH-09/10/11/12/13. Each item maps to a named test.

## Chapter 8 — EDIP (test_ch8_edip.py)

| # | PRD requirement (source) | Test |
|---|---|---|
| 1 | Module entitlement gate; platform tenant blocked; analyst+ authority (Ch.8 security boundaries) | TestAccessControl |
| 2 | Decision creation from SPECTRUM handoff: Needs-Decision, snapshot sealed at creation (Ch.7 rule 6, §3.3.6 writer, PATCH-13 coherent as_of) | TestHandoffAndCreation |
| 3 | Handoff retry correlation: handoff → CONSUMED, correlated to the decision; second decision refused while one stands (PATCH-09, Q7 one non-terminal decision per exposure) | TestHandoffAndCreation |
| 4 | Missing decomposition payload at handoff ⇒ decision cannot be created (fail-closed) — UNSCOREABLE snapshot blocks accept/defer consumption guards | TestHandoffAndCreation |
| 5 | State machine Needs Decision → Planned → In Progress → Mitigated → Verification → Closed; invalid edges refused (Ch.8 rule 2) | TestStateMachine |
| 6 | Unified vocabulary remediate|mitigate|accept-risk|defer (Ch.8 rule 5) | TestStateMachine |
| 7 | Close without verification evidence ⇒ refused (blflaw lesson; failure modes) | TestVerificationAndClosure |
| 8 | Verified closure is ONE version-checked transaction: decision closes AND the exact episode resolves through the Ch.3 exposure service; compare-and-set on both states (rule 4, PATCH-09, D-16) | TestVerificationAndClosure |
| 9 | Verification binds decision revision + current observation version; newer contradictory evidence invalidates it (PATCH-09) | TestVerificationAndClosure |
| 10 | EDIP never writes scores or workflow status; exposure stays `confirmed` through planning/mitigation/verification; finding status untouched (rule 4, D-5/D-16, §3.3.1) | TestNeverWritesCh3 |
| 11 | Accepted Risk is dual-controlled via the Ch.5 primitive: approver ≠ proposer, payload-bound, single-use; fresh snapshot per revision (rule 8, PATCH-13, Q11) | TestAcceptedRiskDualControl |
| 12 | Accepted/Deferred carry mandatory review_due_at; exposure stays current+visible while accepted/deferred (rule 2/8) | TestAcceptedRiskDualControl / TestDeferAndReviewExpiry |
| 13 | Review-expiry effective-state rule: once now ≥ review_due_at the decision IS Needs-Decision on every read/action; first observation materializes + audits; no scheduler (rule 2) | TestDeferAndReviewExpiry |
| 14 | Decision-level reopen (exposure still confirmed): dispute reopens the same decision; closed decisions never reopen (409); recurrence = NEW episode + NEW decision linked back (rule 9, D-16) | TestReopenAndRecurrence |
| 15 | Confirmation withdrawal / supersession auto-supersede the open decision (`confirmation_withdrawn`), effective on reads; no orphan decisions (rule 10, PATCH-10) | TestSupersession |
| 16 | Each decision revision seals its own immutable snapshot; later recomputes never rewrite it; recompute-on-read still reflects new inputs (rule 3, §3.3.6) | TestSnapshotSealing |
| 17 | Tenant isolation; cross-tenant reads/actions fail closed (Ch.8 security boundaries, Q10) | TestTenantIsolation |
| 18 | Every lifecycle mutation audited (Q12) | sprinkled asserts |

## Chapter 9 — STANDARD/GRC (test_ch9_standard.py)

| # | PRD requirement (source) | Test |
|---|---|---|
| 1 | Module entitlement gate; platform blocked; analyst+ (Ch.9 security boundaries) | TestAccessControl |
| 2 | 8 framework catalogs seeded; assessed-status per tenant; default not_assessed (target 1, §9 verified reality) | TestFrameworks |
| 3 | compliance_among_assessed only metric; every percentage renders WITH assessment coverage; bare percentage forbidden (frozen decision 5) | TestComplianceMetric |
| 4 | Control assessments: draft → signed (dual sign-off end_user/PIC, distinct actors) → archived (owned state, target 1) | TestAssessments |
| 5 | Policies: draft → active → superseded/archived versioning (owned state) | TestPolicies |
| 6 | Control evidence: typed allowlist store; download audited (Q12); EDIP remediation evidence mapped BY REFERENCE, never re-scored (frozen decision 6, open #4) | TestControlEvidence |
| 7 | Incident POST: validated, timestamped, deduped on (tenant, source, external_event_id); duplicates create no duplicate obligations (failure modes, V1 shape) | TestIncidentsAndRules |
| 8 | Rule evaluation creates obligation with due_at = trigger(event time) + clock (MAS 12.1.5: 1h); receipt/retry never starts or restarts the clock (PATCH-12, Flow E) | TestIncidentsAndRules |
| 9 | Rule evaluation failure fails VISIBLY on the incident: evaluation_error/manual_review_required row persisted, no obligation, incident unresolved (failure modes) | TestEvaluationFailure |
| 10 | PATCH-11: rule-relevant incident edit atomically creates new input revision, re-pends ALL expected rules (negatives included), reopens a resolved incident with audit; stale attempts remain history; current-revision check guards results | TestIncidentRevisions |
| 11 | Reevaluation reuses stable obligation identities, never duplicates; corrections audited using corrected trigger facts, preserving prior values + submission history (PATCH-11/12) | TestIncidentRevisions |
| 12 | Read-time overdue/breach derivation; breach recorded when first observed; completed-late derives separately and survives closure (failure modes, PATCH-12) | TestObligationsAndSubmissions |
| 13 | Submission without proof → refused; obligation never auto-closed; submission record immutable; human submits outside, Tempris records proof (Flow E, failure modes) | TestObligationsAndSubmissions |
| 14 | Required unfinished evaluations/obligations block resolution; commit-time revision check (PATCH-11) | TestResolutionBlocking |
| 15 | Boundary made structural: no score-bearing writes from outside Ch.3 — no score columns in any standard_* table; exposure/finding state unchanged across a full incident flow (frozen decision 1, D-3) | TestScoringBoundary |
| 16 | Tenant isolation for every surface (Q10) | TestTenantIsolation |
| 17 | Exceptions: requested → approved(admin+) → expired with mandatory expires_at; expiry effective-on-read (open decision #6 deferred — v1 authority = admin+) | TestExceptions |
