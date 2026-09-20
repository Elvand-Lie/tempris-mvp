# PRD-derived acceptance checklist — Chapters 10–12 (PRD-000 v1.11)

Working checklist mapping each binding rule of PRD-000 Chapters 10/11/12 to the
test that proves it. Kept beside the suites it drives
(`test_ch10_*.py`, `test_ch11_*.py`, `test_ch12_*.py`).

## Chapter 10 — CISO / SPOTLIGHT (Executive View)

| # | Binding rule (PRD) | Test |
|---|---|---|
| C10-1 | Read-only consumer; whole input set is already contract (Ch.3 summaries, Ch.7 workflow, Ch.8/9 states, coverage/quality) | `test_ch10_spotlight.py::TestSummary*` |
| C10-2 | Severe-exposure visibility is count + max based; max, NEVER mean — binding on every tile | `test_max_never_mean_tile_matches_extreme_exposure` |
| C10-3 | PROVISIONAL and FINAL always render separately everywhere (no state blending) | `test_final_and_provisional_maxima_render_separately` |
| C10-4 | No tenant-wide risk index by default; V1 `aggregate_tes` mean retired | `test_no_tenant_wide_composite_index_in_payload` |
| C10-5 | Upstream state unavailable → tile renders "unavailable", never zero | `test_missing_upstream_domains_render_unavailable_not_zero` |
| C10-6 | Feed-stale inputs render stale (Ch.1/Ch.3 freshness carried through) | `test_feed_health_tile_surfaces_sync_state` |
| C10-7 | Snapshot capture is append-only, never overwrites history (captured_at, captured_by, payload hash, referenced upstream states) | `test_snapshot_is_append_only` + migration trigger |
| C10-8 | Trends read append-only snapshots; deltas computed between snapshots | `test_snapshot_capture_and_trend_delta` |
| C10-9 | Every number links to the authoritative objects that produced it (drill-down is identity, not copy) | `test_severe_tile_carries_source_identities` |
| C10-10 | Read role gates per Ch.5 (analyst+ read, admin+ capture); module gate; platform sessions blocked | `TestAccessControl` |
| C10-11 | Same-tenant scoping on everything | `TestTenantIsolation` |
| C10-12 | Metrics carry deterministic definitions + as-of provenance | `test_summary_carries_as_of_and_metric_definitions` |
| C10-13 | Capture is audited (Ch.5 audit choke point) | `test_snapshot_capture_is_audited` |

## Chapter 11 — SPEAK / Reports (Deliverables)

| # | Binding rule (PRD) | Test |
|---|---|---|
| C11-1 | Generation never mutates scoring or workflow state (a report is a reader, never a writer) | `test_generation_mutates_nothing` |
| C11-2 | Content-hash-sealed for ALL types; template identity + version; generator actor | `test_report_is_sealed_with_template_and_actor` |
| C11-3 | Sealed score values — §3.3.6 snapshot writer: rendered values stored, NOT recomputed at view time | `test_sealed_values_survive_upstream_change` |
| C11-4 | One coherent source view at a fixed as_of; source identities/versions sealed | `test_seal_carries_source_view_identities` |
| C11-5 | Regeneration creates a NEW version row (parent chain, version+1); old row intact | `test_regenerate_creates_new_version_row` |
| C11-6 | Approved/exported reports cannot be deleted — archive only (hard delete retired) | `test_approved_report_cannot_be_deleted` |
| C11-7 | Register validates tenant exposure ownership at register (V1 posture kept) | `test_register_rejects_cross_tenant_and_foreign_exposures` |
| C11-8 | Artifacts sealed with own hash; download verifies; mismatch → refuse + alarm | `test_download_refuses_and_alarms_on_hash_mismatch` |
| C11-9 | Export writes an audit event (provenance: who/when) | `test_export_is_audited` |
| C11-10 | SPEAK/AI surface fails closed with no model — never invents numbers (mock fallback retired) | `test_speak_chat_fails_closed_without_model` |
| C11-11 | Spreadsheet-formula injection guard on CSV artifacts | `test_csv_artifact_neutralizes_formula_injection` |
| C11-12 | Tenant isolation on register/list/download; module gate; admin+ approval/export gates | `TestAccessControl`, `TestTenantIsolation` |
| C11-13 | Bounded listing / artifact size | `test_list_is_bounded` |
| C11-14 | AI output never consumed as state; report content is never authority (no upstream writes anywhere in the chapter) | `test_generation_mutates_nothing` (row counts) |

## Chapter 12 — SYNTHESIS (Correlation)

| # | Binding rule (PRD) | Test |
|---|---|---|
| C12-1 | Read-time joins over authoritative objects; every row keeps links back to source rows; no new truth stored | `TestUnremediatedSerious`, all endpoints |
| C12-2 | v1 = read-time joins ONLY (materialized summaries deferred behind the scheduler decision) | `test_queries_write_nothing` |
| C12-3 | Degrade loudly: a join built on a missing/failed input domain NAMES the missing domain (silent try/except retired) | `test_missing_domains_are_named_loudly` |
| C12-4 | Unremediated serious exposures: deterministic definition, carried in the answer | `test_unremediated_serious_definition_is_carried` |
| C12-5 | Accepted risks ⋈ obligations: named-missing-domain degradation while Ch.8/Ch.9 are absent | `test_accepted_risk_obligation_join_degrades_without_ch8_ch9` |
| C12-6 | Remediation-recurrence (PATCH-14): new episodes linked to `resolved` predecessors of the same (tenant, finding, asset) tuple; false_positive/supersession episodes are NOT recurrences | `test_recurrence_pairs_resolved_predecessor`, `test_false_positive_and_superseded_are_not_recurrences` |
| C12-7 | Evidence-strength vs coverage gaps: UNSCOREABLE renders, never hides | `test_coverage_gap_names_unscoreable_and_missing_evidence` |
| C12-8 | Feed stale → correlations involving that domain render stale | `test_stale_feed_marks_rows_stale` |
| C12-9 | Deterministic: same inputs → same answer (no time-of-day variance beyond the declared as_of) | `test_answers_are_deterministic` |
| C12-10 | No AI/LLM layer, no prose generation, no upstream writes; tenant-scoped only; module gate | `TestGovernance` |
| C12-11 | Tenant isolation on every correlation | `TestTenantIsolation` |

## Cross-chapter authority checks (regression)

- Ch.3 remains the only score authority: Chapters 10–12 never write
  `asset_exposures`, ledgers, findings, or scores — `test_generation_mutates_nothing`,
  `test_queries_write_nothing` (row-count deltas on upstream tables).
- Ch.7 workflow rows untouched by reads (SPOTLIGHT/SYNTHESIS are read-through).
- Existing focused suites re-run: `test_ch7_spectrum_api.py`,
  `test_exposure_api.py` (authority/tenant invariants intact).
