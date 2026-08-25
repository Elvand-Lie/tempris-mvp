# SYNTHESIS

**Purpose:** Executive tenant exposure/posture aggregation built from authoritative Tempris module data.

---

## Inputs

SYNTHESIS consumes — never produces — the following:

| Input | Source of truth |
|---|---|
| Confirmed customer exposure | `services/customer_posture.py` (`canonical_exposure_rows`, `build_customer_posture`, scope `canonical-customer-exposure-v1`) |
| TES scores | `services/tes_engine.py` (`calculate_finding_tes`), computed live over confirmed exposures |
| CISA KEV resolution | `services/cve_intelligence.py` (`resolve_vulnerability_intelligence`) + `CisaKevEntry` |
| Workflow completeness | `services/workflow_connections.py` (`build_workflow_readiness`, `build_exposure_coverage`) |
| Module telemetry | `services/workflow_connections.py` (`build_module_health`) |
| Global vulnerability intelligence | `CanonicalVulnerability`, `VulnerabilityCvssAssessment`, `CisaKevEntry` via `build_global_intelligence_summary` |
| TES trend | `PostureSnapshot` rows (30-day comparable, same `scope_version`) |

## Outputs

- `GET /api/synthesis/dashboard` — aggregate TES, exposure coverage populations, alerts (confirmed-exposure only), module health, global intelligence block, final-update counters.
- `POST /api/synthesis/tes-snapshot` — persists a `PostureSnapshot` (409 if no scoreable confirmed exposure exists).
- `GET /api/workflow/overview` — the same exposure/workflow/global-intelligence payload used by the dashboard UI (`routers/workflow.py`, requires SYNTHESIS entitlement).

## Source of Truth

- **Confirmed exposure:** the canonical customer exposure service (`customer_posture.py`). A confirmed exposure = tenant `Finding` + confirmed same-tenant `AssetExposure` + active same-tenant `Asset` + open (non-reference, non-N/A) finding status. **`Finding.asset_id` is a legacy export cache and is never confirmation.**
- **Global intelligence:** `CanonicalVulnerability` (CVE identity), `VulnerabilityCvssAssessment` (authoritative CVSS, provenance-preserving), `CisaKevEntry` (KEV catalogue). These tables are global/unscoped. Tenant `Finding` statistics (count, `priority`, `ransomware` flag) are **never** used for global intelligence numbers.

## Population Model (the five populations)

SYNTHESIS separates every stored tenant Finding into exactly one of:

1. **CUSTOMER EXPOSURE** — open finding with confirmed `AssetExposure` to an active asset. This is the only population that constitutes customer risk posture.
2. **CLASSIFICATION / REVIEW BACKLOG** ("Needs classification") — open, non-reference findings with no confirmed exposure that require analyst mapping (suggested asset match, scanner candidate, or non-catalogue intake).
3. **REFERENCE INTELLIGENCE** — findings explicitly marked `reference`/`catalogue` status. Catalogue awareness only; never customer exposure, never in TES.
4. **GLOBAL VULNERABILITY INTELLIGENCE** — the canonical spine tables. Completely outside the tenant Finding table.
5. **WORKFLOW COMPLETENESS** — coverage ratios computed **over population 1 only** (ownership, EDIP treatment).

These populations are never mixed into a shared denominator. `open_finding_count` (= 1 + 874 + 1367 = 2242 in the sample below) is a stored-record total and is never used as a coverage denominator.

## Metric Definitions

### Tenant TES
- **Definition:** mean of TES values across all *scoreable confirmed open* findings for the tenant.
- **Population:** confirmed exposures (population 1) that yield a valid `calculate_finding_tes` result.
- **Formula (conceptual):** `mean(TES(f) for f in confirmed_open_scoreable)`.
- **N/A behaviour:** if no scoreable confirmed exposure exists → `null` (displayed **N/A**), never 0.
- **Example:** 1 confirmed exposure scored at 9.0 → Tenant TES 9.0.

### Confirmed Exposure
- **Definition:** unique open Finding with ≥1 confirmed `AssetExposure` to an active same-tenant Asset, excluding reference/N-A statuses.
- **Counts:** finding–asset pairs from `asset_exposures` with `status="confirmed"`.
- **Does not count:** legacy `Finding.asset_id` pointers; reference-only records; needs-classification records; resolved/mitigated/ignored findings; global KEV catalogue entries.

### Needs Classification
- **Definition:** open, non-reference findings with no confirmed exposure that are queued for analyst asset mapping (scanner-derived candidates, suggested matches, non-catalogue intake).
- **Does not count:** reference intelligence, resolved findings, confirmed exposures.

### Reference Intelligence
- **Definition:** findings explicitly classified `reference`/`catalogue` — global awareness records with no customer exposure claim.
- **Does not count:** anything in the exposure or TES populations.

### TES Coverage
- **Numerator:** confirmed open exposures with a valid server-side TES score.
- **Denominator:** all confirmed open exposures.
- **Example:** `1/1 confirmed exposures scored (100%)`. Unscoreable confirmed exposures appear in `exposure_coverage.unscored_finding_ids`.

### CISA KEV Exposure
- **Definition:** confirmed open customer exposures whose CVE resolves to a `CisaKevEntry` (canonical resolution, legacy flag as read-only fallback).
- **Explicitly distinct from** the global CISA KEV catalogue count (`global_intelligence.cisa_kev_entries`). One is customer risk; the other is catalogue size. Both are labelled on-screen so they cannot be confused.

### Asset Ownership Coverage
- **Definition:** confirmed exposed assets (active assets behind population 1) that have an `owner` recorded / all confirmed exposed assets.

### EDIP Treatment Coverage
- **Definition:** confirmed open exposures with a **persisted analyst EDIP decision** (`EdipDecision` row, created only via the SPECTRUM decision endpoint) / all confirmed open exposures.
- **Recommendation vs decision:** EDIP engine recommendations (`auto_classify`) are display-time suggestions and are **not persisted as decisions**; they never count as treatment coverage. Tenant-wide historical `EdipDecision` counts (e.g. `decisions_with_rationale = 6`) are retained separately as operational history and are never used as confirmed-exposure coverage.

### Global Vulnerability Intelligence
- **Canonical CVEs:** row count of `CanonicalVulnerability`.
- **CISA KEV:** row count of `CisaKevEntry`.
- **Ransomware Linked:** `CisaKevEntry` rows with `known_ransomware_campaign_use = "Known"`.
- **CVSS Critical:** canonical CVEs whose **preferred authoritative assessment** (same deterministic `select_preferred_cvss_assessment` policy as the per-finding resolver: highest version → Primary role → latest modification) scores ≥ 9.0.
- **CVSS coverage:** assessed canonical CVEs / total canonical CVEs. When coverage is absent the dashboard shows the coverage context explicitly; it never falls back to `Finding.priority`.

## Example (current production-like sample)

| Population | Value | Why it is different |
|---|---|---|
| Confirmed exposure | 1 | One open finding with a confirmed asset link — the actual customer risk |
| Needs classification | 874 | Open records awaiting analyst mapping — backlog, not confirmed risk |
| Reference intelligence | 1,367 | Reference-only catalogue records — awareness only |
| Stored open records | 2,242 | 1 + 874 + 1367 — a bookkeeping total, never a denominator |
| Tenant TES | 9.0 | Mean over the 1 scoreable confirmed exposure |
| CISA KEV exposure | 1 | The confirmed exposure resolves to KEV |
| Global KEV catalogue | (e.g. 1,602) | Catalogue size — unrelated to the tenant's 1 exposure |

## Dependencies

ASSETS (active assets, owners) · SCOUT canonical intelligence (`CanonicalVulnerability`/`CisaKevEntry`/`VulnerabilityCvssAssessment`) · SPECTRUM (findings lifecycle, EDIP decisions) · TES engine · EDIP engine · customer_posture (canonical exposure) · workflow_connections (coverage/health) · PostureSnapshot history.

## Consumers

CISO dashboards · SPOTLIGHT report context · Client Reports (via the same posture service) · the SYNTHESIS dashboard UI (compiled SPA + `tempris-modules.js` extension layer).

## What SYNTHESIS Does NOT Do

- Does not scan or create observations (SCOUT).
- Does not confirm or remove an exposure (SPECTRUM/workflow asset binding).
- Does not invent CVSS scores (intelligence spine only; no heuristic derivation).
- Does not treat CISA KEV membership as customer exposure or compliance violation.
- Does not include reference intelligence or needs-classification records in Tenant TES.
- Does not persist analyst EDIP decisions (SPECTRUM owns that).

## Known Limitations

- Module health cards mean "repository query succeeded + records exist" (`operational | recorded`) — data *presence*, not functional monitoring.
- TES trend requires ≥2 comparable `PostureSnapshot` rows within 30 days; otherwise no trend is shown.
- `build_customer_posture` loads all tenant findings into memory per request — fine at current scale, a future optimisation candidate.
- CVSS Critical is exact but bounded-scan based; with very large unassessed catalogues the coverage note (not the critical count) communicates completeness.

## Acceptance Invariants (test-backed)

1. Global intelligence cards derive only from the canonical spine; tenant Finding statistics cannot regress into them.
2. Reference intelligence never appears in confirmed exposure counts.
3. Needs-classification records never appear in confirmed exposure counts.
4. TES coverage denominator = confirmed open exposures.
5. Tenant TES = mean of scoreable confirmed open finding TES only.
6. No scoreable confirmed exposure ⇒ TES `null`/N/A, never a fake zero.
7. CISA exposure = confirmed exposure ∩ CISA KEV resolution.
8. EDIP treatment coverage uses the confirmed-exposure population only.
9. Asset ownership coverage uses confirmed exposed assets only.
10. Alerts surface only open confirmed exposures (reference-only KEV can never alert).
11. UI labels present the five populations separately with no shared misleading denominator.

Invariant coverage lives in `app/backend/tests/test_synthesis_semantics.py`.
