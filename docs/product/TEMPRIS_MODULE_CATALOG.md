# Tempris Module Catalog

The browser is a single-page application. Core compiled views are supplemented by `frontend/extensions/tempris-modules.js`; all authoritative mutations occur through authenticated backend routes registered in `backend/index.py`.

## Module summary

| Area | Classification | Route | Audience | Owns | Consumes |
|---|---|---|---|---|---|
| SYNTHESIS | Commercial module | `/` | All entitled users | Comparable posture snapshots | Canonical posture, module health |
| SPECTRUM | Commercial module | `/spectrum` | Analysts, managers | Finding registry, EDIP decisions/evidence | Intake, SCOUT, reference imports |
| SCOUT | Commercial module | `/scout` | Analysts/operators | Scan jobs and scan observations | Assets, scanner engines, reference catalogue |
| STRIKE | Commercial module | `/strike` | Authorized validation staff | Authorizations, simulations, results | Signed rules of engagement |
| STANDARD | Commercial module | `/standard` | Compliance/security staff | Control assessments/evidence, MAS drafts | Incidents, canonical exposure |
| GRC | Commercial module | `/grc` | Governance staff | AI-governance state, policies, evidence | GRC control definitions |
| ASSETS | Commercial module | `/assets` | Asset owners/operators | Tenant asset inventory | Manual inventory input |
| SPOTLIGHT | Commercial module | `/spotlight` | Executives/report writers | Narrative report history | Canonical tenant facts and safe RAG context |
| CISO | Commercial module | `/ciso` | Admin/Superadmin executives | Read-only executive aggregation | Canonical posture, controls, reports, incidents |
| Client Reports | Platform utility | `/reports` | Admin/report writers | Immutable report registry and artifacts | Canonical exposure, controls, evidence |
| Tenant & Module Administration | Administrative capability | `/packages` | Superadmin | Packages, overrides, configuration version | Tenant registry and entitlement policy |
| Intake & Triage | Platform utility | `/sss-intake` | Analysts/Admin/Superadmin | Intake records and exposure classifications | Assets, connectors, Finding Registry |
| VDP Queue | Internal security operation | `/vdp-queue` | Restricted staff | Researcher submissions and dispositions | Public VDP/SURGE intake |
| Audit Log | Shared platform service | `/audit` | Authorized assurance/admin users | Hash-chained audit records | Mutations across modules |
| SPEAK | Shared platform service | Floating action | Entitled authenticated users | Chat sessions/messages | Tenant-safe platform context and RAG |

DOMINATE’s nine-module count refers only to the nine commercial modules from SYNTHESIS through CISO. Client Reports, Intake & Triage, VDP Queue, Tenant Administration, Audit Log, and SPEAK are utility, administrative, internal-operation, or shared-service surfaces and are not separately counted commercial modules unless the backend entitlement configuration explicitly says otherwise.

## SYNTHESIS

- **Purpose:** prioritized tenant exposure overview and enabled-capability health.
- **Trace:** compiled `/` page → `GET /api/synthesis/dashboard` → `routers/synthesis.py::get_dashboard_data` → `workflow_connections.build_exposure_coverage` → `customer_posture.build_customer_posture` → `findings`, `assets`, `asset_exposures`.
- **Actions:** Refresh is read-only; `POST /api/synthesis/tes-snapshot` stores a comparable `PostureSnapshot`.
- **Metrics:** Tenant TES, trend, confirmed exposure coverage, module health, confirmed KEV alerts. Catalogue-only KEV records are excluded from alerts.
- **Caveat:** trend is unavailable/not comparable until two same-scope snapshots exist.
- **Tests:** `tests/test_ciso_grc_tenant.py`, canonical posture tests.

## SPECTRUM

- **Purpose:** broad tenant Finding Registry and server EDIP decision view.
- **Trace:** `/spectrum` → `GET /api/spectrum/findings?scope=` → `routers/spectrum.py::list_findings` → `Finding`, `AssetExposure`, EDIP history/evidence models.
- **Scopes:** confirmed exposure, unmapped intake, suggested match, reference intelligence, not applicable, resolved, catalogue, and legacy-unverified.
- **Actions:** Generate EDIP Decision posts to `/api/spectrum/findings/{id}/edip`; relationship/source/control/evidence APIs preserve analytical context.
- **Authority:** it displays server decisions and finding TES; it does not score in the browser.

## SCOUT

- **Purpose:** authorized discovery plus clearly separated reference intelligence.
- **Trace:** `/scout` → `/api/scout/stats`, `/api/scanner/history`, `/api/scanner/findings` → `routers/scout.py`, `routers/scanner.py` → `ScanJob`, `ScanFinding`, `Finding`, `AssetExposure` through `scan_normalizer.normalize_observation`.
- **Reference group:** stored reference/catalogue records and labels; not customer exposure.
- **Scan group:** runs, observations, normalized finding candidates, and confirmed links.
- **Actions:** Run SCOUT Scan requires explicit authorization confirmation and server target policy validation.
- **State:** `No EDIP decision` means exactly that; it is not an “active vulnerability” claim.

## STRIKE

- **Purpose:** evidence-aware authorized validation against signed scope.
- **Trace:** `/strike` → `/api/strike/authorizations`, `/api/strike/simulations`, `/api/strike/matrix` → `routers/strike.py` and `services/adversary_engine.py` → `StrikeAuthorization`, `StrikeSimulation`.
- **Outcomes:** `EXPLOITABLE_OBSERVED`, `NO_EXPOSURE_OBSERVED`, `DEFENSIVE_BLOCK_VERIFIED`, `UNTESTED`, `ERROR`.
- **Actions:** create/sign authorization, generate simulation. All records are tenant scoped.
- **Caveat:** “check confidence” describes the check, not protection effectiveness. A defensive block requires evidence and a control identifier.

## STANDARD

- **Purpose:** CTEM-linked regulatory/security control assessment, evidence, advisories, and incident notification drafting.
- **Trace:** `/standard` → `/api/standard/frameworks` and control/evidence routes → `ControlStatus`, `ControlEvidence`; incident route → `Incident` → `IncidentReport`.
- **Metrics:** assessment coverage and compliance among assessed controls are separate.
- **Actions:** update control, attach/delete evidence, generate MAS draft from an actual incident.
- **Caveat:** a draft is not a submitted regulatory notification and never uses global catalogue totals as incident facts.

## GRC

- **Purpose:** AI-governance inventory, SOP/sign-off, policy, evidence, and AI-system risk workflow. It is not STANDARD.
- **Trace:** `/grc` → `/api/grc/state|controls|gap-analysis|policies` → `GrcState`, `GrcSignoff`, `GrcPolicyDocument`, GRC evidence records.
- **Actions:** save state, sign off, create/edit/archive/restore/supersede/delete custom policy, attach evidence.
- **Policy rules:** bundled content is immutable; unreferenced custom policy can be Superadmin-deleted; referenced custom policy archives instead; lifecycle actions are audited.
- **Scoring:** client sees only final AI-system score, band, direction, qualitative drivers, scope, and timestamp.

## ASSETS

- **Purpose:** tenant asset inventory, ownership, identifiers, environment, criticality, and lifecycle.
- **Trace:** `/assets` → `/api/assets` and `/api/assets/stats` → `routers/assets.py` → `Asset`.
- **Actions:** add/edit/decommission/delete subject to role checks. Exact IP/hostname/domain identifiers support deterministic SCOUT mapping.
- **Caveat:** recorded criticality supplies context; CISO’s exposed-asset ranking is based on linked finding severity/count, not asset criticality alone.

## SPOTLIGHT

- **Purpose:** executive narrative generated from tenant-safe authoritative facts.
- **Trace:** `/spotlight` → `POST /api/spotlight/generate` → `services.ai_context.build_service_ai_context` → canonical posture/control/STRIKE facts plus RAG → `SpotlightReport`.
- **Actions:** generate report; history is read through `/api/spotlight/history`.
- **Time:** history rows preserve generation timestamp and stored TES metadata. They are historical reports, not live CISO posture.
- **Fallback:** deterministic offline narrative uses the same structured context if the LLM is unavailable.

## CISO

- **Purpose:** authoritative read-only executive view of current customer posture.
- **Trace:** `/ciso` → `/api/ciso/summary` → `routers/ciso.py::get_ciso_summary` → canonical posture plus controls, snapshots, reports, and incident drafts.
- **Metrics:** confirmed critical/high/open findings, classification queue, reference intelligence, most exposed assets, priority remediation items, incident drafts, comparable trend.
- **Actions:** Refresh and navigation only; mutations happen in the source module.

## Client Reports

- **Purpose:** immutable HTML/JSON/CSV current-state report packages.
- **Trace:** `/reports` → `/api/reports/poc/generate` → `reporting_engine.generate_poc_report_pipeline` → canonical exposure rows/evidence → `GeneratedReport` and configured artifact storage.
- **Actions:** preview/download/details; edit as new draft; regenerate new version; archive/restore; Admin-only delete subject to lifecycle rules.
- **Integrity:** content hash covers generated content. Direct editing is intentionally unavailable.
- **Time:** `snapshot_type=current_state`; assessment period is context only.

## Tenant & Module Administration

- **Purpose:** manage tenant package and module entitlements without impersonation.
- **Trace:** `/packages` → `/api/tenants` and `/api/packages/current` → `routers/tenants.py`, `routers/packages.py`, `services.entitlements` → tenant/package configuration.
- **Breakdowns:** recorded/active/decommissioned assets; total stored findings, confirmed exposure, needs classification, reference, resolved, not applicable.
- **Actions:** assign package/apply override; configuration version prevents accidental overwrite.

## Intake & Triage

- **Purpose:** create and classify tenant finding records, then confirm affected assets at the human evidence boundary.
- **Trace:** forms/connectors → `/api/edip/intake/*` → `Finding`; queue → `/api/workflow/overview`; Assign Assets → `/api/workflow/findings/{id}/assets` → `AssetExposure` → refresh event and canonical posture.
- **Registry contents:** mapped, unmapped, resolved, reference, not-applicable, connector, scanner, catalogue, and manual records.
- **Queue:** only records needing classification. A record may remain in registry while leaving the queue.
- **Actions:** assign/clear assets, reference, not applicable, patch flag, resolve, reopen.

## VDP Queue

- **Purpose:** confidential researcher submission triage.
- **Trace:** public `/api/surge/public/submit` → `SurgeSubmission`; restricted `/api/surge/submissions` → accept/reject/duplicate/delete → accepted finding enters SPECTRUM.
- **Actions:** search/filter/select; accept, duplicate, reject; authorized removal. Actions are tenant/role restricted and audited.

## Audit Log

- **Purpose:** append-only accountability with tenant-scoped verification.
- **Trace:** module mutation → `routers.audit.append_to_audit_log_db` → `AuditLog`; `/api/audit/log` lists and `/api/audit/verify` verifies chain integrity.
- **Caveat:** `OperationalEvent` is the structured aggregation foundation; `AuditLog` remains human/audit evidence. Neither should contain secrets.

## SPEAK

- **Purpose:** conversational explanation of current tenant data and product concepts.
- **Trace:** floating button → SPEAK endpoint in `index.py` → `services.ai_context`/RAG → `ChatSession` and `ChatMessage`.
- **Authority:** read/explain only. It does not create EDIP decisions or execute remediation.
- **Caveat:** generated language is explanatory; source module records remain authoritative.
