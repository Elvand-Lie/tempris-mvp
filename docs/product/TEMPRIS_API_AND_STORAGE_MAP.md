# Tempris API and Storage Map

`backend/index.py` mounts the routers below. Authentication supplies server tenant context; path/body tenant values never authorize access by themselves.

## Route groups

| Prefix / direct route | Router/service | Primary persistence | Purpose |
|---|---|---|---|
| `/api/auth` | `routers/auth.py` | `UserSession`, account security tables | Login/logout/session management |
| `/api/synthesis` | `routers/synthesis.py` | `PostureSnapshot` plus canonical reads | Dashboard and snapshot capture |
| `/api/spectrum` | `routers/spectrum.py` | `Finding`, EDIP decisions, relationship/source/control/evidence/history tables | Confirmed-exposure analysis, scoring contract, EDIP context, and authorised Business Impact assessment |
| `/api/scout` | `routers/scout.py` | `Finding`, `ScanFinding`, `ScanJob` reads | Reference and scan statistics |
| `/api/scanner` | `routers/scanner.py` → `services/scan_normalizer.py` | `ScanJob`, `ScanFinding`, `Finding`, `AssetExposure` | Authorized scanner execution/history/normalization |
| `/api/strike` | `routers/strike.py` → `services/adversary_engine.py` | `StrikeAuthorization`, `StrikeSimulation` | Authorized validation and explicit outcomes |
| `/api/standard` | `routers/standard.py` | `ControlStatus`, `ControlEvidence`, `IncidentReport`, reads `Incident` | Frameworks, evidence, advisories, MAS draft |
| `/api/grc` | `routers/grc.py` | `GrcState`, `GrcSignoff`, `GrcPolicyDocument`, GRC evidence | AI-governance workflow/policy lifecycle |
| `/api/assets` | `routers/assets.py` | `Asset` | Tenant inventory CRUD/stats |
| `/api/edip` | `routers/edip.py` | `Finding`, decisions, evidence/history | SSS/intake/connectors/watch stream |
| `/api/workflow` | `routers/workflow.py` → exposure/posture services | `Finding`, `AssetExposure`, history | Review queue, classification, assign, resolve/reopen |
| `/api/ciso` | `routers/ciso.py` | Read-only across canonical posture, snapshots, controls, reports | Executive current posture |
| `/api/reports` | `routers/reports.py` → `services/reporting_engine.py` | `GeneratedReport` + artifact storage | Immutable report lifecycle |
| `/api/packages` | `routers/packages.py` | Tenant package configuration | Current tenant entitlement |
| `/api/tenants` | `routers/tenants.py` | Tenant/package configuration plus canonical reads | Superadmin tenant/module administration |
| `/api/incidents` | `routers/incidents.py` | `Incident`, `OperationalEvent`, `AuditLog` | Idempotent incident compatibility API |
| `/api/surge` | `routers/surge.py` | `SurgeResearcher`, `SurgeSubmission`, accepted `Finding` | VDP intake/triage |
| `/api/audit` | `routers/audit.py` | `AuditLog` | Tenant audit list/write/chain verification |
| `/api/spotlight/generate`, `/history` | `index.py` → `services/ai_context.py` | `SpotlightReport` | Narrative generation/history |
| SPEAK routes in `index.py` | `index.py`, `ai_context`, RAG/LLM services | `ChatSession`, `ChatMessage` | Tenant-safe conversational explanation |

Supporting route groups (`/api/aev`, `/api/blflaw`, `/api/partner`, `/api/ocq`, `/api/threats`) supply existing connectors/workflows. They do not redefine canonical customer exposure.

## Core objects

| Object/table | Key fields | Authority and lifecycle |
|---|---|---|
| `Finding` / `findings` | tenant, source, status, CVE/SSS data, `cve_context`, server score/decision inputs, legacy `asset_id` | Broad tenant registry. `asset_id` is preserved legacy history only. `cve_context` records analyst Business Impact and server score provenance; it is not a browser scoring contract. |
| `FrameworkDefinition` / `framework_definitions` | ISO framework id/version/server-managed metadata | One authoritative GRC framework catalogue. |
| `FrameworkControl` / `framework_controls` | control identity, requirement, modifier group, order | Server-managed ISO/IEC 42001 controls; customers cannot create controls. |
| `ControlAssessment` / `control_assessments` | tenant control status, PIC, notes, sign-offs | Canonical SOP Builder state used by Gap Analysis and server-side non-CVE context. |
| `PolicyControlLink` / `policy_control_links` | explicit policy-to-control support link | Supporting evidence only; no automatic completion or scoring effect. |
| `Asset` / `assets` | tenant, IP, hostname, tags, owner, criticality, environment, status | Tenant inventory. Decommissioned assets are excluded from current posture. |
| `AssetExposure` / `asset_exposures` | tenant, finding, asset, status, match method, evidence, metadata | Authoritative many-to-many confirmation. Unique per tenant/finding/asset. |
| `ScanJob` / `scan_jobs` | tenant, normalized target, engine/type, timestamps, status, count/error, authorization | One scanner run, including zero results/failure. |
| `ScanFinding` / `scan_findings` | tenant, scan, target, engine evidence, template/CVE, normalized finding, first/last seen | Idempotent scanner observation; may remain observation-only. |
| `StrikeAuthorization` / `strike_authorizations` | tenant, target/scope, rules, signer/status | Required authorization boundary. |
| `StrikeSimulation` / `strike_simulations` | tenant, authorization, result matrix/evidence | Historical explicit validation outcomes. |
| `ControlStatus` / `control_statuses` | tenant, framework, control, status, evidence metadata | STANDARD assessment state. |
| `ControlEvidence` / `control_evidence` | tenant/framework/control, file/reference/integrity metadata | STANDARD evidence record. |
| `GrcPolicyDocument` / `grc_policy_documents` | tenant, version/content, archive/supersede/delete metadata | Custom policy lifecycle; bundled policies remain repository-owned. |
| `Incident` / `incidents` | tenant, source/external ID, discovery, severity/status, assets/findings/evidence/actions | Real observed event. Unique `(tenant, source, external_event_id)`. |
| `IncidentReport` / `incident_reports` | tenant, source incident in payload, generated status/severity/deadline | Generated notification draft; never an incident source itself. |
| `PostureSnapshot` / `posture_snapshots` | tenant, captured time, scope version, canonical counts, Tenant TES | Comparable evidence-scoped posture history. |
| `GeneratedReport` / `generated_reports` | tenant, version, source IDs, content hash, artifact location, lifecycle config | Immutable report registry/artifact metadata. |
| `SpotlightReport` / `spotlight_reports` | tenant, narrative, stored TES metadata, generator/time | Historical narrative report. |
| `OperationalEvent` / `operational_events` | tenant, event type/time, actor/resource/module, metadata/correlation | Structured aggregation foundation, never a scoring source. |
| `AuditLog` / `audit_logs` | tenant/user/action/module/detail/metadata/hash chain | Human/audit accountability and integrity verification. |

## Recursive examples

### Assign Assets

`extensions/tempris-modules.js` asset dialog → `PUT /api/workflow/findings/{finding_id}/assets` → `routers/workflow.py::replace_finding_assets` → `services/exposure_links.py::set_finding_assets` → `AssetExposure` + `FindingStatusHistory`/audit/event → SSE watch → SPECTRUM/CISO/SYNTHESIS refresh.

### Generate Client Report

Client Reports form → `POST /api/reports/poc/generate` → `routers/reports.py::generate_poc_report` → `services/reporting_engine.py::generate_poc_report_pipeline` → `customer_posture.canonical_exposure_rows` + evidence/control reads → immutable HTML/JSON/CSV + `GeneratedReport` + hash/event.

### Nuclei CVE

SCOUT form → `POST /api/scanner/scan` → scanner engine → `ScanJob`/raw observation → `scan_normalizer.normalize_observation` → reuse/create tenant CVE `Finding` → exact target match → confirmed `AssetExposure` or review queue → watcher and canonical posture consumers.

### Assess CVE Business Impact

Confirmed open CVE in SPECTRUM → `PATCH /api/spectrum/findings/{finding_id}/business-impact` → `routers/spectrum.py::update_business_impact` → validated 0-10 assessment plus justification in `Finding.cve_context` → server-side current CVE recalculation, audit/operational event, and finding refresh. The action is tenant-scoped and does not change CVSS or confirm an asset link.

### Incident draft

Authenticated integration → `POST /api/incidents` → link validation → `Incident` → operator requests `POST /api/standard/mas-trm/incident-report` with incident ID → intersection with canonical exposure → `IncidentReport` draft.

## Incident client example

See [`examples/incident_intake.py`](examples/incident_intake.py). It uses placeholder values and does not contain a live credential or target.
