# Canonicalization Changelog

## SCOUT Wave 1: Scan Authorisation, Target-Binding, Execution Safety & SSRF Hardening (2026-08-18)

- Implemented Migration 013 (`013_asset_scan_authorizations.py`) adding additive `asset_scan_authorizations` table and `scan_jobs` target-provenance columns (`asset_id`, `scan_authorization_id`, `authorized_canonical_target`, `target_kind`, `resolved_ips`, `dns_resolved_at`, `initiating_user_id`, `execution_origin`, `failure_reason`).
- Decoupled asset inventory creation from scan authorization: all assets default to unauthorized; scans strictly require an explicit approved `AssetScanAuthorization` record.
- Restricted scan authorization approval to platform `Superadmin` only.
- Bound asset mutation to immediate scan authorization revocation: any modification of asset `hostname` or `ip_address` revokes active authorization with reason `"Asset target modified; re-authorization required"`.
- Implemented authoritative `TargetPolicyService` enforcing EASM global routability boundary and rejecting RFC 1918, loopbacks (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), cloud metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`), CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`), IPv4-mapped IPv6, CIDR blocks, wildcards, and non-http schemes.
- Hardened customer scan endpoints (`POST /api/scanner/run` and `POST /api/scanner/scan`) to accept only `asset_id`, deriving the canonical target from server-side approved authorizations and recording pre-execution DNS resolution.
- Enforced platform kill switch `SCOUT_ACTIVE_SCANNING_ENABLED` (default `false`, returning HTTP 503 when disabled), concurrency caps (2 per-tenant, 5 global), and 30s per-asset cooldown.
- Hardened scanner subprocess lifecycle with unprivileged connect scans (`-sT`), hard wall-clock timeouts with explicit `proc.kill()` and child-process reaping, bounded 10MB output buffers, and safe temp file cleanup.
- Implemented target drift protection in `scan_normalizer.py`, preventing automatic exposure confirmation if scanner target does not match authorized origin host/IPs.
- Updated frontend UI with target classification badges, authorization state indicators, modal dialogs for authorization requests and approvals (eliminating `window.prompt`), and kill switch / asset picker integration in SCOUT workspace.
- Executed full 316-test suite with 100% pass rate.

## Canonical CVE Spine Cutover (2026-08-18)

- Created Migration 011 for additive canonical vulnerability intelligence tables (`canonical_vulnerabilities`, `vulnerability_cvss_assessments`, `cisa_kev_entries`).
- Created Migration 012 for the Strangler Fig schema evolution adding `findings.canonical_cve_id` foreign key and index without modifying legacy columns.
- Implemented offline CLI intelligence importers for CISA KEV and NVD CVE 2.0 snapshots with cryptographic provenance hashing and idempotency.
- Implemented safe, idempotent exact finding linkage CLI with syntax validation (`CVE-YYYY-NNNN`), preserving non-CVE SSS findings with `canonical_cve_id = NULL`.
- Deployed server-authoritative Canonical Intelligence Resolver implementing the deterministic CVSS selection policy (valid assessments -> 4.0 > 3.1 > 3.0 > 2.0 -> Primary > Secondary -> latest source timestamp -> ID tiebreaker) and read-only legacy fallback.
- Integrated Canonical Intelligence Resolver into the Dynamic Live Context TES Engine, deriving CVSS, exploitability (KEV/ransomware/Nuclei match), and asset criticality from confirmed active assets.
- Decoupled global reference CVE notices from customer asset exposure, ensuring regulatory tracking notices never trigger false-positive customer compliance violations.
- Implemented and verified the 9 canonical cutover gates with a 100% test pass rate across all downstream systems (CISO, SYNTHESIS, SPECTRUM, STRIKE, Reporting Engine, Audit Log).
- Executed rehearsal database verification with zero orphaned foreign keys, zero historical score drift, and 100% invariant satisfaction.

## Native module UI restoration hotfix (2026-08-16)

- Restored the retained native SPECTRUM, SCOUT, STRIKE, STANDARD, GRC, and SPOTLIGHT route experiences after the canonicalization extension incorrectly replaced them with fixed-position overlays.
- Kept extension hosting only for newer utility/admin pages that do not have native compiled routes.
- Adapted the restored pages to canonical exposure, corrected STRIKE outcomes, STANDARD coverage/compliance, real-Incident MAS drafts, safe GRC score output, and canonical SPOTLIGHT source metrics.
- Made SYNTHESIS render an unavailable aggregate TES as `N/A` instead of calling `.toFixed()` on `null` or fabricating zero.
- Added executable route ownership and native-control regression checks.

## Canonical exposure v1

- Changed customer-exposure qualification from `Finding.asset_id` to confirmed `AssetExposure` on an active same-tenant asset.
- Preserved legacy pointers as `legacy_unverified` review data rather than silently promoting them.
- Excluded reference, not-applicable, resolved/closed, cross-tenant, and decommissioned-asset records from open posture.
- Consolidated CISO, SYNTHESIS, STANDARD, SPOTLIGHT, Client Reports, and Tenant Access on `CanonicalCustomerPostureService` semantics.
- Separated distinct confirmed findings from many-to-many affected-asset occurrences.
- Introduced `scope_version=canonical-customer-exposure-v1` posture snapshots and comparison rules.

## Presentation corrections

- Removed exact GRC scoring factors/formulas from client API and frontend presentation.
- Added explicit finding scope/status filters to SPECTRUM.
- Split SCOUT catalogue/reference metrics from customer scan activity.
- Replaced SCOUT’s ambiguous `Active` fallback with `No EDIP decision`.
- Replaced ambiguous STRIKE `BLOCKED` semantics with explicit observed outcomes.
- Split STANDARD’s percentage into assessment coverage and compliance among assessed controls.
- Relabelled intake registry semantics and retained resolved/reference/history records.

## Workflow additions

- Added resolve and reopen with preserved history, authorization, audit, operational events, and refresh.
- Added deterministic Nuclei normalization, exact target-to-asset resolution, scan jobs, evidence provenance, and idempotency.
- Added incident intake and made MAS drafts depend on an actual Incident.
- Added safe GRC policy archive, restore, supersede, and conditional hard deletion.
- Added structured `OperationalEvent` telemetry foundation without financial ROI calculation.

## Data preservation

Migration `scripts/migrations/008_canonical_posture_and_operations.py` adds schema and backfills tenant ownership where provable. It never converts legacy finding pointers into confirmed exposures. Existing reports, decisions, findings, assets, and audit history remain intact.

## Final readiness review (2026-08-15)

- Tightened confirmed-exposure status so only `confirmed`, never `accepted`, contributes to posture.
- Preserved removed asset associations as historical `AssetExposure` rows rather than deleting evidence and provenance.
- Removed the legacy `Finding.asset_id` fallback from the frontend's confirmed-asset presentation.
- Required two comparable posture snapshots before SYNTHESIS shows a trend.
- Added missing tenant predicates to STRIKE authorization and background-simulation lookups.
- Added startup schema/index verification for migration 008.
- Made migration 008 safe to run from the guarded container mount, reject orphan STRIKE ownership instead of guessing, verify constraints/indexes, and report idempotent completion.
- Extended the guarded release to back up and restore report artifacts, verify/restore PostgreSQL, publish product documentation, validate the migrated schema after restart, and record the deployed revision.
- Updated frontend cache versions so browsers request the reviewed extension assets.

On 2026-08-16 the production FreeLLM gateway credential and JWT signing secret were rotated in the protected VPS environment. Retired credentials are rejected, replacement authentication passes, the environment remains mode 600, and existing JWT sessions were intentionally invalidated. The canonicalization release remains pending the guarded commit, preflight, backup, migration, deployment, reconciliation, and smoke-test sequence.

## GRC to SSS/TES canonicalization

- Added server-managed ISO/IEC 42001:2023 framework/control storage and canonical tenant `ControlAssessment` rows.
- Made SOP Builder authoritative and Gap Analysis a derived view of the same assessment state.
- Added explicit policy-to-control supporting-evidence links; policy documents never complete controls or directly alter TES.
- Applied live server-side GRC context to open non-CVE SSS TES, retaining prior values as scoring provenance.
- Removed the manual Identity/Agentic silent SSS default and require analyst base severity in native intake.

## CVE live-context correction

- Added additive migration 010 for `Finding.cve_context`; no legacy asset link is promoted or rewritten.
- Replaced CVE seed-time `Finding.raw_inputs` as current context with exact-CVE metadata, confirmed active asset context, authorised Business Impact, and deterministic trusted exploit/threat evidence.
- Added the tenant-scoped SPECTRUM Business Impact action, audit/operational event, and refresh path. Resolved findings retain historical score provenance until reopened.
