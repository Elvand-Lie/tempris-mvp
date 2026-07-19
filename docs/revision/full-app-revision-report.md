# Tempris Full Application Revision Report

Execution date: 2026-07-19

Verdict: REVISION_REQUIRED

## Scope and Source of Truth

The revision used repository source, Git state, migrations, tests, runtime TestClient behavior, the execution PRD, task YAML, implementation completion report, and limitations. No landing-page redesign, compiled frontend bundle edit, remote scan, production deployment, persistent-database purge, or sandbox reset was performed.

The worktree was already dirty at start. Existing modifications in app/backend/services/tes_engine.py, app/deploy/nginx_ssl.conf, app/frontend/index.html, and semantic changes in app/backend/services/redactor.py were preserved.

## Functionality Implemented

- Added tenant ownership to GRC state, GRC signoffs, custom GRC policies, and TES snapshots.
- Added migration 004 with required explicit legacy tenant assignment, dry-run output, SQLite backup, PostgreSQL support, indexing, and idempotency.
- Added startup schema checks that refuse to run when the four new tenant columns are missing.
- Tenant-scoped GRC state, signoffs, policy status, gap analysis, custom policy list/read/update, and TES score queries.
- Made bundled policy files read-only to prevent one tenant from mutating shared content.
- Added tenant-scoped audit listing and per-tenant hash chains.
- Added a role-restricted, read-only CISO API at /api/ciso/summary and /api/ciso/findings/{finding_id}.
- Added safe CISO metrics for posture, critical/high findings, unresolved/overdue remediation, count-based trend, highest-risk assets, compliance gaps, escalations, actions, and report links.
- Removed fictional STRIKE and STANDARD synthesis alerts.
- Replaced unsupported module-health claims with unavailable states.
- Normalized corrupted SPEAK, SPOTLIGHT, and GRC API-visible text to ASCII.
- Tenant-scoped TES snapshots and trend history.
- Hardened report generation with strict source ownership checks, controlled report types, rollback cleanup, server-bound approval actor, safe errors, recursive scoring-field removal, structured CSV output, and spreadsheet-formula neutralization.
- Added one automatic non-destructive smoke command using two fictional tenants and a temporary database.

## Security Fixes

- Corrected GRC evidence audit metadata from an ignored metadata_ input to the AuditEntry metadata field.
- Removed exception text from evidence upload 500 responses.
- Removed cross-tenant audit-log exposure and separated audit hash chains by tenant.
- Removed cross-tenant report listing/raw access for the Superadmin principal tenant.
- Rejected missing and foreign report source IDs instead of silently omitting them.
- Removed internal artifact paths from raw report metadata responses.
- Bound report approval to the authenticated Admin/Superadmin actor.
- Removed a tracked app/freellmapi/.env containing populated encryption keys.
- Stopped FreeLLMAPI from printing generated unified API keys.
- Upgraded drizzle-orm and Vitest, removed unused drizzle-kit, refreshed transitive dependencies, and pinned a compatible patched esbuild.
- Corrected CI checkout/Python actions, installed pip-audit, and added full-history Gitleaks.

## Files Changed by This Revision

- CI: .github/workflows/ci.yml
- Backend registration/models: app/backend/index.py, app/backend/models.py
- Backend routers: app/backend/routers/audit.py, ciso.py, grc.py, reports.py, synthesis.py
- Backend services: app/backend/services/ai_context.py, database.py, reporting_engine.py
- Backend tests: app/backend/tests/conftest.py, test_ciso_grc_tenant.py, test_migration_004.py, test_reports.py
- Operations: scripts/migrations/004_add_grc_tes_tenant_scope.py, scripts/smoke_test.py
- FreeLLMAPI: deleted app/freellmapi/.env; updated package.json, package-lock.json, and src/db/index.ts
- Documentation: full-app-inventory.md, full-app-revision-report.md, security-regression-matrix.md, smoke-test-results.md, remaining-blockers.md

The revision also removed one trailing-space defect from the already-modified redactor file. It did not claim or overwrite the pre-existing Nginx, compiled frontend, TES engine, or broader redactor changes.

## Verification

- Backend: 152/152 tests passed in 321.47 seconds.
- FreeLLMAPI: TypeScript build passed.
- FreeLLMAPI: 135/135 tests passed.
- npm audit: 0 vulnerabilities.
- Smoke test: passed health, login, protected request, finding create/retrieve, foreign-tenant 404, audit, report, CISO summary, logout, and revoked-token 401.
- Migration 004: explicit ownership, dry-run, idempotency, and refusal to guess ownership passed.
- git diff --check: passed.
- pip-audit: unavailable locally; configured for CI.
- Gitleaks: unavailable locally; configured for CI with full history.

## Branding and Frontend

- No major frontend redesign was performed.
- app/frontend contains only compiled distribution assets and no package manifest, source tree, lint, type-check, test, or build configuration.
- Official light and dark logo files were not identifiable in the repository.
- Login, navigation, loading states, favicon, and CISO frontend branding are blocked.
- app/freellmapi is editable TypeScript server source and was built/tested; it is not the Tempris product frontend.

## Product Status

- CISO dashboard: backend complete and tested; frontend blocked.
- Branding: blocked by missing official assets and editable product frontend.
- Partner onboarding: implemented and existing lifecycle/security test passes.
- Package entitlement: unavailable; license_verified is not an entitlement system.
- Reports: JSON/CSV/combined supported; PDF unsupported.
- AEV: disabled by design.
- Infrastructure execution: not automatic.

## Failures Found

- 4 shared GRC/TES tables lacked tenant ownership.
- GRC, audit, TES trend, and custom policy queries crossed tenant boundaries.
- 2 fictional synthesis alerts and 5 fixed module-health claims were returned.
- Report generation silently discarded foreign IDs and used unsafe hand-built CSV.
- Evidence upload exposed internal exception text.
- GRC evidence audit metadata was dropped.
- CI referenced an invalid Python setup action and did not provision real scanners.
- The backend suite depended on test import order and external PYTHONPATH.
- A tracked .env contained 2 populated encryption-key entries.
- FreeLLMAPI initially reported 9 npm advisories: 6 moderate, 2 high, 1 critical.
- FreeLLMAPI printed generated API keys to logs.
- SPEAK, SPOTLIGHT, and GRC returned mojibake in user-visible text.

## Readiness

- Ready for local backend and FreeLLMAPI regression: yes.
- Ready for a green CI run: no, until full-history Gitleaks is run and historical keys are handled.
- Ready for staging: no, until key rotation, migration 004, logo/frontend inputs, and blocker review are complete.

REVISION_REQUIRED

## Final Release Pass

Execution date: 2026-07-19

### Exposed-Key Incident

- The historical backend JWT secret, backend-to-FreeLLM unified key, and FreeLLM encryption key were confirmed active on the approved host using redacted SHA-256 comparisons.
- Created protected mode-600 rollback copies of both runtime environment files and two verified SQLite backups under a timestamped mode-700 host directory.
- Replaced all three runtime values without committing values to source control.
- Re-encrypted 16 live FreeLLM provider-key records with AES-256-GCM and verified that the retired encryption key cannot decrypt them.
- Replaced the live unified API key; a retired-key authenticated request now returns 401 and the replacement key passes authentication against an invalid-model probe without contacting a provider.
- Recreated the existing backend and FreeLLMAPI Compose services. Both loopback health endpoints return 200. A JWT signed with the retired secret is rejected as invalid.
- A first dry-run targeted an unmounted legacy Docker volume. No live records were modified there. The actual mounted volume, deploy_freellm_data, was identified, backed up again, rotated, and verified before the service restart.
- Temporary rotation secret files were deleted after verification. The restricted rollback backups remain available on the host; their retention and eventual secure deletion require an operational decision.

### Release Diff Scope

- Intended release material includes backend tenant/security work, migration 004, smoke tooling, CI/scanner/SBOM/provenance tooling, FreeLLMAPI key-rotation support, tests, revision documentation, and the fingerprint-only .gitleaksignore file.
- app/frontend/index.html is an unknown compiled-bundle pointer change and is deliberately excluded. No compiled frontend bundle is edited or deployed.
- app/deploy/.env and app/freellmapi/.env are removal-only release entries. Local runtime copies remain ignored and were updated on the VPS outside Git.
- docs/video/backend-hardening-demo.md is retained as prior documentation. Generated artifacts, the temporary virtual environment, graph output, databases, backups, tokens, and runtime output remain ignored and excluded.

### Final Local Validation

- python -m compileall app/backend scripts: passed.
- Backend suite using the pinned release manifest: 154 passed in 370.01 seconds.
- Temporary-database smoke test: passed health, login, protected request, finding create/retrieve, cross-tenant rejection, audit, report, CISO summary, logout, revoked-token rejection, and automatic cleanup.
- pip-audit against the updated backend manifest: no known vulnerabilities found.
- FreeLLMAPI: npm ci, TypeScript build, 137 tests, and npm audit all passed; npm audit reported 0 vulnerabilities.
- Full-history Gitleaks: 23 commits scanned, no leaks found. The allowlist contains only two rotated historical runtime fingerprints and eight obsolete test/document fixture fingerprints; it does not contain values.
- SBOM: 232 components generated. Provenance generation and HMAC integrity verification passed with an ephemeral local runtime key. This remains shared-secret integrity verification, not identity-backed signing.
- git diff --check has not yet been rerun after final documentation edits.

### Staging, CI, and Deployment Status

- The approved VPS is reachable and its production backend and FreeLLMAPI services are healthy after the incident rotation.
- /home/tempris/deploy-staging is archive-only: it has no runnable checkout, Compose configuration, environment, database connection, or containers. It is not a staging environment.
- Migration 004 was not run on production. Its local dry-run, backup, ambiguity rejection, index, and idempotency tests pass, but the required staging execution cannot occur without a real staging target and an explicit legacy tenant ID.
- The VPS deployment directory is a non-Git deployment copy with no approved deployment helper. No source release was copied or deployed.
- Git remote read access works. No release commit, push, GitHub CI run, or source deployment has occurred.

### Deferred Items

- Editable Tempris product frontend source and official logo assets are absent. Login, navigation, loading-state, favicon, and CISO UI branding remain blocked.
- Package entitlement, PDF export, and AEV remain deferred.

Final release verdict: BLOCKED
- git diff --check: passed after final documentation edits.
