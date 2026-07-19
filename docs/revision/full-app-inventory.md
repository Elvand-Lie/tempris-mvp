# Tempris Full Application Inventory

Inventory date: 2026-07-19
Repository head: `92534a0 feat: complete Tempris security and product roadmap`

## Scope and Source of Truth

This inventory is based on the live repository, Git state, imports, router registration, models, migrations, CI configuration, tests, static files, and a local backend test run. Deployment snapshots, archives, backups, generated databases, and prior walkthrough documents are not treated as editable source.

Supplied planning inputs found:

- `workDocs/TEMPRIS_AGENT_EXECUTION_PRD.md`
- `workDocs/TEMPRIS_AGENT_TASKS.yaml`
- `docs/implementation/programme-completion-report.md`
- `docs/implementation/LIMITATIONS.md`
- `docs/implementation/programme-blockers.md`
- `docs/implementation/repo-map.md`

Inputs not found in the repository:

- identifiable official Tempris light logo asset;
- identifiable official Tempris dark logo asset;
- a document identifiable as the requested meeting summary.

No replacement branding can be generated or inferred from `favicon.svg`, `icons.svg`, compiled bundles, screenshots, or deployment archives.

## Current Git State

The worktree was dirty before this revision began. Existing changes are preserved:

- modified: `app/backend/routers/grc.py`
- modified: `app/backend/services/redactor.py`
- modified: `app/backend/services/tes_engine.py`
- modified: `app/deploy/nginx_ssl.conf`
- modified: `app/frontend/index.html`
- untracked: `docs/video/backend-hardening-demo.md`

The existing `grc.py` diff also contains mojibake in comments and display strings. This revision will not discard the functional toggle-normalization work already present.

## Application Map

### Product frontend

`app/frontend` is a compiled static distribution:

- `index.html`
- `favicon.svg`
- `icons.svg`
- hashed JavaScript bundles under `assets/`
- hashed CSS bundles under `assets/`
- one hashed hero image

There is no product frontend `package.json`, `src/`, Vite/Webpack configuration, component source, lint configuration, type-check command, or frontend test command. `app/frontend_old` and `app/frontend_backup_` are compiled snapshots, not editable source. `app/freellmapi/src` is editable TypeScript for the separate LLM proxy service; it is not the Tempris product UI.

Consequences:

- login, navigation, header/sidebar, loading state, empty-state, and CISO dashboard UI changes are blocked;
- compiled/minified bundles must not be edited manually;
- product frontend install, lint, type check, tests, and production build cannot be claimed;
- `app/frontend/index.html` and static icon files are editable deployment surfaces, but the official logo assets are absent.

### Backend

The backend is FastAPI in `app/backend`. `index.py` registers every router module present in `app/backend/routers`:

- auth
- spectrum
- scout
- audit
- synthesis
- scanner
- strike
- standard
- assets
- grc
- edip
- surge
- blflaw
- partner
- reports
- aev
- ocq
- threats

SPEAK, SPOTLIGHT, and health endpoints are implemented directly in `index.py`, not in dedicated router files.

### Services

Backend services cover database setup, asset seeding, KEV loading, TES and EDIP decisions, redaction, reporting, threat-pack import, AI context/RAG, LLM fallback behavior, SSS intake, and adversary simulation helpers.

### Models

`app/backend/models.py` defines audit, EDIP, strike, compliance/evidence, incident, spotlight, surge, chat, TES snapshots, assets, scan findings, GRC, findings and supporting records, sessions/revocation, partner onboarding, reports, AEV, and operations tickets.

Tenant-key gaps found in state that can be tenant-sensitive:

- `TesSnapshot` has no `tenant_id`;
- `GrcState` has no `tenant_id`;
- `GrcSignoff` has no `tenant_id`;
- `GrcPolicyDocument` has no `tenant_id`.

`FindingRelationship`, `FindingSource`, `FindingDisputedClaim`, `FindingControl`, `FindingEvidence`, and `FindingStatusHistory` have no direct tenant key and therefore must always be authorized through their owning finding.

### Migrations

The repository has three standalone SQLite-oriented migration scripts:

- `001_add_evidence_tenant.py`
- `002_create_auth_sessions.py`
- `003_add_tenant_isolation_columns.py`

There is no Alembic migration environment. Migration 003 creates generic finding, partner, report, AEV, and operations tables, but no tracked migration adds tenant keys to TES snapshots or GRC state/signoff/policy tables. Runtime `Base.metadata.create_all()` cannot alter existing production tables and is not a substitute for those migrations.

### CI

`.github/workflows/ci.yml` runs backend tests and wrapper scripts for dependency scanning, secret scanning, SBOM generation, provenance, and AI review. The Python setup action is currently invalid: `actions/actions-setup-python@v4` should reference the official setup-python action. The workflow does not run the explicit compile command requested for this revision or the separate `app/freellmapi` TypeScript tests/build.

### Tests

The backend contains 18 test modules. A baseline invocation completed with `142 passed, 26 warnings` in 253.39 seconds. The attempted external temporary directory was denied by the Windows sandbox, so the baseline used test-specific SQLite files in the repository working directory; final validation must use a workspace-local temporary directory.

### Static assets and report templates

No official light/dark Tempris logo assets were found. Existing `favicon.svg` and `icons.svg` cannot be assumed to be the supplied official marks. Reports are generated programmatically as JSON/CSV by `services/reporting_engine.py`; there is no HTML, DOCX, or PDF report template directory. PDF generation is explicitly blocked.

## Findings

### Broken or unsupported references

- The completion report references `routers/speak.py`; SPEAK is inline in `index.py`.
- The completion report references `services/prompt_guard.py`; prompt checks are in `services/llm_client.py` and `services/ai_context.py`.
- The completion report references `tests/test_audit.py`; that file does not exist.
- The completion report references `tests/test_tenant_isolation.py`; that file does not exist.
- The completion report classifies repository inventory complete while listing no implementation or evidence for T-000.

### Router registration and dead endpoints

- All router modules currently present are registered.
- AEV routes are registered but intentionally return `AEV_DISABLED`; this is a controlled disabled workflow, not an active engine.
- PDF report generation is intentionally unsupported.
- No separate package-entitlement API or model exists. License verification is only a Boolean partner-onboarding checkpoint.

### Tenant and authorization defects

- Audit list and integrity verification queries are not tenant-filtered for non-superadmin users.
- GRC state, signoffs, and custom policies are globally stored and queried because their models lack tenant keys.
- TES trend snapshots are global because `TesSnapshot` lacks a tenant key.
- Report generation silently filters cross-tenant source IDs instead of rejecting the attempted reference.
- The existing synthesis trend query is not tenant-scoped.

### Placeholder or misleading runtime data

- Synthesis appends fixed STRIKE and STANDARD alerts unrelated to database state.
- Several synthesis module-health values are fixed to `healthy`.
- `edip_non_cve_extension.py` identifies a `1.4` constant as a placeholder.
- LLM responses deliberately have a local mock fallback.
- Partner sandbox reset deliberately seeds fictional data and is feature-flag/sandbox gated.
- Startup seeders populate assets, findings, audit, and strike demonstration data when tables are empty.

### Reporting defects

- CSV construction does not use a CSV writer and does not neutralize spreadsheet-formula prefixes.
- Cross-tenant IDs supplied to report generation are dropped rather than rejected.
- Report artifact paths are relative to the process working directory.
- No official logo can be embedded because the supplied assets are absent.

### Security and operational limitations

- Authentication uses a configuration-backed in-memory account registry rather than tenant/user database records.
- Login lockout state is process-local and resets on restart.
- HMAC audit integrity is shared-secret integrity, not identity-backed signing.
- Strict frontend CSP validation is blocked by missing editable product frontend source.
- Local dependency and secret scanner binaries were not found during inventory; wrappers and CI remain available.
- AEV remains disabled and PDF remains unsupported.
- Infrastructure execution is outside this revision and must remain approval-gated.

## Evidence-Backed Revision Scope

The smallest coherent revision is:

1. add tenant keys and a migration for GRC state/signoffs/policies and TES snapshots;
2. enforce tenant filtering in GRC, audit, synthesis trend, and report generation;
3. add a role-restricted, tenant-scoped, read-only CISO API with unavailable markers for metrics the schema cannot honestly supply;
4. remove fixed synthesis alert claims;
5. harden CSV generation and report cross-tenant validation;
6. repair CI action/configuration and add the requested deterministic smoke command;
7. add focused authorization, isolation, rollback, redaction, and misuse tests;
8. document branding and product-frontend work as blocked until official assets and editable product frontend source are supplied.
