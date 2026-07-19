# How Tempris Protects Security Data

**Recording target:** approximately 5 minutes. The supplied segment timings total 4:45 to 5:15, so this script treats "46 minutes" as a 4-6 minute target. A 46-minute recording would require material not specified here.

## 1. Authentication and revocation (45 seconds)

**Narration:** "This is a local test identity only. Tempris validates the JWT signature and then validates the matching persisted server-side session. Logging out revokes that session, so the still-unexpired JWT is rejected afterward."

**Command/API:**

```powershell
Set-Location app/backend
$env:ENVIRONMENT = "test"
python -m pytest -q tests/test_sec_i3.py::test_login_creates_persisted_session tests/test_sec_i3.py::test_login_jwt_contains_required_claims tests/test_sec_i3.py::test_valid_active_session_authenticates tests/test_sec_i3.py::test_logout_revokes_session tests/test_sec_i3.py::test_revoked_session_blocked_from_all_routes
```

Show the test's local TestClient sequence only: `POST /api/auth/login` as `alpha.user@example.test`, one authenticated `GET`, `POST /api/auth/logout`, then repeat the same `GET` with the original token.

**Expected result:** login and the first protected request succeed; logout succeeds; the repeated protected request returns `401 Authentication required`.

**Relevant source file:** `app/backend/routers/auth.py`

**Relevant test name:** `test_login_creates_persisted_session`, `test_valid_active_session_authenticates`, `test_logout_revokes_session`, `test_revoked_session_blocked_from_all_routes`

**Redact:** access token, password, session ID, JTI, JWT payload, database URL.

## 2. Tenant isolation (60 seconds)

**Narration:** "Tenant Beta cannot retrieve an Alpha-owned evidence object. The server derives tenant scope from the verified principal, not a tenant value supplied in the request."

**Command/API:**

```powershell
Set-Location app/backend
$env:ENVIRONMENT = "test"
python -m pytest -q tests/test_sec_f3_f4.py::test_cross_tenant_access_fails tests/test_sec_f3_f4.py::test_upload_ignores_provided_tenant_id tests/test_sec_f3_f4.py::test_missing_tenant_id_fails_closed
```

On screen, label the fictional principals `tenant-alpha` and `tenant-beta`; show the equivalent local request made by the test fixture:

```http
GET /api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download
Authorization: Bearer [temporary tenant-beta token - do not display]
```

**Expected result:** the cross-tenant evidence request returns `404`, avoiding disclosure that the Alpha object exists. Caller-provided tenant values do not override the authenticated tenant.

**Relevant source file:** `app/backend/routers/auth.py`, `app/backend/routers/standard.py`

**Relevant test name:** `test_cross_tenant_access_fails`, `test_upload_ignores_provided_tenant_id`, `test_missing_tenant_id_fails_closed`

**Redact:** token, evidence contents, file path, real tenant IDs, names, and identifiers.

## 3. Validation, transactions and redaction (60 seconds)

**Narration:** "EDIP validates the request before looking up or modifying the finding. An unsupported decision is rejected with 422. The public finding representation also excludes private scoring inputs and intermediate calculation data."

**Command/API:**

```powershell
Set-Location app/backend
$env:ENVIRONMENT = "test"
python -m pytest -q tests/test_sec_f2.py::test_unsupported_decision_returns_422 tests/test_sec_f2.py::test_regression_invalid_decision_fixed tests/test_redactor.py::test_global_redactor_strips_private_fields
```

Show this local, fictional request and compare the same public finding's `edip_decision` before and after. Keep the temporary token off screen.

```http
POST /api/spectrum/findings/F-DEMO-001/edip
Authorization: Bearer [temporary token - do not display]
Content-Type: application/json

{"decision":"escalate","rationale":"recording-only invalid input"}
```

**Expected result:** `422` with `INVALID_EDIP_DECISION`; the public decision value is unchanged. `GET /api/spectrum/findings` does not expose `raw_inputs`, `sss_data`, `tes_breakdown`, AGM, DRF, TEF, intermediate calculations, or formula metadata.

**Relevant source file:** `app/backend/routers/spectrum.py`, `app/backend/services/redactor.py`

**Relevant test name:** `test_unsupported_decision_returns_422`, `test_regression_invalid_decision_fixed`, `test_global_redactor_strips_private_fields`

**Redact:** all scores, scoring factors, calculation inputs, formulas, finding titles, CVEs, tokens, and rationale text beyond the fictional example.

## 4. Audit and evidence protection (60 seconds)

**Narration:** "Request-body actor and tenant claims are not authoritative. The audit entry records the authenticated actor and tenant. Evidence downloads use a safe attachment disposition and `nosniff`; a tenant outside the object scope receives no object data."

**Command/API:**

```powershell
Set-Location app/backend
$env:ENVIRONMENT = "test"
python -m pytest -q tests/test_sec_f1.py::test_audit_tenant_spoofing_prevention tests/test_sec_f3_f4.py::test_download_includes_nosniff tests/test_sec_f3_f4.py::test_cross_tenant_access_fails
```

Show one local audit request with fictional spoofed values, then the persisted test assertion. Show only headers from the permitted evidence download:

```http
Content-Disposition: attachment; filename="evidence_file.dat"; ...
X-Content-Type-Options: nosniff
Cache-Control: no-store, private
```

**Expected result:** the audit record contains the authenticated local actor and tenant, not the spoofed body values. The permitted download returns `200` with the headers above; the cross-tenant request returns `404`.

**Relevant source file:** `app/backend/routers/audit.py`, `app/backend/routers/auth.py`, `app/backend/routers/standard.py`

**Relevant test name:** `test_audit_tenant_spoofing_prevention`, `test_download_includes_nosniff`, `test_cross_tenant_access_fails`

**Redact:** audit IDs, timestamps, IP addresses, user IDs, tenant IDs, filenames, evidence body, tokens, and metadata values.

## 5. Platform safety overview (60-90 seconds)

**Narration:** "The remaining examples are local, fictional, and non-destructive. A threat-pack dry run validates without importing. Generated JSON or CSV report manifests include a content hash and tenant scope. The CI workflow calls Tempris wrappers for `pip-audit` and Gitleaks. The purge tool is shown only in dry-run mode. Sandbox reset remains blocked without its feature flag and an authoritative sandbox designation. No major frontend redesign was performed; editable frontend source was unavailable. PDF export remains unsupported, AEV remains disabled, and infrastructure commands are not automatically executed."

**Command/API:**

```http
POST /api/threats/import?dry_run=true
Authorization: Bearer [temporary admin token - do not display]
Content-Type: application/json

[local fictional JSON from fixtures/threat_packs/jce.json]
```

```http
POST /api/reports/generate
Authorization: Bearer [temporary tenant-alpha token - do not display]
Content-Type: application/json

{"report_type":"combined","approved_by":"recording-approver@example.test","source_finding_ids":[],"source_evidence_ids":[],"framework_configuration":{"recording":"local-only"}}
```

```powershell
Get-Content .github/workflows/ci.yml
Get-Content scripts/ci/scan_dependencies.py
Get-Content scripts/ci/scan_secrets.py

$env:ENVIRONMENT = "demo"
$db = Join-Path $env:TEMP "tempris-purge-demo-$PID.db"
@'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.executescript("""
CREATE TABLE findings (id TEXT, cve TEXT, title TEXT, asset_id TEXT, tenant_id TEXT);
CREATE TABLE assets (id TEXT, name TEXT, hostname TEXT, tenant_id TEXT);
CREATE TABLE audit_logs (id INTEGER, action TEXT, detail TEXT, tenant_id TEXT);
INSERT INTO findings VALUES ('DEMO-FINDING-001','CVE-DEMO-0001','Fictional recording finding',NULL,'tenant-alpha');
""")
db.commit()
'@ | python - $db
python scripts/maintenance/purge_test_artifacts.py --db-path $db --tenant-id tenant-alpha --artifact-ids DEMO-FINDING-001 --approval-ref RECORDING-DRY-RUN
```

```http
POST /api/partner/sandbox-reset
Authorization: Bearer [temporary local admin token - do not display]
```

**Expected result:** threat import returns `dry_run_success` with no import; report generation returns a manifest containing `tenant_id`, `content_hash`, and CSV/JSON artifact metadata; CI shows wrapper scripts that invoke `pip-audit` and Gitleaks; purge prints `DRY-RUN` and makes no changes because `--execute` is absent; sandbox reset returns `400 SANDBOX_RESET_BLOCKED` when `SANDBOX_RESET_ENABLED` is unset. Do not run a reset with the flag enabled, do not run `--execute`, and do not show report body content.

**Relevant source file:** `app/backend/routers/threats.py`, `app/backend/services/threat_importer.py`, `app/backend/routers/reports.py`, `app/backend/services/reporting_engine.py`, `.github/workflows/ci.yml`, `scripts/ci/scan_dependencies.py`, `scripts/ci/scan_secrets.py`, `scripts/maintenance/purge_test_artifacts.py`, `app/backend/routers/partner.py`, `app/backend/routers/aev.py`

**Relevant test name:** `test_threat_pack_importer_and_rollback`, `test_reporting_pipeline_and_isolation`, `test_purge_test_artifacts_dry_run_and_execution`, `test_partner_onboarding_and_sandbox_reset`, `test_aev_endpoints_are_disabled`

**Redact:** temporary tokens, report IDs, report content, paths, hashes if linked to real artifacts, CI secrets, scan matches, tenant IDs, and all test database paths. Do not claim an HMAC is identity-backed signing.

## Recording Checklist

- Use a clean local checkout, `ENVIRONMENT=test` or `demo`, temporary SQLite databases, and fictional identities only.
- Do not start a remote scan, connect to a VPS, run purge with `--execute`, enable sandbox reset, invoke AEV, or run infrastructure commands.
- Keep terminal history, environment variables, authorization headers, tokens, passwords, client data, finding data, evidence contents, score values, and formula details out of frame.
- Show HTTP status, safe response keys, and safe headers only.
- State the frontend, PDF, AEV, and infrastructure limitations exactly as in section 5.

## Non-Destructive Pre-Recording Tests

```powershell
Set-Location app/backend
$env:ENVIRONMENT = "test"
python -m pytest -q tests/test_sec_i3.py::test_logout_revokes_session tests/test_sec_i3.py::test_revoked_session_blocked_from_all_routes tests/test_sec_f3_f4.py::test_cross_tenant_access_fails tests/test_sec_f2.py::test_unsupported_decision_returns_422 tests/test_redactor.py::test_global_redactor_strips_private_fields tests/test_sec_f1.py::test_audit_tenant_spoofing_prevention tests/test_sec_f3_f4.py::test_download_includes_nosniff tests/test_reports.py::test_reporting_pipeline_and_isolation
```

Do not use `test_purge_test_artifacts_dry_run_and_execution` or `test_partner_onboarding_and_sandbox_reset` as a pre-record command because each test contains an execution branch. Use only the dry-run and blocked-reset requests shown above. `test_aev_endpoints_are_disabled` is excluded from the passing gate: it currently fails at local login setup before exercising the disabled AEV endpoints. Do not represent it as passing runtime evidence until that test setup is repaired.
