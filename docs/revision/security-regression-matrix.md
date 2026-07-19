# Security and Functional Regression Matrix

Execution date: 2026-07-19

Scope: local FastAPI TestClient, temporary or test-only SQLite databases, fictional tenants and users. No production system, third-party target, or remote scanner was used.

## Functional Workflows

| Workflow | Happy path | Invalid input | Unauthorized role | Cross-tenant | Missing resource | Rollback | Audit | Safe fields | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| Authentication | Passed | Passed | Passed | N/A | Passed | Passed | Passed | Passed | test_sec_i3.py |
| Session revocation | Passed | Passed | Passed | Passed | Passed | Passed | Passed | Passed | test_sec_i3.py |
| Role authorization | Passed | Passed | Passed | Passed | Passed | N/A | Passed | Passed | test_sec_f2.py, test_sec_f3_f4.py, test_ciso_grc_tenant.py |
| Findings | Passed | Passed | Passed | Passed | Passed | Passed | Passed | Passed | test_generic_findings.py, test_blflaw.py, test_sec_f2.py |
| EDIP | Passed | Passed with 422 | Passed | Passed | Passed | Passed | Passed | Passed | test_sec_f2.py, test_sec_i3.py |
| Business-logic flaws | Passed | Passed with 422/409 | Passed | Passed | Passed | Passed | Passed | Passed | test_blflaw.py, smoke test |
| Evidence | Passed | Passed | Passed | Passed | Passed with concealed 404 | Passed | Passed | Passed | test_sec_f3_f4.py |
| Reports | Passed | Passed | Passed | Passed | Passed | Passed | Passed | Passed | test_reports.py |
| Partner onboarding | Passed | Passed | Passed | Passed | Passed | N/A | Passed | Passed | test_partner.py |
| Sandbox controls | Passed | Passed | Passed | Passed | Passed | Passed | Passed | Passed | test_partner.py |
| Threat packs | Passed | Passed | Passed | N/A | Passed | Passed | Passed | Passed | test_threats.py |
| Audit logs | Passed | Passed | Passed | Passed | N/A | Passed | Passed | Passed | test_sec_f1.py, test_ciso_grc_tenant.py |
| GRC state and policies | Passed | Passed | Passed | Passed | Passed | Passed | Passed | Passed | test_ciso_grc_tenant.py |
| CISO dashboard | Passed | N/A: read-only | Passed | Passed | Passed | N/A: read-only | Passed | Passed | test_ciso_grc_tenant.py |
| AEV | Disabled as specified | Rejected | Rejected | N/A | N/A | N/A | N/A | Passed | test_aev.py |
| OCQ | Passed | Passed | Passed | N/A | Passed | Passed | Passed | Passed | test_ocq.py |

## Security Cases

| Case | Result | Test or check |
|---|---|---|
| IDOR/BOLA | Passed | Evidence and CISO foreign IDs return concealed 404 responses |
| Tenant bypass | Passed | Findings, GRC, reports, audit, evidence, CISO, and TES history tested with two tenants |
| Role escalation | Passed | Analyst/Viewer/Read-only restrictions and CISO executive-role restriction |
| Actor spoofing | Passed | Authenticated actor replaces request actor in audit records |
| Tenant spoofing | Passed | Tenant comes from verified principal; request tenant fields are ignored or rejected |
| Mass assignment | Passed | Report approver is server-bound; GRC tenant injection remains tenant-alpha |
| SQL-injection-shaped identifiers | Passed | ORM finding/report/policy paths tested with quote and boolean-expression-shaped input |
| Path traversal | Passed | Evidence path, absolute path, symlink, and filename injection tests |
| Unsafe file preview | Passed | PDF attachment-only; Markdown plain text; HTML/SVG/XML not inline |
| MIME confusion | Passed | Unknown MIME becomes octet-stream; nosniff asserted |
| Sensitive error leakage | Passed | Auth, EDIP, evidence upload, and report internal errors return sanitized details |
| JWT/session bypass | Passed | Missing claims, bad version, stale role/tenant, unknown subject, tampering, and JTI mismatch |
| Revoked-session reuse | Passed | Same unexpired token receives 401 after logout |
| Report authorization | Passed | Cross-tenant generation rejected; raw metadata tenant-scoped |
| Sandbox-reset misuse | Passed | Feature flag, environment, designation, role, and target tenant gates |
| Maintenance-tool misuse | Passed | Purge command requires test environment and explicit IDs; smoke test never purges |
| Scoring-internal leakage | Passed | CISO and reports exclude AGM, DRF, TEF, raw inputs, formulas, and intermediate values |
| Spreadsheet formula injection | Passed | CSV writer quotes fields and prefixes formula-shaped text |
| Secret leakage in runtime logs | Fixed | FreeLLMAPI no longer prints generated unified API keys |
| Tracked secret material | Failed | app/freellmapi/.env was removed, but populated encryption keys remain in Git history until rotated and history-scanned |
| Python dependency audit | Not run locally | pip-audit binary unavailable; CI installs and runs it |
| Git history secret scan | Not run locally | Gitleaks binary unavailable; CI now runs gitleaks/gitleaks-action@v2 with full history |
| Node dependency audit | Passed | npm audit: 0 vulnerabilities after lockfile hardening |

## Constraints

- Purge execution in the automated suite targets only a purpose-built test database.
- Sandbox reset tests target only test fixtures.
- Threat-pack rollback targets only temporary test data.
- No infrastructure command, production migration, remote scan, or third-party request was executed.
