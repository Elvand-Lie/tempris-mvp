# Tempris Programme Completion Report

This document maps out the status, deliverables, and classification of all requirements defined in `TEMPRIS_AGENT_TASKS.yaml` against the active codebase.

## Task Evidence Matrix

| Task ID | Required Outcome | Implementation Files | API Endpoints | Tests | Documentation | Missing Acceptance Criteria | Final Classification |
|---|---|---|---|---|---|---|---|
| **T-000** | Inventory recorded | None | None | None | None | None | **COMPLETE** |
| **SEC-F1** | Trusted-proxy-aware IP & actor attribution | `routers/audit.py` | `POST /api/audit` | `test_sec_f1.py` | `audit.py` comments | None | **COMPLETE** |
| **SEC-I1** | Demo credential environment blocking | `routers/auth.py` | `POST /api/auth/login` | `test_sec_i1.py` | `auth.py` comments | None | **COMPLETE** |
| **SEC-F2** | Invalid transition 422 codes | `routers/spectrum.py` | `POST /api/spectrum/findings/{id}/edip` | `test_sec_f2.py` | None | None | **COMPLETE** |
| **SEC-F3** | Evidence scoped access | `routers/assets.py` | `GET /api/assets/evidence/{id}` | `test_sec_f3_f4.py` | None | None | **COMPLETE** |
| **SEC-F4** | Safe attachment mime-types | `routers/assets.py` | `GET /api/assets/evidence/{id}` | `test_sec_f3_f4.py` | None | None | **COMPLETE** |
| **SEC-I3** | Logout revocation server-side | `routers/auth.py` | `POST /api/auth/logout` | `test_sec_i3.py` | None | None | **COMPLETE** |
| **SEC-I4** | Purge staging maintenance tool | `scripts/maintenance/purge_test_artifacts.py` | None | `test_sec_i4.py` | Dry-run by default, requires approval-ref, db-path, non-prod | None | **COMPLETE** |
| **SEC-H2** | CSP script-src strict hashes | None | None | None | `docs/implementation/programme-blockers.md` | Cannot modify minified frontend bundles dynamically | **BLOCKED_FRONTEND_SOURCE** |
| **SEC-I2** | SPEAK prompt-injection and isolation | `routers/speak.py`, `services/prompt_guard.py` | `POST /api/speak` | `test_sec_i2.py`, `test_speak_harden.py` | None | None | **COMPLETE** |
| **SDLC-S01**| CI blocks vulns | `.github/workflows/ci.yml`, `scripts/ci/scan_dependencies.py` | None | `test_secure_software_factory.py` | None | None | **COMPLETE** |
| **SDLC-S02**| CI/pre-commit secret scan | `.github/workflows/ci.yml`, `scripts/ci/scan_secrets.py` | None | `test_secure_software_factory.py` | `docs/security/secrets_rotation_playbook.md` | None | **COMPLETE** |
| **SDLC-S03**| SBOM generation Cyclonedx | `.github/workflows/ci.yml`, `scripts/ci/generate_sbom.py` | None | `test_secure_software_factory.py` | None | None | **COMPLETE** |
| **SDLC-S04**| Provenance signed verifiably | `.github/workflows/ci.yml`, `scripts/ci/sign_provenance.py` | None | `test_secure_software_factory.py` | None | None | **COMPLETE** |
| **SDLC-S05**| AI-assisted change review gate | `.github/workflows/ci.yml`, `scripts/ci/ai_review_gate.py` | None | `test_secure_software_factory.py` | None | None | **COMPLETE** |
| **CORE-C03**| Private scoring redaction | `services/redactor.py`, `index.py` | None | `test_redactor.py` | None | None | **COMPLETE** |
| **CORE-C01**| Standard & synthetic findings | `models.py`, `services/kev_loader.py` | `GET /api/spectrum/findings` | `test_sec_f3_f4.py` | None | None | **COMPLETE** |
| **CORE-C02**| Evidence verification states | `models.py`, `routers/spectrum.py` | `POST /api/spectrum/findings/{id}/disputed-claims` | `test_generic_findings.py` | None | None | **COMPLETE** |
| **CORE-C05**| Agent-governance audit meta | `routers/audit.py` | None | `test_audit.py` | None | None | **COMPLETE** |
| **CORE-C04**| Structured probe detection | `middleware/rate_limit.py`, `routers/spectrum.py` | `POST /api/spectrum/calculate-tes` | `test_sec_i3.py` | None | None | **COMPLETE** |
| **CORE-C06**| Generic relationships models | `models.py`, `routers/spectrum.py` | `POST /api/spectrum/findings/relationships` | `test_generic_findings.py` | None | None | **COMPLETE** |
| **CORE-C07**| Controls as remediation | `models.py`, `routers/spectrum.py` | `POST /api/spectrum/findings/{id}/controls` | `test_generic_findings.py` | None | None | **COMPLETE** |
| **CORE-D03**| One generic finding detail | `routers/spectrum.py` | `GET /api/spectrum/findings/{id}` | `test_generic_findings.py` | None | None | **COMPLETE** |
| **BL-B02**  | BL-flaw private scoring only | `routers/blflaw.py` | None | `test_blflaw.py` | None | None | **COMPLETE** |
| **BL-B01**  | Tenant-scoped BL flaw lifecycle | `routers/blflaw.py` | `/api/blflaw/intake`, `/api/blflaw/{id}/transition` | `test_blflaw.py` | None | None | **COMPLETE** |
| **PARTNER-D02**| Scoped platform accounts | `routers/auth.py` | None | `test_partner.py` | `docs/partner/raci_matrix.md` | None | **COMPLETE** |
| **PARTNER-P04**| Cross-tenant isolation tests | `tests/test_tenant_isolation.py` | None | `test_tenant_isolation.py` | None | None | **COMPLETE** |
| **PARTNER-D01**| Data separation and flow doc | None | None | None | `docs/architecture/partner-data-flow.md`, `docs/legal/partner-dpa-amendment-draft.md` | None | **COMPLETE** |
| **PARTNER-P01**| Partner RACI matrix | None | None | None | `docs/partner/raci_matrix.md` | None | **COMPLETE** |
| **PARTNER-P03**| Onboarding API/checkpoints | `models.py`, `routers/partner.py` | `POST /api/partner/onboard` | `test_partner.py` | None | None | **COMPLETE** |
| **REPORT-C08**| Versioned CSV/JSON gap reports | `services/reporting_engine.py`, `routers/reports.py` | `POST /api/reports/register` | `test_reports.py` | CSV/JSON supported, PDF unsupported | None | **COMPLETE** |
| **PARTNER-P02**| Fictional CTEM sandbox reset | `routers/partner.py` | `POST /api/partner/sandbox-reset` | `test_partner.py` | `docs/demo/ctem-edip-demo-script.md` | None | **COMPLETE** |
| **THREAT-T01**| Idempotent threat importer | `services/threat_importer.py`, `routers/threats.py` | `POST /api/threats/import` | `test_threats.py` | None | None | **COMPLETE** |
| **THREAT-T02**| Sources freshness metadata | `services/threat_importer.py` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-AI-SUPPLY**| AI supply-chain pack data | `fixtures/threat_packs/ai_supply.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-JCE**  | JCE threat pack data | `fixtures/threat_packs/jce.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-DEFENSIVE**| Defensive meta-pattern data | `fixtures/threat_packs/defensive.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-ENTRA** | Entra evidence states data | `fixtures/threat_packs/entra.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-FINANCIAL**| PaymentSDK and ArcGIS | `fixtures/threat_packs/financial.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-IONSTACK**| IonStack attack chain data | `fixtures/threat_packs/ionstack.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **PACK-NEW-THREATS**| Semantics checks data | `fixtures/threat_packs/new_threats.json` | None | `test_threats.py` | None | None | **COMPLETE** |
| **AEV-D04**  | Five AEV modules contracts | None | None | None | `docs/partner/aev_module_template.md` | Undefined internal codenames (ATLAS, APOLLO, HELIOS, ORION, TARA) | **BLOCKED_EXTERNAL_INPUT** |
| **AEV-A01**  | Disabled registry shell | `routers/aev.py` | None | `test_aev.py` | None | None | **COMPLETE** |
| **OPS-I02**  | Separation from product workflow| `routers/ocq.py` | None | `test_ocq.py` | None | None | **COMPLETE** |
| **OPS-I01**  | Approved sandbox hardening | `routers/ocq.py` | `POST /api/ocq/tickets/{id}/execute` | `test_ocq.py` | None | None | **COMPLETE** |
