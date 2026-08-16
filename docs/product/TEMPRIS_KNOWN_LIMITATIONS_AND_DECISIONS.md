# Known Limitations and Product Decisions

## Deliberate decisions

- `Finding.asset_id` is legacy history only. It is not confirmation and is not deleted during migration.
- An imported or keyword-suggested match is review input, not evidence.
- Process-local SSE/watch delivery is retained because the current deployment is intentionally single-worker. Multi-worker deployment would require a shared event transport and is outside this change.
- Client reports are immutable current-state snapshots. Editing means creating a new version.
- STRIKE `NO_EXPOSURE_OBSERVED` does not claim a defensive block. `DEFENSIVE_BLOCK_VERIFIED` requires recorded prevention evidence.
- Nmap/TCP output remains a SCOUT observation. Only deterministic qualifying Nuclei matches enter the Finding Registry.
- STANDARD and GRC are separate: STANDARD assesses security/regulatory controls; GRC manages AI-governance policy and workflow.
- Tenant & Module Administration controls entitlements; it does not impersonate tenant users.

## Current limitations

- Historical period reconstruction is not implemented. Assessment-period values in client reports are contextual metadata.
- Comparable trends require two `PostureSnapshot` rows with the same `scope_version`.
- Snapshot creation exists at startup and via `/api/synthesis/tes-snapshot`; an external scheduler is not bundled.
- Report delivery-recipient values are intended recipients; the reporting service does not send email.
- Report artifacts depend on the configured persistent report storage path. A missing artifact can coexist with preserved registry metadata.
- Microsoft Graph connector code can be tested with mocks; live operation requires tenant consent and configured credentials.
- VDP removal is restricted and audit logged; accepted submissions become SPECTRUM findings through SURGE triage.
- SPEAK answers from current tenant-scoped context and RAG references; it is not an autonomous remediation agent.
- The full expansion of **SSS** is **UNVERIFIED / PRODUCT CLARIFICATION REQUIRED**.
- Tenant-type classification is configuration metadata; legacy tenant purpose can be **UNVERIFIED / PRODUCT CLARIFICATION REQUIRED** when no authoritative record exists.
- The main frontend has no original package/build pipeline in this repository. The deployed native bundle is reproduced from the last native Git artifact through the fail-closed `scripts/ci/patch_native_frontend.py` compatibility transformer. Route tests verify that SPECTRUM, SCOUT, STRIKE, STANDARD, GRC, and SPOTLIGHT remain native pages and are not extension takeovers.
- The repository defines one guarded VPS target and no independent remote staging host. Migration rehearsal is performed on a disposable database clone; remote staging acceptance requires separately approved infrastructure/access.
- Live Microsoft Graph verification remains incomplete until approved tenant credentials and administrator consent are supplied. Mocked connector verification is not evidence of live consent.
- Earlier Git history contains non-placeholder deployment credentials. They must be rotated before production release even though the current operational `.env` is ignored and untracked.

## Security and privacy boundaries

- All listed tenant data APIs obtain tenant identity from authenticated server context.
- Superadmin management does not grant tenant impersonation.
- Operational events store structured metadata, not raw credentials, access tokens, or unnecessary PII.
- SCOUT runtime target policy rejects unsafe/unapproved targets. Automated tests use direct service fixtures, mocks, or authorized local data.

## Not implemented by this canonicalization

No Kafka, Kubernetes, Helm, ArgoCD, MinIO migration, microservice decomposition, enterprise SSO redesign, frontend rewrite, financial ROI calculator, or AI Sales System work was introduced.
