# Tempris release procedure

This is the repeatable release path for Tempris. Releases are committed and pushed to GitHub first, then copied as a verified source archive to the VPS. GitHub Actions is intentionally not part of this path; the former `Tempris Unified CI/CD Pipeline` workflow was removed.

## Before every release

1. Work from `vps-prod-complete` and review `git status --short`. Do not include untracked source debriefs, PDFs, local databases, archives, `.env` files, or runtime data unless that is explicitly intended.
2. Run the relevant tests and `git diff --check` locally.
3. Commit the intended files and push the exact commit: `git push origin vps-prod-complete`.
4. The verified production target is `tempris@187.127.114.218`, with the application rooted at `/home/tempris`. The deployment script still validates the Compose file and required containers before making changes.

## Guarded release command

From the repository root, first perform a read-only preflight:

```powershell
.\scripts\deploy-vps.ps1
```

If it reports the expected Compose configuration and Tempris containers, release the current committed `HEAD`:

```powershell
.\scripts\deploy-vps.ps1 -Deploy
```

The script refuses tracked worktree changes, archives only committed Git content, verifies SHA-256 after upload, and creates verified timestamped backups of the application source, PostgreSQL database, and generated report artifacts. It preserves `.env`, mounted runtime data, and Docker volumes. Before replacing source, it applies migrations `006_add_sss_sub_class.py`, `007_create_tenant_registry.py`, and `008_canonical_posture_and_operations.py`. Migration 008 runs against the staged backend models and writes a JSON migration report under `/home/tempris/backups/migrations/`. The release then installs the staged source and product documentation, restarts the Compose stack, checks `/api/health`, runs migration 008 in read-only validation mode, and records the deployed Git commit in `/home/tempris/app/REVISION`.

Migration 007 is additive and idempotent. It creates the authoritative `tenants` registry, backfills every distinct non-empty `tenant_id` already present in tenant-scoped tables, explicitly registers `tempris` and `bug-bounty`, and adds the `tenant_packages.version` concurrency field. It does not rename tenants, reassign tenant-owned records, or remove data.

Migration 008 adds canonical exposure, posture-snapshot, scan-job, incident, operational-event, and policy-lifecycle storage. It preserves every legacy `Finding.asset_id` pointer and never converts one into a confirmed `AssetExposure`. On PostgreSQL it refuses to mutate unless a verified external backup is supplied. It also refuses to guess tenant ownership for orphan STRIKE simulations. A second execution validates the completed schema and exits without applying changes.

## Migration 008 staging rehearsal

Before a production release, rehearse migration 008 against a disposable database clone using [the migration runbook](docs/product/TEMPRIS_MIGRATION_008_RUNBOOK.md). For production PostgreSQL, the verified custom-format dump and report-artifact archive are created automatically by the guarded release script. Do not apply migration 008 directly to production without those backups.

The repository does not define a separate remote staging host. Local/database-clone rehearsal proves schema and data preservation, but a remote sandbox deployment still requires the approved VPS connection and credential rotation described below.

After a tenant-administration release, sign in as the Tempris platform Superadmin and verify:

1. `GET /api/tenants?limit=100` lists the expected registered tenants.
2. Opening `/packages` shows the searchable **Tenant & Module Administration** console.
3. Selecting another tenant leaves the signed-in tenant and JWT context unchanged.
4. Saving an entitlement update increments its configuration version and creates a `TENANT_ENTITLEMENTS_UPDATED` event in the Tempris audit chain.
5. A user from the updated tenant is immediately blocked from a disabled module by the backend, not merely hidden in navigation.
6. The `bug-bounty` tenant continues to disclose the Researcher role-isolation constraint.

## Rotate sandbox account passwords

Production rejects the shared password `demo` and duplicate account passwords. To generate six unique credentials, update the protected VPS `.env`, recreate only the backend container, verify all six logins, and write the new account list to a local Git-ignored file, run:

```powershell
.\scripts\rotate-account-passwords.ps1
```

The local output is `workDocs/tempris-account-credentials.local.md`. Never add that file or `app/deploy/.env` to Git. The remote script creates a mode-600 backup under `/home/tempris/backups/credentials/` before replacing the credential values.

The dedicated `researcher@tempris.com` account belongs to the isolated `bug-bounty` tenant. It can create and view SSS test findings only; all other authenticated API routes fail closed. Use `scripts/provision-researcher-account.ps1` to create or replace only that credential before deploying code that requires it. Do not use the full rotation script during an active testing window. Rotate the shared Read-only password with the full rotation script only after testing concludes on 7 August 2026.

## Failure and rollback

If migration, restart, health, or post-deployment schema validation fails, the script's error trap stops the backend as necessary, restores PostgreSQL with `pg_restore --clean --if-exists`, restores the generated report-artifact archive, restores the previous application source/frontend, and restarts Compose. Rollback errors are printed and must be treated as an incident; they are not silently ignored.

For a manual rollback, select the timestamped archive under `<RemoteRoot>/backups/releases/`, restore it to `<RemoteRoot>/app` while preserving `.env` and runtime data, then run:

```bash
cd /home/tempris/app/deploy && docker compose -f docker-compose.prod.yml up -d --build
```

Restore the matching database dump with `pg_restore --clean --if-exists` and restore the matching archive from `<RemoteRoot>/backups/reports/` before restarting. Use the same release identifier for all three artifacts. Verify `/api/health`, report downloads, authenticated routes, and the commit stored in `/home/tempris/app/REVISION` after restoration.

## Credential safety gate

`app/deploy/.env` is required operational configuration, is Git-ignored, and must remain outside release archives. Historical review found that earlier revisions contained non-placeholder deployment credentials. Rotate the affected secrets before the next production release, update the protected VPS `.env`, and revoke the old values. Never copy secret values into tickets, logs, migration reports, or documentation.

## Current VPS status

Verified on 2026-07-22: `tempris@187.127.114.218` serves `sandbox.tempris.tech`; `/home/tempris/app/deploy/docker-compose.prod.yml` validates and the backend, Nginx, LLM, PostgreSQL, Redis, Kafka, and ZooKeeper containers are running. The older SSH-config target `168.110.206.83` is unrelated and must not be used for Tempris deployment.
