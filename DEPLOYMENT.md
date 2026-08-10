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

The script refuses tracked worktree changes, archives only committed Git content, verifies SHA-256 after upload, makes timestamped source and PostgreSQL backups, verifies the database backup with `pg_restore --list`, preserves `.env`, mounted runtime data, and Docker volumes, applies migrations `006_add_sss_sub_class.py` and `007_create_tenant_registry.py`, seeds only the idempotent v62 debrief pack, restarts the production Compose stack, and checks `/api/health`.

Migration 007 is additive and idempotent. It creates the authoritative `tenants` registry, backfills every distinct non-empty `tenant_id` already present in tenant-scoped tables, explicitly registers `tempris` and `bug-bounty`, and adds the `tenant_packages.version` concurrency field. It does not rename tenants, reassign tenant-owned records, or remove data.

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

If the post-restart health check fails, the script restores the previous source archive and restarts Compose. It does not automatically reverse database migrations: migrations 006 and 007 are additive, and database restoration must use the verified backup made by the operator under the actual production database arrangement. Restore that backup if a rollback must also remove the tenant registry or entitlement-version column; do not manually drop them while the application is running.

For a manual rollback, select the timestamped archive under `<RemoteRoot>/backups/releases/`, restore it to `<RemoteRoot>/app` while preserving `.env` and runtime data, then run:

```bash
cd /home/tempris/app/deploy && docker compose -f docker-compose.prod.yml up -d --build
```

## Current VPS status

Verified on 2026-07-22: `tempris@187.127.114.218` serves `sandbox.tempris.tech`; `/home/tempris/app/deploy/docker-compose.prod.yml` validates and the backend, Nginx, LLM, PostgreSQL, Redis, Kafka, and ZooKeeper containers are running. The older SSH-config target `168.110.206.83` is unrelated and must not be used for Tempris deployment.
