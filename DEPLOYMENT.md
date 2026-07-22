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

The script refuses tracked worktree changes, archives only committed Git content, verifies SHA-256 after upload, makes timestamped source and PostgreSQL backups, verifies the database backup with `pg_restore --list`, preserves `.env`, mounted runtime data, and Docker volumes, applies migration `006_add_sss_sub_class.py`, seeds only the idempotent v62 debrief pack, restarts the production Compose stack, and checks `/api/health`.

## Failure and rollback

If the post-restart health check fails, the script restores the previous source archive and restarts Compose. It does not automatically reverse database migrations: migration 006 is additive (a nullable column and index), and database restoration must use the backup made by the operator under the actual production database arrangement.

For a manual rollback, select the timestamped archive under `<RemoteRoot>/backups/releases/`, restore it to `<RemoteRoot>/app` while preserving `.env` and runtime data, then run:

```bash
cd /home/tempris/app/deploy && docker compose -f docker-compose.prod.yml up -d --build
```

## Current VPS status

Verified on 2026-07-22: `tempris@187.127.114.218` serves `sandbox.tempris.tech`; `/home/tempris/app/deploy/docker-compose.prod.yml` validates and the backend, Nginx, LLM, PostgreSQL, Redis, Kafka, and ZooKeeper containers are running. The older SSH-config target `168.110.206.83` is unrelated and must not be used for Tempris deployment.
