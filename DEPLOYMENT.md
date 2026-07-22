# Tempris release procedure

This is the repeatable release path for Tempris. Releases are committed and pushed to GitHub first, then copied as a verified source archive to the VPS. GitHub Actions is intentionally not part of this path; the former `Tempris Unified CI/CD Pipeline` workflow was removed.

## Before every release

1. Work from `vps-prod-complete` and review `git status --short`. Do not include untracked source debriefs, PDFs, local databases, archives, `.env` files, or runtime data unless that is explicitly intended.
2. Run the relevant tests and `git diff --check` locally.
3. Commit the intended files and push the exact commit: `git push origin vps-prod-complete`.
4. Confirm the VPS host, SSH user, and `/home/tempris` application root with the infrastructure owner. The SSH target currently configured on this workstation must not be assumed to be Tempris; the deployment script stops if `app/deploy/docker-compose.prod.yml` or Tempris containers are absent.

## Guarded release command

From the repository root, first perform a read-only preflight:

```powershell
.\scripts\deploy-vps.ps1 -VpsHost <approved-vps-host> -SshUser <ssh-user> -RemoteRoot /home/tempris
```

If it reports the expected Compose configuration and Tempris containers, release the current committed `HEAD`:

```powershell
.\scripts\deploy-vps.ps1 -Deploy -VpsHost <approved-vps-host> -SshUser <ssh-user> -RemoteRoot /home/tempris -DatabaseBackupCommand 'set -a; . app/deploy/.env; set +a; pg_dump -Fc "$DATABASE_URL" > "$BACKUP_FILE"'
```

`DatabaseBackupCommand` runs only on the VPS and must create the PostgreSQL custom-format backup at `$BACKUP_FILE`; it keeps the database URL on the host. The script refuses a dirty worktree, archives only committed Git content, verifies SHA-256 after upload, makes timestamped source and database backups, preserves `.env`, mounted runtime data, and Docker volumes, applies migration `006_add_sss_sub_class.py`, restarts the production Compose stack, and checks `/api/health`.

## Failure and rollback

If the post-restart health check fails, the script restores the previous source archive and restarts Compose. It does not automatically reverse database migrations: migration 006 is additive (a nullable column and index), and database restoration must use the backup made by the operator under the actual production database arrangement.

For a manual rollback, select the timestamped archive under `<RemoteRoot>/backups/releases/`, restore it to `<RemoteRoot>/app` while preserving `.env` and runtime data, then run:

```bash
cd /home/tempris/app/deploy && docker compose -f docker-compose.prod.yml up -d --build
```

## Current VPS status

On 2026-07-22, the SSH target configured in `C:\Users\elvan\.ssh\config` was reachable but had only unrelated Open WebUI/Ollama containers and no `/home/tempris` installation. GitHub can be updated safely; VPS deployment remains blocked until the approved Tempris host or its current location is supplied and passes preflight.
