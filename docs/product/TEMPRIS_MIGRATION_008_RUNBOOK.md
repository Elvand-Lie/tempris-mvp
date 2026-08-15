# Migration 008 Runbook

Migration `008_canonical_posture_and_operations.py` adds canonical customer-posture and operational storage. It is additive and preserves legacy finding pointers. It never promotes `Finding.asset_id` into a confirmed `AssetExposure`.

## Preconditions

- Use the exact committed application revision intended for release.
- Confirm `app/deploy/.env` is ignored and untracked.
- Rotate any credential known to have appeared in Git history before production use.
- Record current application revision, health, schema state, and canonical counts.
- Back up the database and generated report-artifact directory. Verify both backups before migration.

Production uses PostgreSQL. Supply a custom-format `pg_dump` that passes `pg_restore --list`. Migration 008 refuses PostgreSQL mutation unless `--externally-verified-backup` and a readable backup file are supplied.

## Disposable-clone rehearsal

For a SQLite clone:

```powershell
python scripts/migrations/008_canonical_posture_and_operations.py --db-path tmp/migration-008-staging.db --backup-file tmp/migration-008-staging.backup.db --report-file tmp/migration-008-staging-report.json
python scripts/migrations/008_canonical_posture_and_operations.py --db-path tmp/migration-008-staging.db --dry-run
```

The second command must report that the schema is complete without changing data. Verify that legacy `findings.asset_id` values are unchanged and that no `asset_exposures` rows were created from them.

For production PostgreSQL, use only the guarded release script. It creates and verifies the dump, runs migrations before source replacement, and writes the migration report under `/home/tempris/backups/migrations/`.

## Required verification

- Existing tenants, assets, findings, reports, policies, and decisions remain readable.
- `asset_exposures`, `scan_jobs`, `posture_snapshots`, `incidents`, and `operational_events` exist.
- Canonical unique constraints and lookup indexes reported by migration 008 exist.
- Every STRIKE simulation has a provable tenant. An orphan is a blocking data-quality error; do not assign it to a default tenant.
- Confirmed-exposure counts are derived only from confirmed same-tenant links to active assets.
- Reference, not-applicable, resolved, suggested, and legacy/unverified records do not enter open customer posture.

## Guarded release

```powershell
.\scripts\deploy-vps.ps1
.\scripts\deploy-vps.ps1 -Deploy
```

The first command is read-only. The second requires a clean tracked worktree and deploys the committed `HEAD`. It backs up source, PostgreSQL, and report artifacts; applies migrations 006–008; deploys source and docs; restarts Compose; checks health; validates migration 008 again; and records `REVISION`.

## Rollback

Rollback must restore the matching set of:

1. PostgreSQL custom-format dump using `pg_restore --clean --if-exists`.
2. Generated report-artifact archive.
3. Previous application source and frontend assets.
4. Previous application revision and Compose process.

Use artifacts with the same release identifier. After restoration, verify health, authenticated routes, tenant isolation, report downloads, and `REVISION`. Never manually delete migration tables or constraints from a running production system.
