# Migration 010 Runbook

Migration `010_live_cve_tes_context.py` is additive. It adds the `findings.cve_context` JSON field for analyst-assessed business impact and trusted CVE-evidence provenance. It does not modify `raw_inputs`, promote legacy asset pointers, merge CVEs, or change resolved-finding history.

Run after migrations 008 and 009, only after taking and verifying the normal production database and report-artifact backups:

```powershell
python scripts/migrations/010_live_cve_tes_context.py --db-path tmp/migration-010-staging.db
python scripts/migrations/010_live_cve_tes_context.py --db-path tmp/migration-010-staging.db --dry-run
```

For a managed database, use `--database-url-env` in the protected deployment environment. Re-running the migration reports an unchanged complete schema. Roll back only by restoring the verified pre-migration database backup.
