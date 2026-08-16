# Migration 009 Runbook

Migration `009_canonical_grc_framework.py` is additive. It creates canonical GRC framework, control, assessment, and policy-control-link storage; seeds the one ISO/IEC 42001:2023 control catalogue; and preserves legacy SOP/sign-off state as tenant assessments.

It does not delete GRC state, policies, policy versions, evidence, or finding history. It does not infer policy-control links from titles, Markdown, or keywords. Existing policies with no proven explicit relationship remain unmapped supporting documents.

## Rehearsal

Run against a verified disposable database clone after migration 008:

```powershell
python scripts/migrations/009_canonical_grc_framework.py --db-path tmp/migration-009-staging.db
python scripts/migrations/009_canonical_grc_framework.py --db-path tmp/migration-009-staging.db --dry-run
```

The rerun must report a complete schema and retain exactly one ISO framework definition, seven active controls, existing policy content, and no guessed `PolicyControlLink` rows.

## Production gate

- Back up the database before any mutation and verify restoration.
- Run this migration only with the committed application revision that contains `ControlAssessment` and `PolicyControlLink` models.
- Verify each existing tenant with GRC state or policy now has seven assessment rows.
- Confirm no policy link was invented and no non-CVE finding was moved across tenants.
- Verify the native GRC SOP Builder, Gap Analysis, and Intake & Triage routes after release.

## Rollback

Restore the verified database backup and previous application revision as one release unit. Do not drop GRC tables manually from a live database.
