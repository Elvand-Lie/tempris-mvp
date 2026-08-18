# Migration 011 Runbook: Canonical Vulnerability Spine (Phase 1A Shadow Layer)

Migration `011_canonical_vulnerability_spine.py` is an additive, shadow-layer migration. It creates the three foundational tables for the tenant-agnostic vulnerability intelligence layer without modifying any existing tables, columns, constraints, or runtime readers.

## 1. Tables Added
- `canonical_vulnerabilities`: Global vulnerability identity and lifecycle status registry.
- `vulnerability_cvss_assessments`: Provenance-preserving CVSS assessments from authoritative scoring bodies.
- `cisa_kev_entries`: Source-specific CISA Known Exploited Vulnerabilities enrichment records.

## 2. Invariants & Scope Boundaries
- **No mutations to existing tables:** `findings`, `asset_exposures`, `assets`, `audit_logs`, `incident_reports`, and `generated_reports` remain 100% untouched.
- **No data ingestion during migration:** Schema creation only. Ingestion is performed explicitly via offline CLI scripts.
- **No runtime dependencies:** Zero existing application APIs, screens, TES calculations, SCOUT discovery, or STANDARD workflows read from these tables in Phase 1A.

## 3. Migration Execution

### A. Dry Run
```powershell
python scripts/migrations/011_canonical_vulnerability_spine.py --db-path tmp/staging.db --dry-run
```

### B. Live Execution
```powershell
python scripts/migrations/011_canonical_vulnerability_spine.py --db-path tmp/staging.db
```

For managed PostgreSQL or remote environments, pass `--database-url-env` with `DATABASE_URL` set.

## 4. Offline Snapshot Ingestion

Offline snapshot ingestion is explicit and file-based. Network fetching is prohibited.

### A. Ingest CISA KEV Snapshot
```powershell
python app/backend/scripts/import_cve_intelligence.py --source cisa-kev --file app/backend/data/cisa_kev_2026_05_22.json --db-path tmp/staging.db
```

### B. Ingest NVD CVE Snapshot (NVD API 2.0 JSON format)
```powershell
python app/backend/scripts/import_cve_intelligence.py --source nvd-json --file path/to/nvd_snapshot.json --db-path tmp/staging.db
```

## 5. Rollback Procedure
Because Phase 1A is a purely additive shadow layer with no runtime readers, rollback is clean and non-destructive:
1. If un-deployed: revert the migration script and models code.
2. If applied to a staging/production database: execute an approved rollback migration to drop tables `canonical_vulnerabilities`, `vulnerability_cvss_assessments`, and `cisa_kev_entries`. No tenant data, finding records, or historical reports are affected.
