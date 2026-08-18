# Tempris Canonical CVE Spine — End-to-End Deployment & Cutover Runbook

This runbook documents the complete end-to-end operational procedure for deploying and activating the Canonical CVE Spine in staging and production environments.

---

## 1. Executive Overview & Architectural Invariants

The Tempris Canonical CVE Spine decouples global vulnerability intelligence from tenant-scoped security findings and confirmed customer exposures.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Canonical Vulnerability Intelligence Layer (Global, Tenant-Agnostic)     │
│    CanonicalVulnerability ── (1:N) ── VulnerabilityCvssAssessment            │
│                           └── (1:1) ── CisaKevEntry                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Exact Syntax Link (canonical_cve_id)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Tenant Security Finding Layer (Tenant-Scoped)                            │
│    Finding (CVE & Non-CVE SSS) ── Triage State, SSS Data, CVE Context       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Confirmed Evidence
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Active Customer Exposure Layer (Exposure Boundary)                      │
│    AssetExposure (status='confirmed') ── (1:1) ── Active Customer Asset     │
│    * Live Dynamic TES Calculated Only on Confirmed Active Customer Assets   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Non-Negotiable Invariants
1. **Exposure Invariant:** A global CVE catalog notice or CISA KEV entry is **never** customer exposure by itself; exposure is defined strictly by `AssetExposure` (`status='confirmed'`) linking an active customer `Asset` to a `Finding`.
2. **Exact Syntax Matching:** Linkage is strictly exact (`CVE-YYYY-NNNN`); fuzzy or keyword matching is strictly prohibited.
3. **Deterministic CVSS Selection Policy:**
   - Valid assessments only
   - `4.0` > `3.1` > `3.0` > `2.0`
   - `Primary` > `Secondary`
   - Latest `source_modified_at`
   - Stable `id` tie-breaker
4. **Historical Immutability:** Mitigated, resolved, or historical closed findings preserve frozen historical scores.
5. **Non-CVE Isolation:** SSS supply chain and custom architecture findings remain `canonical_cve_id = NULL` and score via server-side SSS/GRC engines.
6. **No Automated Network Ingestion:** Intelligence ingestion is strictly file-based via verifiable offline snapshots.

---

## 2. Pre-Deployment Verification & Cryptographic Backup

Before applying schema changes or ingestion, create a verifiable database snapshot:

### SQLite Environments
```powershell
# Create cryptographic backup
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
Copy-Item "tempris.db" "backups/tempris_pre_cve_cutover_$timestamp.bak.db"
Get-FileHash "backups/tempris_pre_cve_cutover_$timestamp.bak.db" -Algorithm SHA256
```

### PostgreSQL Environments
```bash
RELEASE_TAG="cve-spine-cutover-$(date +%Y%m%d%H%M%S)"
pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f "/tmp/$RELEASE_TAG.dump"
pg_restore --list "/tmp/$RELEASE_TAG.dump" > /dev/null
echo "Backup verified successfully: /tmp/$RELEASE_TAG.dump"
```

---

## 3. Step-by-Step Cutover Procedure

### Step 1: Execute Migration 011 (Canonical Shadow Tables)
Creates `canonical_vulnerabilities`, `vulnerability_cvss_assessments`, and `cisa_kev_entries`.
```powershell
# 1. Dry Run
python scripts/migrations/011_canonical_vulnerability_spine.py --db-path ./tempris.db --dry-run

# 2. Live Run
python scripts/migrations/011_canonical_vulnerability_spine.py --db-path ./tempris.db
```

### Step 2: Execute Migration 012 (Finding Foreign Key Linkage)
Adds `findings.canonical_cve_id` foreign key column and index.
```powershell
# 1. Dry Run
python scripts/migrations/012_finding_canonical_cve_linkage.py --db-path ./tempris.db --dry-run

# 2. Live Run
python scripts/migrations/012_finding_canonical_cve_linkage.py --db-path ./tempris.db
```

### Step 3: Ingest Offline Intelligence Snapshots
Populates canonical vulnerability records, authoritative CVSS assessments, and CISA KEV exploitation data.
```powershell
# Ingest CISA KEV Snapshot
python app/backend/scripts/import_cve_intelligence.py `
  --source cisa-kev `
  --file app/backend/data/cisa_kev_2026_05_22.json `
  --db-path ./tempris.db

# Ingest NVD API 2.0 JSON Snapshot
python app/backend/scripts/import_cve_intelligence.py `
  --source nvd-json `
  --file path/to/nvd_cve_snapshot.json `
  --db-path ./tempris.db
```

### Step 4: Execute Finding Linkage & Canonical Backfill
Safely and idempotently links existing CVE-bearing findings to canonical vulnerability records.
```powershell
# 1. Dry Run (Inspect candidates)
python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db --dry-run

# 2. Live Execution (Link all tenants)
python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db
```

---

## 4. Post-Cutover Verification & Gate Checklist

Run the automated 9-gate verification suite:
```powershell
pytest app/backend/tests/test_canonical_cve_spine_cutover_gates.py -v
```

### Manual Integrity Verification Queries
1. **Zero Orphaned Foreign Keys:**
   ```sql
   SELECT COUNT(*) FROM findings 
   WHERE canonical_cve_id IS NOT NULL 
     AND canonical_cve_id NOT IN (SELECT cve_id FROM canonical_vulnerabilities);
   -- Must return 0
   ```
2. **Non-CVE Finding Isolation:**
   ```sql
   SELECT COUNT(*) FROM findings 
   WHERE canonical_cve_id IS NOT NULL 
     AND (cve IS NULL AND cve_id IS NULL);
   -- Must return 0
   ```
3. **Decoupled Catalogue Exposure Verification:**
   ```sql
   SELECT COUNT(*) FROM asset_exposures ae
   JOIN findings f ON ae.finding_id = f.id
   WHERE ae.status = 'confirmed' 
     AND ae.asset_id NOT IN (SELECT id FROM assets WHERE status = 'active');
   -- Must return 0
   ```

---

## 5. Rollback Procedures

### Scenario A: Rollback Prior to Production Traffic Switch
1. Stop backend services.
2. Restore verified database backup:
   ```powershell
   Copy-Item "backups/tempris_pre_cve_cutover.bak.db" "tempris.db" -Force
   ```
3. Re-launch backend service.

### Scenario B: Schema-Level Rollback (PostgreSQL)
1. Drop added foreign key and column:
   ```sql
   ALTER TABLE findings DROP COLUMN canonical_cve_id;
   DROP TABLE IF EXISTS vulnerability_cvss_assessments;
   DROP TABLE IF EXISTS cisa_kev_entries;
   DROP TABLE IF EXISTS canonical_vulnerabilities;
   ```
2. Revert backend application image.
