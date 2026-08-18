# Migration 012 Runbook: Finding-to-Canonical Vulnerability Linkage

Migration `012_finding_canonical_cve_linkage.py` performs the Strangler Fig schema evolution step for the Tempris CVE spine: adding the nullable `canonical_cve_id` column to the `findings` table with a foreign key constraint referencing `canonical_vulnerabilities(cve_id)` and creating an index on `canonical_cve_id`.

---

## 1. Schema Modifications
* **Table:** `findings`
* **Column Added:** `canonical_cve_id VARCHAR(32) NULL`
* **Constraint:** `FOREIGN KEY (canonical_cve_id) REFERENCES canonical_vulnerabilities(cve_id) ON DELETE RESTRICT`
* **Index Added:** `ix_findings_canonical_cve_id` on `findings(canonical_cve_id)`

---

## 2. Invariants & Guardrails
1. **Preservation of Legacy Fields:**
   `cve`, `cve_id`, `cvss`, `cisa_kev`, `ransomware`, `raw_inputs`, `asset_id`, `asset_data`, `sss_data`, and `cve_context` remain 100% untouched.
2. **Zero Automated External Network Access:**
   No network requests or external data lookups are performed during migration execution.
3. **Decoupled Linkage Step:**
   Migration 012 modifies schema only. Populating `canonical_cve_id` is performed explicitly and safely via the `link_findings_to_canonical.py` CLI utility.
4. **Non-Destructive & Reversible:**
   Safe to execute with zero downtime. Rollback removes the column or restores the pre-migration backup.

---

## 3. Migration Execution

### A. Preflight & Dry Run
Inspect the target schema and verify pending changes:
```powershell
python scripts/migrations/012_finding_canonical_cve_linkage.py --db-path ./tempris.db --dry-run
```
Expected dry-run output:
```json
{
  "before": {
    "canonical_cve_id_exists": false,
    "canonical_cve_index_exists": false,
    "canonical_vulnerabilities_exists": true,
    "database_engine": "sqlite",
    "findings_exists": true,
    "schema_complete": false
  },
  "changed": true,
  "dry_run": true
}
```

### B. Live Schema Migration Execution
Execute the schema change:
```powershell
python scripts/migrations/012_finding_canonical_cve_linkage.py --db-path ./tempris.db
```
For managed PostgreSQL deployments:
```bash
python scripts/migrations/012_finding_canonical_cve_linkage.py --database-url-env
```

---

## 4. Finding Linkage & Backfill Execution

Once the schema migration is applied and canonical intelligence snapshots are ingested, run the exact finding linkage CLI:

### A. Linkage Dry-Run
```powershell
python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db --dry-run
```

### B. Live Linkage (All Tenants)
```powershell
python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db
```

### C. Live Linkage (Single Tenant Scope)
```powershell
python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db --tenant-id tenant-acme
```

---

## 5. Post-Migration Verification Checklist
- [ ] Column `findings.canonical_cve_id` exists.
- [ ] Index `ix_findings_canonical_cve_id` is present.
- [ ] Foreign key constraint to `canonical_vulnerabilities(cve_id)` is active.
- [ ] Zero orphaned foreign keys:
  ```sql
  SELECT COUNT(*) FROM findings 
  WHERE canonical_cve_id IS NOT NULL 
    AND canonical_cve_id NOT IN (SELECT cve_id FROM canonical_vulnerabilities);
  ```
  *(Must return 0)*
- [ ] Non-CVE SSS findings have `canonical_cve_id = NULL`.
- [ ] Historical findings scores and triage decisions are unchanged.

---

## 6. Rollback Procedure
1. If uncommitted / staging:
   ```sql
   ALTER TABLE findings DROP COLUMN canonical_cve_id;
   ```
   *(Or restore the verified cryptographic database backup).*
2. Revert application deployment container / binaries.
