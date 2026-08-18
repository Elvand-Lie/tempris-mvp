# Migration 013 Runbook: Asset Scan Authorizations and Scan Job Provenance

Migration `013_asset_scan_authorizations.py` implements the foundational security, target-binding, and execution-provenance data model for the Tempris SCOUT external attack surface scanner.

---

## 1. Schema Modifications

### A. New Table: `asset_scan_authorizations`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(64) | PRIMARY KEY | Unique authorization ID (`authz-...`) |
| `tenant_id` | VARCHAR(64) | NOT NULL, INDEXED | Tenant isolation boundary |
| `asset_id` | VARCHAR(64) | NOT NULL, INDEXED | Bound asset identity |
| `authorized_target` | VARCHAR(512) | NOT NULL | Canonical target authorized for probing |
| `target_kind` | VARCHAR(32) | NOT NULL | `public_ip` or `public_fqdn` |
| `status` | VARCHAR(32) | NOT NULL, INDEXED | `pending`, `approved`, `revoked`, `expired` |
| `approval_method` | VARCHAR(64) | NOT NULL | `superadmin_manual`, `verified_dns_token`, etc. |
| `evidence` | TEXT | NULL | JSON/text audit verification details |
| `requested_by` | VARCHAR(64) | NOT NULL | User ID who submitted scan request |
| `requested_at` | DATETIME | NOT NULL | Timestamp of request |
| `approved_by` | VARCHAR(64) | NULL | Superadmin user ID who approved |
| `approved_at` | DATETIME | NULL | Timestamp of approval |
| `expires_at` | DATETIME | NULL | Timestamp of expiration (default +90 days) |
| `revoked_by` | VARCHAR(64) | NULL | User ID who revoked authorization |
| `revoked_at` | DATETIME | NULL | Timestamp of revocation |
| `revocation_reason`| TEXT | NULL | Reason for revocation |
| `created_at` | DATETIME | NOT NULL | Timestamp of record creation |
| `updated_at` | DATETIME | NOT NULL | Timestamp of last record update |

### B. Extended Table: `scan_jobs` (Provenance Columns)
| Column | Type | Constraints | Description |
|---|---|---|---|
| `asset_id` | VARCHAR(64) | NULL, INDEXED | Authoritative asset identity |
| `scan_authorization_id` | VARCHAR(64) | NULL, INDEXED | Active authorization snapshot ID |
| `authorized_canonical_target` | VARCHAR(512) | NULL | Immutable copy of authorized target |
| `target_kind` | VARCHAR(32) | NULL | `public_ip` or `public_fqdn` |
| `resolved_ips` | TEXT | NULL | JSON array of resolved IPs at execution time |
| `dns_resolved_at` | DATETIME | NULL | Timestamp of pre-execution DNS resolution |
| `initiating_user_id` | VARCHAR(64) | NULL | User ID who triggered scan job |
| `execution_origin` | VARCHAR(64) | NOT NULL (default `central_vps`) | Provenance marker of scan engine |
| `failure_reason` | TEXT | NULL | Structured failure/policy rejection reason |

---

## 2. Security Invariants & Guardrails

1. **Explicit Additive Evolution:**
   Existing tables, assets, findings, and exposures remain intact. All existing assets default to unauthorized.
2. **Strict Superadmin Approval:**
   Only users with the `Superadmin` platform role can approve `AssetScanAuthorization` records.
3. **Target Invalidation on Mutation:**
   Any update to an asset's `hostname` or `ip_address` immediately revokes active authorizations with reason `"Asset target modified; re-authorization required"`.
4. **Pre-Execution SSRF & Re-Resolution:**
   Scanner verifies that canonical target is globally routable (rejecting RFC 1918, loopbacks, link-local, cloud metadata, ULA, CGNAT) and re-resolves DNS immediately before spawning subprocesses.
5. **Zero External Network Calls in Migration:**
   The migration runs purely against local database schema and makes no network calls.

---

## 3. Migration Execution

### A. Preflight & Dry Run
```powershell
python scripts/migrations/013_asset_scan_authorizations.py --db-path ./tempris.db --dry-run
```

Expected dry-run output:
```json
{
  "before": {
    "asset_scan_authorizations_exists": false,
    "database_engine": "sqlite",
    "scan_jobs_columns": {
      "asset_id": false,
      "authorized_canonical_target": false,
      "dns_resolved_at": false,
      "execution_origin": false,
      "failure_reason": false,
      "initiating_user_id": false,
      "resolved_ips": false,
      "scan_authorization_id": false,
      "target_kind": false
    },
    "scan_jobs_exists": true,
    "schema_complete": false
  },
  "changed": true,
  "dry_run": true
}
```

### B. Apply Migration
```powershell
python scripts/migrations/013_asset_scan_authorizations.py --db-path ./tempris.db --apply
```

### C. Verify Idempotence
Re-running `--apply` returns `changed: false`.

### D. Rollback Plan
To roll back (development/testing environments only):
```powershell
python scripts/migrations/013_asset_scan_authorizations.py --db-path ./tempris.db --rollback
```
