# Exposure Domain (Tempris V2)

The **Exposure Domain** is the authoritative core of Tempris V2 responsible for managing tenant-scoped security findings, recording immutable applicability review decisions, tracking explicit confirmed exposures backed by structured evidence, and providing the single canonical current exposure query for downstream consumption.

---

## 1. Architectural Overview & Boundary Principles

The Exposure Domain enforces strict separation of concerns across four decoupled layers:

```
+-------------------------------------------------------------------------+
|                  Global Vulnerability Intelligence                      |
| (canonical_vulnerabilities, cvss_assessments, cve_records, nvd_records) |
+-------------------------------------------------------------------------+
                                    |
                                    v (Optional canonical_cve_id FK)
+-------------------------------------------------------------------------+
|                         Tenant Findings Layer                           |
|                      (findings table, status: open/closed)              |
+-------------------------------------------------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
+------------------------------------+    +------------------------------------+
|  Applicability Review Log          |    |   Asset Exposure State             |
|  (asset_applicability_reviews)     |    |   (asset_exposures)                |
|  - Append-only audit trail         |    |   - Explicit non-empty evidence    |
|  - APPLICABLE / NOT_APPLICABLE     |    |   - Idempotent confirm / resolve   |
|  - NEEDS_REVIEW / REFERENCE        |    |   - Status: confirmed, resolved    |
+------------------------------------+    +------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                 Canonical Current Exposure Query                        |
|   e.status = 'confirmed' AND f.status = 'open' AND a.status = 'active'  |
|            ORDER BY e.confirmed_at DESC, e.id ASC                       |
+-------------------------------------------------------------------------+
```

### Core Separation Principles

1. **Vulnerability Intelligence vs Tenant Finding**:
   - `canonical_vulnerabilities` stores globally aggregated, public vulnerability intelligence (CVE/NVD/KEV/EPSS/OSV). It contains zero tenant IDs, zero asset links, and zero customer state.
   - `findings` represents a tenant-specific vulnerability occurrence or advisory within a tenant's boundary. A finding may optionally link to `canonical_vulnerabilities(canonical_cve_id)` via a foreign key, but can also represent custom or non-CVE security findings.

2. **Applicability Review vs Confirmed Exposure**:
   - `asset_applicability_reviews` is an **append-only ledger** capturing human or automated triage assessments (`NEEDS_REVIEW`, `REFERENCE`, `APPLICABLE`, `NOT_APPLICABLE`). It records triage history and rationale over time without mutating exposure state.
   - `asset_exposures` is the **active operational exposure state table**. An exposure can only be created or updated via explicit confirmation (`POST /api/exposure/confirm`) with non-empty structured JSONB evidence.

3. **Zero Synthetic Hallucination**:
   - The platform never synthesizes or assumes an asset is exposed based merely on an applicability review or vulnerability match. Exposure requires explicit confirmation backed by evidence.

---

## 2. Invariants & Guarantees

1. **Strict Multi-Tenant Isolation**:
   - Every table (`findings`, `asset_applicability_reviews`, `asset_exposures`) includes `tenant_id` as part of its primary and composite foreign keys.
   - All REST API endpoints enforce `auth.tenant_id`. Any query or mutation targeting a foreign tenant's resource yields `404 Not Found` without disclosing entity existence.
   - The platform control tenant (`00000000-0000-0000-0000-000000000000`) is rejected with `403 Forbidden` (`detail="Platform sessions cannot access tenant modules."`).

2. **Active Asset & Open Finding Enforcement**:
   - An exposure can only be confirmed on an **active asset** (`assets.status = 'active'`) and an **open finding** (`findings.status = 'open'`).
   - Confirmation attempts on decommissioned assets or closed findings are rejected with `400 Bad Request`.

3. **Dynamic Lifecycle Coupling in Canonical Query**:
   - The canonical query (`GET /api/exposure/current`) joins `asset_exposures (e)`, `findings (f)`, and `assets (a)`.
   - Condition: `e.status = 'confirmed' AND f.status = 'open' AND a.status = 'active'`.
   - If an asset is decommissioned (`a.status = 'decommissioned'`), it immediately disappears from current exposures. If reactivated (`a.status = 'active'`), its confirmed exposure reappears dynamically without database mutation on `asset_exposures`.
   - If a finding is closed (`f.status = 'closed'`), it immediately disappears from current exposures.

4. **Deterministic Canonical Ordering**:
   - All canonical current exposure queries enforce deterministic ordering: `ORDER BY e.confirmed_at DESC, e.id ASC`.

5. **Idempotency & Re-confirmation**:
   - Re-confirming an active exposure with new evidence updates the existing record, updates `confirmed_at = now()`, and resets resolution fields.
   - Re-confirming an exposure after it was previously resolved creates/updates an active confirmed record.
   - Closing an already closed finding is idempotent and returns `200 OK`.

---

## 3. REST API Quick Reference

All endpoints are prefixed with `/api/exposure` and require authentication (`Authorization: Bearer <token>`).

| Method | Path | Description | Roles |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/exposure/findings` | Create tenant finding (optional `canonical_cve_id`, `title`, `description`, `severity`). | `analyst`, `admin`, `superadmin` |
| `GET` | `/api/exposure/findings/{id}` | Retrieve tenant finding by ID. | `analyst`, `admin`, `superadmin` |
| `POST` | `/api/exposure/findings/{id}/close` | Close finding with optional `reason`. Idempotent. | `analyst`, `admin`, `superadmin` |
| `POST` | `/api/exposure/reviews` | Record append-only applicability review (`reviewed_by` defaults to actor). | `analyst`, `admin`, `superadmin` |
| `GET` | `/api/exposure/reviews` | List applicability reviews for tenant with optional `finding_id` and `asset_id` filters. | `analyst`, `admin`, `superadmin` |
| `POST` | `/api/exposure/confirm` | Explicitly confirm exposure with structured evidence (`confirmed_by` defaults to actor). | `analyst`, `admin`, `superadmin` |
| `POST` | `/api/exposure/resolve/{id}` | Resolve confirmed exposure (`resolved`, `remediated`, `false_positive`). | `analyst`, `admin`, `superadmin` |
| `GET` | `/api/exposure/current` | Query canonical active exposures with optional `finding_id`, `asset_id`, `cve_id`, `severity` filters. | `analyst`, `admin`, `superadmin` |

---

## 4. Audit Event Schema

Every mutating action generates an audit event recorded via `app.audit.record_audit_event`:

1. `finding.created`:
   - `details`: `{"finding_id": "<uuid>", "title": "<title>", "canonical_cve_id": "<cve_or_null>", "severity": "<sev>"}`
2. `finding.closed`:
   - `details`: `{"finding_id": "<uuid>", "reason": "<reason_or_null>"}`
3. `exposure.review_recorded`:
   - `asset_id`: `<asset_uuid>`
   - `details`: `{"finding_id": "<uuid>", "applicability": "<status>", "reason": "<reason_or_null>"}`
4. `exposure.confirmed`:
   - `asset_id`: `<asset_uuid>`
   - `details`: `{"finding_id": "<uuid>", "exposure_id": "<uuid>"}`
5. `exposure.resolved`:
   - `asset_id`: `<asset_uuid>`
   - `details`: `{"finding_id": "<uuid>", "exposure_id": "<uuid>", "status": "<status>", "reason": "<reason_or_null>"}`
