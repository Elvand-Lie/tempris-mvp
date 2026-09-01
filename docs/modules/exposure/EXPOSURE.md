# Exposure Domain Specification (Tempris V2)

This document provides the formal technical specification for the Exposure Domain in Tempris V2, including database schema contracts, state machines, relational models, API payload definitions, error mappings, and downstream consumption guidelines.

---

## 1. Database Schema & Relational Model

The Exposure Domain database foundation is defined in `TemprisV2/backend/migrations/013_exposure_domain_foundation.sql`.

### Relational Schema Diagram

```
 +---------------------------------------------+
 |            tenants (004)                    |
 | PK: id (uuid)                               |
 +---------------------------------------------+
        ^                       ^
        |                       |
        | 1:N                   | 1:N
        |                       |
 +-------------------+   +------------------------------------+
 |   assets (001)    |   |   canonical_vulnerabilities (007)  |
 | PK: id (uuid)     |   | PK: canonical_cve_id (text)        |
 | FK: tenant_id     |   +------------------------------------+
 |     status        |                  ^
 +-------------------+                  | 1:N (optional)
        ^                               |
        | 1:N            +------------------------------------+
        |                |   findings                         |
        |                | PK: id (uuid)                      |
        |                | FK: tenant_id -> tenants(id)       |
        |                | FK: canonical_cve_id -> canon(cve) |
        |                |     title, description, severity   |
        |                |     status ('open', 'closed')      |
        |                |     created_at, updated_at         |
        |                |     closed_at                      |
        |                +------------------------------------+
        |                               ^
        +---------------+---------------+
                        |
       +----------------+----------------+
       |                                 |
       v 1:N                             v 1:N
+------------------------------------+ +------------------------------------+
| asset_applicability_reviews        | | asset_exposures                    |
| PK: id (uuid)                      | | PK: id (uuid)                      |
| FK: tenant_id -> tenants(id)       | | FK: tenant_id -> tenants(id)       |
| FK: finding_id -> findings(id)     | | FK: finding_id -> findings(id)     |
| FK: asset_id -> assets(id)         | | FK: asset_id -> assets(id)         |
|     applicability (enum)           | |     status (enum: confirmed/etc)   |
|     reviewed_by (text)             | |     evidence (jsonb NOT NULL)      |
|     reason (text)                  | |     confirmed_by (text)            |
|     created_at (timestamptz)       | |     confirmed_at (timestamptz)     |
|                                    | |     resolved_at (timestamptz)      |
|                                    | |     resolved_by (text)             |
|                                    | |     resolution_reason (text)       |
+------------------------------------+ +------------------------------------+
```

### Table Definitions

#### `findings`
Represents a tenant-isolated security finding or vulnerability instance.
- `id UUID PRIMARY KEY`: Random UUID generated upon creation.
- `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`.
- `canonical_cve_id TEXT REFERENCES canonical_vulnerabilities(canonical_cve_id) ON DELETE RESTRICT`: Optional link to vulnerability intelligence.
- `title TEXT NOT NULL`: Finding title / summary.
- `description TEXT`: Extended markdown description or context.
- `severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))`.
- `status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'resolved', 'ignored', 'false_positive'))`.
- `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`.
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`.
- `closed_at TIMESTAMPTZ`: Timestamp when status transitioned to `closed`.

#### `asset_applicability_reviews`
Immutable append-only ledger of human and automated applicability assessments.
- `id UUID PRIMARY KEY`.
- `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`.
- `finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE`.
- `asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE`.
- `applicability TEXT NOT NULL CHECK (applicability IN ('NEEDS_REVIEW', 'REFERENCE', 'APPLICABLE', 'NOT_APPLICABLE'))`.
- `reviewed_by TEXT NOT NULL`: Actor ID who recorded the review.
- `reason TEXT`: Rationale or justification for the assessment.
- `created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()`.

#### `asset_exposures`
Active and historical operational exposure states.
- `id UUID PRIMARY KEY`.
- `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`.
- `finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE`.
- `asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE`.
- `status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'resolved', 'remediated', 'false_positive'))`.
- `evidence JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'object' AND evidence <> '{}'::jsonb)`: Mandatory structured evidence object.
- `confirmed_by TEXT NOT NULL`: Actor ID who confirmed the exposure.
- `confirmed_at TIMESTAMPTZ NOT NULL DEFAULT now()`.
- `resolved_at TIMESTAMPTZ`: Timestamp of resolution.
- `resolved_by TEXT`: Actor ID who resolved the exposure.
- `resolution_reason TEXT`: Rationale for resolution.
- **Unique Partial Index**: `UNIQUE (tenant_id, finding_id, asset_id) WHERE status = 'confirmed'` ensures at most one active confirmed exposure per tenant/finding/asset tuple.

---

## 2. Lifecycle State Machines

### Finding Lifecycle

```
      +-------------+
      | POST create |
      +-------------+
             |
             v
       +-----------+
       |   open    | <-----------------+
       +-----------+                   |
             |                         |
             v POST /close             | (re-open / update)
       +-----------+                   |
       |  closed   | ------------------+
       +-----------+
```

### Exposure Confirmation & Resolution Lifecycle

```
    [ Active Asset ] + [ Open Finding ]
                  |
                  | POST /api/exposure/confirm (non-empty JSONB evidence)
                  v
         +-----------------+
         |    confirmed    | <------------------------+
         +-----------------+                          |
                  |                                   |
                  | POST /api/exposure/resolve/{id}   | POST /api/exposure/confirm
                  v                                   | (re-confirmation with
         +-----------------+                          |  new evidence)
         |    resolved     | -------------------------+
         |   remediated    |
         | false_positive  |
         +-----------------+
```

---

## 3. Canonical Current Exposure Query Contract

Downstream modules (e.g. Synthesis, Reporting, Dashboards) must consume current active exposures exclusively through the canonical query contract:

```sql
SELECT
    e.id AS exposure_id,
    e.tenant_id,
    e.finding_id,
    e.asset_id,
    e.status AS exposure_status,
    e.evidence,
    e.confirmed_by,
    e.confirmed_at,
    f.canonical_cve_id,
    f.title AS finding_title,
    f.severity AS finding_severity,
    f.status AS finding_status,
    a.name AS asset_name,
    a.target_type AS asset_target_type,
    a.normalized_target AS asset_normalized_target,
    a.network_scope AS asset_network_scope,
    a.status AS asset_status
FROM asset_exposures e
JOIN findings f
  ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
JOIN assets a
  ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
WHERE e.tenant_id = :tenant_id
  AND e.status = 'confirmed'
  AND f.status = 'open'
  AND a.status = 'active'
  AND (:finding_id::uuid IS NULL OR e.finding_id = :finding_id::uuid)
  AND (:asset_id::uuid IS NULL OR e.asset_id = :asset_id::uuid)
  AND (:cve_id::text IS NULL OR f.canonical_cve_id = :cve_id::text)
  AND (:severity::text IS NULL OR f.severity = :severity::text)
ORDER BY e.confirmed_at DESC, e.id ASC;
```

### Dynamic Coupling Properties
1. **Asset Decommissioning**: When an asset is marked `status = 'decommissioned'`, the join condition `a.status = 'active'` immediately excludes its exposures from canonical queries. Reactivating the asset (`status = 'active'`) restores its exposures with zero mutation to `asset_exposures`.
2. **Finding Closure**: When a finding is closed (`status = 'closed'`), the join condition `f.status = 'open'` immediately excludes all its exposures.
3. **Deterministic Pagination**: Results are always sorted by `confirmed_at DESC, id ASC`.

---

## 4. REST API Specification

### Common Security Requirements
- **Authentication**: JWT Bearer token via `Authorization: Bearer <token>`.
- **RBAC**: Permitted roles: `analyst`, `admin`, `superadmin`.
- **Platform Tenant Isolation**: Platform Control tenant (`00000000-0000-0000-0000-000000000000`) is rejected with `403 Forbidden` (`detail="Platform sessions cannot access tenant modules."`).
- **Cross-Tenant Concealment**: Requests accessing resources owned by a different tenant return `404 Not Found` without disclosing existence.

### Endpoint Definitions

#### 1. `POST /api/exposure/findings`
- **Request Body**:
  ```json
  {
    "title": "Unauthenticated Remote Code Execution in Apache Struts",
    "severity": "critical",
    "description": "Optional markdown description",
    "canonical_cve_id": "CVE-2017-5638"
  }
  ```
- **Response (201 Created)**: Finding object.
- **Audit Event**: `finding.created`.

#### 2. `GET /api/exposure/findings/{id}`
- **Response (200 OK)**: Finding object.
- **Errors**: `404 Not Found` (non-existent or cross-tenant).

#### 3. `POST /api/exposure/findings/{id}/close`
- **Request Body** (optional):
  ```json
  {
    "reason": "Vulnerability patched across all internal fleets"
  }
  ```
- **Response (200 OK)**: Finding object with `status: "closed"`.
- **Audit Event**: `finding.closed`.

#### 4. `POST /api/exposure/reviews`
- **Request Body**:
  ```json
  {
    "finding_id": "c1f72960-9b37-4d87-9eb3-97996c561502",
    "asset_id": "8488e5e7-aa23-455b-86d7-8495449d0382",
    "applicability": "APPLICABLE",
    "reviewed_by": "analyst-a",
    "reason": "Host running vulnerable Struts version 2.3.31 on port 8080"
  }
  ```
  *(Note: `reviewed_by` is optional; defaults to authenticated `actor_id` if omitted).*
- **Response (201 Created)**: ApplicabilityReview object.
- **Audit Event**: `exposure.review_recorded`.

#### 5. `GET /api/exposure/reviews`
- **Query Params**: `finding_id` (UUID), `asset_id` (UUID).
- **Response (200 OK)**: List of ApplicabilityReview objects sorted by `created_at DESC, id ASC`.

#### 6. `POST /api/exposure/confirm`
- **Request Body**:
  ```json
  {
    "finding_id": "c1f72960-9b37-4d87-9eb3-97996c561502",
    "asset_id": "8488e5e7-aa23-455b-86d7-8495449d0382",
    "evidence": {
      "port": 8080,
      "service": "http",
      "banner": "Apache Struts 2.3.31",
      "poc_verified": true
    },
    "confirmed_by": "analyst-a"
  }
  ```
  *(Note: `confirmed_by` is optional; defaults to authenticated `actor_id` if omitted).*
- **Response (200 OK)**: AssetExposure object.
- **Audit Event**: `exposure.confirmed`.
- **Errors**: `422 Unprocessable Entity` (empty/invalid evidence), `400 Bad Request` (decommissioned asset or closed finding), `404 Not Found` (asset/finding not in tenant).

#### 7. `POST /api/exposure/resolve/{id}`
- **Request Body** (optional):
  ```json
  {
    "status": "resolved",
    "resolved_by": "admin-a",
    "resolution_reason": "Patched to Apache Struts 2.5.30"
  }
  ```
  *(Note: `resolved_by` is optional; defaults to authenticated `actor_id` if omitted; `status` defaults to `resolved`).*
- **Response (200 OK)**: AssetExposure object.
- **Audit Event**: `exposure.resolved`.
- **Errors**: `404 Not Found` (exposure not in tenant), `422 Unprocessable Entity` (invalid status).

#### 8. `GET /api/exposure/current`
- **Query Params**: `finding_id` (UUID), `asset_id` (UUID), `cve_id` (string), `severity` (string).
- **Response (200 OK)**: List of CanonicalExposureItem objects.
