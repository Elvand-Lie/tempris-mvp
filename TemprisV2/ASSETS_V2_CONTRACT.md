# Tempris V2 ASSETS Contract

## 1. Overview & Architecture
Tempris V2 ASSETS is the authoritative, multi-tenant asset inventory and exact-target scan authorization vertical slice. It is implemented with FastAPI (Python) and plain `psycopg` (v3) parameterized SQL on the backend, and a minimal React 18 + TypeScript + Vite application with plain CSS on the frontend. PostgreSQL is configured through `DATABASE_URL`; release verification uses the isolated `tempris_v2_test` database through the local VPS tunnel. The slice enforces strict domain invariants without ORM, repository bloat, or Docker scaffolding.

---

## 2. Key Invariants & Guarantees

### 2.1 Multi-Tenant Context & Authentication
- Every API request derives `tenant_id`, `actor_id` (`sub`), and `role` (`analyst`, `admin`, `superadmin`) exclusively from signed Bearer JWT claims.
- The frontend client exclusively consumes externally issued Bearer JWTs provided by the host environment via `sessionStorage` (`tempris_bearer_token`).
- Zero client-side JWT signing, zero Web Crypto subtle HMAC minting, and zero frontend role switching or claim forgery capabilities exist in the client.
- The frontend decodes token payloads strictly for read-only presentation (e.g. user badges, UI enablement hints); the backend remains strictly authoritative for all tenant isolation and RBAC checks.
- If no token is provided in `sessionStorage`, the frontend displays a clear, dedicated session-required state (`#session-required-state`).
- Client/browser-supplied tenant identifiers in route, query, or body parameters are strictly ignored and discarded.
- Cross-tenant data isolation is enforced at the database level across all tables (`assets`, `asset_scan_authorizations`, `audit_events`).

### 2.2 Role-Based Access Control (RBAC)
- **`analyst`**: Allowed to list, query, create, update, and decommission assets; check target reachability; query statistics; and request scan authorizations. Prohibited from approving or revoking scan authorizations (returns HTTP 403 Forbidden).
- **`admin` / `superadmin`**: Full operational permissions including approval (with strictly future `expires_at`) and revocation of scan authorizations.

### 2.3 Target Normalization & Scope Independence
- **Supported Target Types**: `ip` (IPv4, IPv6), `hostname`, `domain`.
- **Normalization**: RFC 5952 canonical compressed IPv6 formatting; lowercased domains/hostnames with trailing dots removed; trimmed whitespace.
- **Prohibited Target Classes (HTTP 422)**:
  - Loopback (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost`)
  - Unspecified (`0.0.0.0`, `::`)
  - Multicast (`224.0.0.0/4`, `ff00::/8`)
  - Limited Broadcast (`255.255.255.255`)
  - URL schemes (`http://`, `https://`, `//`)
  - Port numbers (`:8080`, `:443`)
  - CIDR notations (`/24`, `/16`)
- **Scope Independence**:
  - RFC 1918 / RFC 4193 private addresses are accepted for both `internal` and `internet` network scopes.
  - Publicly routable addresses may be registered with `internal` network scope.
  - Reachability check failure does not invalidate syntactically valid targets.

### 2.4 Non-Intrusive Target Check (`POST /api/assets/check-target`)
- **Internal Scope**: Syntax and address classification only. Strictly 0 DNS lookups and 0 socket connections. Returns `reachability_status: "unverified"`, `verification_source: null`, and exact message `"Internal collector required for reachability verification."`.
- **Internet Scope**: DNS resolution permitted, followed by raw TCP connect to port 443 then 80 (maximum 2.0s timeout per port). Zero bytes transmitted (no TLS handshake, no HTTP GET/POST, no banner collection, no vulnerability scan). Returns `reachability_status: "verified"` or `reachability_status: "unreachable"`.

### 2.5 Scan Authorization Lifecycle & Atomic Invalidation
- **Exact Tuple Binding**: Authorizations snapshot `(target_type, normalized_target, network_scope)` at the moment of request/approval.
- **Mandatory Future Expiry**: Approvals require an explicit ISO8601 `expires_at` timestamp strictly in the future (past/missing returns HTTP 422).
- **Atomic Invalidation**: Any mutation to `target_type`, `normalized_target`, or `network_scope`—as well as asset decommissioning—automatically and atomically revokes prior active/pending authorizations in the same database transaction.
- **Immediate Expiry**: Authorizations where `expires_at <= now()` are immediately treated as expired and excluded from `authorized_to_scan`.

### 2.6 Asset Statistics Semantics (`GET /api/assets/stats`)
Computes five tenant-isolated counters across active assets:
1. `total_assets`: Active assets in caller's tenant (`status = 'active'`).
2. `reachable_by_scout`: Active assets with `reachability_status = 'verified'` and `network_scope = 'internet'`.
3. `authorized_to_scan`: Distinct active assets with an approved, non-expired (`expires_at > now()`) authorization matching the current exact target tuple.
4. `pending_authorization`: Distinct active assets with a pending authorization request matching the current exact target tuple.
5. `no_scanner_available`: Active assets with `network_scope = 'internal'`.
- Decommissioned assets are strictly excluded from all five counters.

### 2.7 User Interface & Semantic Language
- Built with React 18, TypeScript, Vite, and plain CSS.
- Displays all 5 stats cards with reactive refresh upon all mutations.
- Asset inventory table with compact row action menu (View Details, Edit, Request Auth, Approve Auth [Admin only], Revoke Auth [Admin only], Decommission).
- Target Check displays explicit semantic disclaimers:
  - Reachability indicates network connectivity only; it does not indicate the asset is secure.
  - Scan authorization indicates organizational permission to scan; it does not guarantee network reachability.
- Edit form displays prominent warning that mutating target value, type, or scope atomically revokes active scan authorizations.
- Fully responsive across desktop and mobile viewports down to 320px with keyboard accessibility.

---

## 3. Storage Schema Summary

- `assets`: Primary inventory table with UUID `id`, `tenant_id`, target tuple, metadata, reachability, timestamps, and partial unique index on `(tenant_id, normalized_target) WHERE status = 'active'`.
- `asset_scan_authorizations`: Authorization records bound to asset target tuple with status (`pending`, `approved`, `revoked`, `expired`), requester/approver/revoker audit fields, and `expires_at`.
- `audit_events`: Append-only audit log capturing `asset.created`, `asset.updated`, `asset.decommissioned`, `asset.target_checked`, `scan_authorization.requested`, `scan_authorization.approved`, `scan_authorization.revoked` with sanitized details (zero credential/token/payload leakage).

---

## 4. Test Execution & Release Verification Path

```powershell
# 1. Backend PostgreSQL Acceptance Suite (22 tests)
$env:PYTHONPATH='backend'
backend\.venv\Scripts\python -m pytest -v backend\tests

# 2. Frontend Component Suite (Vitest)
npm --prefix frontend test -- --run

# 3. Frontend Production Build (TypeScript + Vite)
npm --prefix frontend run build

# 4. End-to-End Browser Critical Flow (Playwright)
npm --prefix frontend run test:e2e
```
