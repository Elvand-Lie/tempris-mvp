# Tempris V2 Assets & Collectors Contract

> **Canonical Reference**: For the full, comprehensive specification across all 30+ operational, cryptographic, schema, and lifecycle topics, see the authoritative [ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md](ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md).

## 1. Process-Local Registry & Single-Worker Requirement

The Tempris V2 internal collector registry (`collector_registry.py`) maintains active WebSocket connections, ephemeral challenge states, and in-flight job futures in memory. 

- **Operational Requirement**: The V2 backend **MUST** be deployed and run with **exactly one worker process**:
  ```bash
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
  ```
- **Rationale**: Running multiple Uvicorn workers causes non-deterministic WebSocket connections, where a collector connects to Worker A, but an asset reachability recheck request lands on Worker B, resulting in false `collector_unavailable` statuses and lost job futures.

## 2. Dedicated Database Provisioning

Tempris V2 requires an isolated PostgreSQL database (e.g. `tempris_v2_prod` or `tempris_v2_test`).

### Manual Setup SQL
To provision the dedicated V2 database and user:
```sql
-- Connect to Postgres as superuser (e.g., postgres)
CREATE ROLE tempris_v2_app WITH LOGIN PASSWORD '<secure_password>';
CREATE DATABASE tempris_v2_prod OWNER tempris_v2_app;
GRANT ALL PRIVILEGES ON DATABASE tempris_v2_prod TO tempris_v2_app;

\c tempris_v2_prod tempris_v2_app;
-- Enable pgcrypto extension for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

### Migration Execution
Apply forward migrations sequentially:
1. `backend/migrations/001_initial_assets_schema.sql`
2. `backend/migrations/002_collectors_and_asset_routing.sql`
3. `backend/migrations/003_collector_schema_contract.sql`

## 3. Cryptography & Windows DPAPI Key Protection

- **Daemon Key Generation**: The Windows collector daemon generates an Ed25519 keypair locally upon enrollment.
- **Machine-Wide Data Protection at Rest (DPAPI)**: On Windows, the private signing seed is encrypted using native Windows DPAPI with machine scope (`CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN` in `crypt32.dll`) before being persisted as a raw binary file to `%PROGRAMDATA%\Tempris\Collector\protected_identity.dat`.
- **DACL Security Tiers**:
  - `protected_identity.dat` is protected by a Secret Tier DACL (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), granting Full Access to SYSTEM and Administrators and zero access to standard users.
  - `state.json` (schema_version 2) is protected by an Observer Tier DACL (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;GRGX;;;BU)`), granting Read-Only access to standard users.
- **No Plaintext Private Keys**: Configuration JSON files contain only public metadata and base64url-encoded public keys. Raw signing seeds and DPAPI ciphertexts are never embedded in JSON files.

## 4. Transport Gate & Safety Validation

- **Remote Transport Enforcement**: Remote collector endpoints MUST use `https://` or `wss://`. Plaintext `http://` or `ws://` is strictly rejected unless the target host is a loopback address (`localhost`, `127.0.0.1`, or `[::1]`).
- **Fail-Closed Pre-Authentication**: The collector daemon ignores all `VERIFY_TARGET` frames received prior to receiving `AUTH_SUCCESS`.
- **Target Type & Scope Validation**: Target types must strictly be one of `ip`, `hostname`, `domain`, and network scope must be `internal`. Forbidden address spaces (e.g., link-local, loopback targets, cloud metadata endpoints) fail closed without initiating socket connects or DNS resolution.

## 5. Optimistic Concurrency Control (OCC) for Asset Recheck

- Recheck operations snapshot the asset tuple `(id, tenant_id, status, target_type, target_value, normalized_target, network_scope, collector_id)` and release database locks before initiating asynchronous network probes.
- Updates are applied via an atomic Compare-And-Set (CAS) query. If an asset is concurrently modified, reassigned, or decommissioned during an in-flight probe, the CAS update fails and the stale probe result is discarded with a `409 Conflict` and an `asset.recheck_discarded_conflict` audit event.
