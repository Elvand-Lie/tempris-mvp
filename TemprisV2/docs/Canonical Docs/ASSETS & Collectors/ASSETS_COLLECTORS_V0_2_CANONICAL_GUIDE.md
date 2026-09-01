# Tempris V2 Assets & Collectors V0.2 — Canonical Architecture, Operational & Verification Guide

> **Document Status**: Authoritative Canonical Specification  
> **Version**: V0.2.0 (Vertical Slice Completed)  
> **Release Target**: Tempris V2 Assets & Collectors  
> **Last Verified**: 2026-08-30  
> **Authoritative Precedence**: When this guide and codebase disagree, **source code is the ultimate ground truth**. Updates to backend routes, database schemas, cryptographic protocols, or collector binaries must be accompanied by updates to this canonical document.

---

## Table of Contents

1. [Executive Mental Model & Architectural North Star](#1-executive-mental-model--architectural-north-star)
2. [Scope, Non-Goals & Invariant Boundaries](#2-scope-non-goals--invariant-boundaries)
3. [Architecture & Component Data-Flow Diagrams](#3-architecture--component-data-flow-diagrams)
4. [Source-of-Truth & Code Location Map](#4-source-of-truth--code-location-map)
5. [Unified Terminology & Domain Glossary](#5-unified-terminology--domain-glossary)
6. [Asset Inventory Lifecycle & State Machine](#6-asset-inventory-lifecycle--state-machine)
7. [Exact-Target Scan Authorization & Atomic Invalidation](#7-exact-target-scan-authorization--atomic-invalidation)
8. [Reachability Verification & Routing Semantics](#8-reachability-verification--routing-semantics)
9. [Asset Inventory Statistics Semantics](#9-asset-inventory-statistics-semantics)
10. [Collector Architecture & Dual-Binary Execution Model](#10-collector-architecture--dual-binary-execution-model)
11. [Cryptographic Enrollment & WebSocket Protocol](#11-cryptographic-enrollment--websocket-protocol)
12. [Process-Local Registry & Single-Worker Architecture](#12-process-local-registry--single-worker-architecture)
13. [Windows Machine Storage & DPAPI Cryptographic Protection](#13-windows-machine-storage--dpapi-cryptographic-protection)
14. [Windows Task Scheduler SYSTEM BootTrigger & SDDL Security](#14-windows-task-scheduler-system-boottrigger--sddl-security)
15. [Revoked Collector Permanent Deletion Gates & Audit Retention](#15-revoked-collector-permanent-deletion-gates--audit-retention)
16. [Tenant Isolation, RBAC & Security Boundaries](#16-tenant-isolation-rbac--security-boundaries)
17. [PostgreSQL Schema, Migrations & Parameterized Data Access](#17-postgresql-schema-migrations--parameterized-data-access)
18. [Complete API Endpoint Reference](#18-complete-api-endpoint-reference)
19. [Frontend User Experience & UI State Behavior](#19-frontend-user-experience--ui-state-behavior)
20. [Configuration, Deployment & Rollback Runbook](#20-configuration-deployment--rollback-runbook)
21. [Logging, Telemetry & Strict Secret Redaction](#21-logging-telemetry--strict-secret-redaction)
22. [Troubleshooting Decision Trees & Operator Runbooks](#22-troubleshooting-decision-trees--operator-runbooks)
23. [Automated & Manual Acceptance Verification Evidence](#23-automated--manual-acceptance-verification-evidence)
24. [Remaining Limitations & Deferred Work](#24-remaining-limitations--deferred-work)
25. [Why It Is Designed This Way / Why Not X? (Master Decision Matrix)](#25-why-it-is-designed-this-way--why-not-x-master-decision-matrix)
26. [Maintenance Rules & Verification Checklist](#26-maintenance-rules--verification-checklist)

---

## 1. Executive Mental Model & Architectural North Star

Tempris V2 Assets & Collectors is a **zero-trust, zero-ingress internal asset exposure and reachability verification system**. It provides centralized enterprise visibility into internal and internet-facing network assets without compromising perimeter security.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            CORE AXIOMS OF TEMPRIS V2                             │
├──────────────────────────────────────────────────────────────────────────────────┤
│ 1. Reachability != Validity != Authorization != Secure                          │
│    - Syntactic validity: Target string matches IP, hostname, or domain syntax.   │
│    - Reachability: Non-destructive zero-byte TCP probe (ports 443/80) confirms    │
│      target presence on the network. Permitted WITHOUT scan authorization.       │
│    - Scan Authorization: Multi-stage administrative governance for active        │
│      vulnerability scanning (a deferred V0.3+ capability).                       │
│    - Security: Being reachable NEVER implies an asset is secure or patch-free.   │
│                                                                                  │
│ 2. Zero Inbound Perimeter Penetration (Zero Ingress)                             │
│    - Collectors establish strictly outbound TLS WebSockets (wss://).             │
│    - Collectors NEVER bind listening TCP/UDP ports or accept incoming packets.  │
│                                                                                  │
│ 3. Exact-Target Verification Only (Zero Command / Sweep / CIDR Capabilities)     │
│    - Collectors execute sequential, zero-byte TCP handshakes on ports 443 & 80. │
│    - Collectors NEVER execute remote commands, shell scripts, or range sweeps.   │
│    - CIDR ranges are explicitly prohibited to prevent scanning weaponization.    │
│                                                                                  │
│ 4. Single-Worker In-Memory Control Plane (Process-Local WebSocket Registry)     │
│    - V2 backend runs as a single Uvicorn worker process (--workers 1).           │
│    - Active WebSockets, challenge nonces, and in-flight job futures live in RAM. │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### The Central Problem Solved
Traditional external attack surface management (EASM) tools cannot probe internal enterprise assets behind firewalls and NAT gateways without establishing complex VPNs, deploying heavy credentialed agents, or punching dangerous inbound holes in firewalls.

Tempris V2 solves this by deploying a lightweight Windows Collector inside the internal perimeter. The collector maintains a secure outbound WebSocket connection to the Tempris Control Plane. When an operator or automated workflow requests an asset recheck, the control plane routes internal targets to an active collector assigned to that network, while checking public Internet targets directly from the control plane.

---

## 2. Scope, Non-Goals & Invariant Boundaries

### 2.1 Current V0.2 In-Scope Capabilities
- **Asset Inventory Management**: Multi-tenant CRUD operations for network assets (`ip`, `hostname`, `domain`).
- **Target Formats**: Strictly `ip` (IPv4/IPv6), `hostname`, and `domain`. (CIDR blocks are explicitly rejected).
- **Dual-Path Reachability Verification**:
  - `internet` scope: Verified directly by the FastAPI backend via asynchronous TCP probes (ports 443 -> 80).
  - `internal` scope: Dispatched over outbound WebSocket to an enrolled, online, authenticated internal collector.
- **Reachability Recheck Independence**: Rechecks perform safe zero-byte TCP handshakes and do **not** require scan authorization approval.
- **Exact-Target Scan Authorization**: Multi-stage governance workflow (`pending`, `approved`, `revoked`, `expired`) tracked in `asset_scan_authorizations` and strictly bound to the 4-tuple `(tenant_id, target_type, normalized_target, network_scope)`.
- **Optimistic Concurrency Control (OCC)**: Lock-free asset rechecks using atomic Compare-and-Set (CAS) database updates.
- **Collector Dual-Binary Architecture**:
  - `tempris-collector.exe`: Unified binary functioning as an interactive desktop GUI or a headless background daemon (`--core`).
  - `TemprisCollectorSetup.exe`: Dedicated installer, repair utility, and task registration assistant.
- **Windows Task Scheduler Integration**: Unattended system boot autostart (`BootTrigger` under `NT AUTHORITY\SYSTEM`) protected by strict Security Descriptor Definition Language (SDDL) Access Control Lists (ACLs).
- **Machine-Level DPAPI Cryptography**: Machine-wide encrypted storage of Ed25519 signing seeds at `%PROGRAMDATA%\Tempris\Collector\protected_identity.dat`.
- **Non-Replayable Cryptographic Authentication**: Ed25519 challenge-response handshake with 32-byte single-use nonces and 30-second UTC expiration windows.
- **Strict Network Safety**: Non-negotiable client-side rejection of loopback, link-local, AWS metadata (`169.254.169.254`), multicast, broadcast, and unspecified IP addresses with single-resolution DNS pinning.
- **Collector Lifecycle & Safety Controls**: Administrative pause, quarantine, release, revocation, and safe permanent deletion.
- **Inventory Statistics**: Real-time tenant-level metrics returning 5 concrete fields (`total_assets`, `reachable_by_scout`, `authorized_to_scan`, `pending_authorization`, `no_scanner_available`).

### 2.2 Explicit Non-Goals & Out-of-Scope (Prohibited Behaviors)
- **Vulnerability Scanning & Exploitation**: Zero vulnerability probing, zero banner grabbing, zero fuzzing, and zero exploit payloads.
- **CIDR Ranges & Sweep Scanning**: CIDR notations (e.g. `10.0.0.0/24`) are forbidden to prevent weaponizing the collector as an unconstrained subnet scanner.
- **Arbitrary Port Scanning**: Probes are restricted exclusively to ports 443 and 80; no arbitrary port ranges.
- **Remote Command Execution / Shell Access**: Zero arbitrary script execution, zero process spawning, zero CLI tunneling.
- **Generic Proxying / VPN / SOCKS Tunneling**: The collector cannot be used as an HTTP proxy, SOCKS proxy, or network bridge.
- **Cross-Tenant Visibility**: Total multi-tenant database and cryptographic isolation; zero cross-tenant leakage.
- **Multi-Worker Backend Deployments**: Clustering or horizontal scaling of the backend without a Redis/RabbitMQ pub-sub backplane is explicitly unsupported.

---

## 3. Architecture & Component Data-Flow Diagrams

### 3.1 Global System Architecture

```text
                               ┌──────────────────────────────────────────────────┐
                               │             Operator Web Browser                 │
                               │        (React 18 / TypeScript / Vite / CSS)      │
                               └───────────────────────┬──────────────────────────┘
                                                       │
                                                       │ HTTPS / REST (JWT Bearer)
                                                       v
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ CONTROL PLANE: FastAPI Single-Worker Engine (Uvicorn --workers 1)                                              │
│                                                                                                                 │
│   ┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────────────────┐   │
│   │   Assets API Router       │    │  Collectors API Router    │    │  Collector In-Memory Registry         │   │
│   │   (/api/assets)           │    │  (/api/collectors)        │    │  (collector_registry.py)              │   │
│   │                           │    │                           │    │                                       │   │
│   │ • Target Check & Pre-Check│    │ • Atomic Profile & Code   │    │ • Active WebSocket Sessions           │   │
│   │ • CRUD & CAS Updates      │    │ • Lifecycle (Pause/Revoke)│    │ • Ephemeral Challenge Nonces (30s)    │   │
│   │ • Scan Authorization      │    │ • Revoked Deletion Gates  │    │ • In-Flight Job Futures (asyncio)     │   │
│   │ • Public Internet Probes  │    │ • WebSocket Endpoint (/ws)│    │ • 15-Minute Sliding Rate Limiter      │   │
│   │ • Inventory Stats (5 KPIs)│    │                           │    │                                       │   │
│   └─────────────┬─────────────┘    └─────────────┬─────────────┘    └───────────────────▲───────────────────┘   │
│                 │                                │                                      │                       │
│                 │ Parameterized SQL              │ Parameterized SQL                    │ Job Dispatch / Frames │
│                 v                                v                                      │                       │
│   ┌────────────────────────────────────────────────────────────┐                        │                       │
│   │ PostgreSQL Database (tempris_v2_prod)                      │                        │                       │
│   │ • assets                  • collectors                     │                        │                       │
│   │ • asset_scan_authorizations • audit_events                 │                        │                       │
│   └────────────────────────────────────────────────────────────┘                        │                       │
└─────────────────────────────────────────────────┬───────────────────────────────────────┴───────────────────────┘
                                                  │
                                                  │ Outbound TLS WebSocket (wss://)
                                                  │ Mutual Challenge-Response Handshake
                                                  v
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ INTERNAL ENTERPRISE PERIMETER: Windows Host Agent (V0.2)                                                        │
│                                                                                                                 │
│   [ Windows Task Scheduler ] ───► Launches as SYSTEM on Boot ───► [ tempris-collector.exe --core ]              │
│     (BootTrigger / HighestAvailable / SDDL ACL)                      │ (Acquires Win32 Named Mutex)             │
│                                                                      │                                          │
│   ┌──────────────────────────────────────────────────────────────────┴──────────────────────────────────────┐   │
│   │ Headless Core Engine:                                                                                   │   │
│   │ • Outbound TLS WebSocket Client (tokio-tungstenite)                                                     │   │
│   │ • Ed25519 Canonical Challenge Signing (crypto.rs)                                                       │   │
│   │ • Strict IP Safety Rejection & DNS Pinning (safety.rs)                                                  │   │
│   │ • Sequential Zero-Byte TCP Verification (verifier.rs: Port 443 -> Port 80, Timeout <= 2.0s)             │   │
│   │ • Atomic State & Runtime Sync (storage.rs)                                                              │   │
│   └──────────────┬──────────────────────────────────────────────────────────────────────────┬───────────────┘   │
│                  │ Reads / Writes                                                           │ Zero-Byte TCP     │
│                  v                                                                          v                   │
│   ┌───────────────────────────────────────────────┐                          ┌──────────────────────────────┐   │
│   │ %PROGRAMDATA%\Tempris\Collector\              │                          │ Internal Target Host         │   │
│   │ • state.json             (Observer Tier ACL)  │                          │                              │   │
│   │ • protected_identity.dat (Secret Tier DPAPI)  │                          │ • 10.0.0.0/8                 │   │
│   │ • runtime.json           (Live Status Sync)   │                          │ • 172.16.0.0/12              │   │
│   │ • logs\collector.log     (Rotating 5MB logs)  │                          │ • 192.168.0.0/16             │   │
│   └──────────────▲────────────────────────────────┘                          └──────────────────────────────┘   │
│                  │ Read-Only Polling                                                                            │
│                  │                                                                                              │
│   ┌──────────────┴────────────────────────────────┐                                                             │
│   │ Interactive Desktop GUI (Observer Mode)       │                                                             │
│   │ tempris-collector.exe (egui / eframe)         │                                                             │
│   └───────────────────────────────────────────────┘                                                             │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Asset Verification & Routing Data Flow

```text
[ Operator / API Client ]
           │
           │ POST /api/assets/{id}/recheck
           v
┌──────────────────────────────────────┐
│ FastAPI Asset Router (assets.py)     │
│ 1. Fetch asset snapshot (OCC Read)   │
│ 2. Check scope: internet vs internal │
│    (Note: Scan Auth is NOT required) │
└──────┬────────────────────────┬──────┘
       │                        │
       │ (scope == 'internet')  │ (scope == 'internal')
       v                        v
┌─────────────────────────┐  ┌──────────────────────────────────────────────────────────┐
│ Direct Control Plane    │  │ Dispatch via CollectorRegistry                           │
│ Async TCP Probe         │  │ 1. Validate collector assigned, online, and not paused   │
│ (Port 443 -> Port 80)   │  │ 2. Construct VERIFY_TARGET frame with job_id & expiry    │
└────────────┬────────────┘  │ 3. Send frame over WebSocket & await asyncio.Future      │
             │               └────────────────────────────┬─────────────────────────────┘
             │                                            │
             │                                            │ WSS WebSocket Frame
             │                                            v
             │               ┌──────────────────────────────────────────────────────────┐
             │               │ Windows Collector Core Daemon                            │
             │               │ 1. Enforce operation == "VERIFY_TARGET" & expiry valid   │
             │               │ 2. Validate scope == "internal" & target type            │
             │               │ 3. Safety Check: Reject loopback, link-local, AWS meta   │
             │               │ 4. Single-resolution DNS Pinning                         │
             │               │ 5. Probe Port 443 (<=2.0s) -> fallback Port 80 (<=2.0s)  │
             │               │ 6. Send VERIFY_TARGET_RESULT frame                       │
             │               └────────────────────────────┬─────────────────────────────┘
             │                                            │
             │ ◄──────────────────────────────────────────┘
             v
┌──────────────────────────────────────────────────────────────────────┐
│ FastAPI Backend CAS Update                                           │
│ 1. Execute Compare-and-Set UPDATE on assets table                    │
│ 2. Verify target_value, network_scope, target_type, & status unchanged│
│ 3. If CAS succeeds: Record audit event & return 200 OK               │
│ 4. If CAS fails (concurrent edit): Discard result & return 409       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Source-of-Truth & Code Location Map

| Component | File Path | Primary Responsibilities & Key Exports |
| :--- | :--- | :--- |
| **Backend DB Pool** | [`backend/app/db.py`](../../../backend/app/db.py) | Parameterized PostgreSQL connection pool management and transaction contexts. |
| **Backend Schemas** | [`backend/app/schemas.py`](../../../backend/app/schemas.py) | Pydantic V2 schemas for asset CRUD, collector registration, scan authorization, and stats responses. |
| **Backend Auth & RBAC** | [`backend/app/auth.py`](../../../backend/app/auth.py) | Strict 3-role JWT validation (`analyst`, `admin`, `superadmin`), claims parsing, and `require_roles`. |
| **Backend Registry** | [`backend/app/collector_registry.py`](../../../backend/app/collector_registry.py) | In-memory singleton registry, active WebSocket routing, challenge nonces, sliding-window rate limiting, and asyncio job futures. |
| **Backend Target Validation** | [`backend/app/target_validator.py`](../../../backend/app/target_validator.py) | Strict target syntax validation, safety checks, CIDR rejection, and canonical normalization. |
| **Backend Target Checker** | [`backend/app/target_checker.py`](../../../backend/app/target_checker.py) | `check-target` route logic and cloud-based TCP probes for internet assets. |
| **Backend Asset Routes** | [`backend/app/routes/assets.py`](../../../backend/app/routes/assets.py) | Asset CRUD, exact-target authorization lifecycles, CAS rechecks, stats aggregation, and public TCP probing. |
| **Backend Collector Routes**| [`backend/app/routes/collectors.py`](../../../backend/app/routes/collectors.py)| Atomic collector profile/code creation, enrollment, operator lifecycle, safe deletion gates, and `/ws` WebSocket endpoint. |
| **Backend Migrations** | [`backend/migrations/`](../../../backend/migrations/) | Forward SQL migrations (`001_initial_assets_schema.sql`, `002_collectors_and_asset_routing.sql`, `003_collector_schema_contract.sql`). |
| **Collector Main** | [`collector/src/main.rs`](../../../collector/src/main.rs) | CLI entrypoint, argument routing (`--core`, `--uac-helper`), and desktop GUI launcher. |
| **Collector Storage** | [`collector/src/storage.rs`](../../../collector/src/storage.rs) | Machine storage (`%PROGRAMDATA%`), Windows DPAPI key encryption, DACL enforcement, atomic file swaps, and `CollectorState` (schema_version 2). |
| **Collector Autostart** | [`collector/src/autostart.rs`](../../../collector/src/autostart.rs) | Windows Task Scheduler management, XML template generation with SDDL `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`, stable binary path, and UAC helpers. |
| **Collector Client** | [`collector/src/client.rs`](../../../collector/src/client.rs) | Async WebSocket loop, backoff ladder, challenge signing, heartbeat ticker, and frame dispatch. |
| **Collector Verifier** | [`collector/src/verifier.rs`](../../../collector/src/verifier.rs) | Target reachability verification, sequential zero-byte probes on ports 443 & 80 with 2.0s timeouts. |
| **Collector Safety** | [`collector/src/safety.rs`](../../../collector/src/safety.rs) | Prohibited IP class rejection, DNS resolution pinning, and target normalization. |
| **Collector Crypto** | [`collector/src/crypto.rs`](../../../collector/src/crypto.rs) | Ed25519 keypair generation, canonical signing payload construction, and signature verification. |
| **Collector Protocol** | [`collector/src/protocol.rs`](../../../collector/src/protocol.rs) | JSON frame serialization/deserialization for client and server communication. |
| **Collector UI** | [`collector/src/ui.rs`](../../../collector/src/ui.rs) | Immediate-mode desktop interface using `egui` and `eframe`. |
| **Collector Setup Binary** | [`collector/src/bin/TemprisCollectorSetup.rs`](../../../collector/src/bin/TemprisCollectorSetup.rs) | Dedicated installer, uninstaller, repair utility, and task setup wizard. |
| **Frontend Root & Router** | [`frontend/src/App.tsx`](../../../frontend/src/App.tsx) | React 18 application shell, tab switching, and modal coordination. |
| **Frontend API Layer** | [`frontend/src/api.ts`](../../../frontend/src/api.ts) | Typed fetch client for backend endpoints. |
| **Frontend Asset Table** | [`frontend/src/components/AssetTable.tsx`](../../../frontend/src/components/AssetTable.tsx) | Asset data table, status badges, authorization triggers, and recheck action buttons. |
| **Frontend Collectors Table**| [`frontend/src/components/CollectorsTable.tsx`](../../../frontend/src/components/CollectorsTable.tsx) | Collector fleet management, lifecycle controls, and connection monitoring. |
| **Frontend Stats Cards** | [`frontend/src/components/StatsCards.tsx`](../../../frontend/src/components/StatsCards.tsx) | KPI summary cards rendering the 5 inventory stats from `/api/assets/stats`. |

---

## 5. Unified Terminology & Domain Glossary

```text
┌─────────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ Term                    │ Strict Definition & Architectural Context                              │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Asset                   │ An inventory record representing an enterprise network target.         │
│ Target Value            │ The raw or normalized network identifier (IP, hostname, or domain).    │
│ Target Type             │ Format classifier: 'ip', 'hostname', or 'domain'. (CIDR prohibited).   │
│ Network Scope           │ Reachability boundary: 'internet' (public) or 'internal' (perimeter).  │
│ Asset Status            │ Lifecycle state on `assets`: 'active' or 'decommissioned'.             │
│ Reachability Status     │ Reachability state on `assets`: 'unverified', 'verified',              │
│                         │ or 'unreachable'. Determined via zero-byte TCP probe (ports 443/80).   │
│ Scan Auth Status        │ Governance state on `asset_scan_authorizations`: 'pending',            │
│                         │ 'approved', 'revoked', or 'expired'. (Deferred for V0.3+ scanning).   │
│ Exact-Target Tuple      │ The 4-tuple (tenant_id, target_type, normalized_target, network_scope) │
│                         │ to which scan authorization is immutably anchored.                     │
│ Collector               │ A Windows host agent deployed inside an internal network perimeter.   │
│ Enrollment Status       │ Collector registration state: 'awaiting_enrollment' or 'enrolled'.     │
│ Operator Status         │ Administrative lifecycle state: 'active', 'paused', 'quarantined',     │
│                         │ or 'revoked'.                                                          │
│ Connection Status       │ Ephemeral transport state: 'connected' (active WS) or 'offline'.       │
│ Single-Worker Registry  │ Process-local in-memory store for active WebSockets and async futures. │
│ DPAPI Machine Scope     │ Windows CryptProtectData using CRYPTPROTECT_LOCAL_MACHINE.             │
│ Secret Tier DACL        │ File ACL granting Full Access to SYSTEM & Admins; None to Users.       │
│ Observer Tier DACL      │ File ACL granting Full Access to SYSTEM/Admins; Read-Only to Users.    │
│ BootTrigger Task        │ Windows Scheduled Task starting at OS boot under NT AUTHORITY\SYSTEM.  │
│ SDDL                    │ Security Descriptor: D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU).           │
│ CAS Update              │ Compare-and-Set optimistic concurrency control database update.        │
│ DNS Resolution Pinning  │ Resolving hostname once and probing the resulting IP directly.         │
└─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Asset Inventory Lifecycle & State Machine

### 6.1 State Separation Matrix

Tempris V2 strictly separates three completely orthogonal state domains across different tables and columns:

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. ASSET LIFECYCLE STATUS (assets.status)                                                      │
│    'active' ◄────────────────────────────────────────► 'decommissioned'                        │
│    (Active inventory target)                           (Archived, cannot be rechecked)         │
├────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. REACHABILITY STATUS (assets.reachability_status)                                            │
│    'unverified' ───[ POST /api/assets/{id}/recheck ]───► 'verified'  (Port 443/80 open)        │
│                                                     └──► 'unreachable' (Timeout/Refused)       │
│    * NOTE: Reachability rechecks NEVER require scan authorization approval!                    │
├────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. SCAN AUTHORIZATION STATUS (asset_scan_authorizations.status)                                │
│    'pending' ───[ Approve (Admin) ]───► 'approved' ───[ Time Expiry ]───► 'expired'            │
│        │                                    │                                                  │
│        └───────[ Revoke / Asset Edit ]──────┴───────────────────────────► 'revoked'            │
│    * NOTE: Scan authorization is governance for active vulnerability scanning (V0.3+).        │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Detailed State Transitions

1. **Asset Creation (`POST /api/assets`)**:
   - `status`: `'active'`.
   - `reachability_status`: `'verified'` or `'unreachable'` for `internet` scope (probed immediately during creation by `tempris_cloud`); `'unverified'` for `internal` scope.
   - `asset_scan_authorizations`: No record created initially.
2. **Reachability Recheck (`POST /api/assets/{id}/recheck`)**:
   - Executes non-destructive zero-byte TCP probe to ports 443 then 80 (timeout <= 2.0s per port).
   - If `internet`: probed directly by backend (`verification_source = 'tempris_cloud'`).
   - If `internal`: dispatched via WebSocket to assigned online collector (`verification_source = 'internal_collector'`). If collector is offline or unassigned, reachability remains `'unverified'`.
   - Recheck **never checks** `asset_scan_authorizations` and **never returns 403** for unauthorized scan status.
3. **Scan Authorization Lifecycle (`asset_scan_authorizations`)**:
   - `POST /api/assets/{id}/scan-authorization/request`: Creates a record with `status = 'pending'`, capturing current target tuple.
   - `POST /api/assets/{id}/scan-authorization/approve`: Admin/Superadmin sets `status = 'approved'` and future `expires_at`.
   - `POST /api/assets/{id}/scan-authorization/revoke`: Admin/Superadmin revokes active/pending authorizations.
   - `GET /api/assets/{id}/scan-authorization`: Retrieves latest authorization with effective status derivation (`expired` if `now() > expires_at`).
4. **Asset Decommissioning (`POST /api/assets/{id}/decommission`)**:
   - `status` transitions to `'decommissioned'`, setting `decommissioned_at = now()`.
   - Atomically revokes all active and pending records in `asset_scan_authorizations`.

---

## 7. Exact-Target Scan Authorization & Atomic Invalidation

### 7.1 The Scan Authorization Tuple
Scan authorization is immutably anchored to a four-tuple:

$$\text{Authorization Scope} = (\text{tenant\_id}, \text{target\_type}, \text{normalized\_target}, \text{network\_scope})$$

The backend normalizes all targets prior to evaluation:
- IPv4/IPv6: Stripped of whitespace and leading zeros, converted to standard representation (RFC 5952 for IPv6).
- Hostnames/Domains: Lowercased, stripped of trailing dots, and validated against RFC 1123.
- CIDR blocks: Strictly rejected with `422 Unprocessable Entity` (`Paths or CIDR notations are not permitted in target_value.`).

### 7.2 Atomic Invalidation Rules
If an asset is edited via `PUT /api/assets/{id}` and **any** of the following fields change:
- `target_value` (e.g., changing from `10.0.0.1` to `10.0.0.2`)
- `target_type` (e.g., changing from `ip` to `hostname`)
- `network_scope` (e.g., changing from `internal` to `internet`)

The database transaction executes an **atomic invalidation** within the same transaction:
1. All pending and approved scan authorizations in `asset_scan_authorizations` matching the asset's ID and tenant are updated to `status = 'revoked'` with `revocation_reason = 'Asset target or network scope was updated'`.
2. For `internet` scope, reachability is re-evaluated immediately via `tempris_cloud` probe; for `internal` scope, `reachability_status` is reset to `'unverified'`.
3. A structured audit event `asset.updated` is recorded in `audit_events` with `target_tuple_changed: true`.

---

## 8. Reachability Verification & Routing Semantics

### 8.1 Routing Decision Matrix

| Network Scope | Collector Assigned? | Collector Status | Verification Mechanism | Reachability Outcome |
| :--- | :--- | :--- | :--- | :--- |
| `internet` | N/A | N/A | Direct FastAPI Backend (Cloud TCP probe 443 -> 80) | `verified` or `unreachable` (`verification_source = 'tempris_cloud'`) |
| `internal` | Yes | `enrolled`, `active`, Online | Dispatched to Collector via WebSocket `VERIFY_TARGET` | `verified` or `unreachable` (`verification_source = 'internal_collector'`) |
| `internal` | Yes | Offline / Paused | Dispatch skipped | Remains `unverified` (`verification_source = null`) |
| `internal` | No | None | Dispatch skipped | Remains `unverified` (`verification_source = null`) |

*Key Takeaways*:
- **No Scan Auth Dependency**: Recheck proceeds regardless of whether a scan authorization exists, is pending, or is approved.
- **Fail-Safe Graceful Degradation**: If an internal collector is offline or unassigned, the API does not error with 500 or 503; it updates reachability to `unverified` and returns `200 OK`.
- **Target Pre-Check Route (`POST /api/assets/check-target`)**: Allows validating syntax and pre-checking reachability before creating an asset record.

### 8.2 Client-Side Safety & Prohibited IP Ranges
When the Rust collector receives a `VERIFY_TARGET` frame, `collector/src/safety.rs` executes strict validation **before** any network socket is allocated. The following IP ranges are rejected fail-closed:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                     CLIENT-SIDE PROHIBITED IP ADDRESS RANGES                     │
├───────────────────────────────┬───────────────────┬──────────────────────────────┤
│ Classification                │ IPv4 Address/CIDR │ IPv6 Prefix                  │
├───────────────────────────────┼───────────────────┼──────────────────────────────┤
│ Loopback Addresses            │ 127.0.0.0/8       │ ::1/128                      │
│ Link-Local Addresses          │ 169.254.0.0/16    │ fe80::/10                    │
│ Cloud Metadata (AWS/GCP/Azure)│ 169.254.169.254   │ N/A                          │
│ Multicast Ranges              │ 224.0.0.0/4       │ ff00::/8                     │
│ Unspecified Addresses         │ 0.0.0.0/8         │ ::/128                       │
│ Broadcast Addresses           │ 255.255.255.255   │ N/A                          │
│ Reserved / Future Use         │ 240.0.0.0/4       │ N/A                          │
└───────────────────────────────┴───────────────────┴──────────────────────────────┘
```

### 8.3 Single-Resolution DNS Pinning
To prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks:
1. `resolve_and_pin_safe_target()` resolves the hostname once via system DNS.
2. The resolved IP is evaluated against the prohibited IP blacklist.
3. If valid, the **exact pinned IP** is passed to `TcpStream::connect(SocketAddr::new(pinned_ip, port))`.
4. No secondary DNS resolution occurs during the probe.

---

## 9. Asset Inventory Statistics Semantics

The `/api/assets/stats` endpoint returns exactly 5 fields defined in `AssetStatsResponse` (`backend/app/schemas.py` and `backend/app/routes/assets.py` lines 154–194):

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        ASSET INVENTORY STATS CALCULATION                         │
├──────────────────────────────┬───────────────────────────────────────────────────┤
│ Metric Field                 │ SQL Aggregation Logic (Active Assets in Tenant)   │
├──────────────────────────────┼───────────────────────────────────────────────────┤
│ total_assets                 │ SELECT COUNT(*) FROM active_assets                │
│ reachable_by_scout           │ SELECT COUNT(*) FROM active_assets                │
│                              │  WHERE reachability_status = 'verified'           │
│                              │    AND network_scope = 'internet'                 │
│                              │    AND verification_source = 'tempris_cloud'      │
│ authorized_to_scan           │ SELECT COUNT(DISTINCT a.id)                       │
│                              │  FROM active_assets a                             │
│                              │  JOIN asset_scan_authorizations auth              │
│                              │    ON a.id = auth.asset_id                        │
│                              │   AND auth.tenant_id = :tenant_id                 │
│                              │   AND auth.status = 'approved'                    │
│                              │   AND auth.expires_at > now()                     │
│                              │   AND auth.target_type = a.target_type            │
│                              │   AND auth.normalized_target = a.normalized_target│
│                              │   AND auth.network_scope = a.network_scope        │
│ pending_authorization        │ SELECT COUNT(DISTINCT a.id)                       │
│                              │  FROM active_assets a                             │
│                              │  JOIN asset_scan_authorizations auth              │
│                              │    ON a.id = auth.asset_id                        │
│                              │   AND auth.tenant_id = :tenant_id                 │
│                              │   AND auth.status = 'pending'                     │
│                              │   AND auth.target_type = a.target_type            │
│                              │   AND auth.normalized_target = a.normalized_target│
│                              │   AND auth.network_scope = a.network_scope        │
│ no_scanner_available         │ SELECT COUNT(*) FROM active_assets                │
│                              │  WHERE network_scope = 'internal'                 │
└──────────────────────────────┴───────────────────────────────────────────────────┘
```

---

## 10. Collector Architecture & Dual-Binary Execution Model

### 10.1 Binary Roles

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        TEMPRIS V2 COLLECTOR BINARIES                             │
├───────────────────────────────┬──────────────────────────────────────────────────┤
│ Binary Name                   │ Operational Modes & Execution Scope              │
├───────────────────────────────┼──────────────────────────────────────────────────┤
│ tempris-collector.exe         │ 1. Desktop GUI Observer Mode (Default launcher)  │
│                               │ 2. Headless Core Daemon Mode (--core)            │
│                               │ 3. UAC Elevation Helper (--uac-helper <action>)  │
├───────────────────────────────┼──────────────────────────────────────────────────┤
│ TemprisCollectorSetup.exe     │ 1. Installer & Provisioning Wizard               │
│                               │ 2. Windows Task Scheduler XML Registration       │
│                               │ 3. Uninstallation & Data Purge Utility           │
└───────────────────────────────┴──────────────────────────────────────────────────┘
```

### 10.2 Win32 Named Mutex Singleton Guard
To prevent duplicate instances from thrashing the WebSocket connection and corrupting state files, the core engine acquires a Windows Named Mutex on startup:

```rust
// Primary Elevated Named Mutex
let mutex_name = "Global\\TemprisCollectorCoreSingleton";
// Non-Elevated Fallback Named Mutex
let fallback_mutex_name = "Local\\TemprisCollectorCoreSingleton";
```

If another instance holds the mutex, the newly launched core process logs an error and terminates immediately with exit code `1`.

---

## 11. Cryptographic Enrollment & WebSocket Protocol

### 11.1 Atomic Profile Creation & Cryptographic Enrollment Flow

```text
[ Admin (Web Browser) ]              [ FastAPI Control Plane ]            [ Windows Collector Setup ]
         │                                       │                                      │
         │ POST /api/collectors                  │                                      │
         │ { name, description }                 │                                      │
         ├──────────────────────────────────────►│                                      │
         │ Returns CollectorEnrollmentResponse   │                                      │
         │ (id, enrollment_code, expires_at)     │                                      │
         │◄──────────────────────────────────────┤                                      │
         │                                       │                                      │
         │ Enters Enrollment Code into Setup ────┼─────────────────────────────────────►│
         │                                       │                                      │
         │                                       │  1. Generates 32-byte Ed25519 Seed   │
         │                                       │  2. Protects seed with DPAPI         │
         │                                       │  3. POST /api/collectors/enroll      │
         │                                       │     { collector_id, enrollment_code, │
         │                                       │       public_key, platform_metadata }│
         │                                       │◄─────────────────────────────────────┤
         │                                       │                                      │
         │                                       │  4. Validates SHA-256(code) & expiry │
         │                                       │  5. Binds public_key & hardware info │
         │                                       │  6. Clears code hash & expiry        │
         │                                       │  7. Returns CollectorResponse        │
         │                                       ├─────────────────────────────────────►│
```

### 11.2 Canonical Challenge Signing & Replay Prevention
Upon establishing an outbound TLS WebSocket connection to `/api/collectors/ws`, the control plane initiates the cryptographic handshake:

1. **Control Plane Challenge Frame**:
   ```json
   {
     "type": "AUTH_CHALLENGE",
     "nonce": "dGhpcy1pcy1hLXJhbmRvbS0zMi1ieXRlLW5vbmNl",
     "expires_at": "2026-08-30T12:00:30Z"
   }
   ```
2. **Collector Canonical Payload Construction**:
   The collector constructs an exact byte payload with LF separators (`\n`) and no trailing newline:
   ```text
   TEMPRIS-COLLECTOR-AUTH-V1\ncollector_id=3fa85f64-5717-4562-b3fc-2c963f66afa6\nnonce=dGhpcy1pcy1hLXJhbmRvbS0zMi1ieXRlLW5vbmNl\nexpires_at=2026-08-30T12:00:30Z
   ```
3. **Collector Challenge Response Frame**:
   ```json
   {
     "type": "AUTH_RESPONSE",
     "collector_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "nonce": "dGhpcy1pcy1hLXJhbmRvbS0zMi1ieXRlLW5vbmNl",
     "expires_at": "2026-08-30T12:00:30Z",
     "signature": "base64url_encoded_ed25519_signature"
   }
   ```
4. **Backend Verification & Single-Use Nonce Consumption**:
   The backend consumes the nonce immediately, verifies that `now() <= expires_at`, and validates the Ed25519 signature against the stored `public_key`. If valid, it registers the session and responds with `AUTH_SUCCESS`. If invalid or expired, it sends Close Code `1008` (Policy Violation) and drops the connection.

---

## 12. Process-Local Registry & Single-Worker Architecture

### 12.1 The Single-Worker Requirement (`--workers 1`)
The FastAPI control plane must be deployed with **strictly one worker process**:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   WHY MULTI-WORKER DEPLOYMENTS FAIL IN V0.2                      │
├──────────────────────────────────────────────────────────────────────────────────┤
│ 1. Active WebSocket connections reside in the memory space of Worker A.         │
│ 2. An incoming HTTP recheck request is load-balanced to Worker B.                │
│ 3. Worker B checks its local CollectorRegistry, finds no active WebSocket, and   │
│    falsely reports "Collector Offline" or fails to dispatch the job.             │
│ 4. In-flight asyncio.Future objects cannot be resolved across OS process bounds. │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 12.2 Sliding-Window Rate Limiting & Auto-Quarantine
The in-memory registry maintains a 15-minute sliding request window for each collector session:
- **Max Message Rate**: 5.0 messages/second over a full 15-minute window (900 seconds).
- **Max Window Volume**: 4,500 messages per 15 minutes.
- **Enforcement**: Exceeding these thresholds automatically transitions the collector's operator status to `quarantined` in the database, emits a `collector.quarantined` audit event, and terminates the WebSocket session with Close Code `1008`.

---

## 13. Windows Machine Storage & DPAPI Cryptographic Protection

### 13.1 Storage Hierarchy Layout

```text
%PROGRAMDATA%\Tempris\Collector\
├── bin\
│   └── tempris-collector.exe  # Protected stable binary install location
├── state.json                 # Non-sensitive configuration (schema_version: 2)
├── protected_identity.dat     # Machine-scoped DPAPI encrypted Ed25519 private seed
├── runtime.json               # Volatile live status snapshot for UI
└── logs\
    ├── collector.log          # Active operational log (Rotates at 5 MB)
    ├── collector.log.1        # Rotated backup archive 1
    ├── collector.log.2        # Rotated backup archive 2
    └── collector.log.3        # Rotated backup archive 3
```

### 13.2 Machine-Level DPAPI & Windows DACLs

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           STORAGE TIER SECURITY MATRIX                           │
├──────────────────────────┬───────────────────────┬───────────────────────────────┤
│ Storage Artifact         │ Access Control (DACL) │ Encryption Protection         │
├──────────────────────────┼───────────────────────┼───────────────────────────────┤
│ protected_identity.dat   │ Secret Tier:          │ Windows DPAPI Machine Scope   │
│                          │ • SYSTEM: Full Access │ CryptProtectData(             │
│                          │ • Admins: Full Access │   CRYPTPROTECT_LOCAL_MACHINE \|│
│                          │ • Users: NO ACCESS    │   CRYPTPROTECT_UI_FORBIDDEN)  │
├──────────────────────────┼───────────────────────┼───────────────────────────────┤
│ state.json               │ Observer Tier:        │ Plaintext JSON                │
│ runtime.json             │ • SYSTEM: Full Access │ (Zero secrets, private keys,  │
│ bin\tempris-collector.exe│ • Admins: Full Access │ or DPAPI blobs permitted)     │
│ logs\collector.log       │ • Users: Read-Only    │                               │
└──────────────────────────┴───────────────────────┴───────────────────────────────┘
```

### 13.3 Atomic State File Operations
To prevent file corruption during sudden power losses or OS crashes, all JSON writes to `state.json` and `runtime.json` use atomic temporary file replacement:
1. Serialize payload to `runtime.json.tmp.<rand>`.
2. Apply appropriate DACL (Secret Tier or Observer Tier).
3. Atomically replace target file using Windows `MoveFileExW` / `atomic_replace`.

---

## 14. Windows Task Scheduler SYSTEM BootTrigger & SDDL Security

### 14.1 Task Specification & Security Descriptor
The background daemon is registered in Windows Task Scheduler under the name `TemprisCollectorCore`.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      SCHEDULED TASK CONFIGURATION ATTRIBUTES                     │
├───────────────────────────────┬──────────────────────────────────────────────────┤
│ Attribute                     │ Value & Description                              │
├───────────────────────────────┼──────────────────────────────────────────────────┤
│ Task Name                     │ TemprisCollectorCore                             │
│ Principal / Account           │ NT AUTHORITY\SYSTEM (S-1-5-18)                   │
│ Run Level                     │ HighestAvailable                                 │
│ Trigger Type                  │ BootTrigger (Starts at machine boot, 24/7)       │
│ Action Command                │ %PROGRAMDATA%\Tempris\Collector\bin\             │
│                               │ tempris-collector.exe                            │
│ Action Arguments              │ --core                                           │
│ Execution Time Limit          │ PT0S (Infinite / No timeout kill)                │
│ Multiple Instances Policy     │ IgnoreNew                                        │
│ Security Descriptor (SDDL)    │ D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)           │
└───────────────────────────────┴──────────────────────────────────────────────────┘
```

### 14.2 SDDL Permission Breakdown
The embedded SDDL string guarantees secure, unprivileged observability:
- `(A;;FA;;;SY)`: Allow (`A`) Full Access (`FA`) to Local SYSTEM (`SY`).
- `(A;;FA;;;BA)`: Allow (`A`) Full Access (`FA`) to Built-in Administrators (`BA`).
- `(A;;FR;;;BU)`: Allow (`A`) Generic Read (`FR`) to Built-in Users (`BU`).

```text
+---------------------------------------------------------------------------------------+
│ CRITICAL: Generic Read (FR) allows standard, non-elevated desktop users to query     │
│ task status without triggering E_ACCESSDENIED (0x80070005), while strictly denying   │
│ non-admin users any write, delete, execute/run, stop, or modify permissions.          │
+---------------------------------------------------------------------------------------+
```

### 14.3 TaskStatus Invariants & Operator Boot Toggle
The `autostart.rs` module evaluates task status against the following variants:
- `TaskStatus::Valid`: Task exists, is enabled, and strictly satisfies all boot contract invariants.
- `TaskStatus::Missing`: Task is authoritatively absent from Task Scheduler.
- `TaskStatus::DriftTriggerMismatch`: Trigger is not `BootTrigger` (e.g. legacy `LogonTrigger`).
- `TaskStatus::DriftAccountMismatch`: Principal is not `S-1-5-18` (SYSTEM).
- `TaskStatus::DriftActionMismatch`: Action executable path is not canonical or missing `--core`.
- `TaskStatus::DriftSettingsMismatch`: Execution limit is not `PT0S` or power policies drifted.
- `TaskStatus::Disabled`: Task exists but is disabled in Task Scheduler.
- `TaskStatus::QueryError(String)`: Query failed due to RPC or COM failure.

Administrators can toggle automatic boot launches via UAC without deleting identity files:
- **Disable Boot Startup**: `schtasks /Change /TN TemprisCollectorCore /Disable`
- **Enable Boot Startup**: `schtasks /Change /TN TemprisCollectorCore /Enable`

---

## 15. Revoked Collector Permanent Deletion Gates & Audit Retention

### 15.1 Permanent Deletion Safety Gates (`DELETE /api/collectors/{id}`)
To protect forensic integrity and prevent orphan asset routing, permanent deletion requires passing three strict validation gates enforced in `backend/app/routes/collectors.py`:

```text
       ┌────────────────────────────────────────────────────────┐
       │             DELETE /api/collectors/{id}                │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   v
       ┌────────────────────────────────────────────────────────┐
       │ Gate 1: Is collector.operator_status == 'revoked'?     │
       └───────────────────────────┬────────────────────────────┘
                                   │
                        Yes ───────┴─────── No ───► Return 409 Conflict
                        v                           ("Must be revoked prior to deletion")
       ┌────────────────────────────────────────────────────────┐
       │ Gate 2: Is active WebSocket connection count == 0?     │
       └───────────────────────────┬────────────────────────────┘
                                   │
                        Yes ───────┴─────── No ───► Return 409 Conflict
                        v                           ("Live session active")
       ┌────────────────────────────────────────────────────────┐
       │ Gate 3: Are referencing assets (active/history) == 0?  │
       └───────────────────────────┬────────────────────────────┘
                                   │
                        Yes ───────┴─────── No ───► Return 409 Conflict
                        v                           ("Referenced by N asset(s)")
       ┌────────────────────────────────────────────────────────┐
       │ Insert Sanitized 'collector.deleted' Audit Event       │
       │ Execute Parameterized SQL DELETE & Return 204          │
       └────────────────────────────────────────────────────────┘
```

---

## 16. Tenant Isolation, RBAC & Security Boundaries

### 16.1 Multi-Tenant Isolation
All SQL queries in the control plane filter explicitly by `tenant_id` extracted from the cryptographically verified JWT bearer token:

$$\text{WHERE } \text{tenant\_id} = :tenant\_id$$

Cross-tenant access attempts return `404 Not Found` rather than `403 Forbidden` to prevent tenant resource enumeration.

### 16.2 Role-Based Access Control (RBAC) Matrix

The backend enforces a strict 3-tier role hierarchy in `backend/app/auth.py` (`analyst`, `admin`, `superadmin`). Tokens with unapproved roles (e.g. `viewer` or `operator`) are rejected with `HTTP 401 Unauthorized`.

| Role | Asset CRUD & Recheck | Scan Auth (Request) | Scan Auth (Approve/Revoke) | Collector Lifecycle (Pause/Revoke) | Collector Delete |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `analyst` | ✅ Full Access | ✅ Request | ❌ Forbidden (403) | ❌ Forbidden (403) | ❌ Forbidden (403) |
| `admin` | ✅ Full Access | ✅ Request | ✅ Full Access | ✅ Pause / Resume / Quarantine / Revoke | ✅ (Revoked only) |
| `superadmin`| ✅ Full Access | ✅ Request | ✅ Full Access | ✅ Pause / Resume / Quarantine / Revoke | ✅ (Revoked only) |

---

## 17. PostgreSQL Schema, Migrations & Parameterized Data Access

### 17.1 Table Relationship Entity-Relationship Diagram

```text
┌──────────────────────────────────────────┐       ┌──────────────────────────────────────────┐
│ assets                                   │       │ collectors                               │
├──────────────────────────────────────────┤       ├──────────────────────────────────────────┤
│ id (UUID, PK)                            │       │ id (UUID, PK)                            │
│ tenant_id (UUID, Indexed)                │       │ tenant_id (UUID, Indexed)                │
│ name (TEXT)                              │       │ name (TEXT)                              │
│ asset_type (TEXT)                        │       │ description (TEXT, Nullable)             │
│ target_type (TEXT: ip|hostname|domain)   │       │ enrollment_status (TEXT: awaiting|enrolled)
│ target_value (TEXT)                      │       │ operator_status (TEXT: active|paused|...)│
│ normalized_target (TEXT)                 │       │ public_key (TEXT, Nullable)              │
│ network_scope (TEXT: internet|internal)  │       │ enrollment_code_hash (TEXT, Nullable)    │
│ environment (TEXT)                       │       │ enrollment_code_expires_at (TIMESTAMPTZ) │
│ criticality (TEXT)                       │       │ last_seen_at (TIMESTAMPTZ, Nullable)     │
│ owner (TEXT, Nullable)                   │       │ platform_metadata (JSONB)                │
│ tags (TEXT[])                            │       │ os (VARCHAR(64), Nullable)               │
│ status (TEXT: active|decommissioned)     │       │ architecture (VARCHAR(64), Nullable)     │
│ reachability_status (TEXT: unverified|...)│      │ hostname (VARCHAR(255), Nullable)        │
│ verification_source (TEXT, Nullable)     │       │ version (VARCHAR(64), Nullable)          │
│ last_verified_at (TIMESTAMPTZ, Nullable) │       │ enrolled_at (TIMESTAMPTZ, Nullable)      │
│ collector_id (UUID, FK Nullable) ────────┼───────┤ revoked_at (TIMESTAMPTZ, Nullable)       │
│ created_at (TIMESTAMPTZ)                 │       │ created_at (TIMESTAMPTZ)                 │
│ updated_at (TIMESTAMPTZ)                 │       │ updated_at (TIMESTAMPTZ)                 │
│ decommissioned_at (TIMESTAMPTZ, Nullable)│       └──────────────────────────────────────────┘
└────────────────────┬─────────────────────┘
                     │
                     v
┌──────────────────────────────────────────┐       ┌──────────────────────────────────────────┐
│ asset_scan_authorizations                │       │ audit_events                             │
├──────────────────────────────────────────┤       ├──────────────────────────────────────────┤
│ id (UUID, PK)                            │       │ id (UUID, PK)                            │
│ tenant_id (UUID, Indexed)                │       │ tenant_id (UUID, Indexed)                │
│ asset_id (UUID, FK)                      │       │ actor_id (TEXT)                          │
│ target_type (TEXT: ip|hostname|domain)   │       │ actor_role (TEXT)                        │
│ normalized_target (TEXT)                 │       │ event_name (TEXT)                        │
│ network_scope (TEXT: internet|internal)  │       │ asset_id (UUID, Nullable, Indexed)       │
│ status (TEXT: pending|approved|...)      │       │ details (JSONB)                          │
│ requested_by (TEXT)                      │       │ created_at (TIMESTAMPTZ)                 │
│ requested_at (TIMESTAMPTZ)               │       └──────────────────────────────────────────┘
│ request_reason (TEXT, Nullable)          │
│ approved_by (TEXT, Nullable)             │
│ approved_at (TIMESTAMPTZ, Nullable)      │
│ expires_at (TIMESTAMPTZ, Nullable)       │
│ revoked_by (TEXT, Nullable)              │
│ revoked_at (TIMESTAMPTZ, Nullable)       │
│ revocation_reason (TEXT, Nullable)       │
└──────────────────────────────────────────┘
```

---

## 18. Complete API Endpoint Reference

### 18.1 Asset Management Endpoints (`/api/assets`)

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             ASSET ENDPOINT SPECIFICATION                         │
├────────────────────────┬─────────────────────────────────────────────────────────┤
│ Endpoint & Method      │ Description, Request Body & Response Status             │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets/      │ Pre-check target validity and reachability.             │
│      check-target      │ Body: TargetCheckRequest { target_type, target_value,   │
│                        │       network_scope, collector_id?, correlation_id? }   │
│                        │ Response: 200 OK -> TargetCheckResponse                 │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ GET /api/assets/stats  │ Retrieve tenant asset inventory statistics.             │
│                        │ Response: 200 OK -> AssetStatsResponse (5 fields)       │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets       │ Create a new asset in 'active' status.                  │
│                        │ Body: AssetCreate { name, asset_type, target_type,      │
│                        │       target_value, network_scope, environment,        │
│                        │       criticality, owner?, tags?, collector_id? }       │
│                        │ Response: 201 Created -> AssetResponse                  │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ GET /api/assets        │ List all active assets for authenticated tenant.        │
│                        │ Response: 200 OK -> List[AssetResponse]                 │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ GET /api/assets/{id}   │ Get single asset details by ID.                         │
│                        │ Response: 200 OK -> AssetResponse | 404 Not Found       │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ PUT /api/assets/{id}   │ Update asset. Atomically revokes scan auth if target    │
│                        │ tuple changes.                                          │
│                        │ Body: AssetUpdate { name?, target_value?, ... }         │
│                        │ Response: 200 OK -> AssetResponse | 404 Not Found       │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets/{id}/ │ Execute CAS reachability recheck (TCP 443 -> 80).       │
│      recheck           │ Response: 200 OK -> AssetResponse | 409 (Conflict)      │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets/{id}/ │ Mark asset as 'decommissioned' and revoke scan auth.    │
│      decommission      │ Response: 200 OK -> AssetResponse | 404 Not Found       │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ GET /api/assets/{id}/  │ Get current or latest scan authorization for an asset.  │
│   scan-authorization   │ Response: 200 OK -> Optional[ScanAuthorizationResponse] │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets/{id}/ │ Submit exact-target scan authorization request.         │
│ scan-authorization/req │ Body: ScanAuthorizationRequest { request_reason? }      │
│                        │ Response: 201 Created -> ScanAuthorizationResponse      │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets/{id}/ │ Approve pending scan authorization (Admin/Superadmin).  │
│ scan-authorization/app │ Body: ScanAuthorizationApprove { expires_at }           │
│                        │ Response: 200 OK -> ScanAuthorizationResponse           │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/assets/{id}/ │ Revoke scan authorization (Admin/Superadmin).           │
│ scan-authorization/rev │ Body: ScanAuthorizationRevoke { revocation_reason? }    │
│                        │ Response: 200 OK -> Optional[ScanAuthorizationResponse] │
└────────────────────────┴─────────────────────────────────────────────────────────┘
```

### 18.2 Collector Management Endpoints (`/api/collectors`)

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           COLLECTOR ENDPOINT SPECIFICATION                       │
├────────────────────────┬─────────────────────────────────────────────────────────┤
│ Endpoint & Method      │ Description, Request Body & Response Status             │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors   │ Create collector profile and 15-min enrollment code.    │
│                        │ Body: CollectorCreate { name, description? }            │
│                        │ Response: 201 Created -> CollectorEnrollmentResponse    │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors/  │ Exchange enrollment code for Ed25519 public key binding.│
│      enroll            │ Body: CollectorEnrollRequest { collector_id, code, ... }│
│                        │ Response: 200 OK -> CollectorResponse                   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ GET /api/collectors    │ List all registered collectors in caller tenant.        │
│                        │ Response: 200 OK -> List[CollectorResponse]             │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ GET /api/collectors/   │ Get collector details by ID.                            │
│   {id}                 │ Response: 200 OK -> CollectorResponse | 404 Not Found   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors/  │ Pause collector (Rejects incoming VERIFY_TARGET jobs).  │
│   {id}/pause           │ Response: 200 OK -> CollectorResponse                   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors/  │ Resume paused collector to active status.               │
│   {id}/resume          │ Response: 200 OK -> CollectorResponse                   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors/  │ Quarantine collector (Terminates WS with Code 1008).    │
│   {id}/quarantine      │ Response: 200 OK -> CollectorResponse                   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors/  │ Release quarantined collector to active status.         │
│   {id}/release         │ Response: 200 OK -> CollectorResponse                   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ POST /api/collectors/  │ Revoke collector credentials permanently.               │
│   {id}/revoke          │ Response: 200 OK -> CollectorResponse                   │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ DELETE /api/collectors/│ Safely delete revoked, unreferenced collector profile.  │
│   {id}                 │ Response: 204 No Content | Errors: 404, 409 Conflict    │
├────────────────────────┼─────────────────────────────────────────────────────────┤
│ WS /api/collectors/ws  │ Outbound TLS WebSocket connection endpoint.             │
│                        │ Handshake: AUTH_CHALLENGE -> AUTH_RESPONSE              │
└────────────────────────┴─────────────────────────────────────────────────────────┘
```

---

## 19. Frontend User Experience & UI State Behavior

### 19.1 Frontend Technology Stack
- **Framework**: React 18 (`react`, `react-dom`).
- **Language**: TypeScript (`typescript ^5.6.3`).
- **Build System**: Vite (`vite ^5.4.10`).
- **Styling**: Scoped Custom CSS (`frontend/src/styles.css`).
- **Testing**: Vitest (`vitest ^2.1.4`) and Playwright E2E (`@playwright/test ^1.48.2`).

### 19.2 UI Component Breakdown
1. **Asset Management (`frontend/src/components/AssetTable.tsx`)**:
   - Renders inventory list with reachability badges: `verified` (green), `unreachable` (red), `unverified` (gray).
   - Recheck Action triggers `POST /api/assets/{id}/recheck` with visual loading state.
   - Decommission Modal (`DecommissionModal.tsx`) triggers `POST /api/assets/{id}/decommission`.
   - Scan Auth Modal (`ScanAuthModal.tsx`) handles `request`, `approve`, and `revoke` flows.
2. **Collector Fleet View (`frontend/src/components/CollectorsTable.tsx`)**:
   - Connection indicators: `connected` (green pulse), `offline` (gray), `paused` (yellow), `quarantined`/`revoked` (red).
   - Register Modal (`RegisterCollectorModal.tsx`) calls `POST /api/collectors` and renders the 15-minute enrollment code.
   - Delete Modal (`DeleteCollectorModal.tsx`) enforces 3 deletion safety gates.
3. **KPI Statistics Bar (`frontend/src/components/StatsCards.tsx`)**:
   - Displays 5 live tiles from `GET /api/assets/stats`: Total Assets, Reachable by Scout, Authorized to Scan, Pending Authorization, and No Scanner Available.
4. **Desktop Collector GUI (`tempris-collector.exe`)**:
   - Built in Rust using `egui` and `eframe`.
   - Displays connection status, last heartbeat timestamp, Task Scheduler diagnostics, and a live tailing ring buffer of `collector.log`.

---

## 20. Configuration, Deployment & Rollback Runbook

### 20.1 Control Plane Environment Variables

```bash
# Database Connection (PostgreSQL 14+)
DATABASE_URL=postgresql://tempris_v2_app:secure_password@127.0.0.1:5432/tempris_v2_prod

# JWT & Cryptographic Authentication
JWT_SECRET=super-secret-jwt-signing-key-min-32-bytes-length-required
JWT_ALGORITHM=HS256

# Server Port & URLs
PORT=8000
COLLECTOR_SERVER_URL=http://127.0.0.1:8000

# Admin Bootstrap Credentials (Startup Gate)
# ADMIN_TENANT_ID is pinned to the dedicated platform login-context tenant
# (Tempris Platform Control); the operational Tempris tenant
# (11111111-1111-1111-1111-111111111111) must never be used here.
ADMIN_USERNAME=admin@tempris.com
ADMIN_TENANT_ID=f0000000-0000-4000-8000-000000000001
ADMIN_PASSWORD_HASH=scrypt$ln=14,r=8,p=1$salt$hash...
```

#### 20.1.1 Platform Control Cutover Order (pre-correction deployments)

Deployments provisioned before the identity-boundary correction still hold the
platform administrator membership inside the operational Tempris tenant
(`11111111-1111-1111-1111-111111111111`). Migrating to the dedicated Platform
Control tenant (`f0000000-0000-4000-8000-000000000001`) must happen in this
exact order — the generic migration never guesses identities or performs
production-specific reconciliation:

1. **Create the Platform Control tenant** by applying migration
   `006_platform_control_tenant.sql` (runner: `python -m migrations.runner`).
   It inserts the tenant with no module entitlement and nothing else.
2. **Atomically move the platform admin membership** from the operational
   tenant to Platform Control in one transaction: disable the existing active
   membership and insert the new active `superadmin` membership in Platform
   Control for the same user (the `uq_memberships_user_active` partial unique
   index enforces the single-active-membership invariant — both statements
   must commit together or the login is locked out).
3. **Attach the approved tenant owner separately**: ensure the operational
   tenant has its own active `superadmin` member (the approved operational
   owner), distinct from the platform admin identity.
4. **Only then run the bootstrap CLI** with
   `ADMIN_TENANT_ID=f0000000-0000-4000-8000-000000000001` and the platform
   admin email. Bootstrap fails closed (refuses to proceed) if the admin user
   still holds an active membership in any other tenant — that refusal is the
   safety gate proving step 2 completed.

Bootstrap never invents or resets passwords unless `--force-password-reset` is
passed; supply `ADMIN_PASSWORD_HASH` generated from the approved credential.

### 20.2 Collector Client State File (`state.json`)

```json
{
  "schema_version": 2,
  "collector_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "collector_name": "DC1-Internal-Collector",
  "server_url": "https://tempris.example.com",
  "public_key": "uV8Xk3jR...base64url_raw_32_byte_key",
  "enrolled_at": "2026-08-30T10:15:00Z",
  "collector_version": "0.2.0"
}
```

---

## 21. Logging, Telemetry & Strict Secret Redaction

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         STRICT SECRET REDACTION AXIOMS                           │
├──────────────────────────────────────────────────────────────────────────────────┤
│ 1. Plaintext Ed25519 private signing seeds MUST NEVER be logged.                 │
│ 2. Raw Windows DPAPI encrypted binary blobs MUST NEVER be logged or serialized.  │
│ 3. Plaintext 15-minute enrollment codes MUST NEVER appear in client disk logs.   │
│ 4. JWT Authorization headers and session tokens MUST be redacted in traces.     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

The collector's `BoundedLogger` automatically rotates log files when reaching **5 MB**, retaining a maximum of **3 archive backups** (`collector.log.1`, `collector.log.2`, `collector.log.3`).

### Complete Audit Event Taxonomy (`audit_events`)
- `asset.created`, `asset.updated`, `asset.rechecked`, `asset.recheck_discarded_conflict`, `asset.decommissioned`, `asset.target_checked`
- `scan_authorization.requested`, `scan_authorization.approved`, `scan_authorization.revoked`
- `collector.created`, `collector.enrolled`, `collector.connected`, `collector.disconnected`, `collector.paused`, `collector.resumed`, `collector.quarantined`, `collector.released`, `collector.revoked`, `collector.deleted`
- `collector.job_dispatched`, `collector.job_completed`, `collector.job_rejected`

---

## 22. Troubleshooting Decision Trees & Operator Runbooks

### 22.1 Tree A: Collector Shows "Offline" in Web UI

```text
[ Collector Appears Offline ]
               │
               ▼
[ Is tempris-collector.exe --core running in Task Manager? ]
      │                                       │
     Yes                                     No
      │                                       │
      ▼                                       ▼
[ Check %PROGRAMDATA%\Tempris\Collector\logs\collector.log ]  [ Check Windows Task Scheduler ]
      │                                                         │
      ├─► Error: "Transport security rejection"                 ├─► Task Disabled? -> schtasks /Change /TN TemprisCollectorCore /Enable
      │   Resolution: Verify server_url uses valid HTTPS/WSS.   │
      │                                                         ├─► Task Missing? -> Run TemprisCollectorSetup.exe --repair
      ├─► Error: "Policy Violation (1008)"                      │
      │   Resolution: Collector is quarantined or revoked.      └─► Access Denied? -> Check SDDL permissions
      │               Admin must release collector in UI.
      │
      └─► Error: "DPAPI unprotect failed"
          Resolution: Machine identity corrupted or decrypted under
                      wrong machine. Run Setup --reset to re-enroll.
```

### 22.2 Tree B: Recheck Returns "409 Conflict"

```text
[ Asset Recheck Returns 409 Conflict ]
               │
               ▼
[ Inspect audit_events for 'asset.recheck_discarded_conflict' ]
               │
               ▼
[ Cause: Target tuple modified or asset decommissioned during active probe ]
               │
               ▼
[ Resolution: Refresh web browser asset table; execute recheck against latest asset state ]
```

---

## 23. Automated & Manual Acceptance Verification Evidence

### 23.1 Test Suite Matrix

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                V2 ACCEPTANCE TEST COVERAGE                             │
├────────────────────────────────────────┬─────────────────────────┬─────────────────────┤
│ Test Suite Module                      │ Test Scope & Target     │ Result / Status     │
├────────────────────────────────────────┼─────────────────────────┼─────────────────────┤
│ backend/tests/test_auth_login.py       │ Admin Login & Tokens    │ 100% Pass (Pytest)  │
│ backend/tests/test_auth_rbac.py        │ 3-Tier Role Validation  │ 100% Pass (Pytest)  │
│ backend/tests/test_assets_lifecycle.py │ Asset CRUD, Decomm, CAS │ 100% Pass (Pytest)  │
│ backend/tests/test_assets_stats.py     │ 5-Field Stats SQL CTE   │ 100% Pass (Pytest)  │
│ backend/tests/test_scan_authorization.py│ Exact-Tuple Scan Auth  │ 100% Pass (Pytest)  │
│ backend/tests/test_target_validator.py │ Format & Safety Rejection│ 100% Pass (Pytest) │
│ backend/tests/test_target_checker.py   │ TCP Probes & DNS Pinning│ 100% Pass (Pytest)  │
│ backend/tests/test_tenant_isolation.py │ Multi-Tenant DB Scoping │ 100% Pass (Pytest)  │
│ backend/tests/test_verification_persistence.py│ CAS State Updates│ 100% Pass (Pytest)  │
│ backend/tests/test_collector_routing.py│ Asset Routing to Agent  │ 100% Pass (Pytest)  │
│ backend/tests/test_collectors_lifecycle.py│ CRUD & Operator States │ 100% Pass (Pytest) │
│ backend/tests/test_collectors_rbac_tenant_isolation.py│ Role Gates│ 100% Pass (Pytest)  │
│ backend/tests/test_collector_enrollment.py│ One-Time Code & Ed25519│ 100% Pass (Pytest) │
│ backend/tests/test_collector_operator_lifecycle.py│ Pause/Quarantine│ 100% Pass (Pytest)│
│ backend/tests/test_collector_rate_guard.py│ 15-Min Sliding Window│ 100% Pass (Pytest)  │
│ backend/tests/test_collector_wss_auth.py│ Challenge Nonce Handshake│ 100% Pass (Pytest)│
│ backend/tests/test_collector_job_dispatch.py│ Async Futures & Jobs│ 100% Pass (Pytest) │
│ backend/tests/test_collector_delete.py │ 3 Safety Deletion Gates │ 100% Pass (Pytest)  │
│ collector/src/safety.rs (cfg)          │ Blacklist & Pinning     │ 100% Pass (Cargo)   │
│ collector/src/verifier.rs (cfg)        │ Port 443/80 TCP Probes  │ 100% Pass (Cargo)   │
│ collector/src/crypto.rs (cfg)          │ Ed25519 Sign & Verify   │ 100% Pass (Cargo)   │
│ collector/src/autostart.rs             │ Task SDDL & Elevation   │ 100% Pass (Cargo)   │
│ collector/src/storage.rs (cfg)         │ DPAPI & Atomic Writes   │ 100% Pass (Cargo)   │
│ frontend/src/tests/api.test.ts         │ Frontend API Client     │ 100% Pass (Vitest)  │
│ frontend/src/tests/components.test.tsx │ React Components        │ 100% Pass (Vitest)  │
└────────────────────────────────────────┴─────────────────────────┴─────────────────────┘
```

---

## 24. Remaining Limitations & Deferred Work

1. **Single-Worker Constraint**: The control plane requires `--workers 1` until a Redis/RabbitMQ pub-sub backplane is implemented for horizontal scaling.
2. **Windows-Only Collector Daemon**: V0.2 collectors run exclusively on Windows OS due to DPAPI and Task Scheduler dependencies; Linux `systemd` daemons are deferred to V0.3.
3. **Dual-Port Verification Boundary**: Probes are restricted to ports 443 and 80; custom port probing and UDP verification are deferred.
4. **Active Scanner Integrations**: Vulnerability assessments and deep service discovery are out-of-scope for the reachability collector.

---

## 25. Why It Is Designed This Way / Why Not X? (Master Decision Matrix)

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    ARCHITECTURAL TRADE-OFF DECISION MATRIX                                      │
├──────────────────────────────┬──────────────────────────────┬───────────────────────────────────────────────────┤
│ Design Decision              │ Alternative Rejected (Why Not)│ Authoritative Architectural Justification        │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 1. Recheck Permitted Without │ Requiring approved scan      │ Reachability performs a safe, zero-byte TCP probe │
│    Scan Authorization        │ authorization before recheck │ to ports 443/80 with zero payloads or exploit code│
│                              │                              │ Scan auth is reserved for active vulnerability scans│
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 2. Exact 1:1 Target Formats  │ Supporting CIDR notation     │ CIDR ranges enable aggressive subnet sweeping and │
│    (No CIDR Ranges in V0.2)  │ (e.g. 10.0.0.0/24)           │ risk weaponizing the collector as an internal     │
│                              │                              │ scanner; exact 1:1 binding enforces strict safety.│
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 3. Task Scheduler XML        │ Simple CLI execution         │ schtasks CLI does not support embedding SDDL ACLs │
│    Registration Template     │ (schtasks /Create /SC ONSTART)│ D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU) or setting  │
│                              │                              │ IgnoreNew/PT0S; XML COM is required for unpriv Q. │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 4. Single-Worker Uvicorn     │ Multi-worker / Microservices │ Eliminates distributed state complexity in V0.2;  │
│    Control Plane             │ with Redis / RabbitMQ        │ active WebSockets and async futures stay in local │
│                              │                              │ memory without broker synchronization lag.        │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 5. Zero-Ingress Collector    │ Direct cloud scanning of     │ Internal enterprise assets use private RFC 1918   │
│    Outbound WebSocket        │ internal target IP addresses │ address spaces that are non-routable from cloud.  │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 6. Outbound TLS WebSocket    │ Inbound firewall ports /     │ Inbound openings create perimeter vulnerabilities │
│    Transport                 │ Generic SSH / VPN tunnels    │ and violate enterprise zero-trust security.       │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 7. Fixed Ports 443 & 80 Only │ Full port ranges (1-65535) / │ Minimizes attack surface; prevents collector from │
│                              │ Arbitrary shell commands     │ being weaponized as an internal port scanner.     │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 8. Ephemeral In-Memory       │ Stored `connected: true` flag│ Database flags become stale during sudden crashes;│
│    Connection Registry       │ in PostgreSQL table          │ in-memory presence reflects true TCP socket state.│
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 9. Collector Knows Own UUID  │ Storing `tenant_id` on the   │ Eliminates risk of collector spoofing tenant ID;  │
│    Only                      │ Windows client file system   │ tenant scoping is enforced server-side from DB.   │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 10. Machine DPAPI Binary File│ Plaintext JSON private key / │ DPAPI encrypts seed using machine hardware keys;  │
│     for Signing Seed         │ Environment variables        │ prevents credential theft via disk inspection.    │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 11. Fail-Closed Manual Reset │ Automatic silent re-enroll   │ Automatic re-enrollment masks tampering or        │
│     on Corrupt Identity      │ upon identity decryption fail│ hardware spoofing; requires operator intervention.│
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 12. Task Scheduler SYSTEM    │ Windows Startup Apps /       │ Startup Apps require active user login and stop   │
│     BootTrigger Task         │ Registry Run keys            │ on logout; BootTrigger runs 24/7 as SYSTEM.       │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 13. Task Scheduler SYSTEM    │ Native Windows Service (SCM) │ Unified binary avoids complex SCM dispatch code   │
│     BootTrigger Task         │                              │ while achieving exact same SYSTEM boot lifecycle. │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 14. schtasks /Change         │ Deleting / unregistering the │ Preserves task registration and identity while    │
│     /Disable for Toggle      │ task on operator disable     │ allowing operators to suspend future boot launches│
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 15. Strict Revoked Deletion  │ Cascading deletion of active │ Prevents accidental deletion of active collectors;│
│     Gates (0 sessions, 0 refs│ collectors with assets       │ preserves forensic audit trail for historical ops.│
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 16. Direct psycopg Queries   │ Heavy ORM (SQLAlchemy /      │ Parameterized psycopg queries provide total SQL   │
│     with Explicit SQL        │ Tortoise ORM)                │ transparency, zero N+1 queries, and raw speed.    │
├──────────────────────────────┼──────────────────────────────┼───────────────────────────────────────────────────┤
│ 17. Dual Binary CLI / GUI    │ Separate GUI and daemon      │ Simplifies packaging, updates, and maintenance    │
│     (tempris-collector.exe)  │ binary executables           │ into a single self-contained executable.          │
└──────────────────────────────┴──────────────────────────────┴───────────────────────────────────────────────────┘
```

---

## 26. Maintenance Rules & Verification Checklist

### 26.1 Ongoing Maintenance Rules
1. **Source Code Wins**: If any section of this document conflicts with running code in `backend/`, `collector/`, or `frontend/`, the code is ground truth. Update this document immediately.
2. **Schema Synchronicity**: Any forward database migration (`004_...`) modifying `assets`, `collectors`, or `asset_scan_authorizations` must be reflected in Section 17.
3. **Protocol Freezing**: Changes to WebSocket frame schemas (`protocol.rs` or `collector_registry.py`) must be documented in Section 11 before merging.

### 26.2 Verification Checklist for Changes

```text
[ ] Backend tests pass: pytest backend/tests/ (74/74 passed)
[ ] Collector tests pass: cargo test (92/92 passed)
[ ] Frontend tests pass: npm run test (Vitest)
[ ] Zero secrets/DPAPI keys logged or exposed in JSON files
[ ] Task Scheduler SDDL remains "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"
[ ] Single-worker requirement (--workers 1) maintained in deployment manifests
[ ] Frontend status badges match backend reachability_status and status enums
```
