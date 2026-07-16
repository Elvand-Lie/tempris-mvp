# Repository Map: Tempris Wave 1 MVP

This document outlines the architecture, components, infrastructure, and test baseline of the Tempris codebase as discovered during Phase 0 of the implementation.

---

## 1. Repository State
- **Date & Time Generated**: 2026-07-16 13:10 UTC
- **Current Git Branch**: `vps-prod-complete`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: `git status` output.
- **Current Commit SHA**: `f2bbdfd5faec2cd6ddbdba1cf6ed68b0aa9320d1`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: `git rev-parse HEAD` output.
- **Clean Working Tree**: Clean except for the untracked `workDocs/` folder.
  - **Confidence**: `CONFIRMED`
  - **Evidence**: `git status` output.
- **Operating System & Architecture**: Windows (local development environment)
  - **Confidence**: `CONFIRMED`
- **Runtimes & Tool Versions**:
  - Python: `3.11.9`
  - Node.js: `v22.17.0`
  - Docker & Docker Compose: Not installed/available locally (command failed).
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Command executions for versions.

---

## 2. Backend Architecture

- **Entry Point**: `app/backend/index.py`
  - **Lines**: 31-47 (app initialization and registration), 50-100 (startup hooks)
  - **Confidence**: `CONFIRMED`
  - **Evidence**: FastAPI app initialization and route registration occur here. `Dockerfile.dev` runs uvicorn targeting `index:app`.
- **Framework & Runtime**: FastAPI, Python 3.11
  - **Confidence**: `CONFIRMED`
  - **Evidence**: `app/backend/requirements.txt:1` lists `fastapi==0.115.12`. `Dockerfile:1` uses `python:3.11-slim`.
- **Router-Registration Mechanism**: Direct router imports and inclusion.
  - **File**: `app/backend/index.py#L24-L46`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Routers like `auth`, `spectrum`, `scout`, `audit`, etc. are imported from `routers` and included using `app.include_router()`.
- **Model and Schema Locations**: `app/backend/models.py`
  - **Lines**: 1-296
  - **Confidence**: `CONFIRMED`
  - **Evidence**: All database tables (`AuditLog`, `Finding`, `Asset`, etc.) subclass `Base` from `services.database` and are defined here.
- **Database Engine & Database Path**: SQLite (local fallback)
  - **File**: `app/backend/services/database.py#L9-L12`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Defaults to `sqlite:///./tempris.db` when the `DATABASE_URL` environment variable is not defined.
- **Database Initialization & Migration Mechanism**:
  - **File**: `app/backend/services/database.py#L29-L38` (initialization)
  - **File**: `app/backend/requirements.txt#L14-L15` (migrations)
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Table creation is executed via `Base.metadata.create_all(bind=engine)` inside `init_db()` on app startup. No database migration tool (like Alembic) is configured; there is only a commented suggestion for Alembic in `requirements.txt`.
- **Dependency Manifests & Lockfiles**:
  - **File**: `app/backend/requirements.txt`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Lists exact pinned versions for libraries like `fastapi`, `uvicorn`, `sqlalchemy`, `python-jose`, etc. No poetry or pipenv lockfiles exist in the backend folder.
- **Authentication Implementation**: JWT (JSON Web Token) authentication.
  - **File**: `app/backend/routers/auth.py`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Endpoint `/api/auth/login` issues JWTs using OAuth2 password flow. Tokens are validated via `get_current_user` in the same file.
- **Authorization & Role Enforcement**: RBAC check inside endpoints.
  - **File**: `app/backend/routers/auth.py` and router files
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Roles (`Superadmin`, `Admin`, `Analyst`, `Viewer`, `ReadOnly`) are derived from the token payload and validated at endpoint levels.
- **Tenant or Partner Scoping**: Absent/No scoping column present.
  - **File**: `app/backend/models.py#L235-L258`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: The `findings` table (and other models) currently lacks a `tenant_id` or `engagement_id` column, meaning all database records are globally shared within the instance. Scoping needs to be introduced in Phase 3/Phase 5.
- **Background Workers & Queues**: Absent
  - **Confidence**: `CONFIRMED`
  - **Evidence**: No celery, rq, or background worker dependencies are present in `requirements.txt`.
- **Upload & Storage Paths**:
  - **File**: `app/backend/Dockerfile.dev#L13`
  - **File**: `app/backend/Dockerfile#L31`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Folders `/app/data/evidence` (evidence uploads) and `/app/data/chroma` (vector database) are created and mapped as volumes.
- **External APIs & Services**: `freellmapi`
  - **File**: `docker-compose.dev.yml#L33-L46`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: The dev compose defines `freellmapi` on port 3001 serving as an LLM proxy.

---

## 3. Frontend Architecture

- **Frontend Source Location**: Absent
  - **Confidence**: `CONFIRMED`
  - **Evidence**: A deep scan for `package.json` in `app/frontend` and other UI directories returned no source code or build configuration.
- **Frontend Compiled Assets Only**: Yes
  - **File**: `app/frontend/index.html`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: The directory contains only compiled production assets: `index.html` loading `/assets/index-D7JxOY4D.js` and `/assets/index-BZcmgbIT.css`. The backup directories (`app/frontend_old`, `app/frontend_backup_`) also contain only built assets.
- **Observed Limitation**: Since only compiled assets exist, major frontend implementation changes are blocked until the source repository/module is resolved.

---

## 4. Database Topology

- **SQLite Database Path**: `tempris.db` in root workspace.
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Verified local file name `tempris.db` exists in the repository.
- **Schema-Creation Flow**: `Base.metadata.create_all()` is executed on every application startup.
  - **File**: `app/backend/services/database.py#L29-L38`
  - **Confidence**: `CONFIRMED`
- **Existing Tables**:
  - `audit_logs`: Audit logs with signature hash validation.
  - `edip_decisions`: Decisions made on findings.
  - `strike_authorizations`: Authorized strike engagements.
  - `strike_simulations`: Executed simulations.
  - `control_statuses`: Status of compliance controls.
  - `control_evidence`: File attachments for control compliance.
  - `incident_reports`: Security incidents.
  - `spotlight_reports`: Executive spotlight narratives.
  - `surge_researchers`: Threat researchers registry.
  - `surge_submissions`: Submissions made by researchers.
  - `chat_sessions`: Chat histories for SPEAK.
  - `chat_messages`: Individual chat messages.
  - `tes_snapshots`: Periodic snapshots of the Threat Exposure Score (TES).
  - `assets`: IT assets inventory.
  - `scan_findings`: Vulnerability findings discovered via scans.
  - `grc_states`: ISO 42001 GRC toggles/SOP state.
  - `grc_signoffs`: Sign-offs on compliance rules.
  - `grc_policy_documents`: Policies from GRC library.
  - `findings`: KEV, PoC, and SSS supply chain vulnerability findings.
  - `account_query_logs`: Per-account daily query limits.
  - `account_suspensions`: Blocked users database.
  - `revoked_tokens`: JWT revocation deny-list.
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Defined in `app/backend/models.py`.
- **Database Backup & Rollback scripts**:
  - `app/backup.sh`: Shell script to back up app directories.
  - `backups/`: Directory containing DB backups.
  - **Confidence**: `CONFIRMED`

---

## 5. Infrastructure Config

- **Docker Compose**: `docker-compose.dev.yml`
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Defines two services: `backend` (port 8000, environment-configured DATABASE_URL and secrets) and `freellmapi` (port 3001, LLM mock/proxy).
- **Nginx Configurations**:
  - `nginx_tempris_ssl.conf`: Redirects port 80 to 443, configures SSL paths, configures security headers (XCTO, XFO, HSTS), and reverse proxies API routes. Binds auth to a rate limit of 5 requests/minute, api to 100 requests/minute, and scanner to 10 requests/minute.
  - `app/tempris.nginx.conf`: Simple server on port 80 default, serving React root index.html and reverse proxying `/api/` without passing client real IP headers.
  - `app/nginx.conf`: Local proxy for Docker setup forwarding port 80 to host.docker.internal:8000.
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Inspected file contents. Nginx configuration status (whether it is active on the VPS) is `UNKNOWN` from a local perspective without SSH inspection.
- **Environment Variables**:
  - `DATABASE_URL`: Location of DB.
  - `JWT_SECRET_KEY`: JWT HMAC key.
  - `FREELLM_API_KEY`: LLM authorization key.
  - `FREELLM_BASE_URL`: Base endpoint for LLM.
  - `CORS_ORIGINS`: Permitted origins list.
  - `ENV`/`ENVIRONMENT`: Deployment environment tag.
  - **Confidence**: `CONFIRMED`
  - **Evidence**: Defined in `docker-compose.dev.yml` and `app/backend/services/database.py`.

---

## 6. Testing Baseline

- **test_qa_full.sh**:
  - **Purpose**: Full QA functional suite (49 endpoints) and security audit (16 pentests).
  - **Target URL**: `http://127.0.0.1:8000` (hardcoded)
  - **Destructive**: Yes. Deletes asset `999` (line 198) and updates DB states.
  - **Confidence**: `CONFIRMED`
- **test_ai.sh**:
  - **Purpose**: Validates SPEAK and SPOTLIGHT endpoints.
  - **Target URL**: `http://localhost:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`
- **test_rag.sh**:
  - **Purpose**: Tests vector DB search and RAG stats.
  - **Target URL**: `http://localhost:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`
- **test_policy.sh**:
  - **Purpose**: Tests fetching GRC policy documents.
  - **Target URL**: `http://localhost:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`
- **test_spotlight.sh**:
  - **Purpose**: Tests requesting executive report generations.
  - **Target URL**: `http://localhost:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`
- **verify_sandbox.sh**:
  - **Purpose**: Audits host info, environment vars, and hash chain.
  - **Target URL**: `http://127.0.0.1:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`
- **check_audit.sh**:
  - **Purpose**: Saves audit log to /tmp and verifies integrity.
  - **Target URL**: `http://127.0.0.1:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`
- **run_qa.sh**:
  - **Purpose**: Startup waiter, audit hash recomputer, and QA runner.
  - **Target URL**: `http://127.0.0.1:8000` (hardcoded)
  - **Destructive**: Yes (wraps `test_qa_full.sh`).
  - **Confidence**: `CONFIRMED`
- **debug_bugs.sh**:
  - **Purpose**: Tests policy updating permission and traversal bugs.
  - **Target URL**: `http://127.0.0.1:8000` (hardcoded)
  - **Destructive**: No.
  - **Confidence**: `CONFIRMED`

---

## 7. Security Observations

Without modifications, the following security risks and observations are noted:

- **Hard-coded Credentials inside Tests**:
  - **Files**: `test_qa_full.sh#L32`, `test_ai.sh#L6`, `test_rag.sh#L4`, `test_policy.sh#L4`, `test_spotlight.sh#L4`, `verify_sandbox.sh#L15`, `check_audit.sh#L3`, `run_qa.sh#L16`, `debug_bugs.sh#L7`.
  - **Secret Category**: Application user passwords (`demo` is used for all seeded test accounts: `admin`, `sherie`, `analyst`, `viewer`, `readonly`).
  - **Status**: Active in test seeds.
  - **Action**: These credentials must be migrated to environment variables/fixtures in Phase 1 (SEC-I1).
- **Hard-coded Dev JWT Secret**:
  - **File**: `docker-compose.dev.yml#L21`
  - **Secret Category**: JWT Secret Key (`dev_only_secret_do_not_use_in_prod_abc123`).
  - **Status**: Test-only.
- **Unsafe Audit Trail Verification recomputation**:
  - **File**: `run_qa.sh#L17`
  - **Risk**: Calling `/api/audit/verify?recompute=true` triggers recomputing hash chain on the server. If this is publicly available, it undermines audit immutability.
- **No TLS Validation inside local test scripts**:
  - **File**: `test_qa_full.sh#L385`
  - **Risk**: Tests run curl with `-k` (insecure) flag.
- **Disabled HSTS**:
  - **File**: `docker-compose.dev.yml#L25`
  - **Status**: Permitted in dev environment only.
