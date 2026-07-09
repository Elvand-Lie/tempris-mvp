# Tempris CTEM Platform — Architecture & Deployment Guide

## Table of Contents

1. [Platform Overview](#platform-overview)
2. [System Architecture](#system-architecture)
3. [Database Architecture](#database-architecture)
4. [Module Architecture](#module-architecture)
5. [Security Architecture](#security-architecture)
6. [API Reference](#api-reference)
7. [Deployment Guide](#deployment-guide)
8. [Maintenance & Operations](#maintenance--operations)

---

## Platform Overview

Tempris is a **Continuous Threat Exposure Management (CTEM)** platform that integrates vulnerability intelligence, adversary simulation, compliance monitoring, and AI-powered security analysis into a single pane of glass.

### Core Modules

| Module | Purpose | Backend Router |
|---|---|---|
| **SYNTHESIS** | Master dashboard — TES gauge, module health, alerts | `synthesis.py` |
| **SPECTRUM** | CVE browser with EDIP auto-classification (Fix/Defer/Accept) | `spectrum.py` |
| **SCOUT** | Vulnerability scanner + CISA KEV intelligence | `scout.py` |
| **STRIKE** | Adversary simulation engine (MITRE ATT&CK) | `strike.py` |
| **STANDARD** | GRC compliance controls (ISO 42001, MAS TRM, PDPA) | `standard.py` |
| **SPOTLIGHT** | AI-generated executive reports | `index.py` |
| **SPEAK** | AI chatbot with full platform awareness | `index.py` |
| **GRC-TES** | Tempris Exposure Score calculator | `grc_tes.py` |
| **ASSETS** | Infrastructure asset inventory | `assets.py` |
| **AUDIT** | Immutable audit trail | `audit.py` |

### Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + TypeScript + Vite |
| Backend | Python FastAPI + Uvicorn |
| Database | PostgreSQL 16 (production) / SQLite (development) |
| AI/LLM | FreeLLMAPI (OpenAI-compatible) |
| Vector DB | ChromaDB (RAG embeddings) |
| Containers | Docker + Docker Compose |
| Reverse Proxy | Nginx (SSL termination) |
| Message Queue | Kafka + Zookeeper |
| Cache | Redis |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NGINX (Port 80/443)                       │
│                    SSL Termination + Reverse Proxy                │
├─────────────────────┬───────────────────────────────────────────┤
│                     │                                           │
│   Static Frontend   │         API Proxy (/api/*)                │
│   (React SPA)       │              │                            │
│                     │              ▼                             │
│                     │   ┌─────────────────────────┐             │
│                     │   │   FastAPI Backend :8000  │             │
│                     │   │                         │             │
│                     │   │  ┌──── Middleware ─────┐ │             │
│                     │   │  │ IP Rate Limiter     │ │             │
│                     │   │  │ Account Rate Limiter│ │             │
│                     │   │  │ ToS Enforcer        │ │             │
│                     │   │  │ Security Headers    │ │             │
│                     │   │  │ CORS                │ │             │
│                     │   │  └────────────────────-┘ │             │
│                     │   │                         │             │
│                     │   │  ┌──── Services ──────┐ │             │
│                     │   │  │ EDIP Engine         │ │             │
│                     │   │  │ Adversary Engine    │ │             │
│                     │   │  │ LLM Client          │ │             │
│                     │   │  │ RAG Engine          │ │             │
│                     │   │  │ AI Context Builder  │ │             │
│                     │   │  │ KEV Loader          │ │             │
│                     │   │  └────────────────────-┘ │             │
│                     │   └─────────────────────────┘             │
│                     │        │          │         │              │
│                     │        ▼          ▼         ▼              │
│                     │   PostgreSQL  FreeLLM   ChromaDB           │
│                     │    :5432      :3001     (embedded)         │
└─────────────────────┴───────────────────────────────────────────┘
```

### Request Flow

1. Client → **Nginx** (SSL termination)
2. Nginx → **FastAPI** (port 8000)
3. Middleware chain: IP Rate Limit → Account Rate Limit → ToS Enforcer → Security Headers
4. **JWT Auth Guard** validates token + checks account suspension
5. Router endpoint → **Service layer** → **Database**
6. Response passes through middleware (headers added)
7. For AI endpoints: response gets **context binding footer** appended

---

## Database Architecture

### Engine Selection

The platform uses SQLAlchemy ORM with automatic engine selection:

```python
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///tempris.db")
```

- **Production (VPS):** `postgresql://tempris:PASSWORD@localhost:5432/tempris`
- **Development (local):** `sqlite:///tempris.db` (zero config)

### Entity Relationship Diagram

```
┌─────────────────────┐     ┌────────────────────────┐
│     findings         │     │       assets            │
├─────────────────────┤     ├────────────────────────┤
│ id (PK)              │     │ id (PK)                 │
│ cve (IDX)            │◄───│ name                    │
│ title                │     │ ip_address              │
│ vendor (IDX)         │     │ asset_type              │
│ product              │     │ criticality             │
│ cvss (IDX)           │     │ status                  │
│ priority (IDX)       │     │ os_info                 │
│ cisa_kev (IDX)       │     │ owner                   │
│ ransomware (IDX)     │     │ tags (JSON)             │
│ date_added           │     │ created_at              │
│ short_description    │     └────────────────────────┘
│ required_action      │
│ raw_inputs (JSON)    │     ┌────────────────────────┐
│ asset_id             │     │    edip_decisions       │
│ asset_data (JSON)    │     ├────────────────────────┤
│ sss_data (JSON)      │     │ id (PK)                 │
│ source (IDX)         │     │ finding_id (IDX)        │
│ created_at           │     │ decision                │
└─────────────────────┘     │ rationale               │
                             │ decided_by              │
┌─────────────────────┐     │ created_at              │
│  account_query_logs  │     └────────────────────────┘
├─────────────────────┤
│ id (PK)              │     ┌────────────────────────┐
│ account_email (IDX)  │     │   chat_sessions         │
│ endpoint_group       │     ├────────────────────────┤
│ query_date (IDX)     │     │ id (PK)                 │
│ daily_count          │     │ user_email              │
│ flagged_anomaly      │     │ created_at              │
│ anomaly_ratio        │     └────────┬───────────────┘
└─────────────────────┘              │ 1:N
                             ┌───────┴────────────────┐
┌─────────────────────┐     │    chat_messages        │
│ account_suspensions  │     ├────────────────────────┤
├─────────────────────┤     │ id (PK)                 │
│ id (PK)              │     │ session_id (FK)         │
│ email (IDX)          │     │ role                    │
│ reason               │     │ content                 │
│ suspended_at         │     │ created_at              │
│ suspended_by         │     └────────────────────────┘
│ auto_suspended       │
│ is_active (IDX)      │     ┌────────────────────────┐
│ unsuspended_at       │     │    audit_logs           │
└─────────────────────┘     ├────────────────────────┤
                             │ id (PK)                 │
┌─────────────────────┐     │ timestamp               │
│   tes_snapshots      │     │ user_email              │
├─────────────────────┤     │ action                  │
│ id (PK)              │     │ module                  │
│ score                │     │ detail                  │
│ band                 │     │ ip_address              │
│ total_findings       │     └────────────────────────┘
│ critical_count       │
│ ransomware_count     │     ┌────────────────────────┐
│ asset_count          │     │  spotlight_reports      │
│ created_at           │     ├────────────────────────┤
└─────────────────────┘     │ id (PK)                 │
                             │ report_type             │
┌─────────────────────┐     │ narrative               │
│   control_status     │     │ model_used              │
├─────────────────────┤     │ generated_by            │
│ id (PK)              │     │ created_at              │
│ control_id (IDX)     │     └────────────────────────┘
│ framework            │
│ status               │     ┌────────────────────────┐
│ responsible          │     │  strike_simulations     │
│ updated_at           │     ├────────────────────────┤
└─────────────────────┘     │ id (PK)                 │
                             │ target_host             │
                             │ results (JSON)          │
                             │ created_at              │
                             └────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **Indexed columns** on findings (cve, vendor, cvss, priority, cisa_kev, ransomware, source) | Sub-millisecond filtering on 1600+ findings |
| **JSON columns** for raw_inputs, asset_data, sss_data | Flexible schema for varying data sources |
| **Idempotent seeding** | `seed_findings.py` checks existing IDs before insert — safe to re-run |
| **In-memory + DB suspension cache** | Fast O(1) suspension checks without DB round-trip per request |
| **Daily query logs** | Enable anomaly detection with 7-day rolling averages |

### Data Sources → Database Flow

```
CISA KEV JSON ──────┐
                     │
PoC CVE JSON ────────┼──→ seed_findings.py ──→ PostgreSQL (findings table)
                     │
SSS Supply Chain ────┘

On startup:
1. init_db() creates all tables
2. ensure_findings_seeded() checks if findings table is empty
3. If empty → runs seed_all() to import from JSON files
4. Subsequent startups skip seeding (idempotent)
```

---

## Module Architecture

### EDIP Decision Engine

The **E**valuate → **D**ecide → **I**mplement → **P**atch engine is the core AI classifier:

```
Finding Input:
  cvss: 9.8
  asset_criticality: "critical"
  cisa_kev: true
  ransomware: true
  asset_context: {name: "FortiGate-FW-01", ip: "10.0.1.1", id: "TMPR-A-0017"}
      │
      ▼
┌─────────────────────────────┐
│   EDIP auto_classify()       │
│                               │
│   Rule 1: CVSS ≥ 9 + KEV    │──→ FIX (0.95 confidence)
│   Rule 2: CVSS ≥ 7 + KEV    │──→ FIX (0.90)
│   Rule 3: Ransomware + High │──→ FIX (0.88)
│   Rule 4: Exploit mature     │──→ FIX (0.85)
│   Rule 5: CVSS < 4 + comp   │──→ ACCEPT CANDIDATE (0.80)
│   Rule 6: Low risk + no KEV │──→ DEFER (0.65-0.75)
│   Default: Mixed signals     │──→ MANUAL (0.0)
└─────────────────────────────┘
      │
      ▼
Output (context-bound):
  "AUTO-FIX: CVSS 9.8 (Critical) on FortiGate-FW-01 (10.0.1.1, Ref: TMPR-A-0017).
   Listed in CISA KEV. Linked to active ransomware campaigns.
   Immediate remediation required per CTEM policy."
```

### AI Pipeline (SPEAK + SPOTLIGHT)

```
User Query
    │
    ▼
Sanitize (injection detection) ──→ Block if injection detected
    │
    ▼
Build Context:
  ├── Finding stats (SQL COUNT queries)
  ├── Asset inventory counts
  ├── STRIKE simulation results
  ├── Compliance control status
  └── Top 5 critical CVEs
    │
    ▼
RAG Retrieval (ChromaDB vector search)
    │
    ▼
DB Keyword Search (Finding.cve/vendor/title ilike)
    │
    ▼
FreeLLMAPI Chat Completion ──→ Fallback: intelligent mock response
    │
    ▼
Output Filter (system prompt leak detection)
    │
    ▼
Context Binding Footer appended:
  "Report generated for analyst@tempris.com |
   Infrastructure: FortiGate-FW-01, Palo-Alto-PA-5200, Dell-R740-DB01 |
   Generated: 2026-06-29T07:00:00Z | Ref: TMPR-8A3F2C1D9E0B"
```

---

## Security Architecture

### Middleware Stack (execution order)

```
Request → CORS → Rate Limiter → ToS Enforcer → Security Headers → Route Handler
```

| Layer | File | Purpose |
|---|---|---|
| CORS | `index.py` | Configurable origins, no wildcard in prod |
| IP Rate Limiter | `rate_limit.py` | Token bucket per IP (auth: 5/min, scanner: 10/min, api: 100/min) |
| Account Rate Limiter | `rate_limit.py` | Per-account daily caps (SPEAK: 50, SPOTLIGHT: 10, EDIP: 200, general: 1000) |
| Anomaly Detection | `rate_limit.py` | Flags at 3× 7-day rolling average |
| ToS Enforcer | `tos_enforcer.py` | Pattern classifier → auto-suspend |
| Security Headers | `index.py` | X-Content-Type-Options, X-Frame-Options, CSP, HSTS |

### Anti-Distillation Defenses

| Defense | How It Works |
|---|---|
| **Per-account caps** | Daily query limits on AI endpoints. Prevents systematic extraction. |
| **Anomaly detection** | 3× rolling average triggers flag. Persisted to DB for review. |
| **Burst detection** | >10 AI requests in 60 seconds → auto-suspend |
| **Harvesting detection** | >20 unique queries in 5 minutes → auto-suspend |
| **CVE enumeration detection** | >15 sequential CVE-pattern queries → auto-suspend |
| **Output context binding** | Every AI output references client-specific asset names, IPs, and unique hashes |

### Authentication Flow

```
Login (email + password)
    │
    ▼
bcrypt.verify() → JWT token (HS256, 60-min expiry)
    │
    ▼
Subsequent requests: Bearer token in Authorization header
    │
    ▼
get_current_user():
  1. Decode JWT
  2. Check account suspension (in-memory cache)
  3. Return user payload
    │
    ▼
require_role() decorator for RBAC:
  Superadmin > Admin > Analyst > Viewer > Read-only
```

---

## API Reference

### Core Endpoints

| Method | Path | Auth | Module |
|---|---|---|---|
| `POST` | `/api/auth/login` | No | Login |
| `GET` | `/api/health` | No | Health check |
| `GET` | `/api/synthesis/dashboard` | Yes | Dashboard telemetry |
| `GET` | `/api/spectrum/findings` | Yes | Paginated CVE list |
| `GET` | `/api/spectrum/findings/{id}` | Yes | Single finding detail |
| `GET` | `/api/scout/stats` | Yes | Vulnerability statistics |
| `GET` | `/api/scout/findings` | Yes | Scanner findings |
| `POST` | `/api/speak/chat` | Yes | AI chatbot |
| `GET` | `/api/speak/history` | Yes | Chat history |
| `POST` | `/api/spotlight/generate` | Yes | Generate AI report |
| `GET` | `/api/standard/compliance` | Yes | Compliance controls |
| `POST` | `/api/strike/authorize` | Yes | Authorize adversary sim |
| `GET` | `/api/assets` | Yes | Asset inventory |
| `GET` | `/api/audit/logs` | Yes | Audit trail |

---

## Deployment Guide

### VPS Information

| Property | Value |
|---|---|
| IP Address | `187.127.114.218` |
| SSH User | `devuser` |
| App Directory | `/home/tempris/app/` |
| Backend | `/home/tempris/app/backend/` |
| Frontend | `/home/tempris/app/frontend/` |
| Compose | `/home/tempris/app/deploy/` |

### Container Architecture

```
┌─ tempris_nginx ─────────────── Port 80/443
│
├─ tempris_backend ──────────── Port 8000 (health-checked)
│
├─ tempris-app-postgres-1 ───── Port 5432 (localhost only)
│
├─ tempris_llm (FreeLLMAPI) ─── Port 3001
│
├─ tempris-app-redis-1 ──────── Port 6379
│
├─ tempris-app-kafka-1 ──────── Port 9092
│
└─ tempris-app-zookeeper-1 ──── Port 2181
```

### Deployment Steps

#### 1. Prepare Deploy Archive (Local)

```powershell
# Stage changed files
$files = @(
  "tempris/api/models.py",
  "tempris/api/index.py",
  "tempris/api/middleware/*",
  "tempris/api/routers/auth.py",
  "tempris/api/routers/spectrum.py",
  "tempris/api/services/*",
  "tempris/api/scripts/*"
)
# Create tar
tar -czf deploy.tar.gz -C tempris/api .
```

#### 2. Build Frontend (Local)

```powershell
cd tempris
npm run build
tar -czf frontend.tar.gz -C dist .
```

#### 3. Upload to VPS

```powershell
scp deploy.tar.gz devuser@187.127.114.218:/home/devuser/
scp frontend.tar.gz devuser@187.127.114.218:/home/devuser/
```

#### 4. Deploy on VPS

```bash
# SSH in
ssh devuser@187.127.114.218

# Backend
echo 'PASSWORD' | sudo -S tar -xzf /home/devuser/deploy.tar.gz -C /home/tempris/app/backend/
echo 'PASSWORD' | sudo -S chown -R tempris:tempris /home/tempris/app/backend/

# Frontend
echo 'PASSWORD' | sudo -S tar -xzf /home/devuser/frontend.tar.gz -C /home/tempris/app/frontend/
echo 'PASSWORD' | sudo -S chown -R tempris:tempris /home/tempris/app/frontend/

# Restart backend
echo 'PASSWORD' | sudo -S docker restart tempris_backend

# Verify
sleep 10
curl -s http://localhost:8000/api/health
```

#### 5. Verify

```bash
# Check backend is healthy
sudo docker ps --format '{{.Names}} {{.Status}}' | grep backend
# Should show: tempris_backend Up Xs (healthy)

# Check API
curl -s http://localhost:8000/api/health
# Should return: {"status":"Tempris API running"}

# Check logs for errors
sudo docker logs tempris_backend --tail 20
```

---

## Maintenance & Operations

### Database Backups

Automated daily at 03:00 via cron:
```bash
# /home/tempris/app/backup.sh
# Retention: 7 days
# Location: /home/tempris/backups/tempris_db_YYYYMMDD_HHMMSS.sql.gz
```

### Monitoring Commands

```bash
# Check all containers
sudo docker ps --format '{{.Names}} {{.Status}}'

# Backend logs (last 50 lines)
sudo docker logs tempris_backend --tail 50

# Database size
sudo docker exec tempris-app-postgres-1 psql -U tempris -c "SELECT pg_size_pretty(pg_database_size('tempris'));"

# Findings count
sudo docker exec tempris-app-postgres-1 psql -U tempris -c "SELECT COUNT(*) FROM findings;"

# Check suspended accounts
sudo docker exec tempris-app-postgres-1 psql -U tempris -c "SELECT email, reason, suspended_at FROM account_suspensions WHERE is_active = true;"

# Check rate limit anomalies
sudo docker exec tempris-app-postgres-1 psql -U tempris -c "SELECT * FROM account_query_logs WHERE flagged_anomaly = true ORDER BY query_date DESC LIMIT 10;"
```

### Unsuspending an Account

```bash
sudo docker exec tempris-app-postgres-1 psql -U tempris -c "
  UPDATE account_suspensions 
  SET is_active = false, unsuspended_at = NOW() 
  WHERE email = 'user@example.com' AND is_active = true;
"
# Then restart backend to refresh in-memory cache:
sudo docker restart tempris_backend
```

### Adding New Findings

1. Place new JSON data files in `/home/tempris/app/backend/data/`
2. Run seed script:
```bash
sudo docker exec tempris_backend python scripts/seed_findings.py
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///tempris.db` | PostgreSQL connection string |
| `JWT_SECRET_KEY` | (dev fallback) | HMAC key for JWT signing. **Must be set in production.** |
| `FREELLM_BASE_URL` | `http://localhost:3001/v1` | FreeLLMAPI endpoint |
| `FREELLM_API_KEY` | (none) | API key for LLM service |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Comma-separated allowed origins |
| `ENABLE_HSTS` | `false` | Enable Strict-Transport-Security header |
| `DB_PASSWORD` | required | PostgreSQL password supplied via environment or `.env` |
