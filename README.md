# Tempris MVP

Tempris is a cybersecurity exposure management platform. This repo contains the full-stack application running at [sandbox.tempris.tech](https://sandbox.tempris.tech).

## Architecture

```
┌──────────────┐     ┌───────────────────┐     ┌───────────────────┐
│ nginx (:443) │────▶│ backend (:8000)   │────▶│ freellmapi (:3001)│
│  SSL + proxy │     │ FastAPI (Python)   │     │ Node.js / TS      │
│  rate-limit  │     │ + serves frontend  │     │ LLM proxy         │
└──────────────┘     └───────────────────┘     └───────────────────┘
                           │                          │
                     ┌─────▼──────┐             ┌─────▼──────┐
                     │ PostgreSQL │             │  SQLite    │
                     │  (prod)    │             │ freeapi.db │
                     │ or SQLite  │             └────────────┘
                     │  (dev)     │
                     └────────────┘
```

**Key modules:** SPECTRUM · SCOUT · SYNTHESIS · SPEAK · SPOTLIGHT · STANDARD · SCANNER · STRIKE · ASSETS · GRC · EDIP · SURGE

---

## Quick Start — Local Development

### Prerequisites

- **Python 3.11+**
- **Node.js 20+** (only if you want FreeLLMAPI running for live AI)
- **Docker Desktop** (optional — for the Docker workflow)

### Option A: Run Without Docker (Fastest)

```bash
# 1. Clone and switch to the correct branch
git clone https://github.com/Elvand-Lie/tempris-mvp.git
cd tempris-mvp
git checkout vps-prod

# 2. Create a Python virtual environment
cd app/backend
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
# source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables (SQLite + dev defaults)
# Windows PowerShell:
$env:DATABASE_URL="sqlite:///./tempris.db"
$env:JWT_SECRET_KEY="dev_secret_key_change_in_prod"
$env:FREELLM_API_KEY=""
$env:FREELLM_BASE_URL="http://localhost:3001/v1"
$env:CORS_ORIGINS="http://localhost:5173,http://localhost:8000"
$env:ENABLE_HSTS="false"

# macOS/Linux:
# export DATABASE_URL="sqlite:///./tempris.db"
# export JWT_SECRET_KEY="dev_secret_key_change_in_prod"
# export FREELLM_API_KEY=""
# export FREELLM_BASE_URL="http://localhost:3001/v1"
# export CORS_ORIGINS="http://localhost:5173,http://localhost:8000"
# export ENABLE_HSTS="false"

# 5. Run the backend
python index.py
```

The app will be available at **http://localhost:8000**.

#### Demo Credentials

| Email | Password | Role |
|-------|----------|------|
| `sherie@tempris.com` | `demo` | Superadmin |
| `admin@tempris.com` | `demo` | Admin |
| `analyst@tempris.com` | `demo` | Analyst |
| `viewer@tempris.com` | `demo` | Viewer |
| `readonly@tempris.com` | `demo` | Read-only |

### Option B: Run With Docker (Full Stack)

```bash
# 1. Clone and switch branch
git clone https://github.com/Elvand-Lie/tempris-mvp.git
cd tempris-mvp
git checkout vps-prod

# 2. Start everything (backend + FreeLLMAPI)
docker compose -f docker-compose.dev.yml up --build
```

The app will be available at **http://localhost:8000**.

> **Note:** The dev Docker setup uses SQLite and skips nginx/SSL. AI chat (SPEAK/SPOTLIGHT) will use mock responses unless you configure FreeLLMAPI with real API keys.

---

## Environment Variables

### Backend (`app/deploy/.env`)

See [`app/deploy/.env.example`](app/deploy/.env.example) for the full template.

| Variable | Required (Prod) | Required (Dev) | Description |
|----------|:---:|:---:|-------------|
| `DATABASE_URL` | ✅ | ❌ | PostgreSQL connection string. Falls back to SQLite if unset. |
| `JWT_SECRET_KEY` | ✅ | ❌ | JWT signing secret. Uses dev fallback if unset. |
| `FREELLM_API_KEY` | ❌ | ❌ | FreeLLMAPI key. Mock responses if unset. |
| `FREELLM_BASE_URL` | ❌ | ❌ | LLM proxy URL. Defaults to `http://localhost:3001/v1`. |
| `CORS_ORIGINS` | ✅ | ❌ | Comma-separated allowed origins. Has dev defaults. |
| `ENABLE_HSTS` | ✅ | ❌ | HSTS header. Set `true` in prod, `false` locally. |

### FreeLLMAPI (`app/freellmapi/.env`)

See [`app/freellmapi/.env.example`](app/freellmapi/.env.example) for the full template.

| Variable | Required | Description |
|----------|:---:|-------------|
| `ENCRYPTION_KEY` | ✅ | Encryption key for API key storage. |
| `PORT` | ❌ | Server port. Defaults to `3001`. |

---

## Module Notes for Local Dev

| Module | Works Locally? | Notes |
|--------|:-:|-------|
| SPECTRUM | ✅ | Full functionality |
| SCOUT | ✅ | Full functionality |
| SYNTHESIS | ✅ | Full functionality |
| STANDARD | ✅ | Full functionality |
| ASSETS | ✅ | Full functionality |
| GRC | ✅ | Full functionality |
| EDIP | ✅ | Full functionality |
| SURGE | ✅ | Full functionality |
| STRIKE | ✅ | Full functionality |
| AUDIT | ✅ | Full functionality |
| SPEAK | ⚠️ | Returns mock responses without FreeLLMAPI |
| SPOTLIGHT | ⚠️ | Returns mock responses without FreeLLMAPI |
| SCANNER | ⚠️ | Requires `nmap` and `nuclei` installed locally |

---

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `vps-prod` | **Use this.** 1:1 copy of what runs on sandbox.tempris.tech |
| `main` | Legacy — ignore for now |
| `master` | Legacy — ignore for now |

---

## Production Deployment

Production uses `app/deploy/docker-compose.prod.yml` which includes:
- Nginx with SSL (Let's Encrypt)
- PostgreSQL database
- FreeLLMAPI with real API keys
- Rate limiting, HSTS, security headers

See `app/deploy/` for production configs.
