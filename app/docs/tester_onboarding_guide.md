# Tempris CTEM Platform — Tester Onboarding Guide

**Last updated:** June 19, 2026

---

## 1. What is Tempris?

Tempris is a **Continuous Threat Exposure Management (CTEM)** platform for regulated financial institutions in Singapore. It combines vulnerability scanning, adversary simulation, AI-assisted analysis, and compliance management into one dashboard.

### Core Modules

| Module | What It Does | Route Prefix |
|--------|-------------|--------------|
| **Spectrum** | KEV findings dashboard, EDIP decisions, CTEM lifecycle | `/api/spectrum` |
| **STRIKE** | MITRE ATT&CK adversary simulation engine | `/api/strike` |
| **Scanner** | Port/service scanner with SSRF protection | `/api/scanner` |
| **Scout** | Threat intelligence feed | `/api/scout` |
| **Standard** | Compliance frameworks (MAS TRM, ISO 27001), evidence management | `/api/standard` |
| **GRC** | ISO 42001 AI governance, SOP management, sign-offs | `/api/grc` |
| **Synthesis** | TES (Threat Exposure Score) dashboard and snapshots | `/api/synthesis` |
| **SPEAK** | AI chat assistant (RAG-enhanced) | `/api/speak` |
| **Spotlight** | AI report generator (executive, technical, compliance) | `/api/spotlight` |
| **Audit** | TACF audit log with cryptographic hash chain | `/api/audit` |
| **Assets** | Asset inventory CRUD | `/api/assets` |
| **Auth** | JWT login, RBAC, brute force protection | `/api/auth` |

---

## 2. Environment Setup

### Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend)
- Git

### Clone and Install

```powershell
git clone <repo-url> c:\Tempris
cd c:\Tempris\tempris

# Backend dependencies
cd api
pip install -r requirements.txt

# Frontend dependencies
cd ..
npm install
```

### Run Tests Locally

```powershell
cd c:\Tempris\tempris
python -m pytest tests/ -v --tb=short -W ignore::DeprecationWarning
```

Expected: **80 passed** in ~30-40 seconds.

---

## 3. Test Accounts

The production sandbox uses a unique password for every account. Authorized operators can rotate them with `.\scripts\rotate-account-passwords.ps1`; the script writes the current values to the Git-ignored local file `workDocs/tempris-account-credentials.local.md`. The shared password `demo` is only valid in a local `ENVIRONMENT=demo` deployment.

| Email | Role | Access Level |
|-------|------|-------------|
| `sherie@tempris.com` | Superadmin | Full access to everything |
| `admin@tempris.com` | Admin | All CRUD + approve + reports |
| `analyst@tempris.com` | Analyst | CRUD findings, EDIP, scans |
| `viewer@tempris.com` | Viewer | Read-only all modules |
| `readonly@tempris.com` | Read-only | Audit logs + compliance reports only |

### Getting a Token

```bash
curl -X POST https://sandbox.tempris.tech/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"sherie@tempris.com\",\"password\":\"$TEMPRIS_SUPERADMIN_PASSWORD\"}"
```

Use the returned `access_token` as: `Authorization: Bearer <token>`

---

## 4. Live Sandbox

| URL | Purpose |
|-----|---------|
| `https://sandbox.tempris.tech` | Main app (login with an assigned sandbox account) |
| `https://sandbox.tempris.tech/api/health` | API health check |
| `https://sandbox.tempris.tech/vdp` | VDP policy and confidential SURGE intake |
| `https://sandbox.tempris.tech/.well-known/security.txt` | security.txt |

---

## 5. Test File Structure

```
c:\Tempris\tempris\tests\
├── conftest.py                              # Shared fixtures (DO NOT MODIFY)
├── __init__.py                              # Package marker
├── test_auth.py                             # Auth unit tests (6)
├── test_spectrum.py                         # Spectrum unit tests (8)
├── test_audit.py                            # Audit unit tests (6)
├── test_standard_assets_synthesis.py        # Standard + Assets + Synthesis (11)
├── test_strike_scanner_scout_grc.py         # Strike + Scanner + Scout + GRC (11)
├── test_ai_adversarial_security_exploits.py # AI + Security tests (10)
├── test_middleware.py                       # Middleware tests (6)
└── test_integration.py                     # End-to-end flows (22)
```

---

## 6. How to Write New Tests

### Use Existing Fixtures

```python
def test_my_new_test(client, admin_headers):
    """Description of what this test validates."""
    resp = client.get("/api/some/endpoint", headers=admin_headers)
    assert resp.status_code == 200
```

Available fixtures from `conftest.py`:
- `client` — FastAPI TestClient
- `superadmin_headers` — Auth headers for Superadmin
- `admin_headers` — Auth headers for Admin
- `viewer_headers` — Auth headers for Viewer
- `expired_headers` — Expired token
- `db` — Direct database session
- `sample_asset` — Pre-inserted test asset
- `sample_audit_entries` — Pre-inserted audit log with hash chain
- `mock_llm` — Mocked FreeLLM API
- `mock_rag` — Mocked RAG engine
- `mock_kev` — Mocked KEV data

### Test Naming Convention

```python
def test_<action>_<condition>_<expected_result>(self, client, headers):
    """Human-readable description."""
```

Example: `test_viewer_cannot_delete_asset`

### Run a Single Test File

```powershell
python -m pytest tests/test_auth.py -v --tb=short -W ignore::DeprecationWarning
```

### Run Full Suite

```powershell
python -m pytest tests/ -v --tb=short -W ignore::DeprecationWarning
```

---

## 7. Manual Testing Checklist (For New Testers)

### UI/UX Testing
- [ ] Login with each role → verify correct dashboard permissions
- [ ] Navigate every sidebar tab → check for broken layouts
- [ ] Resize browser → verify responsive design
- [ ] Test on Chrome, Firefox, Safari, Edge
- [ ] Test on mobile (iPhone/Android viewport)

### Feature Testing
- [ ] Spectrum: View findings → make EDIP decision → verify lifecycle update
- [ ] STRIKE: Create authorization → sign → run simulation → view results
- [ ] Scanner: Scan an external target → view findings
- [ ] Standard: Upload evidence file → download → delete
- [ ] GRC: Toggle controls → sign off as PIC → verify TES score changes
- [ ] SPEAK: Ask security question → verify AI response is relevant
- [ ] Spotlight: Generate executive report → verify PDF/narrative quality
- [ ] Audit: Verify all actions appear in audit log with timestamps

### Security Testing
- [ ] Try accessing admin pages as Viewer → should get redirected/blocked
- [ ] Try URL manipulation to access other users' data
- [ ] Check for sensitive data in browser DevTools → Network tab
- [ ] Verify no API keys/secrets visible in frontend source

### Accessibility
- [ ] Tab through all interactive elements → verify focus order
- [ ] Check color contrast on dark/light text
- [ ] Verify form labels and error messages are clear

---

## 8. Reporting Bugs

When you find a bug, document:

1. **Steps to reproduce** (exact clicks/API calls)
2. **Expected behavior** vs **Actual behavior**
3. **Screenshots** (use browser DevTools if needed)
4. **Console errors** (browser F12 → Console tab)
5. **Role used** (which test account)
6. **Browser/device**

File bugs as GitHub issues or in the shared testing spreadsheet.

---

## 9. Important Rules

> **DO NOT modify `conftest.py`** — it's shared across all test files and carefully configured.

> **DO NOT test against production** — only use `sandbox.tempris.tech`.

> **DO NOT use real credentials** — only demo accounts listed above.

> Rate limits: 5 requests/min on `/api/auth`, 10/min on `/api/scanner`, 100/min on everything else.
