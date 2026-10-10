# Tempris — Terra Xin Yun Partner Demo (WO-10)

Replay, not engine: this app only loads, displays, resets and audits a
checksum-pinned synthetic pack for the fictional **Northwind Freight** estate.
No Tempris engine, scoring logic, prompts, detection content or source runs
here, and none of it ships in the pack.

This is an **independent deployment** — it does not touch, share routes with,
or depend on the operational Tempris V2 application or its production VPS.

## Layout

```
demo/
  pack/northwind_freight.v1.json   synthetic estate + 5 journeys (versioned, SHA-256 pinned)
  api/                             FastAPI: TOTP auth, RLS-scoped pack serving, reset, audit
  frontend/                        React (Vite): presenter mode, journeys, watermark, reset
  scripts/nightly_reset.py         host-side nightly baseline restore (cron)
  tests/test_wo10.py               reset integrity, checksum rejection, no-secrets, Journey E card
  tests/test_wo10_access.py        expired/revoked accounts, invite-only enrollment, lockout, audit, reset < 60 s
  api/issue_invite.py              Tempris admin: mint a single-name presenter invite
  docker-compose.yml               edge (Caddy, 443) + internal app network (no outbound)
  Caddyfile                        demo.tempris.com.sg TLS termination
  .env.example                     template (never commit .env)
```

## Run locally

```bash
docker run -d --name terra-demo-pg -e POSTGRES_USER=demo -e POSTGRES_PASSWORD=demo \
  -e POSTGRES_DB=terra_demo -p 5433:5432 postgres:16

cd demo/api
python -m pip install -r requirements.txt
export DATABASE_URL=postgresql://demo:demo@localhost:5433/terra_demo
python -c "from app.db import init_schema; init_schema()"
python provision_presenter.py presenter-01 '<password>'   # prints TOTP URI + pack sha256
export DEMO_PACK_SHA256=<sha256 from the line above>
export DEMO_PACK_PATH=$(pwd)/../pack/northwind_freight.v1.json
uvicorn app.main:app --port 8018

cd ../frontend && npm install && npx vite   # http://localhost:5175 (proxy set to :8018)
```

## Deploy (separate demo VPS only)

```bash
cp .env.example .env   # set DEMO_DB_PASSWORD + DEMO_PACK_SHA256
docker compose up -d --build
```

Nightly reset (host cron):
```
0 3 * * * docker compose -f /opt/terra-demo/docker-compose.yml exec -T api python /srv/scripts/nightly_reset.py
```
The API image bakes `pack/` and `scripts/` (see `api/Dockerfile`, build context = repo `demo/`).

## Access control (WO-10 10c)

Accounts are issued by Tempris, two ways:

- `provision_presenter.py <name> '<password>'` (admin; also renews or resets).
- In-app enrollment ("Create a presenter account") **only with a Tempris invite**:
  set `DEMO_INVITE_SECRET` (32+ random characters) in `.env` on the demo host,
  then run `python issue_invite.py <name> [hours]` and give that code to that
  presenter. Each invite enrolls exactly one username, expires (max 7 days) and
  can never overwrite, reset or un-revoke an existing account. Without
  `DEMO_INVITE_SECRET`, in-app enrollment is disabled.

Named presenter accounts only, mandatory TOTP MFA,
lockout after 5 failed attempts, 30-minute idle timeout, 90-day expiry,
instant revocation (delete the user row or set `revoked`), single `presenter`
role, all sessions scoped to tenant `terra` via Postgres RLS. Logins,
journey steps, resets, exports (`POST /demo/export`) and refused enrollments are
written to the append-only audit table.

After any pack change, re-pin `DEMO_PACK_SHA256` (the API refuses to start or
reset with a stale pin).

## Test credentials

Controlled local test accounts are created by `provision_presenter.py` at
provisioning time. No credentials are committed to the repository.

## Missing source documents (reported, not invented)

- **Doc 37 — Partner Demo Environment Brief**: not found in the repo or
  Downloads; journeys A–D talk tracks are constructed to WO-10's own journey
  definitions and marked `talk_track_source: constructed` in the pack.
- **External Journey A–D cards**: only the Journey E card (Doc 12 v148) and
  the login guide (Doc 11 v148) exist; Journey E uses the card verbatim.
- **Journey E offline video** (`Tempris_AI_Agents_as_Assets_Video_v148.mp4`):
  not in the repo — the presenter fallback media must be supplied separately.
