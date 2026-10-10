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
  tests/test_tenant_isolation.py   runtime role privileges, RLS isolation, audit append-only
  tests/test_journey_audit.py      journey-step audit validation against the pinned pack
  api/issue_invite.py              Tempris admin: mint a single-name presenter invite
  docker-compose.yml               demo stack (edge on loopback 8080, api/db fully internal)
  Caddyfile                        edge routes; TLS terminates on the production nginx gateway
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

## Deploy

Two supported topologies:

**A. Shared VPS (current, approved temporary deviation).** The stack lives in
`/home/tempris/terra-demo`; TLS terminates on the EXISTING production nginx
gateway (host network mode), which serves `demo.tempris.com.sg` /
`demo.tempris-singapore.com` from a vhost proxying to this stack's edge on
`127.0.0.1:8080`. Certificates live under `/var/www/certbot/letsencrypt/`
(a path already bind-mounted into the gateway container); renewal runs from
the tempris crontab. Nothing in this stack publishes a public port.

```bash
cp .env.example .env   # set DEMO_DB_PASSWORD, DB_APP_PASSWORD,
                       # DEMO_INVITE_SECRET, DEMO_PACK_SHA256
docker compose up -d --build
docker compose exec -T -e PYTHONPATH=/srv api python /srv/scripts/nightly_reset.py
```

**B. Dedicated demo VPS (original WO-10 design).** Same stack; give the edge
ports `443:443` + `80:80` and use the `demo.tempris-singapore.com { tls ... }`
site block in `Caddyfile` (see `kit/deploy/DEPLOY.md`).

Rollback either topology without touching Tempris V1/V2 — and without losing
data (never use `down -v`; it deletes the PostgreSQL volume holding presenter
accounts and audit history):

```bash
# before any deploy: snapshot the database (preserving rollback ability)
docker compose exec -T db sh -c \
  'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > terra-demo-db-$(date +%F).sql

# roll the application back, keeping the data volume:
git checkout <previous-commit> -- demo   # or reuse the previous image tag
docker compose build api && docker compose up -d --no-deps api
```

Note: rolling the API image back while KEEPING a database already migrated to
the role-separated schema is safe for reads and logins only if the previous
image establishes the tenant context for audit writes; images older than
`b8755a9` do not, so their audit writes (including login) would be refused by
the audit_events RLS policy. If that state is ever reached, either re-deploy
the new image (preferred) or restore the pre-deploy `pg_dump` snapshot taken
above. Full teardown (last resort only): `docker compose down -v`.

## Database roles (WO-10 10b)

Two roles, separated at init time (`app/db.py::init_schema`, idempotent — safe
against an existing database, preserves accounts and audit history):

- **Bootstrap role** (`ADMIN_DATABASE_URL`, the image's `POSTGRES_USER`):
  schema/role management only, never used at request time.
- **Runtime application role** (`DATABASE_URL`, `DB_APP_ROLE`/`DB_APP_PASSWORD`):
  `NOSUPERUSER NOBYPASSRLS`. Granted: read/insert/delete on pack tables and
  blobs (reset reloads them), insert+read on `audit_events`, CRUD on
  `users`/`sessions`. Row-level security (tenant-scoped policies on pack
  tables, blobs and audit events) therefore applies to every request; the
  tenant context is set transaction-scoped via
  `set_config('app.tenant_id', ..., false)` inside the same transaction.

Audit immutability: the runtime role has **no UPDATE/DELETE privilege** on
`audit_events`, and a `BEFORE UPDATE OR DELETE` trigger rejects mutation even
for the bootstrap role unless an operator deliberately runs
`SET app.audit_admin = 'on'` in that session. Limitation: a true superuser or
the bootstrap role can still lift the trigger and the guard config — that is
administrator-level access by definition and is out of the application's reach.

Nightly reset (host cron, 03:00 SGT = 19:00 UTC on a UTC host; the script
locates the app package itself, no PYTHONPATH needed):
```
0 19 * * * cd <demo-dir> && docker compose exec -T api python /srv/scripts/nightly_reset.py
```
The API image bakes `pack/`, `scripts/` and the invite CLI (see
`api/Dockerfile`, build context = repo `demo/`).

## Reproducible deployment from a fresh checkout

`demo/frontend/dist` is a build artifact and intentionally not committed.
`docker compose up -d --build` reproduces everything in Docker: the `webdist`
one-shot service builds the React app (node:22, `npm ci`) into the shared
`dist` volume, `bootstrap` runs schema/role setup as the admin role, and `api`
starts only after both succeed — holding no admin credentials. The live
shared-VPS deployment instead serves a host-built `./frontend/dist` bind
mount; that operator override is documented here and configured on the host.

Reproduce the verification suite (Postgres 16 on 127.0.0.1:5433, database
`terra_demo`):

```bash
cd demo
DATABASE_URL=postgresql://demo:demo@localhost:5433/terra_demo \
  python -m pytest tests/ -q          # 32 tests
cd frontend && npm ci && npm run build  # frontend build + tsc
```

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
journey steps, resets, exports (`POST /demo/export` records an initiated
print/export; the browser cannot confirm a file save) and refused enrollments
are written to the append-only audit table.

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
