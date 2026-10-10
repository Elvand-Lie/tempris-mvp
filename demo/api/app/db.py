# demo/api/app/db.py — Postgres with tenant-scoped row-level security.
# Every demo query runs inside a transaction with `SET app.tenant_id` so the
# RLS policies below pin all reads/writes to the presenter's tenant.
#
# Two database roles:
#   * the bootstrap role from DATABASE_URL bootstrap (POSTGRES_USER, a
#     superuser in the stock image) runs ONLY schema/role management via
#     ADMIN_DATABASE_URL at init time;
#   * the runtime application role (DB_APP_ROLE, no SUPERUSER, no BYPASSRLS)
#     is what DATABASE_URL points at in production. RLS applies to it.
from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg
from psycopg import sql

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://demo:demo@localhost:5433/terra_demo"
)
ADMIN_DATABASE_URL = os.environ.get("ADMIN_DATABASE_URL", DATABASE_URL)
DB_APP_ROLE = os.environ.get("DB_APP_ROLE", "terra_app")
DB_APP_PASSWORD = os.environ.get("DB_APP_PASSWORD", "")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'terra',
    password_hash   TEXT NOT NULL,          -- scrypt: salt$hex
    totp_secret     TEXT NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username),
    tenant_id  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit_events (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    username   TEXT NOT NULL,
    event      TEXT NOT NULL,
    detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
    at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

# Pack tables: identical shape, every row carries tenant_id, RLS denies
# anything outside the session's app.tenant_id.
PACK_TABLES = {
    "pack_assets": "assets",
    "pack_relationships": "relationships",
    "pack_findings": "findings",
    "pack_evidence": "evidence",
    "pack_edip": "edip_verifications",
    "pack_decisions": "decisions",
    "pack_remediations": "remediations",
}

SCHEMA += """
CREATE TABLE IF NOT EXISTS pack_blobs (
    tenant_id TEXT NOT NULL,
    key       TEXT NOT NULL,
    payload   JSONB NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
"""

for table in PACK_TABLES:
    SCHEMA += f"""
CREATE TABLE IF NOT EXISTS {table} (
    tenant_id TEXT NOT NULL,
    ord       INT NOT NULL,
    payload   JSONB NOT NULL,
    PRIMARY KEY (tenant_id, ord)
);
"""

RLS = """
DROP POLICY IF EXISTS tenant_isolation ON {t};
CREATE POLICY tenant_isolation ON {t}
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
"""

for table in [*PACK_TABLES, "pack_blobs", "audit_events"]:
    SCHEMA += RLS.format(t=table)

# Presenters and sessions are tenant rows too, but the login path must read
# a user before a session exists — those tables stay outside RLS and are
# only reachable through parameterised service queries.


@contextmanager
def connect(url: str | None = None):
    conn = psycopg.connect(url or DATABASE_URL, autocommit=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def tenant_conn(tenant_id: str):
    """Connection pinned to one tenant by Postgres RLS."""
    with connect() as conn:
        with conn.cursor() as cur:
            # set_config(..., false) = transaction-local; cannot leak out
            cur.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (tenant_id,)
            )
        yield conn


def init_schema() -> None:
    """Bootstrap/migrate the schema as the ADMIN role. Idempotent and safe to
    run against an existing demo database: it never drops data — it creates
    the runtime app role (no SUPERUSER, no BYPASSRLS), grants it exactly the
    privileges the service needs, and installs the append-only audit guard.
    Preserves existing presenter accounts and audit history."""
    with connect(ADMIN_DATABASE_URL) as conn:
        conn.execute(SCHEMA)
        if DB_APP_PASSWORD:
            conn.execute(
                sql.SQL(
                    "DO $$ BEGIN "
                    "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {r}) THEN "
                    "EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', {r}, {p}); "
                    "ELSE EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L', {r}, {p}); "
                    "END IF; END $$;"
                ).format(r=sql.Literal(DB_APP_ROLE), p=sql.Literal(DB_APP_PASSWORD))
            )
            app_role = sql.Identifier(DB_APP_ROLE)
            conn.execute(
                sql.SQL(
                    "ALTER ROLE {role} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                ).format(role=app_role)
            )
            # Runtime grants: everything the service does, nothing more.
            #   pack tables + blobs: read/insert/delete (reset reloads them)
            #   audit_events:        insert + read only — append-only at the
            #                        privilege level (UPDATE/DELETE not granted)
            #   users/sessions:      full CRUD (lockout, expiry, revocation)
            for table in [*PACK_TABLES, "pack_blobs"]:
                conn.execute(
                    sql.SQL("GRANT SELECT, INSERT, DELETE ON {t} TO {r}")
                    .format(t=sql.Identifier(table), r=app_role)
                )
            conn.execute(
                sql.SQL("GRANT SELECT, INSERT ON audit_events TO {r}").format(r=app_role)
            )
            conn.execute(
                sql.SQL("GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO {r}")
                .format(r=app_role)
            )
            for table in ("users", "sessions"):
                conn.execute(
                    sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {r}")
                    .format(t=sql.Identifier(table), r=app_role)
                )
        # Append-only guard, defence in depth: applies even to the bootstrap
        # role. An operator can deliberately lift it per-session with
        # `SET app.audit_admin = 'on'`; the application cannot.
        conn.execute(
            """
            CREATE OR REPLACE FUNCTION audit_append_only() RETURNS TRIGGER AS $$
            BEGIN
                IF current_setting('app.audit_admin', true) IS DISTINCT FROM 'on' THEN
                    RAISE EXCEPTION 'audit_events is append-only'
                        USING ERRCODE = '42501';
                END IF;
                RETURN COALESCE(NEW, OLD);
            END $$ LANGUAGE plpgsql
            """
        )
        conn.execute("DROP TRIGGER IF EXISTS audit_no_mutation ON audit_events")
        conn.execute(
            """
            CREATE TRIGGER audit_no_mutation
                BEFORE UPDATE OR DELETE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION audit_append_only()
            """
        )
