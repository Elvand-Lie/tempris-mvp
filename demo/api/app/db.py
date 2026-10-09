# demo/api/app/db.py — Postgres with tenant-scoped row-level security.
# Every demo query runs inside a transaction with `SET app.tenant_id` so the
# RLS policies below pin all reads/writes to the presenter's tenant.
from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg
from psycopg import sql

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://demo:demo@localhost:5433/terra_demo"
)

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
def connect():
    conn = psycopg.connect(DATABASE_URL, autocommit=False)
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
    with connect() as conn:
        conn.execute(SCHEMA)
