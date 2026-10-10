# demo/tests/test_tenant_isolation.py — WO-10 10b: the runtime database role
# is not a superuser, RLS applies to it, and audit_events is append-only.
# Run: DATABASE_URL=postgresql://demo:pw@host/db python -m pytest tests/test_tenant_isolation.py -q
from __future__ import annotations

import os
import pathlib
import sys
import urllib.parse

import psycopg
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "api"))

os.environ.setdefault("DATABASE_URL", "postgresql://demo:demo@localhost:5433/terra_demo")
os.environ["DB_APP_PASSWORD"] = "isolation-test-pw"

from app import db  # noqa: E402

# Module import order must not matter: force the role settings on the already
# imported db module before bootstrapping, whatever other test files set.
db.DB_APP_PASSWORD = os.environ["DB_APP_PASSWORD"]
db.ADMIN_DATABASE_URL = db.DATABASE_URL
db.init_schema()

APP_URL = urllib.parse.urlunsplit(urllib.parse.urlsplit(db.DATABASE_URL)._replace(
    netloc=f"{db.DB_APP_ROLE}:{db.DB_APP_PASSWORD}@"
    + (urllib.parse.urlsplit(db.DATABASE_URL).hostname or "")
    + (f":{urllib.parse.urlsplit(db.DATABASE_URL).port}" if urllib.parse.urlsplit(db.DATABASE_URL).port else ""),
))


def app_conn(tenant: str | None = None):
    """Runtime-role connection, optionally pinned to a tenant (txn-scoped)."""
    conn = psycopg.connect(APP_URL, autocommit=False)
    if tenant is not None:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, false)", (tenant,))
    return conn


@pytest.fixture()
def seed_two_tenants():
    """One pack row + one audit row for tenant OTHER, via the bootstrap role
    (superuser bypasses RLS; that is exactly why runtime never uses it)."""
    with psycopg.connect(db.ADMIN_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM pack_assets WHERE tenant_id = 'other'")
            cur.execute(
                "INSERT INTO pack_assets (tenant_id, ord, payload) VALUES ('other', 9999, '{\"id\":\"ast-other\"}')"
            )
            cur.execute(
                "INSERT INTO audit_events (tenant_id, username, event, detail) VALUES ('other', 'other-user', 'test.other', '{}')"
            )
    yield
    with psycopg.connect(db.ADMIN_DATABASE_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SET app.audit_admin = 'on'")
            cur.execute("DELETE FROM audit_events WHERE event = 'test.other'")
            cur.execute("DELETE FROM pack_assets WHERE tenant_id = 'other'")


def test_runtime_role_has_no_superuser_or_bypassrls():
    with psycopg.connect(db.ADMIN_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = %s",
                (db.DB_APP_ROLE,),
            )
            row = cur.fetchone()
    assert row is not None, "runtime role must exist"
    assert row == (False, False, True)


def test_app_role_cannot_read_other_tenant(seed_two_tenants):
    with app_conn("terra") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pack_assets WHERE tenant_id = 'other'")
            assert cur.fetchone()[0] == 0


def test_app_role_cannot_write_other_tenant(seed_two_tenants):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with app_conn("terra") as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO pack_assets (tenant_id, ord, payload) VALUES ('other', 9998, '{}')"
                )


def test_missing_tenant_context_exposes_nothing(seed_two_tenants):
    with app_conn(None) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pack_assets")
            assert cur.fetchone()[0] == 0  # RLS fails closed
            # DELETE is granted to the app role; RLS still filters every row.
            cur.execute("DELETE FROM pack_findings")
            assert cur.rowcount == 0
            # INSERT without a tenant context violates the WITH CHECK clause.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    "INSERT INTO pack_findings (tenant_id, ord, payload) VALUES ('terra', 9999, '{}')"
                )


def test_app_role_cannot_reset_another_tenants_pack(seed_two_tenants):
    with app_conn("terra") as conn:
        with conn.cursor() as cur:
            for t in db.PACK_TABLES:
                cur.execute(f"DELETE FROM {t}")
            cur.execute("DELETE FROM pack_blobs")
    with psycopg.connect(db.ADMIN_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM pack_assets WHERE tenant_id = 'other'")
            assert cur.fetchone()[0] == 1  # untouched


def test_audit_events_append_only_for_app_role(seed_two_tenants):
    with app_conn("terra") as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_events (tenant_id, username, event, detail) VALUES ('terra', 'qa', 'test.append', '{}')"
            )
            cur.execute("SELECT id FROM audit_events WHERE event = 'test.append'")
            row_id = cur.fetchone()[0]
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("UPDATE audit_events SET event = 'tampered' WHERE id = %s", (row_id,))
            conn.rollback()
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("DELETE FROM audit_events WHERE id = %s", (row_id,))
            conn.rollback()


def test_audit_trigger_blocks_even_the_bootstrap_role(seed_two_tenants):
    target = None
    with psycopg.connect(db.ADMIN_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM audit_events WHERE tenant_id = 'other' LIMIT 1")
            target = cur.fetchone()[0]
            # The trigger raises with SQLSTATE 42501 -> InsufficientPrivilege.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("UPDATE audit_events SET event = 'tampered' WHERE id = %s", (target,))
    with psycopg.connect(db.ADMIN_DATABASE_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SET app.audit_admin = 'on'")
            cur.execute("UPDATE audit_events SET event = 'test.other-admin' WHERE id = %s", (target,))


def test_reset_preserves_audit_history(seed_two_tenants):
    with psycopg.connect(db.ADMIN_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM audit_events")
            before = cur.fetchone()[0]
    with app_conn("terra") as conn:
        with conn.cursor() as cur:
            for t in [*db.PACK_TABLES, "pack_blobs"]:
                cur.execute(f"DELETE FROM {t}")
    with psycopg.connect(db.ADMIN_DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM audit_events")
            assert cur.fetchone()[0] == before
