# backend/tests/conftest.py
import os
import sys
import uuid
import time
import pytest
from pathlib import Path
from starlette.testclient import TestClient

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
env_path = backend_dir / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

from app.main import app
from app.db import get_db_connection, init_db, close_db
from app.auth import create_test_token
from app.config import PLATFORM_TENANT_ID
from app.routes.auth import login_rate_guard
from migrations.runner import run_migrations

# Operational tenants for persona tests. TENANT_A is the operational Tempris
# tenant (11111111-1111-1111-1111-111111111111); it is NOT the platform tenant.
TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")

PLATFORM_ADMIN_EMAIL = "platform-admin@tempris.test"

TEST_PASSWORD = "tempris-admin-2026"
TEST_PASSWORD_HASH = "scrypt$16384$8$1$688dbe89a4ffcfe6457beeaf5503ef0a$8329a7eb365132ada7161ce8af1875b7f50a9b442ea5709849f0be7f00b5391f"

FIXTURE_USERS = [
    # (email, full_name, password_hash, status, is_platform_admin, tenant_id, role)
    ("admin", "Tempris Admin", TEST_PASSWORD_HASH, "active", False, TENANT_A, "admin"),
    ("admin@tempris.io", "Tempris Admin Email", TEST_PASSWORD_HASH, "active", False, TENANT_A, "admin"),
    ("admin-a", "Admin Tenant A", TEST_PASSWORD_HASH, "active", False, TENANT_A, "admin"),
    ("analyst-a", "Analyst Tenant A", TEST_PASSWORD_HASH, "active", False, TENANT_A, "analyst"),
    ("superadmin-a", "Superadmin Tenant A", TEST_PASSWORD_HASH, "active", False, TENANT_A, "superadmin"),
    ("admin-b", "Admin Tenant B", TEST_PASSWORD_HASH, "active", False, TENANT_B, "admin"),
    ("analyst-b", "Analyst Tenant B", TEST_PASSWORD_HASH, "active", False, TENANT_B, "analyst"),
    ("superadmin-b", "Superadmin Tenant B", TEST_PASSWORD_HASH, "active", False, TENANT_B, "superadmin"),
    ("test-user", "Test User", TEST_PASSWORD_HASH, "active", False, TENANT_A, "admin"),
    ("valid-user", "Valid User", TEST_PASSWORD_HASH, "active", False, TENANT_A, "admin"),
    ("super-1", "Superadmin 1", TEST_PASSWORD_HASH, "active", False, TENANT_A, "superadmin"),
    ("analyst-1", "Analyst 1", TEST_PASSWORD_HASH, "active", False, TENANT_A, "analyst"),
]

def seed_fixture_auth_data(conn):
    with conn.cursor() as cur:
        for email, full_name, pwd_hash, u_status, is_plat, tenant_id, role in FIXTURE_USERS:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, %s, %s, %s, %s)
                ON CONFLICT ((LOWER(email))) DO UPDATE
                SET full_name = EXCLUDED.full_name,
                    password_hash = EXCLUDED.password_hash,
                    status = EXCLUDED.status,
                    is_platform_admin = EXCLUDED.is_platform_admin
                RETURNING id;
            """, (email, full_name, pwd_hash, u_status, is_plat))
            user_row = cur.fetchone()
            user_id = user_row["id"] if isinstance(user_row, dict) else user_row[0]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, %s, 'active')
                ON CONFLICT (tenant_id, user_id) DO UPDATE
                SET role = EXCLUDED.role,
                    status = 'active';
            """, (str(tenant_id), str(user_id), role))
    conn.commit()


def ensure_platform_admin_session(email: str = PLATFORM_ADMIN_EMAIL) -> dict:
    """
    Idempotently provision a platform administrator: an active user with
    is_platform_admin = TRUE whose sole active membership is a superadmin
    membership in the dedicated Platform Control tenant. Returns auth headers
    for that platform-authority session.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Platform Control Admin', %s, 'active', TRUE)
                ON CONFLICT ((LOWER(email))) DO UPDATE
                SET status = 'active', is_platform_admin = TRUE
                RETURNING id;
                """,
                (email, TEST_PASSWORD_HASH),
            )
            user_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'superadmin', 'active')
                ON CONFLICT (tenant_id, user_id) DO UPDATE
                SET role = 'superadmin', status = 'active';
                """,
                (str(PLATFORM_TENANT_ID), str(user_id)),
            )
        conn.commit()
    token = create_test_token(str(PLATFORM_TENANT_ID), actor_id=email, role="superadmin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def platform_admin_headers():
    return ensure_platform_admin_session()

@pytest.fixture(autouse=True)
def reset_login_rate_guard():
    """Reset global login rate guard state and restore its clock before and after every test."""
    def _reset():
        login_rate_guard.reset()
        login_rate_guard.clock = time.time

    _reset()
    yield
    _reset()

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    init_db()
    with get_db_connection() as conn:
        run_migrations(conn)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (id, name, slug, status, version)
                VALUES
                    (%s, 'Tempris', 'tempris', 'active', 1),
                    (%s, 'Tenant B', 'tenant-b', 'active', 1)
                ON CONFLICT (id) DO UPDATE
                SET name = EXCLUDED.name, status = 'active';
            """, (str(TENANT_A), str(TENANT_B)))

            cur.execute("""
                INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version)
                VALUES
                    (%s, 'CORE_ASSETS', '{}'::jsonb, 1),
                    (%s, 'CORE_ASSETS', '{}'::jsonb, 1)
                ON CONFLICT (tenant_id) DO NOTHING;
            """, (str(TENANT_A), str(TENANT_B)))
        conn.commit()
        seed_fixture_auth_data(conn)
    yield
    close_db()

@pytest.fixture(autouse=True)
def clean_database():
    """Clean test tenant data between test runs for isolation."""
    def _do_clean():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # P0-06 SSS history is DB-enforced immutable (migration 019:
                # UPDATE/DELETE rejected, composite FKs RESTRICT findings), so
                # the findings DELETE below cannot see the referenced rows
                # removed per-tenant any other way. TRUNCATE clears the whole
                # table without firing row triggers (test DB only).
                # P0-06/P0-08 (019/021/022): SSS history is DB-enforced
                # immutable and derivations/override-bindings/attestations all
                # FK-reference chapter5_approvals, whose own trigger forbids
                # DELETE and whose audit is FK-pinned to it — the whole cluster
                # must be cleared in one atomic TRUNCATE statement (test DB
                # only; TRUNCATE does not fire row triggers).
                cur.execute(
                    "TRUNCATE non_cve_sss_proposals, non_cve_sss_derivations, "
                    "non_cve_classifications, non_cve_sss_override_proposals, "
                    "chapter5_approvals, chapter5_approval_audit, "
                    "exposure_non_exploitation_attestations;"
                )
                cur.execute("TRUNCATE identity_boundary_audit, tenant_identity_boundary;")
                cur.execute("DELETE FROM audit_events WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM scout_observations WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM scout_tool_runs WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM scout_jobs WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM asset_scan_authorizations WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM exposure_exploitation_evidence WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM exposure_business_impact WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM exposure_reachability_evidence WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM asset_exposures WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM asset_applicability_reviews WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM findings WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM assets WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                cur.execute("DELETE FROM collectors WHERE tenant_id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                # Clean any non-fixture memberships and users
                cur.execute("""
                    DELETE FROM tenant_memberships
                    WHERE user_id NOT IN (
                        SELECT id FROM users WHERE LOWER(email) = ANY(%s)
                    );
                """, ([u[0].lower() for u in FIXTURE_USERS],))
                cur.execute("""
                    DELETE FROM users
                    WHERE LOWER(email) != ALL(%s);
                """, ([u[0].lower() for u in FIXTURE_USERS],))
                # Reset statuses of fixture tenants and users
                cur.execute("UPDATE tenants SET status = 'active' WHERE id IN (%s, %s);", (str(TENANT_A), str(TENANT_B)))
                # Identity-boundary invariant: the Platform Control tenant never
                # holds a module entitlement, even if a test assigned one mid-run.
                cur.execute("DELETE FROM tenant_entitlements WHERE tenant_id = %s;", (str(PLATFORM_TENANT_ID),))
                cur.execute("UPDATE tenants SET status = 'active' WHERE id = %s;", (str(PLATFORM_TENANT_ID),))
                cur.execute("UPDATE users SET status = 'active', is_platform_admin = FALSE WHERE LOWER(email) = ANY(%s);", ([u[0].lower() for u in FIXTURE_USERS],))
                cur.execute("UPDATE tenant_memberships SET status = 'active';")
                cur.execute("""
                    INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version)
                    VALUES
                        (%s, 'CORE_ASSETS', '{}'::jsonb, 1),
                        (%s, 'CORE_ASSETS', '{}'::jsonb, 1)
                    ON CONFLICT (tenant_id) DO UPDATE
                    SET package_id = 'CORE_ASSETS', module_overrides = '{}'::jsonb, version = 1;
                """, (str(TENANT_A), str(TENANT_B)))
                cur.execute("UPDATE modules SET status = 'active' WHERE id = 'ASSETS';")
            conn.commit()
            seed_fixture_auth_data(conn)

    _do_clean()
    yield
    _do_clean()

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def auth_headers_tenant_a_admin():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="admin-a", role="admin")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_tenant_a_analyst():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="analyst-a", role="analyst")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_tenant_b_admin():
    token = create_test_token(tenant_id=str(TENANT_B), actor_id="admin-b", role="admin")
    return {"Authorization": f"Bearer {token}"}
