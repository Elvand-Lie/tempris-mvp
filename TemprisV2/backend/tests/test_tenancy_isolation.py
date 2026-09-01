# backend/tests/test_tenancy_isolation.py
import uuid
import pytest
from starlette.testclient import TestClient
from fastapi import FastAPI, Depends

from app.auth import AuthContext, require_platform_admin, create_test_token, PLATFORM_TENANT_ID
from app.db import get_db_connection
from tests.conftest import TENANT_A, TENANT_B, TEST_PASSWORD, TEST_PASSWORD_HASH

def test_single_membership_derivation_for_distinct_tenants(client: TestClient):
    """Users in different tenants automatically derive their respective active tenant context on login."""
    user_a_email = f"user-tenant-a-{uuid.uuid4().hex[:8]}@tempris.com"
    user_b_email = f"user-tenant-b-{uuid.uuid4().hex[:8]}@tempris.com"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # User A in Tenant A
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'User A', %s, 'active', FALSE)
                RETURNING id;
            """, (user_a_email, TEST_PASSWORD_HASH))
            user_a_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'analyst', 'active');
            """, (str(TENANT_A), str(user_a_id)))

            # User B in Tenant B
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'User B', %s, 'active', FALSE)
                RETURNING id;
            """, (user_b_email, TEST_PASSWORD_HASH))
            user_b_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(TENANT_B), str(user_b_id)))
        conn.commit()

    # Login User A -> derives Tenant A and role analyst
    resp_a = client.post(
        "/api/auth/login",
        json={"email": user_a_email, "password": TEST_PASSWORD}
    )
    assert resp_a.status_code == 200
    assert resp_a.json()["tenant_id"] == str(TENANT_A)
    assert resp_a.json()["role"] == "analyst"

    # Login User B -> derives Tenant B and role admin
    resp_b = client.post(
        "/api/auth/login",
        json={"email": user_b_email, "password": TEST_PASSWORD}
    )
    assert resp_b.status_code == 200
    assert resp_b.json()["tenant_id"] == str(TENANT_B)
    assert resp_b.json()["role"] == "admin"

def test_login_rejected_for_user_with_zero_active_memberships(client: TestClient):
    """Active user with 0 active memberships (e.g. only disabled memberships) cannot log in."""
    user_email = f"no-member-{uuid.uuid4().hex[:8]}@tempris.com"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'No Member User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            # Insert disabled membership
            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'analyst', 'disabled');
            """, (str(TENANT_A), str(user_id)))
        conn.commit()

    resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"

def test_login_rejected_for_user_in_disabled_tenant(client: TestClient):
    """Active user whose sole active membership is in a disabled tenant cannot log in."""
    dis_tenant_id = uuid.uuid4()
    user_email = f"dis-tenant-user-{uuid.uuid4().hex[:8]}@tempris.com"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (id, name, slug, status, version)
                VALUES (%s, 'Disabled Test Tenant', %s, 'disabled', 1);
            """, (str(dis_tenant_id), f"dis-slug-{dis_tenant_id.hex[:8]}"))

            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Disabled Tenant User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(dis_tenant_id), str(user_id)))
        conn.commit()

    resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"

def test_fail_closed_on_corrupt_multiple_active_memberships(client: TestClient):
    """
    If corrupt legacy state contains >1 active memberships, login fails closed with 401
    and logs an auth.configuration_error audit event under PLATFORM_TENANT_ID.
    """
    corrupt_email = f"corrupt-user-{uuid.uuid4().hex[:8]}@tempris.com"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Temporarily drop partial unique index to insert corrupt state
            cur.execute("DROP INDEX IF EXISTS uq_memberships_user_active;")

            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Corrupt User', %s, 'active', FALSE)
                RETURNING id;
            """, (corrupt_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            # Insert 2 active memberships for same user across Tenant A and Tenant B
            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES
                    (gen_random_uuid(), %s, %s, 'admin', 'active'),
                    (gen_random_uuid(), %s, %s, 'analyst', 'active');
            """, (str(TENANT_A), str(user_id), str(TENANT_B), str(user_id)))
        conn.commit()

    try:
        # Attempt login
        resp = client.post(
            "/api/auth/login",
            json={"email": corrupt_email, "password": TEST_PASSWORD}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"

        # Verify audit configuration error event recorded under PLATFORM_TENANT_ID
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT tenant_id, event_name, actor_id, details
                    FROM audit_events
                    WHERE event_name = 'auth.configuration_error' AND actor_id = %s;
                """, (corrupt_email,))
                audit_row = cur.fetchone()
                assert audit_row is not None
                assert str(audit_row["tenant_id"]) == str(PLATFORM_TENANT_ID)
                assert audit_row["event_name"] == "auth.configuration_error"
                assert "Multiple active memberships" in str(audit_row["details"])
    finally:
        # Cleanup corrupt memberships and restore partial unique index
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM tenant_memberships WHERE user_id = %s;", (str(user_id),))
                cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_memberships_user_active ON tenant_memberships (user_id) WHERE status = 'active';")
            conn.commit()

def test_require_platform_admin_guard_enforcement():
    """
    require_platform_admin succeeds ONLY for active user with is_platform_admin = TRUE in PLATFORM_TENANT_ID.
    Fails with 403 Forbidden for superadmins of other tenants or users with is_platform_admin = FALSE.
    """
    test_app = FastAPI()

    @test_app.get("/platform-admin-only")
    def platform_admin_route(auth: AuthContext = Depends(require_platform_admin)):
        return {
            "status": "ok",
            "tenant_id": str(auth.tenant_id),
            "actor_id": auth.actor_id,
            "is_platform_admin": auth.is_platform_admin
        }

    plat_admin_email = f"plat-admin-{uuid.uuid4().hex[:8]}@tempris.com"
    non_plat_superadmin_email = f"tenant-b-super-{uuid.uuid4().hex[:8]}@tempris.com"
    plat_tenant_regular_admin_email = f"plat-regular-{uuid.uuid4().hex[:8]}@tempris.com"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # 1. Genuine Platform Admin: in PLATFORM_TENANT_ID and is_platform_admin = TRUE
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Platform Admin Genuine', %s, 'active', TRUE)
                RETURNING id;
            """, (plat_admin_email, TEST_PASSWORD_HASH))
            plat_admin_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'superadmin', 'active');
            """, (str(PLATFORM_TENANT_ID), str(plat_admin_id)))

            # 2. Superadmin of Tenant B: in TENANT_B, is_platform_admin = FALSE
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Tenant B Superadmin', %s, 'active', FALSE)
                RETURNING id;
            """, (non_plat_superadmin_email, TEST_PASSWORD_HASH))
            non_plat_superadmin_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'superadmin', 'active');
            """, (str(TENANT_B), str(non_plat_superadmin_id)))

            # 3. Regular admin in PLATFORM_TENANT_ID: is_platform_admin = FALSE
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Platform Regular Admin', %s, 'active', FALSE)
                RETURNING id;
            """, (plat_tenant_regular_admin_email, TEST_PASSWORD_HASH))
            plat_regular_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(PLATFORM_TENANT_ID), str(plat_regular_id)))
        conn.commit()

    with TestClient(test_app) as test_c:
        # 1. Genuine Platform Admin accesses platform-guarded route -> 200 OK
        token_plat = create_test_token(tenant_id=str(PLATFORM_TENANT_ID), actor_id=plat_admin_email, role="superadmin")
        resp1 = test_c.get("/platform-admin-only", headers={"Authorization": f"Bearer {token_plat}"})
        assert resp1.status_code == 200
        assert resp1.json()["status"] == "ok"
        assert resp1.json()["is_platform_admin"] is True

        # 2. Superadmin of Tenant B accesses platform-guarded route -> 403 Forbidden
        token_b = create_test_token(tenant_id=str(TENANT_B), actor_id=non_plat_superadmin_email, role="superadmin")
        resp2 = test_c.get("/platform-admin-only", headers={"Authorization": f"Bearer {token_b}"})
        assert resp2.status_code == 403
        assert "Platform administrator authority required" in resp2.json()["detail"]

        # 3. Regular Admin in Platform Tenant (is_platform_admin = FALSE) -> 403 Forbidden
        token_reg = create_test_token(tenant_id=str(PLATFORM_TENANT_ID), actor_id=plat_tenant_regular_admin_email, role="admin")
        resp3 = test_c.get("/platform-admin-only", headers={"Authorization": f"Bearer {token_reg}"})
        assert resp3.status_code == 403
        assert "Platform administrator authority required" in resp3.json()["detail"]
