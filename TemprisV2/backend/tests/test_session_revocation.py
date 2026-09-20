# backend/tests/test_session_revocation.py
import uuid
import time
import jwt
import pytest
from starlette.testclient import TestClient

from app.config import JWT_SECRET
from app.db import get_db_connection
from tests.conftest import TENANT_A, TENANT_B, TEST_PASSWORD, TEST_PASSWORD_HASH

def test_login_success_and_jwt_claim_integrity(client: TestClient):
    """
    Verifies database login yields authoritative 5-claim JWT with exact 3600s lifetime
    and returns token_type, expires_in, tenant_id, role in response.
    """
    user_email = f"revoc-user-{uuid.uuid4().hex[:8]}@tempris.com"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Revocation User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(TENANT_A), str(user_id)))
        conn.commit()

    now_before = int(time.time()) - 2
    resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600
    assert data["tenant_id"] == str(TENANT_A)
    assert data["role"] == "admin"

    token = data["token"]
    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

    # Strict 6-claim verification (session-bound shape: jti names the
    # persisted user_sessions row; sub is the user UUID)
    expected_claims = {"sub", "tenant_id", "role", "iat", "exp", "jti", "email"}
    assert set(decoded.keys()) == expected_claims
    assert decoded["sub"] == str(user_id)
    assert decoded["tenant_id"] == str(TENANT_A)
    assert decoded["role"] == "admin"
    assert isinstance(decoded["iat"], int)
    assert isinstance(decoded["exp"], int)
    assert decoded["exp"] - decoded["iat"] == 3600
    assert decoded["iat"] >= now_before

def test_immediate_revocation_on_membership_deletion(client: TestClient):
    """Deleting user membership immediately revokes active token on next HTTP request."""
    user_email = f"del-member-{uuid.uuid4().hex[:8]}@tempris.com"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Del Member User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(TENANT_A), str(user_id)))
        conn.commit()

    login_resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Initial request succeeds
    get_resp = client.get("/api/assets", headers=headers)
    assert get_resp.status_code == 200

    # Delete membership from database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tenant_memberships WHERE user_id = %s;", (str(user_id),))
        conn.commit()

    # Next request immediately rejected with 401 Session invalid or expired
    revoked_resp = client.get("/api/assets", headers=headers)
    assert revoked_resp.status_code == 401
    assert revoked_resp.json()["detail"] == "Session invalid or expired"

def test_immediate_revocation_on_membership_deactivation(client: TestClient):
    """Updating membership status to 'disabled' immediately invalidates session."""
    user_email = f"dis-member-{uuid.uuid4().hex[:8]}@tempris.com"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Dis Member User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(TENANT_A), str(user_id)))
        conn.commit()

    login_resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Initial request succeeds
    get_resp = client.get("/api/assets", headers=headers)
    assert get_resp.status_code == 200

    # Disable membership in database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET status = 'disabled' WHERE user_id = %s;", (str(user_id),))
        conn.commit()

    # Next request immediately rejected with 401 Session invalid or expired
    revoked_resp = client.get("/api/assets", headers=headers)
    assert revoked_resp.status_code == 401
    assert revoked_resp.json()["detail"] == "Session invalid or expired"

def test_immediate_revocation_on_tenant_deactivation(client: TestClient):
    """Updating tenant status to 'disabled' immediately invalidates session for all tenant members."""
    tenant_id = uuid.uuid4()
    user_email = f"tenant-dis-{uuid.uuid4().hex[:8]}@tempris.com"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (id, name, slug, status, version)
                VALUES (%s, 'Deactivating Tenant', %s, 'active', 1);
            """, (str(tenant_id), f"deact-{tenant_id.hex[:8]}"))

            cur.execute("""
                INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version)
                VALUES (%s, 'CORE_ASSETS', '{}'::jsonb, 1);
            """, (str(tenant_id),))

            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Tenant Deact User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(tenant_id), str(user_id)))
        conn.commit()

    login_resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Initial request succeeds
    get_resp = client.get("/api/assets", headers=headers)
    assert get_resp.status_code == 200

    # Deactivate tenant in database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenants SET status = 'disabled' WHERE id = %s;", (str(tenant_id),))
        conn.commit()

    # Next request immediately rejected with 401 Session invalid or expired
    revoked_resp = client.get("/api/assets", headers=headers)
    assert revoked_resp.status_code == 401
    assert revoked_resp.json()["detail"] == "Session invalid or expired"

def test_immediate_revocation_on_user_deactivation(client: TestClient):
    """Updating user status to 'disabled' immediately invalidates session."""
    user_email = f"user-dis-{uuid.uuid4().hex[:8]}@tempris.com"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'User Deact Target', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(TENANT_A), str(user_id)))
        conn.commit()

    login_resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Initial request succeeds
    get_resp = client.get("/api/assets", headers=headers)
    assert get_resp.status_code == 200

    # Deactivate user in database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET status = 'disabled' WHERE id = %s;", (str(user_id),))
        conn.commit()

    # Next request immediately rejected with 401 Session invalid or expired
    revoked_resp = client.get("/api/assets", headers=headers)
    assert revoked_resp.status_code == 401
    assert revoked_resp.json()["detail"] == "Session invalid or expired"

def test_immediate_revocation_on_role_mutation(client: TestClient):
    """Mutating role in database (e.g. admin -> analyst) immediately invalidates old token carrying stale role claim."""
    user_email = f"role-mut-{uuid.uuid4().hex[:8]}@tempris.com"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Role Mutate User', %s, 'active', FALSE)
                RETURNING id;
            """, (user_email, TEST_PASSWORD_HASH))
            user_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');
            """, (str(TENANT_A), str(user_id)))
        conn.commit()

    login_resp = client.post(
        "/api/auth/login",
        json={"email": user_email, "password": TEST_PASSWORD}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Initial request succeeds
    get_resp = client.get("/api/assets", headers=headers)
    assert get_resp.status_code == 200

    # Mutate role to 'analyst' in database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET role = 'analyst' WHERE user_id = %s;", (str(user_id),))
        conn.commit()

    # Token minted with role='admin' is rejected because DB role is now 'analyst'
    revoked_resp = client.get("/api/assets", headers=headers)
    assert revoked_resp.status_code == 401
    assert revoked_resp.json()["detail"] == "Session invalid or expired"

def test_absence_of_tenant_switching_endpoint(client: TestClient, auth_headers_tenant_a_admin):
    """Confirms no /api/auth/switch-tenant endpoint exists in scope."""
    resp = client.post(
        "/api/auth/switch-tenant",
        json={"tenant_id": str(TENANT_B)},
        headers=auth_headers_tenant_a_admin
    )
    assert resp.status_code in (404, 405)
