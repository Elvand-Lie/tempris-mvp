"""ORG-01 amended boundary, platform bootstrap leg.

Proves the two-step bootstrap the platform UI exposes: tenant creation
invites the FIRST Superadmin as a pending membership (an unactivated account
never holds active access), and the platform activation step
(POST /api/platform/users/{id}/activate, wired to the PlatformAdminConsole
'pending' sub-tab) sets the initial password and promotes the pending
membership atomically — after which the first Superadmin can log in and use
the tenant Organization endpoints.
"""
import uuid

from app.db import get_db_connection


def test_platform_bootstrap_activate_then_first_superadmin_login(client, platform_admin_headers):
    email = f"bootstrap-super-{uuid.uuid4().hex[:8]}@flow.test"

    created = client.post(
        "/api/platform/tenants",
        headers=platform_admin_headers,
        json={
            "name": f"Bootstrap Flow Tenant {uuid.uuid4().hex[:8]}",
            "initial_superadmin_email": email,
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert created.status_code == 201
    body = created.json()
    tenant_id = body["id"]
    super_id = body["initial_superadmin"]["id"]

    # Step 1 result: pending account + pending superadmin membership.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.status AS user_status, u.password_hash IS NOT NULL AS has_hash,
                       m.status AS membership_status
                FROM users u JOIN tenant_memberships m ON m.user_id = u.id
                WHERE u.id = %s AND m.tenant_id = %s;
                """,
                (super_id, tenant_id),
            )
            assert cur.fetchone() == {
                "user_status": "pending",
                "has_hash": False,
                "membership_status": "pending",
            }

    # The pre-activation Superadmin cannot log in and the platform pending
    # list names the account for the activation step.
    early_login = client.post(
        "/api/auth/login", json={"email": email, "password": "whatever-1"}
    )
    assert early_login.status_code in (401, 403)

    pending = client.get("/api/platform/users/pending", headers=platform_admin_headers)
    assert pending.status_code == 200
    assert any(row["id"] == super_id for row in pending.json())

    # Step 2: platform activation — password + atomic membership promotion.
    activated = client.post(
        f"/api/platform/users/{super_id}/activate",
        headers=platform_admin_headers,
        json={"initial_password": "first-super-pass-1"},
    )
    assert activated.status_code == 200
    assert activated.json()["memberships"] == [
        {"tenant_id": tenant_id, "role": "superadmin", "status": "active"}
    ]

    # The first Superadmin can now log in and manage the organization.
    login = client.post(
        "/api/auth/login", json={"email": email, "password": "first-super-pass-1"}
    )
    assert login.status_code == 200
    assert login.json()["role"] == "superadmin"
    assert login.json()["tenant_id"] == tenant_id

    org = client.get(
        "/api/org/members",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )
    assert org.status_code == 200
    assert any(row["id"] == super_id and row["role"] == "superadmin" for row in org.json())
