import uuid

import pytest

from app.auth import create_test_token
from app.db import get_db_connection


TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _headers(actor="superadmin-a", role="superadmin"):
    token = create_test_token(str(TENANT_A), actor_id=actor, role=role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def restore_admin_b_membership():
    yield
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM tenant_memberships
                WHERE tenant_id = %s AND user_id = (SELECT id FROM users WHERE email = 'admin-b');
                """,
                (str(TENANT_A),),
            )
            cur.execute(
                """
                UPDATE tenant_memberships SET status = 'active'
                WHERE tenant_id = %s AND user_id = (SELECT id FROM users WHERE email = 'admin-b');
                """,
                (str(TENANT_B),),
            )
        conn.commit()


def test_org_tenant_returns_server_derived_platform_flag_and_modules(client):
    response = client.get("/api/org/tenant", headers=_headers())
    assert response.status_code == 200
    assert response.json()["id"] == str(TENANT_A)
    assert response.json()["effective_modules"] == [
        "ASSETS", "EDIP", "SPEAK", "SPECTRUM", "SPOTLIGHT", "STANDARD",
        "STRIKE", "SYNTHESIS",
    ]
    assert response.json()["is_platform_admin"] is False

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_platform_admin = TRUE WHERE email = 'superadmin-a';")
        conn.commit()

    response = client.get("/api/org/tenant", headers=_headers())
    assert response.status_code == 200
    assert response.json()["is_platform_admin"] is True


def test_org_tenant_metadata_allows_every_authenticated_role(client):
    for actor, role in (("admin-a", "admin"), ("analyst-a", "analyst")):
        response = client.get("/api/org/tenant", headers=_headers(actor, role))
        assert response.status_code == 200
        assert response.json()["id"] == str(TENANT_A)


def test_org_member_endpoints_allow_admin_but_not_analyst(client):
    response = client.get("/api/org/members", headers=_headers("admin-a", "admin"))
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    response = client.get("/api/org/members", headers=_headers("analyst-a", "analyst"))
    assert response.status_code == 403

    response = client.post(
        "/api/org/members",
        headers=_headers("analyst-a", "analyst"),
        json={"email": "analyst-invite-blocked@test.example", "role": "analyst"},
    )
    assert response.status_code == 403

    response = client.post(
        "/api/org/users/00000000-0000-0000-0000-000000000000/activate",
        headers=_headers("analyst-a", "analyst"),
        json={"initial_password": "whatever-1"},
    )
    assert response.status_code == 403


def test_admin_invites_and_manages_ordinary_members_only(client):
    admin = _headers("admin-a", "admin")

    # Tenant Admin may invite ordinary users (analyst/admin)...
    response = client.post(
        "/api/org/members", headers=admin,
        json={"email": "Ordinary.User@Org02.Test", "role": "analyst"},
    )
    assert response.status_code == 201
    user_id = response.json()["id"]
    assert response.json()["status"] == "pending"

    # ...but never create a Superadmin membership.
    response = client.post(
        "/api/org/members", headers=admin,
        json={"email": "would.be.super@Org02.Test", "role": "superadmin"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Tenant Admins cannot create or modify Superadmin memberships"
    )

    # Superadmin activates the invited account so the membership is in force.
    activated = client.post(
        f"/api/org/users/{user_id}/activate", headers=_headers(),
        json={"initial_password": "org02-pass-1"},
    )
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"
    assert activated.json()["membership"] == {"role": "analyst", "status": "active"}

    # Tenant Admin manages ordinary members: role analyst<->admin and disable.
    response = client.patch(
        f"/api/org/members/{user_id}", headers=admin, json={"role": "admin"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "admin"

    response = client.patch(
        f"/api/org/members/{user_id}", headers=admin, json={"status": "disabled"}
    )
    assert response.status_code == 200
    assert response.json()["membership_status"] == "disabled"

    # Re-enabling is allowed: the account itself is active.
    response = client.patch(
        f"/api/org/members/{user_id}", headers=admin, json={"status": "active"}
    )
    assert response.status_code == 200
    assert response.json()["membership_status"] == "active"

    # ...but removal stays a Superadmin authority.
    response = client.delete(f"/api/org/members/{user_id}", headers=admin)
    assert response.status_code == 403

    # ...and activation of pending accounts is not a Tenant Admin action.
    response = client.post(
        "/api/org/members", headers=admin,
        json={"email": "Second.Pending@Org02.Test", "role": "analyst"},
    )
    assert response.status_code == 201
    second_id = response.json()["id"]
    response = client.post(
        f"/api/org/users/{second_id}/activate", headers=admin,
        json={"initial_password": "org02-pass-2"},
    )
    assert response.status_code == 403


def test_admin_cannot_modify_superadmin_memberships_or_promote_into_superadmin(client):
    admin = _headers("admin-a", "admin")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = 'super-1';")
            super_id = cur.fetchone()["id"]
            cur.execute("SELECT id FROM users WHERE email = 'admin-a';")
            admin_id = cur.fetchone()["id"]

    # Never edit a Superadmin membership...
    response = client.patch(
        f"/api/org/members/{super_id}", headers=admin, json={"role": "admin"}
    )
    assert response.status_code == 403
    response = client.patch(
        f"/api/org/members/{super_id}", headers=admin, json={"status": "disabled"}
    )
    assert response.status_code == 403

    # ...and never promote anyone into Superadmin.
    response = client.patch(
        f"/api/org/members/{admin_id}", headers=admin, json={"role": "superadmin"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Tenant Admins cannot create or modify Superadmin memberships"
    )

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role, status FROM tenant_memberships WHERE tenant_id = %s AND user_id = %s;",
                (str(TENANT_A), str(super_id)),
            )
            assert cur.fetchone() == {"role": "superadmin", "status": "active"}


def test_superadmin_activation_enable_guard_and_audit(client):
    # A never-activated account still cannot have its membership enabled
    # directly; it must go through the activation endpoint.
    response = client.post(
        "/api/org/members", headers=_headers(),
        json={"email": "Enable.Guard@Org02.Test", "role": "analyst"},
    )
    assert response.status_code == 201
    user_id = response.json()["id"]

    response = client.patch(
        f"/api/org/members/{user_id}", headers=_headers(), json={"status": "active"}
    )
    assert response.status_code == 409
    assert response.json()["detail"] == (
        "User account is not active. A Superadmin must activate the account "
        "before its membership can be enabled"
    )

    # Superadmin activation: account + membership become active atomically.
    response = client.post(
        f"/api/org/users/{user_id}/activate", headers=_headers(),
        json={"initial_password": "org02-activate-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "enable.guard@org02.test"
    assert body["status"] == "active"
    assert body["membership"] == {"role": "analyst", "status": "active"}

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, password_hash IS NOT NULL AS has_hash FROM users WHERE id = %s;",
                (user_id,),
            )
            assert cur.fetchone() == {"status": "active", "has_hash": True}
            cur.execute(
                """
                SELECT event_name FROM audit_events
                WHERE tenant_id = %s AND details->>'user_id' = %s
                ORDER BY created_at;
                """,
                (str(TENANT_A), user_id),
            )
            assert [row["event_name"] for row in cur.fetchall()] == [
                "org.member_added",
                "org.user_activated",
            ]

    # A second activation attempt fails: no pending invitation remains.
    response = client.post(
        f"/api/org/users/{user_id}/activate", headers=_headers(),
        json={"initial_password": "org02-activate-2"},
    )
    assert response.status_code == 404


def test_superadmin_activation_is_tenant_scoped_and_state_gated(client):
    # admin-b belongs to TENANT_B only — nothing pending in TENANT_A.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = 'admin-b';")
            admin_b_id = cur.fetchone()["id"]

    response = client.post(
        f"/api/org/users/{admin_b_id}/activate", headers=_headers(),
        json={"initial_password": "org02-cross-1"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Pending organization member not found in this tenant"

    # A disabled account with an outstanding invitation is not activatable by
    # a tenant Superadmin. (The account carries a password hash: the users
    # check constraint only permits disabled state for once-active accounts.)
    response = client.post(
        "/api/org/members", headers=_headers(),
        json={"email": "Disabled.Acct@Org02.Test", "role": "analyst"},
    )
    assert response.status_code == 201
    disabled_id = response.json()["id"]
    from tests.conftest import TEST_PASSWORD_HASH

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET status = 'disabled', password_hash = %s WHERE id = %s;",
                (TEST_PASSWORD_HASH, disabled_id),
            )
        conn.commit()

    response = client.post(
        f"/api/org/users/{disabled_id}/activate", headers=_headers(),
        json={"initial_password": "org02-cross-2"},
    )
    assert response.status_code == 409
    assert "not pending" in response.json()["detail"]

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM users WHERE id = %s;", (disabled_id,))
            assert cur.fetchone()["status"] == "disabled"


def test_add_new_pending_member_list_update_delete_and_audit(client):
    response = client.post(
        "/api/org/members",
        headers=_headers(),
        json={"email": "New.Member@Ticket04.Test", "role": "analyst"},
    )
    assert response.status_code == 201
    user_id = response.json()["id"]

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status, password_hash FROM users WHERE id = %s;", (user_id,))
            assert cur.fetchone() == {"status": "pending", "password_hash": None}

    listed = client.get("/api/org/members", headers=_headers())
    assert listed.status_code == 200
    assert any(row["id"] == user_id and row["role"] == "analyst" for row in listed.json())

    # ORG-01: the tenant Superadmin shapes the membership's role, and the
    # invitation stays pending — the account was never activated.
    updated = client.patch(
        f"/api/org/members/{user_id}",
        headers=_headers(),
        json={"role": "admin"},
    )
    assert updated.status_code == 200
    assert updated.json()["role"] == "admin"
    assert updated.json()["membership_status"] == "pending"

    # ORG-01: enabling the membership is not account activation. The account is
    # still pending, so the membership cannot be enabled before the Superadmin
    # activates the account (POST /api/org/users/{id}/activate).
    enable_rejected = client.patch(
        f"/api/org/members/{user_id}",
        headers=_headers(),
        json={"status": "active"},
    )
    assert enable_rejected.status_code == 409
    assert enable_rejected.json()["detail"] == (
        "User account is not active. A Superadmin must activate the account "
        "before its membership can be enabled"
    )

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM tenant_memberships WHERE user_id = %s;",
                (user_id,),
            )
            assert cur.fetchone()["status"] == "pending"

    removed = client.delete(f"/api/org/members/{user_id}", headers=_headers())
    assert removed.status_code == 204

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_memberships WHERE user_id = %s;",
                (user_id,),
            )
            assert cur.fetchone()["count"] == 0
            cur.execute(
                """
                SELECT event_name FROM audit_events
                WHERE tenant_id = %s AND details->>'user_id' = %s
                ORDER BY created_at;
                """,
                (str(TENANT_A), user_id),
            )
            assert [row["event_name"] for row in cur.fetchall()] == [
                "org.member_added",
                "org.member_updated",
                "org.member_removed",
            ]


def test_add_member_rejects_user_with_active_membership_in_other_tenant(client):
    response = client.post(
        "/api/org/members",
        headers=_headers(),
        json={"email": "admin-b", "role": "admin"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "User already has an active organization membership"


def test_add_member_reuses_user_with_only_disabled_membership(client):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tenant_memberships SET status = 'disabled'
                WHERE user_id = (SELECT id FROM users WHERE email = 'admin-b');
                """
            )
        conn.commit()

    response = client.post(
        "/api/org/members",
        headers=_headers(),
        json={"email": "admin-b", "role": "analyst"},
    )
    assert response.status_code == 201
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tenant_id, role, status FROM tenant_memberships
                WHERE user_id = (SELECT id FROM users WHERE email = 'admin-b') AND status = 'active';
                """
            )
            membership = cur.fetchone()
    assert membership["tenant_id"] == TENANT_A
    assert membership["role"] == "analyst"


def test_reactivate_disabled_membership_conflict_returns_409_and_preserves_rows(client):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = 'admin-b';")
            user_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, 'analyst', 'disabled');
                """,
                (str(TENANT_A), str(user_id)),
            )
        conn.commit()

    response = client.patch(
        f"/api/org/members/{user_id}",
        headers=_headers(),
        json={"status": "active"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "User already has an active organization membership"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tenant_id, role, status FROM tenant_memberships
                WHERE user_id = %s ORDER BY tenant_id;
                """,
                (str(user_id),),
            )
            assert cur.fetchall() == [
                {"tenant_id": TENANT_A, "role": "analyst", "status": "disabled"},
                {"tenant_id": TENANT_B, "role": "admin", "status": "active"},
            ]


def test_org_member_lookup_is_tenant_scoped(client):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = 'admin-b';")
            user_id = cur.fetchone()["id"]

    response = client.patch(
        f"/api/org/members/{user_id}",
        headers=_headers(),
        json={"role": "analyst"},
    )
    assert response.status_code == 404

    response = client.delete(f"/api/org/members/{user_id}", headers=_headers())
    assert response.status_code == 404

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role, status FROM tenant_memberships WHERE tenant_id = %s AND user_id = %s;",
                (str(TENANT_B), str(user_id)),
            )
            assert cur.fetchone() == {"role": "admin", "status": "active"}
