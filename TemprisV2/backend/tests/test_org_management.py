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


def test_org_member_endpoints_require_superadmin(client):
    for actor, role in (("admin-a", "admin"), ("analyst-a", "analyst")):
        response = client.get("/api/org/members", headers=_headers(actor, role))
        assert response.status_code == 403


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

    updated = client.patch(
        f"/api/org/members/{user_id}",
        headers=_headers(),
        json={"role": "admin", "status": "active"},
    )
    assert updated.status_code == 200
    assert updated.json()["role"] == "admin"

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
