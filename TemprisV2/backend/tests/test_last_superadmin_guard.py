import uuid

from app.auth import create_test_token
from app.db import get_db_connection


TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _headers():
    token = create_test_token(str(TENANT_B), actor_id="superadmin-b", role="superadmin")
    return {"Authorization": f"Bearer {token}"}


def _user_id(email):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
            return cur.fetchone()["id"]


def test_cannot_demote_or_disable_last_active_superadmin(client):
    user_id = _user_id("superadmin-b")
    for payload in ({"role": "admin"}, {"status": "disabled"}):
        response = client.patch(
            f"/api/org/members/{user_id}", headers=_headers(), json=payload
        )
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "Cannot remove or demote the last active superadmin of an organization"
        )


def test_cannot_delete_last_active_superadmin(client):
    user_id = _user_id("superadmin-b")
    response = client.delete(f"/api/org/members/{user_id}", headers=_headers())
    assert response.status_code == 409


def test_can_demote_superadmin_when_another_active_superadmin_exists(client):
    target_id = _user_id("superadmin-b")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tenant_memberships SET role = 'superadmin'
                WHERE tenant_id = %s AND user_id = (SELECT id FROM users WHERE email = 'admin-b');
                """,
                (str(TENANT_B),),
            )
        conn.commit()

    response = client.patch(
        f"/api/org/members/{target_id}",
        headers=_headers(),
        json={"role": "admin"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "admin"
