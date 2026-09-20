import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier
from unittest.mock import AsyncMock

import jwt
import pytest

from app.auth import PLATFORM_TENANT_ID, create_test_token
from app.config import JWT_SECRET
from app.db import get_db_connection
from app.routes import platform as platform_routes

from conftest import PLATFORM_ADMIN_EMAIL, ensure_platform_admin_session


TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _platform_headers():
    return ensure_platform_admin_session()


def _create_ownerless_tenant(slug="ticket04-ownerless"):
    tenant_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (id, name, slug, status, version)
                VALUES (%s, 'Ticket 04 Ownerless', %s, 'active', 1);
                """,
                (str(tenant_id), f"{slug}-{tenant_id}"),
            )
            cur.execute(
                """
                INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version)
                VALUES (%s, 'CORE_ASSETS', '{}'::jsonb, 1);
                """,
                (str(tenant_id),),
            )
        conn.commit()
    return tenant_id


@pytest.fixture(autouse=True)
def clean_ticket04_platform_rows():
    yield
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM audit_events
                WHERE details->>'target_tenant_id' IN (
                    SELECT id::text FROM tenants WHERE slug LIKE 'ticket04-%'
                )
                OR tenant_id IN (
                    SELECT id FROM tenants WHERE slug LIKE 'ticket04-%'
                );
                """
            )
            cur.execute(
                """
                DELETE FROM tenant_memberships
                WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'ticket04-%');
                """
            )
            cur.execute(
                "DELETE FROM tenant_entitlements WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'ticket04-%');"
            )
            cur.execute("DELETE FROM tenants WHERE slug LIKE 'ticket04-%';")
            cur.execute("DELETE FROM users WHERE email LIKE '%@ticket04.test';")
        conn.commit()


def test_platform_routes_require_server_verified_platform_admin(client):
    # Provision a superadmin membership in the Platform Control tenant, then
    # strip the is_platform_admin flag: the session stays valid but lacks
    # server-verified platform authority, so platform routes must 403.
    ensure_platform_admin_session()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET is_platform_admin = FALSE WHERE LOWER(email) = %s;",
                (PLATFORM_ADMIN_EMAIL,),
            )
        conn.commit()
    token = create_test_token(str(PLATFORM_TENANT_ID), actor_id=PLATFORM_ADMIN_EMAIL, role="superadmin")
    response = client.get(
        "/api/platform/tenants", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


def test_create_tenant_is_atomic_and_audited(client):
    email = "initial.owner@ticket04.test"
    response = client.post(
        "/api/platform/tenants",
        headers=_platform_headers(),
        json={
            "name": "Ticket 04 Tenant",
            "slug": "ticket04-created",
            "initial_superadmin_email": email,
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert response.status_code == 201
    tenant_id = response.json()["id"]

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.status AS user_status, u.password_hash, m.role, m.status AS membership_status,
                       te.package_id, te.version
                FROM users u
                JOIN tenant_memberships m ON m.user_id = u.id
                JOIN tenant_entitlements te ON te.tenant_id = m.tenant_id
                WHERE u.email = %s AND m.tenant_id = %s;
                """,
                (email, tenant_id),
            )
            row = cur.fetchone()
            assert row == {
                "user_status": "pending",
                "password_hash": None,
                "role": "superadmin",
                "membership_status": "active",
                "package_id": "CORE_ASSETS",
                "version": 1,
            }
            cur.execute(
                """
                SELECT tenant_id, actor_role FROM audit_events
                WHERE event_name = 'platform.tenant_created'
                  AND details->>'target_tenant_id' = %s;
                """,
                (tenant_id,),
            )
            audit = cur.fetchone()
            assert audit["tenant_id"] == PLATFORM_TENANT_ID
            assert audit["actor_role"] == "platform_admin"


def test_tenant_create_generates_unique_slugs_from_name(client):
    headers = _platform_headers()
    first = client.post(
        "/api/platform/tenants",
        headers=headers,
        json={
            "name": "Ticket04 Auto Slug",
            "initial_superadmin_email": "auto-slug-one@ticket04.test",
            "base_package_id": "CORE_ASSETS",
        },
    )
    second = client.post(
        "/api/platform/tenants",
        headers=headers,
        json={
            "name": "Ticket04 Auto Slug",
            "initial_superadmin_email": "auto-slug-two@ticket04.test",
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["slug"] == "ticket04-auto-slug"
    assert second.json()["slug"] == "ticket04-auto-slug-2"


def test_tenant_create_rolls_back_new_user_when_slug_conflicts(client):
    email = "rollback.owner@ticket04.test"
    response = client.post(
        "/api/platform/tenants",
        headers=_platform_headers(),
        json={
            "name": "Will Roll Back",
            "slug": "tenant-b",
            "initial_superadmin_email": email,
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Tenant slug already exists"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE email = %s;", (email,))
            assert cur.fetchone() is None


def test_concurrent_distinct_slug_same_email_classifies_email_conflict_and_rolls_back(client, monkeypatch):
    headers = _platform_headers()
    race_id = uuid.uuid4().hex
    email = f"concurrent-{race_id}@ticket04.test"
    slugs = [f"ticket04-race-a-{race_id}", f"ticket04-race-b-{race_id}"]
    barrier = Barrier(2)
    real_get_db_connection = platform_routes.get_db_connection

    class BarrierCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def __enter__(self):
            self.cursor.__enter__()
            return self

        def __exit__(self, *args):
            return self.cursor.__exit__(*args)

        def execute(self, query, params=None, **kwargs):
            if "INSERT INTO users" in str(query):
                barrier.wait(timeout=10)
            return self.cursor.execute(query, params, **kwargs)

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class BarrierConnection:
        def __init__(self, conn):
            self.conn = conn

        def cursor(self, *args, **kwargs):
            return BarrierCursor(self.conn.cursor(*args, **kwargs))

        def __getattr__(self, name):
            return getattr(self.conn, name)

    @contextmanager
    def synchronized_connections():
        with real_get_db_connection() as conn:
            yield BarrierConnection(conn)

    monkeypatch.setattr(platform_routes, "get_db_connection", synchronized_connections)

    def create(slug):
        return client.post(
            "/api/platform/tenants",
            headers=headers,
            json={
                "name": f"Concurrent {slug}",
                "slug": slug,
                "initial_superadmin_email": email,
                "base_package_id": "CORE_ASSETS",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(create, slugs))

    assert sorted(response.status_code for response in responses) == [201, 409]
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["detail"] == "User already has an active organization membership"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
            user_id = cur.fetchone()["id"]
            cur.execute("SELECT id FROM tenants WHERE slug = ANY(%s);", (slugs,))
            tenants = cur.fetchall()
            assert len(tenants) == 1
            cur.execute("SELECT COUNT(*) AS count FROM tenant_memberships WHERE user_id = %s;", (str(user_id),))
            assert cur.fetchone()["count"] == 1
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(tenants[0]["id"]),),
            )
            assert cur.fetchone()["count"] == 1


def test_tenant_create_rejects_active_membership_collision(client):
    response = client.post(
        "/api/platform/tenants",
        headers=_platform_headers(),
        json={
            "name": "Collision",
            "slug": "ticket04-collision",
            "initial_superadmin_email": "admin-b",
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "User already has an active organization membership"


def test_disable_tenant_uses_occ_and_awaits_session_termination(client, monkeypatch):
    tenant_id = _create_ownerless_tenant("ticket04-disable")
    terminate = AsyncMock(return_value=[])
    monkeypatch.setattr(platform_routes.collector_registry, "terminate_tenant_sessions", terminate)

    response = client.patch(
        f"/api/platform/tenants/{tenant_id}",
        headers=_platform_headers(),
        json={"status": "disabled", "expected_version": 1},
    )
    assert response.status_code == 200
    assert response.json()["version"] == 2
    terminate.assert_awaited_once_with(tenant_id, close_code=1008, reason="Tenant disabled")

    stale = client.patch(
        f"/api/platform/tenants/{tenant_id}",
        headers=_platform_headers(),
        json={"name": "Stale", "expected_version": 1},
    )
    assert stale.status_code == 409


def test_initial_superadmin_repair_gate_and_active_membership_collision(client):
    headers = _platform_headers()
    tenant_id = _create_ownerless_tenant("ticket04-repair")
    response = client.put(
        f"/api/platform/tenants/{tenant_id}/initial-superadmin",
        headers=headers,
        json={"email": "repair.owner@ticket04.test"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "superadmin"

    again = client.put(
        f"/api/platform/tenants/{tenant_id}/initial-superadmin",
        headers=headers,
        json={"email": "another.owner@ticket04.test"},
    )
    assert again.status_code == 409
    assert again.json()["detail"] == "Tenant already has an active superadmin"

    collision_tenant = _create_ownerless_tenant("ticket04-repair-collision")
    collision = client.put(
        f"/api/platform/tenants/{collision_tenant}/initial-superadmin",
        headers=headers,
        json={"email": "admin-b"},
    )
    assert collision.status_code == 409
    assert collision.json()["detail"] == "User already has an active organization membership"


@pytest.mark.parametrize(
    "overrides,detail",
    [
        ({"UNKNOWN": True}, "Unknown module 'UNKNOWN' in overrides"),
        ({"ASSETS": "true"}, "Override value for module 'ASSETS' must be a strict boolean"),
        ({"ASSETS": 1}, "Override value for module 'ASSETS' must be a strict boolean"),
        ({"ASSETS": None}, "Override value for module 'ASSETS' must be a strict boolean"),
        ([], "module_overrides must be a JSON object"),
    ],
)
def test_entitlement_override_validation_is_strict(client, overrides, detail):
    response = client.put(
        f"/api/platform/tenants/{TENANT_B}/entitlements",
        headers=_platform_headers(),
        json={
            "package_id": "CORE_ASSETS",
            "module_overrides": overrides,
            "expected_version": 1,
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == detail


def test_entitlement_occ_and_valid_update(client):
    headers = _platform_headers()
    stale = client.put(
        f"/api/platform/tenants/{TENANT_B}/entitlements",
        headers=headers,
        json={
            "package_id": "CORE_ASSETS",
            "module_overrides": {},
            "expected_version": 99,
        },
    )
    assert stale.status_code == 409

    response = client.put(
        f"/api/platform/tenants/{TENANT_B}/entitlements",
        headers=headers,
        json={
            "package_id": "CORE_ASSETS",
            "module_overrides": {"ASSETS": False},
            "expected_version": 1,
        },
    )
    assert response.status_code == 200
    assert response.json()["module_overrides"] == {"ASSETS": False}
    assert response.json()["version"] == 2
    assert response.json()["updated_by"] is not None


def test_pending_user_list_activation_and_login_preserve_five_claim_jwt(client):
    email = "activate.owner@ticket04.test"
    password = "activated-password-2026"
    created = client.post(
        "/api/platform/tenants",
        headers=_platform_headers(),
        json={
            "name": "Activation Tenant",
            "slug": "ticket04-activation",
            "initial_superadmin_email": email,
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert created.status_code == 201
    user_id = created.json()["initial_superadmin"]["id"]

    pending = client.get("/api/platform/users/pending", headers=_platform_headers())
    assert pending.status_code == 200
    assert any(user["id"] == user_id for user in pending.json())

    activated = client.post(
        f"/api/platform/users/{user_id}/activate",
        headers=_platform_headers(),
        json={"initial_password": password},
    )
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"

    login = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    claims = jwt.decode(login.json()["token"], JWT_SECRET, algorithms=["HS256"])
    assert set(claims) == {"sub", "tenant_id", "role", "iat", "exp", "jti", "email"}
    assert "is_platform_admin" not in claims


def test_tenant_list_excludes_platform_control_tenant(client):
    response = client.get("/api/platform/tenants", headers=_platform_headers())
    assert response.status_code == 200
    ids = {t["id"] for t in response.json()}
    assert str(PLATFORM_TENANT_ID) not in ids
    # Operational tenants (incl. Tempris 11111111-1111-1111-1111-111111111111) stay administrable.
    assert "11111111-1111-1111-1111-111111111111" in ids


def test_tenant_list_returns_active_superadmin_count(client):
    headers = _platform_headers()
    tenant_id = _create_ownerless_tenant("ticket04-sa-count")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for i, role in enumerate(["analyst", "admin"]):
                user_id = uuid.uuid4()
                cur.execute(
                    "INSERT INTO users (id, email, status, password_hash) VALUES (%s, %s, 'active', %s);",
                    (str(user_id), f"member-{role}-{i}@ticket04.test", "scrypt$16384$8$1$688dbe89a4ffcfe6457beeaf5503ef0a$8329a7eb365132ada7161ce8af1875b7f50a9b442ea5709849f0be7f00b5391f"),
                )
                cur.execute(
                    "INSERT INTO tenant_memberships (tenant_id, user_id, role, status) VALUES (%s, %s, %s, 'active');",
                    (str(tenant_id), str(user_id), role),
                )
        conn.commit()

    response = client.get("/api/platform/tenants", headers=headers)
    assert response.status_code == 200
    tenant = next(t for t in response.json() if t["id"] == str(tenant_id))
    assert tenant["member_count"] == 2
    assert tenant["active_superadmin_count"] == 0


def test_pending_users_include_organization_name_and_role(client):
    headers = _platform_headers()
    created = client.post(
        "/api/platform/tenants",
        headers=headers,
        json={
            "name": "Pending Org Tenant",
            "slug": "ticket04-pending-org",
            "initial_superadmin_email": "pending-org@ticket04.test",
            "base_package_id": "CORE_ASSETS",
        },
    )
    assert created.status_code == 201

    response = client.get("/api/platform/users/pending", headers=headers)
    assert response.status_code == 200
    user = next(u for u in response.json() if u["email"] == "pending-org@ticket04.test")
    assert user["organization_name"] == "Pending Org Tenant"
    assert user["organization_role"] == "superadmin"
