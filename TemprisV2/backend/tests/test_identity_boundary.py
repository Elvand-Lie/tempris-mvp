# backend/tests/test_identity_boundary.py
"""
Persona acceptance tests for the V2 identity boundary between the dedicated
Platform Control tenant (f0000000-0000-4000-8000-000000000001) and the
operational Tempris tenant (11111111-1111-1111-1111-111111111111):

1. Platform admin: /api/platform allowed; tenant modules (/api/assets,
   /api/collectors) AND Organization member management (/api/org/members)
   forbidden — module denial holds even if an entitlement is accidentally
   assigned. GET /api/org/tenant stays reachable as session metadata.
2. Tenant superadmin: Organization member management allowed, /api/platform 403.
3. Tenant admin/analyst: neither Organization member management nor platform APIs.
4. Direct cross-tenant reads remain 404.
5. Platform Control is excluded from the platform tenant list, holds no
   entitlement, and is not targetable by platform repair endpoints.
"""
import pytest

from app.auth import PLATFORM_TENANT_ID, create_test_token
from app.db import get_db_connection

from conftest import PLATFORM_ADMIN_EMAIL, TENANT_A, TENANT_B, ensure_platform_admin_session


def _tenant_headers(actor_id: str, role: str, tenant_id=TENANT_A) -> dict:
    token = create_test_token(str(tenant_id), actor_id=actor_id, role=role)
    return {"Authorization": f"Bearer {token}"}


def _platform_control_entitlement_count() -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(PLATFORM_TENANT_ID),),
            )
            return cur.fetchone()["count"]


# ---------------------------------------------------------------------------
# Persona 1: platform administrator
# ---------------------------------------------------------------------------

def test_platform_admin_can_use_platform_but_not_tenant_modules(client):
    headers = ensure_platform_admin_session()

    platform = client.get("/api/platform/tenants", headers=headers)
    assert platform.status_code == 200

    assets = client.get("/api/assets", headers=headers)
    assert assets.status_code == 403
    assert assets.json()["detail"] == "Platform sessions cannot access tenant modules."

    collectors = client.get("/api/collectors", headers=headers)
    assert collectors.status_code == 403

    # Organization member management is a tenant capability, not a platform one.
    org_members = client.get("/api/org/members", headers=headers)
    assert org_members.status_code == 403
    assert org_members.json()["detail"] == "Platform sessions cannot manage tenant organization members."

    # Session metadata stays reachable: it is how the frontend AuthContext
    # resolves the Platform Control login context.
    metadata = client.get("/api/org/tenant", headers=headers)
    assert metadata.status_code == 200
    assert metadata.json()["id"] == str(PLATFORM_TENANT_ID)
    assert metadata.json()["is_platform_admin"] is True


def test_platform_admin_forbidden_from_tenant_modules_even_with_entitlement(client):
    # Simulate an accidentally assigned entitlement on the Platform Control
    # tenant. The require_module root defense must still deny module access.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version)
                VALUES (%s, 'CORE_ASSETS', '{}'::jsonb, 1)
                ON CONFLICT (tenant_id) DO NOTHING;
                """,
                (str(PLATFORM_TENANT_ID),),
            )
        conn.commit()

    headers = ensure_platform_admin_session()
    assert client.get("/api/assets", headers=headers).status_code == 403
    assert client.get("/api/collectors", headers=headers).status_code == 403


def test_platform_session_denied_every_member_route_with_zero_mutations(client):
    """
    A platform-authority session must be rejected by every Organization member
    route (list/add/update/remove) with 403 and must not mutate a single
    membership or user row, even though its Platform Control membership carries
    the superadmin role.
    """
    headers = ensure_platform_admin_session()

    def _platform_rows():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS count FROM tenant_memberships WHERE tenant_id = %s;",
                    (str(PLATFORM_TENANT_ID),),
                )
                memberships = cur.fetchone()["count"]
                cur.execute(
                    "SELECT COUNT(*) AS count FROM users WHERE LOWER(email) = %s;",
                    ("never-created-org-member@tempris.test",),
                )
                return memberships, cur.fetchone()["count"]

    memberships_before, users_before = _platform_rows()
    assert memberships_before >= 1  # the platform admin's own membership

    # The platform admin's own user id: a tempting PATCH/DELETE target inside
    # the Platform Control tenant. It must never be reachable via org routes.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE LOWER(email) = %s;", (PLATFORM_ADMIN_EMAIL,))
            own_user_id = cur.fetchone()["id"]

    listed = client.get("/api/org/members", headers=headers)
    assert listed.status_code == 403

    added = client.post(
        "/api/org/members",
        headers=headers,
        json={"email": "never-created-org-member@tempris.test", "role": "analyst"},
    )
    assert added.status_code == 403
    assert added.json()["detail"] == "Platform sessions cannot manage tenant organization members."

    updated = client.patch(
        f"/api/org/members/{own_user_id}",
        headers=headers,
        json={"role": "analyst"},
    )
    assert updated.status_code == 403

    removed = client.delete(f"/api/org/members/{own_user_id}", headers=headers)
    assert removed.status_code == 403

    memberships_after, users_after = _platform_rows()
    assert memberships_after == memberships_before
    assert users_after == users_before == 0


# ---------------------------------------------------------------------------
# Persona 2: tenant superadmin
# ---------------------------------------------------------------------------

def test_tenant_superadmin_uses_org_but_not_platform(client):
    headers = _tenant_headers("superadmin-a", "superadmin")

    org = client.get("/api/org/members", headers=headers)
    assert org.status_code == 200

    platform = client.get("/api/platform/tenants", headers=headers)
    assert platform.status_code == 403
    assert platform.json()["detail"] == "Platform administrator authority required."


# ---------------------------------------------------------------------------
# Persona 3: tenant admin / analyst
# ---------------------------------------------------------------------------

# ORG-01 (amended boundary): a Tenant Admin may view the organization's
# members (limited management), an Analyst may not. Neither touches the
# platform plane.
def test_tenant_admin_views_members_but_neither_role_touches_platform(client):
    admin_headers = _tenant_headers("admin-a", "admin")
    assert client.get("/api/org/members", headers=admin_headers).status_code == 200
    assert client.get("/api/platform/tenants", headers=admin_headers).status_code == 403

    analyst_headers = _tenant_headers("analyst-a", "analyst")
    assert client.get("/api/org/members", headers=analyst_headers).status_code == 403
    assert client.get("/api/platform/tenants", headers=analyst_headers).status_code == 403


# ---------------------------------------------------------------------------
# Tenant isolation preserved
# ---------------------------------------------------------------------------

def test_direct_cross_tenant_reads_remain_404(client):
    owner = _tenant_headers("superadmin-b", "superadmin", tenant_id=TENANT_B)
    created = client.post(
        "/api/assets",
        headers=owner,
        json={
            "name": "Boundary Isolation Asset",
            "asset_type": "server",
            "target_type": "domain",
            "target_value": "isolation.example.com",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "medium",
        },
    )
    assert created.status_code == 201
    asset_id = created.json()["id"]

    intruder = _tenant_headers("admin-a", "admin")
    assert client.get(f"/api/assets/{asset_id}", headers=intruder).status_code == 404


# ---------------------------------------------------------------------------
# Platform Control tenant hygiene
# ---------------------------------------------------------------------------

def test_platform_control_excluded_from_list_and_has_no_entitlement(client):
    headers = ensure_platform_admin_session()

    listed = client.get("/api/platform/tenants", headers=headers)
    assert listed.status_code == 200
    ids = {t["id"] for t in listed.json()}
    assert str(PLATFORM_TENANT_ID) not in ids
    # The operational Tempris tenant remains present and administrable.
    assert str(TENANT_A) in ids

    assert _platform_control_entitlement_count() == 0


def test_platform_control_not_targetable_by_repair_endpoints(client):
    headers = ensure_platform_admin_session()
    platform_id = str(PLATFORM_TENANT_ID)

    assert client.get(f"/api/platform/tenants/{platform_id}", headers=headers).status_code == 404
    assert (
        client.patch(
            f"/api/platform/tenants/{platform_id}",
            headers=headers,
            json={"status": "disabled", "expected_version": 1},
        ).status_code
        == 404
    )
    assert (
        client.put(
            f"/api/platform/tenants/{platform_id}/initial-superadmin",
            headers=headers,
            json={"email": "repair@tempris.test"},
        ).status_code
        == 404
    )
    assert client.get(f"/api/platform/tenants/{platform_id}/entitlements", headers=headers).status_code == 404
    assert (
        client.put(
            f"/api/platform/tenants/{platform_id}/entitlements",
            headers=headers,
            json={"package_id": "CORE_ASSETS", "module_overrides": {}, "expected_version": 1},
        ).status_code
        == 404
    )

    # The tenant itself still exists as the platform login context.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT name, slug, status FROM tenants WHERE id = %s;",
                (platform_id,),
            )
            row = cur.fetchone()
            assert row["name"] == "Tempris Platform Control"
            assert row["slug"] == "tempris-platform-control"
            assert row["status"] == "active"
