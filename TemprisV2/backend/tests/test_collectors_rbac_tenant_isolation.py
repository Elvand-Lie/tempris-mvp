# backend/tests/test_collectors_rbac_tenant_isolation.py
import uuid
import pytest
from starlette.testclient import TestClient
from app.auth import create_test_token

def test_collectors_cross_tenant_isolation(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_b_admin
):
    # 1. Tenant A creates a collector
    create_resp = client.post(
        "/api/collectors",
        json={"name": "Tenant A Secure Collector", "description": "Classified to A"},
        headers=auth_headers_tenant_a_admin
    )
    assert create_resp.status_code == 201
    col_a_id = create_resp.json()["id"]

    # 2. Tenant B lists collectors -> Tenant A's collector is not returned
    b_list = client.get("/api/collectors", headers=auth_headers_tenant_b_admin)
    assert b_list.status_code == 200
    assert not any(c["id"] == col_a_id for c in b_list.json())

    # 3. Tenant B attempts to get Tenant A's collector -> 404 (zero existence disclosure)
    b_get = client.get(f"/api/collectors/{col_a_id}", headers=auth_headers_tenant_b_admin)
    assert b_get.status_code == 404
    assert b_get.json()["detail"] == "Collector not found"

    # 4. Tenant B attempts lifecycle mutations on Tenant A's collector -> 404
    for action in ["pause", "resume", "quarantine", "release", "revoke"]:
        b_action = client.post(f"/api/collectors/{col_a_id}/{action}", headers=auth_headers_tenant_b_admin)
        assert b_action.status_code == 404
        assert b_action.json()["detail"] == "Collector not found"


def test_collectors_rbac_roles(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst
):
    # Superadmin can create collector
    tenant_id = "11111111-1111-1111-1111-111111111111"
    superadmin_token = create_test_token(tenant_id=tenant_id, actor_id="super-1", role="superadmin")
    superadmin_headers = {"Authorization": f"Bearer {superadmin_token}"}

    sa_create = client.post(
        "/api/collectors",
        json={"name": "Superadmin Created Collector"},
        headers=superadmin_headers
    )
    assert sa_create.status_code == 201
    col_id = sa_create.json()["id"]

    # Superadmin can pause collector
    sa_pause = client.post(f"/api/collectors/{col_id}/pause", headers=superadmin_headers)
    assert sa_pause.status_code == 200

    # Analyst role receives 403 on create and lifecycle mutations
    analyst_token = create_test_token(tenant_id=tenant_id, actor_id="analyst-1", role="analyst")
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    analyst_create = client.post("/api/collectors", json={"name": "Analyst Collector"}, headers=analyst_headers)
    assert analyst_create.status_code == 403

    analyst_pause = client.post(f"/api/collectors/{col_id}/pause", headers=analyst_headers)
    assert analyst_pause.status_code == 403

    # Invalid/unauthorized role receives 401
    invalid_role_token = create_test_token(tenant_id=tenant_id, actor_id="unknown-1", role="unknown_role")
    inv_headers = {"Authorization": f"Bearer {invalid_role_token}"}
    inv_create = client.post("/api/collectors", json={"name": "Invalid Role Collector"}, headers=inv_headers)
    assert inv_create.status_code == 401
