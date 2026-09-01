# backend/tests/test_tenant_isolation.py
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_cross_tenant_isolation(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_b_admin
):
    # 1. Tenant A creates an asset
    create_resp = client.post(
        "/api/assets",
        json={
            "name": "Tenant A Secret Database",
            "asset_type": "database",
            "target_type": "ip",
            "target_value": "192.168.100.50",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "critical"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert create_resp.status_code == 201
    asset_a = create_resp.json()
    asset_a_id = asset_a["id"]

    # 2. Tenant B lists assets - must not see Tenant A's asset
    list_b = client.get("/api/assets", headers=auth_headers_tenant_b_admin)
    assert list_b.status_code == 200
    assert len(list_b.json()) == 0

    # 3. Tenant B directly requests Tenant A's asset by ID - must return 404
    get_b = client.get(f"/api/assets/{asset_a_id}", headers=auth_headers_tenant_b_admin)
    assert get_b.status_code == 404

    # 4. Tenant B attempts to mutate Tenant A's asset - must return 404
    put_b = client.put(
        f"/api/assets/{asset_a_id}",
        json={"name": "Hijacked Asset"},
        headers=auth_headers_tenant_b_admin
    )
    assert put_b.status_code == 404

    # 5. Tenant B attempts to decommission Tenant A's asset - must return 404
    decom_b = client.post(
        f"/api/assets/{asset_a_id}/decommission",
        headers=auth_headers_tenant_b_admin
    )
    assert decom_b.status_code == 404

    # 6. Tenant B creates an asset with the EXACT same normalized target (192.168.100.50) - must succeed (tenant-scoped uniqueness)
    create_b_resp = client.post(
        "/api/assets",
        json={
            "name": "Tenant B Independent Asset",
            "asset_type": "database",
            "target_type": "ip",
            "target_value": "192.168.100.50",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "medium"
        },
        headers=auth_headers_tenant_b_admin
    )
    assert create_b_resp.status_code == 201
    assert create_b_resp.json()["id"] != asset_a_id

    # 7. Verify audit events are strictly tenant-isolated in DB
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT tenant_id FROM audit_events WHERE asset_id = %s;", (asset_a_id,))
            rows = cur.fetchall()
            for r in rows:
                assert str(r["tenant_id"]) == "11111111-1111-1111-1111-111111111111"

def test_collector_cross_tenant_isolation(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_b_admin
):
    # 1. Tenant A creates collector
    col_a_resp = client.post(
        "/api/collectors",
        json={"name": "Tenant A Secret Collector"},
        headers=auth_headers_tenant_a_admin
    )
    assert col_a_resp.status_code == 201
    col_a_id = col_a_resp.json()["id"]

    # 2. Tenant B listing collectors does not see Tenant A collector
    list_b = client.get("/api/collectors", headers=auth_headers_tenant_b_admin)
    assert list_b.status_code == 200
    assert len(list_b.json()) == 0

    # 3. Tenant B getting Tenant A collector by ID returns 404
    get_b = client.get(f"/api/collectors/{col_a_id}", headers=auth_headers_tenant_b_admin)
    assert get_b.status_code == 404

