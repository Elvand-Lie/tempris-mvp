# backend/tests/test_collector_routing.py
import uuid
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_collector_creation_and_routing_invariants(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst,
    auth_headers_tenant_b_admin
):
    # 1. Admin creates a collector profile for Tenant A
    create_col_resp = client.post(
        "/api/collectors",
        json={"name": "HQ Edge Collector 01", "description": "DMZ internal collector"},
        headers=auth_headers_tenant_a_admin
    )
    assert create_col_resp.status_code == 201
    col_a = create_col_resp.json()
    col_a_id = col_a["id"]
    assert col_a["name"] == "HQ Edge Collector 01"
    assert col_a["enrollment_status"] == "awaiting_enrollment"
    assert col_a["operator_status"] == "active"
    assert "enrollment_code" in col_a
    assert col_a["enrollment_code"].startswith("col_enc_")
    assert col_a["enrollment_code_expires_at"] is not None

    # 2. Analyst can list and get collector details
    list_resp = client.get("/api/collectors", headers=auth_headers_tenant_a_analyst)
    assert list_resp.status_code == 200
    collectors = list_resp.json()
    assert len(collectors) == 1
    assert collectors[0]["id"] == col_a_id

    get_resp = client.get(f"/api/collectors/{col_a_id}", headers=auth_headers_tenant_a_analyst)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == col_a_id

    # 3. Create internal asset assigned to valid Tenant A collector
    create_asset_resp = client.post(
        "/api/assets",
        json={
            "name": "Internal DB via Collector",
            "asset_type": "database",
            "target_type": "ip",
            "target_value": "10.200.1.5",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high",
            "collector_id": col_a_id
        },
        headers=auth_headers_tenant_a_admin
    )
    assert create_asset_resp.status_code == 201
    asset_data = create_asset_resp.json()
    asset_id = asset_data["id"]
    assert asset_data["collector_id"] == col_a_id
    assert asset_data["reachability_status"] == "unverified"

    # 4. Foreign tenant collector assignment fails closed with 404 (zero existence disclosure)
    create_col_b_resp = client.post(
        "/api/collectors",
        json={"name": "Tenant B Collector", "description": "Private to B"},
        headers=auth_headers_tenant_b_admin
    )
    assert create_col_b_resp.status_code == 201
    col_b_id = create_col_b_resp.json()["id"]

    # Tenant A attempts to create asset referencing Tenant B collector
    foreign_create_resp = client.post(
        "/api/assets",
        json={
            "name": "Asset with Foreign Collector",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.200.1.6",
            "network_scope": "internal",
            "environment": "development",
            "criticality": "low",
            "collector_id": col_b_id
        },
        headers=auth_headers_tenant_a_admin
    )
    assert foreign_create_resp.status_code == 404
    assert foreign_create_resp.json()["detail"] == "Collector not found"

    # Tenant A attempts to update existing asset referencing Tenant B collector
    foreign_update_resp = client.put(
        f"/api/assets/{asset_id}",
        json={"collector_id": col_b_id},
        headers=auth_headers_tenant_a_admin
    )
    assert foreign_update_resp.status_code == 404
    assert foreign_update_resp.json()["detail"] == "Collector not found"

    # 5. Non-existent collector ID returns 404
    random_col_id = str(uuid.uuid4())
    non_existent_create_resp = client.post(
        "/api/assets",
        json={
            "name": "Asset with Random Collector",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.200.1.7",
            "network_scope": "internal",
            "environment": "development",
            "criticality": "low",
            "collector_id": random_col_id
        },
        headers=auth_headers_tenant_a_admin
    )
    assert non_existent_create_resp.status_code == 404

    # 6. Revoked collector returns 404 on assignment
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE collectors SET operator_status = 'revoked' WHERE id = %s;",
                (col_a_id,)
            )
        conn.commit()

    revoked_create_resp = client.post(
        "/api/assets",
        json={
            "name": "Asset with Revoked Collector",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.200.1.8",
            "network_scope": "internal",
            "environment": "development",
            "criticality": "low",
            "collector_id": col_a_id
        },
        headers=auth_headers_tenant_a_admin
    )
    assert revoked_create_resp.status_code == 404
    assert revoked_create_resp.json()["detail"] == "Collector not found"

    revoked_update_resp = client.put(
        f"/api/assets/{asset_id}",
        json={"collector_id": col_a_id},
        headers=auth_headers_tenant_a_admin
    )
    assert revoked_update_resp.status_code == 404
    assert revoked_update_resp.json()["detail"] == "Collector not found"

    # 7. Unlink collector from asset (set to None)
    unlink_resp = client.put(
        f"/api/assets/{asset_id}",
        json={"collector_id": None},
        headers=auth_headers_tenant_a_admin
    )
    assert unlink_resp.status_code == 200
    assert unlink_resp.json()["collector_id"] is None
