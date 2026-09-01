# backend/tests/test_verification_persistence.py
import uuid
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_internet_asset_verification_persistence_on_create(client: TestClient, auth_headers_tenant_a_admin):
    # Create an internet asset (e.g. 1.1.1.1 or 8.8.8.8 which are public and reachable)
    resp = client.post(
        "/api/assets",
        json={
            "name": "Cloudflare DNS",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "1.1.1.1",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert resp.status_code == 201
    asset = resp.json()
    assert asset["network_scope"] == "internet"
    assert asset["reachability_status"] in ("verified", "unreachable")
    assert asset["verification_source"] == "tempris_cloud"
    assert asset["last_verified_at"] is not None

    # Verify directly from DB
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT reachability_status, verification_source, last_verified_at FROM assets WHERE id = %s;", (asset["id"],))
            row = cur.fetchone()
            assert row["verification_source"] == "tempris_cloud"
            assert row["last_verified_at"] is not None

def test_internal_asset_persists_unverified_with_zero_io(client: TestClient, auth_headers_tenant_a_admin):
    # Create an internal asset
    resp = client.post(
        "/api/assets",
        json={
            "name": "Internal LDAP Server",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.0.1.100",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "critical"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert resp.status_code == 201
    asset = resp.json()
    assert asset["network_scope"] == "internal"
    assert asset["reachability_status"] == "unverified"
    assert asset["verification_source"] is None
    assert asset["last_verified_at"] is None

def test_recheck_internet_and_internal_assets(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_b_admin
):
    # 1. Create internet asset
    create_net_resp = client.post(
        "/api/assets",
        json={
            "name": "Internet Web Srv",
            "asset_type": "web_app",
            "target_type": "ip",
            "target_value": "1.0.0.1",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "medium"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert create_net_resp.status_code == 201
    net_asset = create_net_resp.json()
    net_asset_id = net_asset["id"]

    # Recheck internet asset
    recheck_net_resp = client.post(f"/api/assets/{net_asset_id}/recheck", headers=auth_headers_tenant_a_admin)
    assert recheck_net_resp.status_code == 200
    rechecked_net = recheck_net_resp.json()
    assert rechecked_net["id"] == net_asset_id
    assert rechecked_net["verification_source"] == "tempris_cloud"
    assert rechecked_net["last_verified_at"] is not None

    # 2. Create internal asset
    create_int_resp = client.post(
        "/api/assets",
        json={
            "name": "Internal App Srv",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "192.168.5.5",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert create_int_resp.status_code == 201
    int_asset = create_int_resp.json()
    int_asset_id = int_asset["id"]

    # Recheck internal asset
    recheck_int_resp = client.post(f"/api/assets/{int_asset_id}/recheck", headers=auth_headers_tenant_a_admin)
    assert recheck_int_resp.status_code == 200
    rechecked_int = recheck_int_resp.json()
    assert rechecked_int["reachability_status"] == "unverified"
    assert rechecked_int["verification_source"] is None

    # 3. Cross-tenant recheck returns 404
    assert client.post(f"/api/assets/{net_asset_id}/recheck", headers=auth_headers_tenant_b_admin).status_code == 404

    # 4. Decommissioned asset recheck returns 400
    client.post(f"/api/assets/{net_asset_id}/decommission", headers=auth_headers_tenant_a_admin)
    decom_recheck = client.post(f"/api/assets/{net_asset_id}/recheck", headers=auth_headers_tenant_a_admin)
    assert decom_recheck.status_code == 400

    # 5. Check audit events in DB
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_name FROM audit_events WHERE asset_id = %s AND event_name = 'asset.rechecked';",
                (net_asset_id,)
            )
            assert len(cur.fetchall()) >= 1
