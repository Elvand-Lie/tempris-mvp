# backend/tests/test_assets_lifecycle.py
import uuid
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_asset_crud_and_duplicate_lifecycle(client: TestClient, auth_headers_tenant_a_admin):
    # 1. Create asset
    create_payload = {
        "name": "Core Web App",
        "asset_type": "web_app",
        "target_type": "domain",
        "target_value": "  APP.EXAMPLE.COM.  ",
        "network_scope": "internal",
        "environment": "production",
        "criticality": "critical",
        "owner": "secops@example.com",
        "tags": ["core", "pci"]
    }
    resp = client.post("/api/assets", json=create_payload, headers=auth_headers_tenant_a_admin)
    assert resp.status_code == 201
    asset = resp.json()
    asset_id = asset["id"]
    assert asset["name"] == "Core Web App"
    assert asset["normalized_target"] == "app.example.com"
    assert asset["network_scope"] == "internal"
    assert asset["status"] == "active"
    assert asset["reachability_status"] == "unverified"
    assert asset["tags"] == ["core", "pci"]

    # 2. Duplicate active target within same tenant must fail with 409
    dup_resp = client.post(
        "/api/assets",
        json={
            "name": "Duplicate Web App",
            "asset_type": "web_app",
            "target_type": "domain",
            "target_value": "app.example.com",
            "network_scope": "internal",
            "environment": "staging",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert dup_resp.status_code == 409

    # 3. List active assets
    list_resp = client.get("/api/assets", headers=auth_headers_tenant_a_admin)
    assert list_resp.status_code == 200
    assets = list_resp.json()
    assert len(assets) == 1
    assert assets[0]["id"] == asset_id

    # 4. Get asset by ID
    get_resp = client.get(f"/api/assets/{asset_id}", headers=auth_headers_tenant_a_admin)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == asset_id

    # 5. Insert an approved authorization record directly in DB to test atomic revocation on mutation
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    id, tenant_id, asset_id, target_type, normalized_target,
                    network_scope, status, requested_by
                ) VALUES (
                    gen_random_uuid(), %s, %s, 'domain', 'app.example.com',
                    'internal', 'approved', 'admin-a'
                );
                """,
                (asset["tenant_id"], asset_id)
            )
        conn.commit()

    # 6. Update asset target tuple (e.g. change target_value to new domain)
    update_payload = {
        "target_value": "app-v2.example.com"
    }
    update_resp = client.put(f"/api/assets/{asset_id}", json=update_payload, headers=auth_headers_tenant_a_admin)
    assert update_resp.status_code == 200
    updated = update_resp.json()
    assert updated["normalized_target"] == "app-v2.example.com"

    # Verify authorization was atomically revoked
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, revocation_reason FROM asset_scan_authorizations WHERE asset_id = %s;",
                (asset_id,)
            )
            auth_row = cur.fetchone()
            assert auth_row["status"] == "revoked"
            assert "updated" in auth_row["revocation_reason"]

    # 7. Decommission asset
    decom_resp = client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)
    assert decom_resp.status_code == 200
    decom = decom_resp.json()
    assert decom["status"] == "decommissioned"
    assert decom["decommissioned_at"] is not None

    # Decommissioned asset is excluded from active list
    list_after_decom = client.get("/api/assets", headers=auth_headers_tenant_a_admin).json()
    assert len(list_after_decom) == 0

    # 8. Re-registering the same decommissioned target succeeds
    re_reg_resp = client.post(
        "/api/assets",
        json={
            "name": "Re-registered Web App",
            "asset_type": "web_app",
            "target_type": "domain",
            "target_value": "app.example.com",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert re_reg_resp.status_code == 201
    assert re_reg_resp.json()["normalized_target"] == "app.example.com"

def test_scope_independence_in_asset_creation(client: TestClient, auth_headers_tenant_a_admin):
    # 1. Public IP declared as internal scope
    resp_pub_internal = client.post(
        "/api/assets",
        json={
            "name": "Public IP in Internal Network",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "8.8.8.8",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "medium"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert resp_pub_internal.status_code == 201
    assert resp_pub_internal.json()["network_scope"] == "internal"
    assert resp_pub_internal.json()["reachability_status"] == "unverified"

    # 2. Private IP declared as internet scope (unreachable connect is fine)
    resp_priv_internet = client.post(
        "/api/assets",
        json={
            "name": "Private IP via Internet Gateway",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.0.0.55",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert resp_priv_internet.status_code == 201
    assert resp_priv_internet.json()["network_scope"] == "internet"
    assert resp_priv_internet.json()["reachability_status"] in ("verified", "unreachable")
    assert resp_priv_internet.json()["verification_source"] == "tempris_cloud"

def test_scope_mutation_atomically_revokes_authorization(client: TestClient, auth_headers_tenant_a_admin):
    # Create asset
    create_res = client.post(
        "/api/assets",
        json={
            "name": "Scope Mutation Test",
            "asset_type": "api",
            "target_type": "domain",
            "target_value": "scope-test.example.com",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_id = create_res.json()["id"]

    # Insert approved authorization
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    id, tenant_id, asset_id, target_type, normalized_target,
                    network_scope, status, requested_by
                ) VALUES (
                    gen_random_uuid(), '11111111-1111-1111-1111-111111111111', %s, 'domain', 'scope-test.example.com',
                    'internal', 'approved', 'admin-a'
                );
                """,
                (asset_id,)
            )
        conn.commit()

    # Mutate ONLY network_scope from internal to internet
    update_res = client.put(
        f"/api/assets/{asset_id}",
        json={"network_scope": "internet"},
        headers=auth_headers_tenant_a_admin
    )
    assert update_res.status_code == 200
    assert update_res.json()["network_scope"] == "internet"

    # Verify authorization is revoked
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM asset_scan_authorizations WHERE asset_id = %s;",
                (asset_id,)
            )
            assert cur.fetchone()["status"] == "revoked"

def test_analyst_role_operations(client: TestClient, auth_headers_tenant_a_analyst):
    # Analyst can create asset
    res = client.post(
        "/api/assets",
        json={
            "name": "Analyst Created Asset",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "192.168.1.200",
            "network_scope": "internal",
            "environment": "staging",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_analyst
    )
    assert res.status_code == 201

    # Analyst can list assets
    list_res = client.get("/api/assets", headers=auth_headers_tenant_a_analyst)
    assert list_res.status_code == 200

def test_audit_log_events_and_data_minimization(client: TestClient, auth_headers_tenant_a_admin):
    # Perform actions: target check, create, update, decommission
    client.post(
        "/api/assets/check-target",
        json={"target_type": "ip", "target_value": "10.10.10.10", "network_scope": "internal"},
        headers=auth_headers_tenant_a_admin
    )

    create_res = client.post(
        "/api/assets",
        json={
            "name": "Audit Test Srv",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.10.10.10",
            "network_scope": "internal",
            "environment": "test",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_id = create_res.json()["id"]

    client.put(
        f"/api/assets/{asset_id}",
        json={"name": "Audit Test Srv Renamed"},
        headers=auth_headers_tenant_a_admin
    )

    client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)

    # Inspect audit events in DB
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_name, details FROM audit_events WHERE tenant_id = '11111111-1111-1111-1111-111111111111' ORDER BY created_at ASC;"
            )
            rows = cur.fetchall()
            events = [r["event_name"] for r in rows]
            assert "asset.target_checked" in events
            assert "asset.created" in events
            assert "asset.updated" in events
            assert "asset.decommissioned" in events

            # Verify data minimization (no secret/token keys)
            for r in rows:
                details = r["details"]
                assert "password" not in details
                assert "secret" not in details
                assert "token" not in details
                assert "authorization" not in details
