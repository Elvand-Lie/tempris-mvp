# backend/tests/test_tenant_disable_flow.py
import base64
import json
import uuid
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.db import get_db_connection
from app.collector_crypto import (
    generate_enrollment_code,
    build_canonical_challenge_bytes,
)
from tests.conftest import TENANT_A, TENANT_B

def test_human_assets_endpoints_403_when_unentitled(client: TestClient, auth_headers_tenant_a_admin):
    """Test that all human assets endpoints return 403 when ASSETS entitlement is revoked."""
    # 1. Disable ASSETS for TENANT_A
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET module_overrides = '{"ASSETS": false}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

    # 2. Check /api/assets/stats
    res = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403
    assert "Tenant does not possess active entitlement for module 'ASSETS'" in res.json()["detail"]

    # 3. Check /api/assets
    res = client.get("/api/assets", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

    # 4. Check POST /api/assets
    res = client.post("/api/assets", json={
        "name": "Test Asset",
        "target_type": "ipv4",
        "target_value": "192.0.2.1",
        "network_scope": "internet"
    }, headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

    # 5. Check POST /api/assets/check-target
    res = client.post("/api/assets/check-target", json={
        "target_type": "ipv4",
        "target_value": "192.0.2.1",
        "network_scope": "internet"
    }, headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

def test_human_collectors_endpoints_403_when_unentitled(client: TestClient, auth_headers_tenant_a_admin):
    """Test that all human collectors endpoints return 403 when ASSETS entitlement is revoked."""
    # 1. Disable ASSETS for TENANT_A
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET module_overrides = '{"ASSETS": false}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

    # 2. Check GET /api/collectors
    res = client.get("/api/collectors", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403
    assert "Tenant does not possess active entitlement for module 'ASSETS'" in res.json()["detail"]

    # 3. Check POST /api/collectors
    res = client.post("/api/collectors", json={
        "name": "Collector 1",
        "description": "Test Collector"
    }, headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

    # 4. Check GET /api/collectors/{id}
    random_id = str(uuid.uuid4())
    res = client.get(f"/api/collectors/{random_id}", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

    # 5. Check POST /api/collectors/{id}/pause
    res = client.post(f"/api/collectors/{random_id}/pause", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

    # 6. Check DELETE /api/collectors/{id}
    res = client.delete(f"/api/collectors/{random_id}", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 403

def test_collector_enrollment_403_when_unentitled(client: TestClient, auth_headers_tenant_a_admin):
    """Test that collector enrollment returns 403 if tenant does not possess ASSETS entitlement."""
    # 1. Create a collector while entitled
    res = client.post("/api/collectors", json={
        "name": "Enrollment Test Collector",
        "description": "Will attempt enroll after de-entitle"
    }, headers=auth_headers_tenant_a_admin)
    assert res.status_code == 201
    col_data = res.json()
    collector_id = col_data["id"]
    enrollment_code = col_data["enrollment_code"]

    # 2. De-entitle TENANT_A
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET module_overrides = '{"ASSETS": false}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

    # 3. Attempt enrollment
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_res = client.post("/api/collectors/enroll", json={
        "collector_id": collector_id,
        "enrollment_code": enrollment_code,
        "public_key": pub_key_b64,
        "platform_metadata": {"hostname": "agent-1", "os": "linux"}
    })
    assert enroll_res.status_code == 403
    assert "Tenant does not possess active entitlement for module 'ASSETS'" in enroll_res.json()["detail"]

def test_collector_websocket_1008_when_unentitled(client: TestClient, auth_headers_tenant_a_admin):
    """Test that collector WebSocket handshake closes with code 1008 if tenant is de-entitled."""
    # 1. Create & enroll collector while entitled
    res = client.post("/api/collectors", json={
        "name": "WS Test Collector",
        "description": "WS Handshake Test"
    }, headers=auth_headers_tenant_a_admin)
    assert res.status_code == 201
    col_data = res.json()
    collector_id = col_data["id"]
    enrollment_code = col_data["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_res = client.post("/api/collectors/enroll", json={
        "collector_id": collector_id,
        "enrollment_code": enrollment_code,
        "public_key": pub_key_b64,
        "platform_metadata": {"hostname": "agent-ws", "os": "linux"}
    })
    assert enroll_res.status_code == 200

    # 2. De-entitle TENANT_A
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET module_overrides = '{"ASSETS": false}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

    # 3. Attempt WebSocket handshake
    try:
        with client.websocket_connect("/api/collectors/ws") as ws:
            challenge = ws.receive_json()
            nonce = challenge["nonce"]
            expires_at = challenge["expires_at"]

            canonical_bytes = build_canonical_challenge_bytes(
                uuid.UUID(collector_id),
                nonce,
                expires_at
            )
            sig = priv_key.sign(canonical_bytes)
            sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

            ws.send_json({
                "type": "AUTH_RESPONSE",
                "collector_id": collector_id,
                "nonce": nonce,
                "expires_at": expires_at,
                "signature": sig_b64
            })

            # Server should close socket with code 1008
            msg = ws.receive_json()
            # If a message is received instead of close, fail
            pytest.fail(f"Expected websocket disconnect, received: {msg}")
    except WebSocketDisconnect as e:
        assert e.code == 1008

def test_tenant_entitlement_isolation(client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin):
    """Test that de-entitling Tenant B does not affect Tenant A's access."""
    # De-entitle Tenant B only
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET module_overrides = '{"ASSETS": false}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_B),))
        conn.commit()

    # Tenant A should succeed
    res_a = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin)
    assert res_a.status_code == 200

    res_a_col = client.get("/api/collectors", headers=auth_headers_tenant_a_admin)
    assert res_a_col.status_code == 200

    # Tenant B should be forbidden (403)
    res_b = client.get("/api/assets/stats", headers=auth_headers_tenant_b_admin)
    assert res_b.status_code == 403

    res_b_col = client.get("/api/collectors", headers=auth_headers_tenant_b_admin)
    assert res_b_col.status_code == 403
