# backend/tests/test_collector_wss_auth.py
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.db import get_db_connection
from app.collector_crypto import (
    build_canonical_challenge_bytes,
    normalize_ed25519_public_key,
)
from app.collector_registry import collector_registry

def test_collector_wss_valid_handshake_and_heartbeat(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    # 1. Create and enroll collector
    create_resp = client.post(
        "/api/collectors",
        json={"name": "WSS Test Collector"},
        headers=auth_headers_tenant_a_admin
    )
    assert create_resp.status_code == 201
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post(
        "/api/collectors/enroll",
        json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64}
    )
    assert enroll_resp.status_code == 200

    # 2. Connect WebSocket and complete challenge-response handshake
    with client.websocket_connect("/api/collectors/ws") as ws:
        challenge = ws.receive_json()
        assert challenge["type"] == "AUTH_CHALLENGE"
        nonce = challenge["nonce"]
        expires_at = challenge["expires_at"]

        # Sign canonical bytes
        canonical_bytes = build_canonical_challenge_bytes(col_id, nonce, expires_at)
        sig = priv_key.sign(canonical_bytes)
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

        ws.send_json({
            "type": "AUTH_RESPONSE",
            "collector_id": col_id,
            "nonce": nonce,
            "expires_at": expires_at,
            "signature": sig_b64
        })

        auth_success = ws.receive_json()
        assert auth_success["type"] == "AUTH_SUCCESS"
        assert auth_success["collector_id"] == col_id
        assert auth_success["status"] == "connected"

        # Check derived status via REST API while connected
        get_resp = client.get(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
        assert get_resp.status_code == 200
        col_state = get_resp.json()
        assert col_state["connection_status"] == "connected"
        assert col_state["status"] == "connected"

        # 3. Send HEARTBEAT and receive HEARTBEAT_ACK
        ws.send_json({"type": "HEARTBEAT", "timestamp": "2026-08-28T12:00:00Z"})
        hb_ack = ws.receive_json()
        assert hb_ack["type"] == "HEARTBEAT_ACK"
        assert "timestamp" in hb_ack

    # After WebSocket context exit, socket is closed -> should derive offline
    get_after_resp = client.get(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert get_after_resp.status_code == 200
    assert get_after_resp.json()["connection_status"] == "offline"
    assert get_after_resp.json()["status"] == "offline"


def test_collector_wss_invalid_signature_rejected(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    # Create and enroll collector
    create_resp = client.post("/api/collectors", json={"name": "Bad Sig Collector"}, headers=auth_headers_tenant_a_admin)
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post("/api/collectors/enroll", json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64})
    assert enroll_resp.status_code == 200

    # Another key pair that doesn't match registered public key
    wrong_priv_key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/api/collectors/ws") as ws:
            challenge = ws.receive_json()
            nonce = challenge["nonce"]
            expires_at = challenge["expires_at"]

            # Sign with wrong key
            canonical_bytes = build_canonical_challenge_bytes(col_id, nonce, expires_at)
            wrong_sig = wrong_priv_key.sign(canonical_bytes)
            wrong_sig_b64 = base64.urlsafe_b64encode(wrong_sig).decode().rstrip("=")

            ws.send_json({
                "type": "AUTH_RESPONSE",
                "collector_id": col_id,
                "nonce": nonce,
                "expires_at": expires_at,
                "signature": wrong_sig_b64
            })
            ws.receive_json()

    assert exc_info.value.code == 1008


def test_collector_wss_replayed_nonce_rejected(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    create_resp = client.post("/api/collectors", json={"name": "Replay Collector"}, headers=auth_headers_tenant_a_admin)
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post("/api/collectors/enroll", json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64})
    assert enroll_resp.status_code == 200

    captured_nonce = None
    captured_expires_at = None

    # First connection obtains challenge
    with client.websocket_connect("/api/collectors/ws") as ws1:
        challenge = ws1.receive_json()
        captured_nonce = challenge["nonce"]
        captured_expires_at = challenge["expires_at"]

        # Sign validly for session 1
        canonical_bytes = build_canonical_challenge_bytes(col_id, captured_nonce, captured_expires_at)
        sig = priv_key.sign(canonical_bytes)
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

        ws1.send_json({
            "type": "AUTH_RESPONSE",
            "collector_id": col_id,
            "nonce": captured_nonce,
            "expires_at": captured_expires_at,
            "signature": sig_b64
        })
        auth_res = ws1.receive_json()
        assert auth_res["type"] == "AUTH_SUCCESS"

    # Second connection tries to replay session 1's nonce
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/api/collectors/ws") as ws2:
            _ = ws2.receive_json()  # session 2 challenge

            canonical_bytes = build_canonical_challenge_bytes(col_id, captured_nonce, captured_expires_at)
            sig = priv_key.sign(canonical_bytes)
            sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

            ws2.send_json({
                "type": "AUTH_RESPONSE",
                "collector_id": col_id,
                "nonce": captured_nonce,  # Replayed nonce from session 1
                "expires_at": captured_expires_at,
                "signature": sig_b64
            })
            ws2.receive_json()

    assert exc_info.value.code == 1008


def test_collector_wss_quarantined_and_revoked_rejection(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    create_resp = client.post("/api/collectors", json={"name": "Lifecycle WSS Collector"}, headers=auth_headers_tenant_a_admin)
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post("/api/collectors/enroll", json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64})
    assert enroll_resp.status_code == 200

    # 1. Admin quarantines collector
    quarantine_resp = client.post(f"/api/collectors/{col_id}/quarantine", headers=auth_headers_tenant_a_admin)
    assert quarantine_resp.status_code == 200
    assert quarantine_resp.json()["operator_status"] == "quarantined"

    # Connection attempt by quarantined collector is closed with code 1008
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/api/collectors/ws") as ws:
            ch = ws.receive_json()
            nonce, expires_at = ch["nonce"], ch["expires_at"]
            msg_bytes = build_canonical_challenge_bytes(col_id, nonce, expires_at)
            sig_b64 = base64.urlsafe_b64encode(priv_key.sign(msg_bytes)).decode().rstrip("=")
            ws.send_json({
                "type": "AUTH_RESPONSE",
                "collector_id": col_id,
                "nonce": nonce,
                "expires_at": expires_at,
                "signature": sig_b64
            })
            ws.receive_json()
    assert exc_info.value.code == 1008

    # 2. Admin releases collector from quarantine
    release_resp = client.post(f"/api/collectors/{col_id}/release", headers=auth_headers_tenant_a_admin)
    assert release_resp.status_code == 200
    assert release_resp.json()["operator_status"] == "active"

    # Reconnect succeeds
    with client.websocket_connect("/api/collectors/ws") as ws:
        ch = ws.receive_json()
        nonce, expires_at = ch["nonce"], ch["expires_at"]
        msg_bytes = build_canonical_challenge_bytes(col_id, nonce, expires_at)
        sig_b64 = base64.urlsafe_b64encode(priv_key.sign(msg_bytes)).decode().rstrip("=")
        ws.send_json({
            "type": "AUTH_RESPONSE",
            "collector_id": col_id,
            "nonce": nonce,
            "expires_at": expires_at,
            "signature": sig_b64
        })
        auth_success = ws.receive_json()
        assert auth_success["type"] == "AUTH_SUCCESS"

    # 3. Admin revokes collector permanently
    revoke_resp = client.post(f"/api/collectors/{col_id}/revoke", headers=auth_headers_tenant_a_admin)
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["operator_status"] == "revoked"

    # Reconnect fails permanently
    with pytest.raises(WebSocketDisconnect) as exc_info2:
        with client.websocket_connect("/api/collectors/ws") as ws:
            ch = ws.receive_json()
            nonce, expires_at = ch["nonce"], ch["expires_at"]
            msg_bytes = build_canonical_challenge_bytes(col_id, nonce, expires_at)
            sig_b64 = base64.urlsafe_b64encode(priv_key.sign(msg_bytes)).decode().rstrip("=")
            ws.send_json({
                "type": "AUTH_RESPONSE",
                "collector_id": col_id,
                "nonce": nonce,
                "expires_at": expires_at,
                "signature": sig_b64
            })
            ws.receive_json()
    assert exc_info2.value.code == 1008
