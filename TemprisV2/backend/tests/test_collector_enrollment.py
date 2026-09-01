# backend/tests/test_collector_enrollment.py
import base64
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from starlette.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.db import get_db_connection

def test_collector_enrollment_full_lifecycle(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    # 1. Admin creates collector profile
    create_resp = client.post(
        "/api/collectors",
        json={"name": "Enrollment Test Collector", "description": "Testing Ed25519 enrollment"},
        headers=auth_headers_tenant_a_admin
    )
    assert create_resp.status_code == 201
    col_data = create_resp.json()
    col_id = col_data["id"]
    enrollment_code = col_data["enrollment_code"]

    # Generate Ed25519 key pair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    pub_key_b64 = base64.urlsafe_b64encode(pub_key.public_bytes_raw()).decode("utf-8").rstrip("=")

    # 2. Rejection of invalid enrollment code (hash mismatch)
    bad_code_resp = client.post(
        "/api/collectors/enroll",
        json={
            "collector_id": col_id,
            "enrollment_code": "col_enc_invalid_code_1234567890",
            "public_key": pub_key_b64,
            "platform_metadata": {"os": "windows", "hostname": "TEST-HOST-01"}
        }
    )
    assert bad_code_resp.status_code == 400
    assert bad_code_resp.json()["detail"] == "Invalid enrollment code"

    # 3. Rejection of invalid public key format (not 32 bytes)
    bad_key_resp = client.post(
        "/api/collectors/enroll",
        json={
            "collector_id": col_id,
            "enrollment_code": enrollment_code,
            "public_key": "dG9vX3Nob3J0",  # "too_short"
            "platform_metadata": {"os": "windows"}
        }
    )
    assert bad_key_resp.status_code == 422
    assert "Invalid Ed25519 public key" in bad_key_resp.json()["detail"]

    # 4. Successful enrollment
    enroll_resp = client.post(
        "/api/collectors/enroll",
        json={
            "collector_id": col_id,
            "enrollment_code": enrollment_code,
            "public_key": pub_key_b64,
            "platform_metadata": {
                "os": "windows",
                "os_version": "10.0.26200",
                "arch": "x86_64",
                "hostname": "PROD-WIN-01"
            }
        }
    )
    assert enroll_resp.status_code == 200
    enrolled_col = enroll_resp.json()
    assert enrolled_col["id"] == col_id
    assert enrolled_col["enrollment_status"] == "enrolled"
    assert enrolled_col["operator_status"] == "active"
    assert enrolled_col["status"] == "offline"  # Enrolled + active + not yet connected socket
    assert enrolled_col["public_key"] == pub_key_b64
    assert enrolled_col["platform_metadata"]["hostname"] == "PROD-WIN-01"

    # Verify DB cleared the enrollment code and hash
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT enrollment_status, public_key, enrollment_code_hash, enrollment_code_expires_at FROM collectors WHERE id = %s;",
                (col_id,)
            )
            row = cur.fetchone()
            assert row["enrollment_status"] == "enrolled"
            assert row["public_key"] == pub_key_b64
            assert row["enrollment_code_hash"] is None
            assert row["enrollment_code_expires_at"] is None

            # Verify audit event recorded
            cur.execute(
                "SELECT * FROM audit_events WHERE event_name = 'collector.enrolled' AND details->>'collector_id' = %s;",
                (col_id,)
            )
            audit_row = cur.fetchone()
            assert audit_row is not None
            assert audit_row["actor_role"] == "collector"

    # 5. Rejection of subsequent/duplicate enrollment (single-use)
    dup_resp = client.post(
        "/api/collectors/enroll",
        json={
            "collector_id": col_id,
            "enrollment_code": enrollment_code,
            "public_key": pub_key_b64,
            "platform_metadata": {"os": "windows"}
        }
    )
    assert dup_resp.status_code == 400
    assert dup_resp.json()["detail"] == "Collector is already enrolled"


def test_collector_enrollment_expired_rejection(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    # Create collector
    create_resp = client.post(
        "/api/collectors",
        json={"name": "Expired Test Collector"},
        headers=auth_headers_tenant_a_admin
    )
    assert create_resp.status_code == 201
    col_data = create_resp.json()
    col_id = col_data["id"]
    enrollment_code = col_data["enrollment_code"]

    # Manually expire the code in DB
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE collectors SET enrollment_code_expires_at = now() - interval '1 minute' WHERE id = %s;",
                (col_id,)
            )
            conn.commit()

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode("utf-8").rstrip("=")

    # Attempt enrollment with expired code
    enroll_resp = client.post(
        "/api/collectors/enroll",
        json={
            "collector_id": col_id,
            "enrollment_code": enrollment_code,
            "public_key": pub_key_b64
        }
    )
    assert enroll_resp.status_code == 400
    assert enroll_resp.json()["detail"] == "Enrollment code has expired"
