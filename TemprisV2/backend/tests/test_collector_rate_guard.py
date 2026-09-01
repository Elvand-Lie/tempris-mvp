# backend/tests/test_collector_rate_guard.py
import base64
import time
import uuid
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.collector_crypto import build_canonical_challenge_bytes
from app.collector_registry import collector_registry, CollectorSession
from app.db import get_db_connection

class FakeClock:
    def __init__(self, start_time: float = 1000.0):
        self.current_time = start_time

    def __call__(self) -> float:
        return self.current_time

    def advance(self, seconds: float):
        self.current_time += seconds

def test_collector_rate_calculation_sliding_window():
    clock = FakeClock(1000.0)
    session = CollectorSession(
        collector_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        websocket=None,
        clock=clock
    )

    assert session.get_rate() == 0.0

    # Record 10 messages across 2 seconds
    for _ in range(10):
        session.record_message()
        clock.advance(0.2)

    # 10 messages over ~1.8 seconds -> ~5.56 msg/s
    rate = session.get_rate()
    assert 4.5 <= rate <= 6.0

    # Advance clock past 15 minutes (900s)
    clock.advance(1000.0)
    session.record_message()  # New single message
    # Old messages pruned
    assert len(session.message_timestamps) == 1
    assert session.get_rate() == 0.0


def test_collector_rate_guard_exact_900s_boundaries_in_memory():
    """
    Tests exact boundary conditions for 15-minute (900.0s) sustained rate guard (M3):
    - Negative test: 4500 messages across 899.999s (span < 900.0s) must return False
    - Positive test: 4501 messages across 900.0s (span >= 900.0s and rate >= 5.0 msg/s) must return True
    """
    # 1. Negative test at 899.999 seconds
    clock_neg = FakeClock(1000.0)
    session_neg = CollectorSession(clock=clock_neg)
    for i in range(4500):
        t = 1000.0 + i * (899.999 / 4499.0)
        clock_neg.current_time = t
        session_neg.record_message()

    assert session_neg.is_rate_limit_exceeded() is False

    # 2. Positive test at 900.0 seconds
    clock_pos = FakeClock(1000.0)
    session_pos = CollectorSession(clock=clock_pos)
    for i in range(4501):
        t = 1000.0 + i * (900.0 / 4500.0)
        clock_pos.current_time = t
        session_pos.record_message()

    assert session_pos.is_rate_limit_exceeded() is True


def test_collector_derived_status_lowercase_contract():
    """
    Tests that collector derived status returns machine-readable lowercase strings (M2).
    """
    col_id = uuid.uuid4()
    # Awaiting enrollment
    assert collector_registry.get_derived_status("awaiting_enrollment", "active", col_id) == "awaiting_enrollment"
    # Paused
    assert collector_registry.get_derived_status("enrolled", "paused", col_id) == "paused"
    # Quarantined
    assert collector_registry.get_derived_status("enrolled", "quarantined", col_id) == "quarantined"
    # Revoked
    assert collector_registry.get_derived_status("enrolled", "revoked", col_id) == "revoked"
    # Enrolled + active, not connected
    assert collector_registry.get_derived_status("enrolled", "active", col_id) == "offline"


def test_collector_rate_guard_auto_quarantine(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    # Create and enroll collector
    create_resp = client.post("/api/collectors", json={"name": "Rate Guard Test Collector"}, headers=auth_headers_tenant_a_admin)
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post("/api/collectors/enroll", json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64})
    assert enroll_resp.status_code == 200

    fake_clock = FakeClock(2000.0)
    collector_registry.set_clock(fake_clock)

    try:
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
            auth_res = ws.receive_json()
            assert auth_res["type"] == "AUTH_SUCCESS"

            session = collector_registry.get_session(uuid.UUID(col_id))
            assert session is not None

            # Simulate sustained traffic >= 5.0 msg/s over 15 minutes (900 seconds)
            # Inject 4500 messages spanning 900 seconds
            for i in range(4501):
                fake_clock.current_time = 2000.0 + i * (900.0 / 4500.0)
                session.record_message()

            assert session.is_rate_limit_exceeded() is True

            # Sending next frame triggers automated quarantine check in receive loop
            with pytest.raises(WebSocketDisconnect) as exc_info:
                ws.send_json({"type": "HEARTBEAT", "timestamp": "2026-08-28T12:00:00Z"})
                # Server checks rate limit, updates DB, sends close frame 1008
                ws.receive_json()

            assert exc_info.value.code == 1008

        # Verify DB status updated to quarantined
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT operator_status FROM collectors WHERE id = %s;", (col_id,))
                row = cur.fetchone()
                assert row["operator_status"] == "quarantined"

                # Verify audit event
                cur.execute(
                    "SELECT * FROM audit_events WHERE event_name = 'collector.quarantined' AND details->>'collector_id' = %s;",
                    (col_id,)
                )
                audit_row = cur.fetchone()
                assert audit_row is not None
                assert audit_row["actor_role"] == "system"

    finally:
        # Restore real clock
        collector_registry.set_clock(time.time)
