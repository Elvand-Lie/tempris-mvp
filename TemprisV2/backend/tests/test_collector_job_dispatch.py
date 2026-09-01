# backend/tests/test_collector_job_dispatch.py
import asyncio
import json
import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.auth import create_test_token
from app.collector_registry import collector_registry
from app.db import get_db_connection
from tests.conftest import TENANT_A

class MockCollectorWebSocket:
    def __init__(self, col_id: uuid.UUID, response_mode: str = "verified"):
        self.col_id = col_id
        self.response_mode = response_mode
        self.sent_frames = []

    async def send_text(self, text: str):
        self.sent_frames.append(text)
        data = json.loads(text)
        if data.get("type") == "VERIFY_TARGET":
            job_id = data["job_id"]
            if self.response_mode == "verified":
                collector_registry.handle_verify_target_result(self.col_id, {
                    "type": "VERIFY_TARGET_RESULT",
                    "job_id": job_id,
                    "reachability_status": "verified",
                    "resolved_ip": data.get("target_value"),
                    "ports_checked": [443, 80],
                    "open_port": 443,
                    "error_message": None
                })
            elif self.response_mode == "unreachable":
                collector_registry.handle_verify_target_result(self.col_id, {
                    "type": "VERIFY_TARGET_RESULT",
                    "job_id": job_id,
                    "reachability_status": "unreachable",
                    "resolved_ip": data.get("target_value"),
                    "ports_checked": [443, 80],
                    "open_port": None,
                    "error_message": "Connection refused on ports 443, 80"
                })
            elif self.response_mode == "disconnect":
                collector_registry.unregister_session(self.col_id, reason="Collector disconnected unexpectedly.")
            elif self.response_mode == "timeout":
                # Do nothing, simulate server timeout
                pass

    async def close(self, code=1000, reason=""):
        pass

@pytest.mark.asyncio
async def test_internal_asset_verification_dispatch_success():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        tenant_id = TENANT_A
        token = create_test_token(tenant_id=str(tenant_id), role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Create collector
        col_res = await ac.post("/api/collectors", json={"name": "Job Dispatch Collector"}, headers=headers)
        assert col_res.status_code == 201
        col_id = uuid.UUID(col_res.json()["id"])

        # 2. Register mock active session in registry
        mock_ws = MockCollectorWebSocket(col_id, response_mode="verified")
        collector_registry.register_session(col_id, tenant_id, mock_ws, "active")

        # 3. Create internal asset
        asset_res = await ac.post("/api/assets", json={
            "name": "Internal Service",
            "asset_type": "service",
            "target_type": "ip",
            "target_value": "10.0.1.50",
            "network_scope": "internal",
            "collector_id": str(col_id)
        }, headers=headers)
        assert asset_res.status_code == 201
        asset_id = asset_res.json()["id"]
        assert asset_res.json()["reachability_status"] == "unverified"
        assert asset_res.json()["verification_source"] is None

        # 4. Recheck asset
        recheck_res = await ac.post(f"/api/assets/{asset_id}/recheck", headers=headers)
        assert recheck_res.status_code == 200
        rechecked = recheck_res.json()
        assert rechecked["reachability_status"] == "verified"
        assert rechecked["verification_source"] == "internal_collector"
        assert rechecked["last_verified_at"] is not None

        # Verify audit event in DB
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM audit_events WHERE event_name = 'asset.rechecked' AND asset_id = %s;",
                    (asset_id,)
                )
                audit_row = cur.fetchone()
                assert audit_row is not None
                assert audit_row["details"]["reachability_status"] == "verified"
                assert audit_row["details"]["verification_source"] == "internal_collector"

        collector_registry.unregister_session(col_id)

@pytest.mark.asyncio
async def test_internal_asset_verification_dispatch_unreachable():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        tenant_id = TENANT_A
        token = create_test_token(tenant_id=str(tenant_id), role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        col_res = await ac.post("/api/collectors", json={"name": "Unreachable Dispatch Collector"}, headers=headers)
        col_id = uuid.UUID(col_res.json()["id"])

        mock_ws = MockCollectorWebSocket(col_id, response_mode="unreachable")
        collector_registry.register_session(col_id, tenant_id, mock_ws, "active")

        asset_res = await ac.post("/api/assets", json={
            "name": "Unreachable Internal Host",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.0.1.99",
            "network_scope": "internal",
            "collector_id": str(col_id)
        }, headers=headers)
        asset_id = asset_res.json()["id"]

        recheck_res = await ac.post(f"/api/assets/{asset_id}/recheck", headers=headers)
        assert recheck_res.status_code == 200
        rechecked = recheck_res.json()
        assert rechecked["reachability_status"] == "unreachable"
        assert rechecked["verification_source"] == "internal_collector"
        assert rechecked["last_verified_at"] is not None

        collector_registry.unregister_session(col_id)

@pytest.mark.asyncio
async def test_internal_asset_verification_collector_offline_or_paused():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        tenant_id = TENANT_A
        token = create_test_token(tenant_id=str(tenant_id), role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        col_res = await ac.post("/api/collectors", json={"name": "Offline Collector"}, headers=headers)
        col_id = uuid.UUID(col_res.json()["id"])

        # No session registered in collector_registry (offline)
        asset_res = await ac.post("/api/assets", json={
            "name": "Internal Asset with Offline Collector",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.0.1.120",
            "network_scope": "internal",
            "collector_id": str(col_id)
        }, headers=headers)
        asset_id = asset_res.json()["id"]

        # Recheck when offline: remains unverified
        recheck_res = await ac.post(f"/api/assets/{asset_id}/recheck", headers=headers)
        assert recheck_res.status_code == 200
        rechecked = recheck_res.json()
        assert rechecked["reachability_status"] == "unverified"
        assert rechecked["verification_source"] is None
        assert rechecked["last_verified_at"] is None

        # Register session as paused
        mock_ws = MockCollectorWebSocket(col_id, response_mode="verified")
        collector_registry.register_session(col_id, tenant_id, mock_ws, "paused")

        recheck_paused_res = await ac.post(f"/api/assets/{asset_id}/recheck", headers=headers)
        assert recheck_paused_res.status_code == 200
        rechecked_paused = recheck_paused_res.json()
        assert rechecked_paused["reachability_status"] == "unverified"
        assert rechecked_paused["verification_source"] is None

        collector_registry.unregister_session(col_id)

@pytest.mark.asyncio
async def test_internal_asset_verification_disconnect_during_job():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        tenant_id = TENANT_A
        token = create_test_token(tenant_id=str(tenant_id), role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        col_res = await ac.post("/api/collectors", json={"name": "Disconnect Collector"}, headers=headers)
        col_id = uuid.UUID(col_res.json()["id"])

        mock_ws = MockCollectorWebSocket(col_id, response_mode="disconnect")
        collector_registry.register_session(col_id, tenant_id, mock_ws, "active")

        asset_res = await ac.post("/api/assets", json={
            "name": "Disconnect Target Asset",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.0.1.130",
            "network_scope": "internal",
            "collector_id": str(col_id)
        }, headers=headers)
        asset_id = asset_res.json()["id"]

        recheck_res = await ac.post(f"/api/assets/{asset_id}/recheck", headers=headers)
        assert recheck_res.status_code == 200
        rechecked = recheck_res.json()
        assert rechecked["reachability_status"] == "unverified"
        assert rechecked["verification_source"] is None
        assert rechecked["last_verified_at"] is None

        # Verify audit event in DB is collector.job_rejected, NOT collector.job_completed
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM audit_events WHERE event_name = 'collector.job_rejected' AND asset_id = %s;",
                    (asset_id,)
                )
                audit_row = cur.fetchone()
                assert audit_row is not None
                assert audit_row["details"]["collector_id"] == str(col_id)

                cur.execute(
                    "SELECT * FROM audit_events WHERE event_name = 'collector.job_completed' AND asset_id = %s;",
                    (asset_id,)
                )
                assert cur.fetchone() is None

@pytest.mark.asyncio
async def test_session_replacement_race_in_registry():
    """
    Proves that when an old WebSocket connection is superseded by a new connection,
    stale operations (heartbeat, unregister, result submission) from the old session
    cannot unregister or mutate the new active session (H3).
    """
    collector_id = uuid.uuid4()
    tenant_id = TENANT_A

    mock_ws_1 = MockCollectorWebSocket(collector_id)
    session_1 = collector_registry.register_session(collector_id, tenant_id, mock_ws_1, "active")
    s1_id = session_1.session_id

    # New session arrives and supersedes session 1
    mock_ws_2 = MockCollectorWebSocket(collector_id)
    session_2 = collector_registry.register_session(collector_id, tenant_id, mock_ws_2, "active")
    s2_id = session_2.session_id
    assert s1_id != s2_id

    # Active session is now session 2
    assert collector_registry.get_session(collector_id).session_id == s2_id

    # Old session 1 attempts to unregister - must be ignored!
    res_unreg = collector_registry.unregister_session(collector_id, session_id=s1_id)
    assert res_unreg is None
    assert collector_registry.get_session(collector_id).session_id == s2_id
    assert collector_registry.is_connected(collector_id) is True

    # Old session 1 attempts to record heartbeat - must return False
    hb_res = collector_registry.record_heartbeat(collector_id, session_id=s1_id)
    assert hb_res is False

    # Old session 1 attempts to submit verify result - must return False
    res_handled = collector_registry.handle_verify_target_result(
        collector_id,
        {"job_id": str(uuid.uuid4()), "reachability_status": "verified"},
        session_id=s1_id
    )
    assert res_handled is False

    # Proper unregister with session 2 ID cleans up cleanly
    res_unreg_2 = collector_registry.unregister_session(collector_id, session_id=s2_id)
    assert res_unreg_2 is not None
    assert collector_registry.get_session(collector_id) is None


@pytest.mark.asyncio
async def test_optimistic_cas_asset_recheck_concurrent_mutation():
    """
    Proves that if an asset is concurrently modified or decommissioned while an
    internal probe is in-flight, the stale probe result is discarded with a 409 Conflict
    and an audit record 'asset.recheck_discarded_conflict' (H4).
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        tenant_id = TENANT_A
        token = create_test_token(tenant_id=str(tenant_id), role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        col_res = await ac.post("/api/collectors", json={"name": "CAS Collector"}, headers=headers)
        col_id = uuid.UUID(col_res.json()["id"])

        # Create custom mock WS that concurrently modifies the asset in DB during probe dispatch
        class MutatingMockWS:
            def __init__(self, target_asset_id: str):
                self.target_asset_id = target_asset_id

            async def send_text(self, text: str):
                data = json.loads(text)
                if data.get("type") == "VERIFY_TARGET":
                    job_id = data["job_id"]
                    # Concurrently modify the asset target in DB
                    with get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE assets SET target_value = '10.99.99.99', normalized_target = '10.99.99.99' WHERE id = %s;",
                                (self.target_asset_id,)
                            )
                        conn.commit()

                    # Now deliver verified result for the old target
                    collector_registry.handle_verify_target_result(col_id, {
                        "type": "VERIFY_TARGET_RESULT",
                        "job_id": job_id,
                        "status": "completed",
                        "reachable": True,
                        "method": "tcp_probe",
                        "port": 443,
                        "reachability_status": "verified",
                        "started_at": "2026-08-28T12:00:00Z",
                        "completed_at": "2026-08-28T12:00:01Z"
                    })

            async def close(self, code=1000, reason=""):
                pass

        asset_res = await ac.post("/api/assets", json={
            "name": "CAS Test Asset",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.0.1.200",
            "network_scope": "internal",
            "collector_id": str(col_id)
        }, headers=headers)
        asset_id = asset_res.json()["id"]

        mock_ws = MutatingMockWS(asset_id)
        collector_registry.register_session(col_id, tenant_id, mock_ws, "active")

        # Recheck asset - must fail with 409 Conflict due to CAS mismatch
        recheck_res = await ac.post(f"/api/assets/{asset_id}/recheck", headers=headers)
        assert recheck_res.status_code == 409
        assert "modified during recheck" in recheck_res.json()["detail"]

        # Verify audit event for discarded conflict
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM audit_events WHERE event_name = 'asset.recheck_discarded_conflict' AND asset_id = %s;",
                    (asset_id,)
                )
                conflict_audit = cur.fetchone()
                assert conflict_audit is not None
                assert conflict_audit["details"]["reason"] == "concurrent_mutation_or_decommission"

        collector_registry.unregister_session(col_id)
