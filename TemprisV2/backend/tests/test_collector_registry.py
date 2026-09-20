# backend/tests/test_collector_registry.py
import asyncio
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.collector_registry import CollectorRegistry, CollectorSession
from tests.conftest import TENANT_A, TENANT_B

@pytest.mark.asyncio
async def test_terminate_tenant_sessions_targeting():
    """Test that terminate_tenant_sessions only terminates sessions belonging to target tenant."""
    registry = CollectorRegistry()

    col_a1 = uuid.uuid4()
    col_a2 = uuid.uuid4()
    col_b1 = uuid.uuid4()

    ws_a1 = AsyncMock()
    ws_a2 = AsyncMock()
    ws_b1 = AsyncMock()

    registry.register_session(collector_id=col_a1, tenant_id=TENANT_A, websocket=ws_a1)
    registry.register_session(collector_id=col_a2, tenant_id=TENANT_A, websocket=ws_a2)
    registry.register_session(collector_id=col_b1, tenant_id=TENANT_B, websocket=ws_b1)

    assert len(registry._sessions) == 3

    terminated = await registry.terminate_tenant_sessions(TENANT_A, close_code=1008, reason="Tenant disabled")
    assert set(terminated) == {col_a1, col_a2}

    # Tenant A sessions should be removed
    assert registry.get_session(col_a1) is None
    assert registry.get_session(col_a2) is None

    # Tenant B session should remain intact
    session_b = registry.get_session(col_b1)
    assert session_b is not None
    assert session_b.tenant_id == TENANT_B

@pytest.mark.asyncio
async def test_terminate_tenant_sessions_in_flight_job_resolution():
    """Test that terminating tenant sessions resolves in-flight jobs as failed / unverified."""
    registry = CollectorRegistry()
    col_id = uuid.uuid4()
    ws_mock = AsyncMock()

    session = registry.register_session(collector_id=col_id, tenant_id=TENANT_A, websocket=ws_mock)

    # Attach in-flight future
    loop = asyncio.get_running_loop()
    job_id_1 = str(uuid.uuid4())
    job_id_2 = str(uuid.uuid4())
    fut_1 = loop.create_future()
    fut_2 = loop.create_future()
    session.in_flight_jobs[job_id_1] = fut_1
    session.in_flight_jobs[job_id_2] = fut_2

    assert not fut_1.done()
    assert not fut_2.done()

    await registry.terminate_tenant_sessions(TENANT_A, close_code=1008, reason="Tenant subscription suspended")

    assert fut_1.done()
    assert fut_2.done()

    res_1 = fut_1.result()
    assert res_1["status"] == "failed"
    assert res_1["reachability_status"] == "unverified"
    assert res_1["error_message"] == "Tenant subscription suspended"

    res_2 = fut_2.result()
    assert res_2["status"] == "failed"
    assert res_2["reachability_status"] == "unverified"
    assert res_2["error_message"] == "Tenant subscription suspended"

    assert len(session.in_flight_jobs) == 0

@pytest.mark.asyncio
async def test_terminate_tenant_sessions_websocket_close():
    """Test that WebSocket is closed with code 1008 and reason immediately before return without sleeping."""
    registry = CollectorRegistry()
    col_id = uuid.uuid4()
    ws_mock = AsyncMock()

    registry.register_session(collector_id=col_id, tenant_id=TENANT_A, websocket=ws_mock)
    await registry.terminate_tenant_sessions(TENANT_A, close_code=1008, reason="Tenant disabled")

    ws_mock.close.assert_awaited_once_with(code=1008, reason="Tenant disabled")

@pytest.mark.asyncio
async def test_terminate_tenant_sessions_close_exception_guaranteed_unregister():
    """Test that session is unregister-cleaned even if websocket.close raises an exception."""
    registry = CollectorRegistry()
    col_id = uuid.uuid4()
    ws_mock = AsyncMock()
    ws_mock.close.side_effect = RuntimeError("WebSocket connection dropped")

    registry.register_session(collector_id=col_id, tenant_id=TENANT_A, websocket=ws_mock)
    terminated = await registry.terminate_tenant_sessions(TENANT_A, close_code=1008, reason="Tenant disabled")

    assert terminated == [col_id]
    assert registry.get_session(col_id) is None
    ws_mock.close.assert_awaited_once_with(code=1008, reason="Tenant disabled")

def test_handle_verify_target_result_safe_drop():
    """Test handle_verify_target_result safely drops late results without throwing errors."""
    registry = CollectorRegistry()
    col_id = uuid.uuid4()

    # 1. Unknown collector -> returns False
    res = registry.handle_verify_target_result(
        collector_id=col_id,
        result_payload={"job_id": "job-123", "status": "completed"}
    )
    assert res is False

    # 2. Registered collector, but payload missing job_id -> returns False
    ws_mock = AsyncMock()
    session = registry.register_session(collector_id=col_id, tenant_id=TENANT_A, websocket=ws_mock)
    res = registry.handle_verify_target_result(
        collector_id=col_id,
        result_payload={"status": "completed"}
    )
    assert res is False

    # 3. Registered collector, job_id not in in_flight_jobs (late arrival) -> returns False
    res = registry.handle_verify_target_result(
        collector_id=col_id,
        result_payload={"job_id": "missing-job", "status": "completed"}
    )
    assert res is False

    # 4. Registered collector, future already done -> returns False safely
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    fut = loop.create_future()
    fut.set_result({"status": "already_done"})
    session.in_flight_jobs["done-job"] = fut

    res = registry.handle_verify_target_result(
        collector_id=col_id,
        result_payload={"job_id": "done-job", "status": "late_frame"}
    )
    assert res is False
    loop.close()

@pytest.mark.asyncio
async def test_terminate_tenant_sessions_empty_tenant():
    """Test terminate_tenant_sessions on tenant with no sessions returns empty list."""
    registry = CollectorRegistry()
    col_id = uuid.uuid4()
    ws_mock = AsyncMock()
    registry.register_session(collector_id=col_id, tenant_id=TENANT_B, websocket=ws_mock)

    terminated = await registry.terminate_tenant_sessions(TENANT_A)
    assert terminated == []
    assert registry.get_session(col_id) is not None

@pytest.mark.asyncio
async def test_terminate_tenant_sessions_awaitable_close_proves_completion_before_return():
    """Proves WebSocket close() is awaited to completion before terminate_tenant_sessions returns."""
    registry = CollectorRegistry()
    col_id = uuid.uuid4()

    close_completed = False

    async def delayed_close(code=1000, reason=None):
        nonlocal close_completed
        await asyncio.sleep(0.02)
        close_completed = True

    ws_mock = MagicMock()
    ws_mock.close = AsyncMock(side_effect=delayed_close)

    registry.register_session(collector_id=col_id, tenant_id=TENANT_A, websocket=ws_mock)

    # When terminate_tenant_sessions returns, close_completed MUST already be True (synchronous/deterministic completion)
    terminated = await registry.terminate_tenant_sessions(TENANT_A, close_code=1008, reason="Tenant disabled")
    assert terminated == [col_id]
    assert close_completed is True
    assert registry.get_session(col_id) is None


@pytest.mark.asyncio
async def test_collector_version_captured_from_scout_capabilities():
    """Test that collector_version in SCOUT_CAPABILITIES is captured and sanitized onto the session."""
    import json
    registry = CollectorRegistry()
    col_id = uuid.uuid4()
    ws_mock = AsyncMock()

    # Simulate incoming message frames
    incoming = [
        json.dumps({
            "type": "SCOUT_CAPABILITIES",
            "capabilities": {
                "nmap": {"available": True, "version": "7.94"},
                "nuclei": {"available": False},
                "collector_version": "0.3.0",
            }
        }),
        json.dumps({"type": "HEARTBEAT", "timestamp": "2026-09-05T12:00:00Z"}),
    ]
    ws_mock.receive_text.side_effect = incoming

    session = registry.register_session(collector_id=col_id, tenant_id=TENANT_A, websocket=ws_mock)

    # Intercepted receive_text should swallow SCOUT_CAPABILITIES, populate version, and return HEARTBEAT
    received = await ws_mock.receive_text()
    assert json.loads(received)["type"] == "HEARTBEAT"
    assert session.collector_version == "0.3.0"
    assert registry.get_collector_version(col_id) == "0.3.0"
    assert session.capabilities["nmap"]["available"] is True

