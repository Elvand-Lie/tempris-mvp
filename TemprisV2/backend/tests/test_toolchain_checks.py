# backend/tests/test_toolchain_checks.py
import json
import uuid

from starlette.testclient import TestClient

from app.collector_registry import collector_registry
from app.db import get_db_connection

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"


class _ScriptedSocket:
    """Captures server frames; receive_text feeds one queued client frame back
    through the registry interceptor (the real SCOUT_CAPABILITIES path)."""

    def __init__(self):
        self.sent_frames = []
        self.inbox = []

    async def send_text(self, payload):
        self.sent_frames.append(json.loads(payload))

    async def receive_text(self):
        return self.inbox.pop(0)


def _insert_collector(collector_id, tenant_id=TENANT_A):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collectors (id, tenant_id, name, description,
                    enrollment_status, operator_status, public_key)
                VALUES (%s, %s, %s, 'toolchain check test', 'enrolled', 'active', 'dGVzdC1rZXk=');
                """,
                (str(collector_id), str(tenant_id), f"tc-{collector_id.hex[:8]}"),
            )
        conn.commit()


def _delete_collector(collector_id):
    collector_registry.unregister_session(collector_id, reason="test teardown")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM collector_toolchain_checks WHERE collector_id = %s;", (str(collector_id),))
            cur.execute("DELETE FROM collectors WHERE id = %s;", (str(collector_id),))
        conn.commit()


def _connect(collector_id, tenant_id=TENANT_A):
    socket = _ScriptedSocket()
    session = collector_registry.register_session(
        collector_id=collector_id,
        tenant_id=uuid.UUID(tenant_id),
        websocket=socket,
        operator_status="active",
    )
    session.capabilities = {"nmap": {"available": True, "version": "7.99"}}
    return socket


def _last_check(client, headers, collector_id):
    return client.get(f"/api/collectors/{collector_id}", headers=headers).json()["last_toolchain_check"]


def test_noop_check_completes_with_correlated_id(client: TestClient, auth_headers_tenant_a_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id)
    try:
        socket = _connect(collector_id)
        res = client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200, res.text
        check_id = res.json()["check_id"]
        assert res.json()["status"] == "checking"

        # Dispatch frame carried the persisted check_id
        assert socket.sent_frames and socket.sent_frames[0]["type"] == "CHECK_UPDATE"
        assert socket.sent_frames[0]["check_id"] == check_id

        # Still 'dispatched' until the collector responds
        assert _last_check(client, auth_headers_tenant_a_admin, collector_id)["status"] == "dispatched"

        # Collector answers with a no-op SCOUT_CAPABILITIES (same versions, old timestamp)
        socket.inbox.append(json.dumps({
            "type": "SCOUT_CAPABILITIES",
            "capabilities": {
                "nmap": {"available": True, "version": "7.99"},
                "update_status": "up_to_date",
                "last_checked_at": "2026-09-06T13:55:00Z",
            },
        }))
        socket.inbox.append(json.dumps({"type": "PING"}))
        import asyncio
        asyncio.run(socket.receive_text())

        chk = _last_check(client, auth_headers_tenant_a_admin, collector_id)
        assert chk["check_id"] == check_id
        assert chk["status"] == "completed"
        assert chk["finished_at"] is not None
        assert chk["result"]["update_status"] == "up_to_date"
        assert chk["result"]["nmap_version"] == "7.99"
    finally:
        _delete_collector(collector_id)


def test_heartbeat_never_completes_a_check(client: TestClient, auth_headers_tenant_a_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id)
    try:
        socket = _connect(collector_id)
        client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin)
        socket.inbox.append(json.dumps({
            "type": "HEARTBEAT",
            "capabilities": {"nmap": {"available": True, "version": "7.99"}},
        }))
        socket.inbox.append(json.dumps({"type": "PING"}))
        import asyncio
        asyncio.run(socket.receive_text())
        assert _last_check(client, auth_headers_tenant_a_admin, collector_id)["status"] == "dispatched"
    finally:
        _delete_collector(collector_id)


def test_failed_update_check_is_reported_as_failed(client: TestClient, auth_headers_tenant_a_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id)
    try:
        socket = _connect(collector_id)
        client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin)
        socket.inbox.append(json.dumps({
            "type": "SCOUT_CAPABILITIES",
            "capabilities": {
                "nmap": {"available": True, "version": "7.99"},
                "update_status": "error",
                "update_check": {"succeeded": False, "error": "manifest fetch unreachable"},
            },
        }))
        socket.inbox.append(json.dumps({"type": "PING"}))
        import asyncio
        asyncio.run(socket.receive_text())
        chk = _last_check(client, auth_headers_tenant_a_admin, collector_id)
        assert chk["status"] == "failed"
        assert chk["result"]["error"] == "manifest fetch unreachable"
    finally:
        _delete_collector(collector_id)


def test_collector_disconnect_fails_pending_check(client: TestClient, auth_headers_tenant_a_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id)
    try:
        _connect(collector_id)
        client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin)
        collector_registry.unregister_session(collector_id, reason="simulated disconnect")
        chk = _last_check(client, auth_headers_tenant_a_admin, collector_id)
        assert chk["status"] == "failed"
    finally:
        _delete_collector(collector_id)


def test_stale_check_times_out(client: TestClient, auth_headers_tenant_a_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id)
    try:
        _connect(collector_id)
        client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE collector_toolchain_checks SET timeout_at = now() - interval '1 second' WHERE collector_id = %s;",
                    (str(collector_id),),
                )
            conn.commit()
        chk = _last_check(client, auth_headers_tenant_a_admin, collector_id)
        assert chk["status"] == "timed_out"
        assert chk["finished_at"] is not None
    finally:
        _delete_collector(collector_id)


def test_repeated_request_supersedes_pending_check(client: TestClient, auth_headers_tenant_a_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id)
    try:
        _connect(collector_id)
        first = client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin).json()["check_id"]
        second = client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_a_admin).json()["check_id"]
        assert first != second
        chk = _last_check(client, auth_headers_tenant_a_admin, collector_id)
        assert chk["check_id"] == second
        assert chk["status"] == "dispatched"
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM collector_toolchain_checks WHERE check_id = %s;", (first,))
                assert cur.fetchone()["status"] == "superseded"
    finally:
        _delete_collector(collector_id)


def test_cross_tenant_check_update_is_404(client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id, TENANT_A)
    try:
        _connect(collector_id)
        res = client.post(f"/api/collectors/{collector_id}/check-update", headers=auth_headers_tenant_b_admin)
        assert res.status_code == 404
    finally:
        _delete_collector(collector_id)
