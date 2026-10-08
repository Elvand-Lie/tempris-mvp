# tests/test_collector_host_binding.py
# PRD V3 §2.12 minimum slice: a Collector ID (Ed25519 enrollment) anchors its
# OWN host asset via an explicit operator binding; reported network location is
# mutable state on that SAME asset row across DHCP changes; IP is never used to
# create, infer, or rebind identity; WSS scan routing is unaffected.
import base64
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from app.collector_crypto import build_canonical_challenge_bytes
from app.db import get_db_connection


def _create_asset(client, headers, target="192.168.1.25", name="Laptop Host"):
    res = client.post(
        "/api/assets",
        json={
            "name": name,
            "asset_type": "workstation",
            "target_type": "ip",
            "target_value": target,
            "network_scope": "internal",
            "environment": "production",
            "criticality": "medium",
        },
        headers=headers,
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _enrolled_collector(client, headers, name="Host Collector"):
    res = client.post("/api/collectors", json={"name": name}, headers=headers)
    assert res.status_code == 201, res.text
    col_id = res.json()["id"]
    code = res.json()["enrollment_code"]
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")
    enroll = client.post(
        "/api/collectors/enroll",
        json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64},
    )
    assert enroll.status_code == 200, enroll.text
    return col_id, priv_key


def _ws_session(client, ws, col_id, priv_key):
    challenge = ws.receive_json()
    assert challenge["type"] == "AUTH_CHALLENGE"
    sig = priv_key.sign(build_canonical_challenge_bytes(col_id, challenge["nonce"], challenge["expires_at"]))
    ws.send_json({
        "type": "AUTH_RESPONSE",
        "collector_id": col_id,
        "nonce": challenge["nonce"],
        "expires_at": challenge["expires_at"],
        "signature": base64.urlsafe_b64encode(sig).decode().rstrip("="),
    })
    auth = ws.receive_json()
    assert auth["type"] == "AUTH_SUCCESS"


def _heartbeat(ws, ip: str):
    ws.send_json({
        "type": "HEARTBEAT",
        "timestamp": "2026-09-24T12:00:00Z",
        "network_state": {
            "observed_at": "2026-09-24T12:00:00+00:00",
            "addresses": [{"interface": "eth0", "ip": ip, "prefix": 24}],
        },
    })
    ack = ws.receive_json()
    assert ack["type"] == "HEARTBEAT_ACK"


def test_bind_report_move_and_same_asset_identity(client, auth_headers_tenant_a_admin):
    asset_id = _create_asset(client, auth_headers_tenant_a_admin)
    col_id, priv_key = _enrolled_collector(client, auth_headers_tenant_a_admin)

    # explicit operator bind, one collector <-> one host asset
    bind = client.put(
        f"/api/collectors/{col_id}/host-binding",
        json={"asset_id": asset_id},
        headers=auth_headers_tenant_a_admin,
    )
    assert bind.status_code == 201, bind.text
    assert bind.json()["asset_id"] == asset_id

    got = client.get(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    assert got.status_code == 200
    assert got.json()["asset_id"] == asset_id
    assert got.json()["current_location"] is None

    with client.websocket_connect("/api/collectors/ws") as ws:
        _ws_session(client, ws, col_id, priv_key)
        # Monday: 192.168.1.25
        _heartbeat(ws, "192.168.1.25")

    got = client.get(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    assert got.json()["current_location"]["addresses"][0]["ip"] == "192.168.1.25"
    assert len(got.json()["observation_history"]) == 1

    with client.websocket_connect("/api/collectors/ws") as ws:
        _ws_session(client, ws, col_id, priv_key)
        # Tuesday, after DHCP move: 192.168.10.10 — location update, SAME identity
        _heartbeat(ws, "192.168.10.10")

    got = client.get(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    body = got.json()
    assert body["asset_id"] == asset_id  # identity anchor unchanged
    assert body["current_location"]["addresses"][0]["ip"] == "192.168.10.10"
    assert len(body["observation_history"]) == 2  # history retained

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT network_location FROM assets WHERE id = %s", (asset_id,))
            row = cur.fetchone()
            assert row["network_location"]["addresses"][0]["ip"] == "192.168.10.10"
            # no rebinding by IP: the routing edge stays untouched, no new assets appeared
            cur.execute("SELECT collector_id FROM assets WHERE id = %s", (asset_id,))
            routing = cur.fetchone()["collector_id"]
            cur.execute("SELECT collector_id FROM collector_host_bindings WHERE asset_id = %s", (asset_id,))
            bound = cur.fetchone()["collector_id"]
            cur.execute("SELECT COUNT(*) AS c FROM assets")
            assert cur.fetchone()["c"] == 1
            cur.execute("SELECT COUNT(*) AS c FROM asset_network_observations WHERE asset_id = %s", (asset_id,))
            assert cur.fetchone()["c"] == 2
    assert routing is None  # assets.collector_id is routing only — never the identity bind
    assert bound == uuid.UUID(col_id)

    # unbind removes the bind but not the asset or history
    unbind = client.delete(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    assert unbind.status_code == 200
    got = client.get(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    assert got.status_code == 404


def test_heartbeat_without_binding_is_noop(client, auth_headers_tenant_a_admin):
    col_id, priv_key = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Unbound Collector")
    with client.websocket_connect("/api/collectors/ws") as ws:
        _ws_session(client, ws, col_id, priv_key)
        _heartbeat(ws, "192.168.1.99")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM asset_network_observations WHERE collector_id = %s", (col_id,))
            assert cur.fetchone()["c"] == 0


def test_backward_compatible_heartbeat_without_network_state(client, auth_headers_tenant_a_admin):
    col_id, priv_key = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Legacy Heartbeat")
    with client.websocket_connect("/api/collectors/ws") as ws:
        _ws_session(client, ws, col_id, priv_key)
        ws.send_json({"type": "HEARTBEAT", "timestamp": "2026-09-24T12:00:00Z"})
        assert ws.receive_json()["type"] == "HEARTBEAT_ACK"


def test_binding_uniqueness_and_rebind_idempotent(client, auth_headers_tenant_a_admin):
    asset1 = _create_asset(client, auth_headers_tenant_a_admin, target="192.168.1.30", name="Host One")
    asset2 = _create_asset(client, auth_headers_tenant_a_admin, target="192.168.1.31", name="Host Two")
    col_a, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Collector A")
    col_b, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Collector B")

    assert client.put(f"/api/collectors/{col_a}/host-binding", json={"asset_id": asset1},
                      headers=auth_headers_tenant_a_admin).status_code == 201
    # asset already bound to another collector
    assert client.put(f"/api/collectors/{col_b}/host-binding", json={"asset_id": asset1},
                      headers=auth_headers_tenant_a_admin).status_code == 409
    # collector already bound to another asset
    assert client.put(f"/api/collectors/{col_a}/host-binding", json={"asset_id": asset2},
                      headers=auth_headers_tenant_a_admin).status_code == 409
    # same pair is idempotent
    again = client.put(f"/api/collectors/{col_a}/host-binding", json={"asset_id": asset1},
                       headers=auth_headers_tenant_a_admin)
    assert again.status_code in (200, 201)
    assert again.json()["already_bound"] is True


def test_binding_tenant_isolated(client, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin):
    asset_a = _create_asset(client, auth_headers_tenant_a_admin, target="192.168.1.40", name="Tenant A Host")
    col_b, _ = _enrolled_collector(client, auth_headers_tenant_b_admin, name="Tenant B Collector")
    res = client.put(
        f"/api/collectors/{col_b}/host-binding",
        json={"asset_id": asset_a},
        headers=auth_headers_tenant_b_admin,
    )
    assert res.status_code == 404  # zero cross-tenant existence disclosure


def test_binding_requires_internal_active_asset(client, auth_headers_tenant_a_admin):
    res = client.post(
        "/api/assets",
        json={
            "name": "Internet Asset",
            "asset_type": "server",
            "target_type": "domain",
            "target_value": "example.test",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "low",
        },
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 201
    internet_asset = res.json()["id"]
    col, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Internal Only")
    bind = client.put(
        f"/api/collectors/{col}/host-binding",
        json={"asset_id": internet_asset},
        headers=auth_headers_tenant_a_admin,
    )
    assert bind.status_code == 422


# --- Release-critical fail-closed gaps ---

from datetime import datetime, timedelta, timezone  # noqa: E402
from tests.conftest import TENANT_A  # noqa: E402
from tests.test_scout_sprint03 import MockCollectorWebSocket  # noqa: E402
from app.collector_registry import collector_registry  # noqa: E402


def test_stale_replaced_session_cannot_persist_heartbeat(client, auth_headers_tenant_a_admin):
    col_id, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Reconnect Collector")
    col_uuid = uuid.UUID(col_id)
    ws1 = MockCollectorWebSocket(col_uuid, TENANT_A)
    session1 = collector_registry.register_session(col_uuid, TENANT_A, ws1)
    ws2 = MockCollectorWebSocket(col_uuid, TENANT_A)
    session2 = collector_registry.register_session(col_uuid, TENANT_A, ws2)
    assert session2.session_id != session1.session_id
    # a heartbeat emitted by the stale (replaced) session is rejected...
    assert collector_registry.record_heartbeat(col_uuid, session_id=session1.session_id) is False
    # ...so the WS route (which gates persistence on this bool) cannot write
    # network_state from a replaced session. The live session still passes.
    assert collector_registry.record_heartbeat(col_uuid, session_id=session2.session_id) is True


def test_network_state_validation_and_monotonic_current(client, auth_headers_tenant_a_admin):
    asset_id = _create_asset(client, auth_headers_tenant_a_admin, target="192.168.1.25")
    col_id, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Validated Collector")
    assert client.put(f"/api/collectors/{col_id}/host-binding", json={"asset_id": asset_id},
                      headers=auth_headers_tenant_a_admin).status_code == 201
    col_uuid = uuid.UUID(col_id)

    # garbage is rejected outright: non-list addresses, invalid IP, bad entries
    for garbage in (
        {"observed_at": "2026-09-24T12:00:00+00:00", "addresses": "not-a-list"},
        {"observed_at": "2026-09-24T12:00:00+00:00", "addresses": [{"interface": "eth0", "ip": "999.1.2.3", "prefix": 24}]},
        {"observed_at": "2026-09-24T12:00:00+00:00", "addresses": [{"interface": "eth0", "ip": "192.168.1.25", "prefix": "x"}]},
        {"observed_at": "not-a-timestamp", "addresses": []},
        "totally-not-a-dict",
    ):
        assert collector_registry.record_network_observation(col_uuid, garbage) is None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM asset_network_observations WHERE asset_id = %s", (asset_id,))
            assert cur.fetchone()["c"] == 0

    t1 = datetime.now(timezone.utc)
    ok1 = collector_registry.record_network_observation(col_uuid, {
        "observed_at": t1.isoformat(),
        "addresses": [{"interface": "eth0", "ip": "192.168.1.25", "prefix": 24}],
    })
    assert ok1 is not None

    # an OLDER reordered frame never rolls the current location back,
    # but is still kept in append-only history
    ok2 = collector_registry.record_network_observation(col_uuid, {
        "observed_at": (t1 - timedelta(hours=1)).isoformat(),
        "addresses": [{"interface": "eth0", "ip": "192.168.1.99", "prefix": 24}],
    })
    assert ok2 is not None

    got = client.get(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    body = got.json()
    assert body["current_location"]["addresses"][0]["ip"] == "192.168.1.25"
    assert len(body["observation_history"]) == 2

    # oversized input is bounded to the first 64 entries
    flood = {"observed_at": datetime.now(timezone.utc).isoformat(),
             "addresses": [{"interface": f"i{n}", "ip": f"10.1.0.{n}", "prefix": 24} for n in range(1, 200)]}
    ok3 = collector_registry.record_network_observation(col_uuid, flood)
    assert ok3 is not None
    got = client.get(f"/api/collectors/{col_id}/host-binding", headers=auth_headers_tenant_a_admin)
    assert len(got.json()["current_location"]["addresses"]) == 64


def test_delete_collector_blocked_while_host_bound(client, auth_headers_tenant_a_admin):
    asset_id = _create_asset(client, auth_headers_tenant_a_admin, target="192.168.1.45", name="Delete Guard Host")
    col_id, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Delete Guard")
    assert client.put(f"/api/collectors/{col_id}/host-binding", json={"asset_id": asset_id},
                      headers=auth_headers_tenant_a_admin).status_code == 201

    assert client.post(f"/api/collectors/{col_id}/revoke", headers=auth_headers_tenant_a_admin).status_code == 200
    # deletion must NOT cascade-destroy the identity bind and location history
    blocked = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert blocked.status_code == 409
    assert "host binding" in blocked.json()["detail"]

    # explicit unbind makes deletion possible
    assert client.delete(f"/api/collectors/{col_id}/host-binding",
                         headers=auth_headers_tenant_a_admin).status_code == 200
    deleted = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert deleted.status_code == 204


def _seed_approved_auth(asset_id, normalized_target):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    tenant_id, asset_id, target_type, normalized_target, network_scope,
                    status, requested_by, approved_by, approved_at, expires_at
                ) VALUES (%s, %s, 'ip', %s, 'internal', 'approved',
                          'fixture', 'fixture', now(), %s)
                RETURNING id
                """,
                (str(TENANT_A), str(asset_id), normalized_target,
                 datetime.now(timezone.utc) + timedelta(hours=1)),
            )
            auth_id = cur.fetchone()["id"]
        conn.commit()
    return auth_id


def test_target_mismatch_blocks_dispatch_until_operator_confirms(client, auth_headers_tenant_a_admin):
    asset_id = _create_asset(client, auth_headers_tenant_a_admin, target="192.168.1.61", name="Mismatch Host")
    col_id, _ = _enrolled_collector(client, auth_headers_tenant_a_admin, name="Mismatch Collector")
    col_uuid = uuid.UUID(col_id)
    # route the asset to the collector (assets.collector_id — routing edge only)
    assert client.put(f"/api/assets/{asset_id}", json={"collector_id": col_id},
                      headers=auth_headers_tenant_a_admin).status_code == 200
    assert client.put(f"/api/collectors/{col_id}/host-binding", json={"asset_id": asset_id},
                      headers=auth_headers_tenant_a_admin).status_code == 201
    _seed_approved_auth(asset_id, "192.168.1.61")

    ws = MockCollectorWebSocket(col_uuid, TENANT_A, caps={
        "nmap": {"available": True, "version": "7.94", "templates_version": None},
    })
    session = collector_registry.register_session(col_uuid, TENANT_A, ws)
    session.capabilities = ws.caps

    # host DHCP-moves and now reports an address that is NOT the asset target
    result = collector_registry.record_network_observation(col_uuid, {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "addresses": [{"interface": "eth0", "ip": "192.168.10.61", "prefix": 24}],
    })
    assert result is not None and result["target_mismatch"] is True

    # fail-closed: prior authorization revoked, dispatch blocked
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT target_validation_state FROM assets WHERE id = %s", (asset_id,))
            assert cur.fetchone()["target_validation_state"] == "needs_revalidation"
            cur.execute(
                "SELECT status FROM asset_scan_authorizations WHERE asset_id = %s",
                (asset_id,),
            )
            assert all(row["status"] == "revoked" for row in cur.fetchall())

    blocked = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert blocked.status_code == 409
    assert "revalidation" in blocked.json()["detail"]

    # operator confirms the relocation on the SAME asset row, re-approves
    moved = client.put(f"/api/assets/{asset_id}", json={"target_value": "192.168.10.61"},
                       headers=auth_headers_tenant_a_admin)
    assert moved.status_code == 200
    assert moved.json()["id"] == asset_id  # identity preserved
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT target_validation_state FROM assets WHERE id = %s", (asset_id,))
            assert cur.fetchone()["target_validation_state"] == "ok"
    _seed_approved_auth(asset_id, "192.168.10.61")

    relaunched = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert relaunched.status_code == 201
    assert relaunched.json()["collector_id"] == col_id
    assert any(f.get("type") == "SCOUT_JOB" and f.get("target") == "192.168.10.61" for f in ws.sent_frames)

    # a matching heartbeat report clears nothing improperly / stays consistent
    ok_match = collector_registry.record_network_observation(col_uuid, {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "addresses": [{"interface": "eth0", "ip": "192.168.10.61", "prefix": 24}],
    })
    assert ok_match["target_mismatch"] is False
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT target_validation_state FROM assets WHERE id = %s", (asset_id,))
            assert cur.fetchone()["target_validation_state"] == "ok"
