# tests/test_scout_dhcp_continuity.py
# PRD V3 §2.12 / §2.11 #7 context: a laptop Collector on a DHCP network keeps
# an OUTBOUND WSS session; SCOUT jobs to another device on that network must
# route by collector_id over the authenticated session — never by the laptop's
# IP — and must survive a laptop disconnect/reconnect. A scanned device's own
# DHCP move is an operator-confirmed target relocation on the SAME asset row
# (identity stable, authorizations revoked, no silent rebind).
import uuid
from datetime import datetime, timedelta, timezone

from tests.conftest import TENANT_A
from tests.test_scout_sprint03 import (
    MockCollectorWebSocket,
    setup_connected_collector,
)
from app.collector_registry import collector_registry
from app.db import get_db_connection


def _insert_approved_authorization(asset_id: uuid.UUID, target: str) -> uuid.UUID:
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
                (str(TENANT_A), str(asset_id), target, datetime.now(timezone.utc) + timedelta(hours=1)),
            )
            auth_id = cur.fetchone()["id"]
        conn.commit()
    return auth_id


def test_job_routing_survives_collector_reconnect_and_target_relocation(
    client, auth_headers_tenant_a_admin
):
    # Laptop collector connected on 192.168.1.x; scanned device (e.g. router)
    # is at 192.168.1.1. Job dispatch must reference only the target and the
    # collector identity — never the laptop's own IP.
    col_id, asset_id, auth_id, ws = setup_connected_collector(
        target="192.168.1.1", mode="success"
    )
    old_session_id = collector_registry.get_session(col_id).session_id

    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 201
    first_job = res.json()
    assert first_job["route"] == "COLLECTOR_INTERNAL"
    assert first_job["collector_id"] == str(col_id)
    assert ws.sent_frames[0]["target"] == "192.168.1.1"
    frame_json = repr(ws.sent_frames[0])
    assert "192.168.1." not in frame_json.replace("192.168.1.1", "")  # no laptop-IP field

    # DHCP events: the laptop renews to a different address and reconnects
    # (new WSS session, same collector identity), while the scanned device
    # itself moves 192.168.1.1 -> 192.168.10.10.
    collector_registry.unregister_session(
        col_id, session_id=old_session_id, reason="test: laptop reconnect"
    )
    new_ws = MockCollectorWebSocket(col_id, TENANT_A, mode="success")
    new_session = collector_registry.register_session(col_id, TENANT_A, new_ws)
    new_session.capabilities = new_ws.caps
    assert new_session.session_id != old_session_id

    put_res = client.put(
        f"/api/assets/{asset_id}",
        json={"target_value": "192.168.10.10"},
        headers=auth_headers_tenant_a_admin,
    )
    assert put_res.status_code == 200
    relocated = put_res.json()
    # Identity anchor: the asset row id survives the address change
    assert relocated["id"] == str(asset_id)
    assert relocated["normalized_target"] == "192.168.10.10"

    # Old authorization was revoked by the tuple change (fail-closed, no silent rebind)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM asset_scan_authorizations WHERE id = %s",
                (str(auth_id),),
            )
            assert cur.fetchone()["status"] == "revoked"
    _insert_approved_authorization(asset_id, "192.168.10.10")

    res2 = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res2.status_code == 201
    second_job = res2.json()
    assert second_job["collector_id"] == str(col_id)

    # Job routed over the NEW session; old session received nothing further
    assert any(
        f.get("type") == "SCOUT_JOB" and f.get("target") == "192.168.10.10"
        for f in new_ws.sent_frames
    )
    assert len(ws.sent_frames) == 1

    # No laptop-IP-shaped field exists anywhere in the dispatched frame
    scout_frame = next(f for f in new_ws.sent_frames if f.get("type") == "SCOUT_JOB")
    assert set(scout_frame) <= {
        "type", "job_id", "engine", "profile", "target", "target_type",
        "network_scope", "timeout_seconds", "expires_at",
    }
