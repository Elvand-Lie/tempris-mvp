# backend/tests/test_assets_stats.py
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_asset_stats_five_counters_and_invariants(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst,
    auth_headers_tenant_b_admin
):
    # 1. Initial empty state: all 5 counters are 0
    init_stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_analyst).json()
    assert init_stats == {
        "total_assets": 0,
        "reachable_by_scout": 0,
        "authorized_to_scan": 0,
        "pending_authorization": 0,
        "no_scanner_available": 0
    }

    # 2. Asset 1: Active, Internet scope, verified reachability, approved future authorization
    res1 = client.post(
        "/api/assets",
        json={
            "name": "Asset 1 Internet Verified Approved",
            "asset_type": "web_app",
            "target_type": "domain",
            "target_value": "one.example.com",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_1_id = res1.json()["id"]

    # Mark reachability as verified in DB with compatible verification_source
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE assets SET reachability_status = 'verified', verification_source = 'tempris_cloud', last_verified_at = now() WHERE id = %s;",
                (asset_1_id,)
            )
        conn.commit()

    # Approve authorization
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    client.post(
        f"/api/assets/{asset_1_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_admin
    )

    # 3. Asset 2: Active, Internet scope, unverified reachability, pending authorization
    res2 = client.post(
        "/api/assets",
        json={
            "name": "Asset 2 Internet Unverified Pending",
            "asset_type": "api",
            "target_type": "domain",
            "target_value": "two.example.com",
            "network_scope": "internet",
            "environment": "staging",
            "criticality": "medium"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_2_id = res2.json()["id"]

    client.post(
        f"/api/assets/{asset_2_id}/scan-authorization/request",
        json={"request_reason": "Pre-deployment scan"},
        headers=auth_headers_tenant_a_analyst
    )

    # 4. Asset 3: Active, Internal scope, unverified reachability, approved authorization
    res3 = client.post(
        "/api/assets",
        json={
            "name": "Asset 3 Internal Approved",
            "asset_type": "database",
            "target_type": "ip",
            "target_value": "10.50.0.1",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "critical"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_3_id = res3.json()["id"]

    client.post(
        f"/api/assets/{asset_3_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_admin
    )

    # 5. Asset 4: Active, Internet scope, verified reachability, EXPIRED authorization
    res4 = client.post(
        "/api/assets",
        json={
            "name": "Asset 4 Expired Authorization",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "93.184.216.34",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_4_id = res4.json()["id"]

    # Mark reachability verified with compatible source and insert expired authorization directly in DB
    past_expiry = datetime.now(timezone.utc) - timedelta(days=2)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE assets SET reachability_status = 'verified', verification_source = 'tempris_cloud', last_verified_at = now() WHERE id = %s;",
                (asset_4_id,)
            )
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    id, tenant_id, asset_id, target_type, normalized_target,
                    network_scope, status, requested_by, approved_by, approved_at, expires_at
                ) VALUES (
                    gen_random_uuid(), '11111111-1111-1111-1111-111111111111', %s, 'ip', '93.184.216.34',
                    'internet', 'approved', 'admin-a', 'admin-a', now(), %s
                );
                """,
                (asset_4_id, past_expiry)
            )
        conn.commit()

    # 6. Asset 5: Decommissioned asset with approved authorization (must be excluded from ALL counters)
    res5 = client.post(
        "/api/assets",
        json={
            "name": "Asset 5 Decommissioned",
            "asset_type": "server",
            "target_type": "domain",
            "target_value": "decom.example.com",
            "network_scope": "internet",
            "environment": "development",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_5_id = res5.json()["id"]

    client.post(
        f"/api/assets/{asset_5_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_admin
    )
    client.post(f"/api/assets/{asset_5_id}/decommission", headers=auth_headers_tenant_a_admin)

    # Check Tenant A stats
    stats_a = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
    assert stats_a["total_assets"] == 4                # Assets 1, 2, 3, 4 (Asset 5 is decommissioned)
    assert stats_a["reachable_by_scout"] == 2          # Assets 1, 4 (internet + verified)
    assert stats_a["authorized_to_scan"] == 2          # Assets 1, 3 (approved + non-expired; Asset 4 is expired, 5 is decom)
    assert stats_a["pending_authorization"] == 1       # Asset 2
    assert stats_a["no_scanner_available"] == 1        # Asset 3 (internal scope)

    # 7. Check Multi-Tenant isolation: Tenant B stats remain 0
    stats_b = client.get("/api/assets/stats", headers=auth_headers_tenant_b_admin).json()
    assert stats_b == {
        "total_assets": 0,
        "reachable_by_scout": 0,
        "authorized_to_scan": 0,
        "pending_authorization": 0,
        "no_scanner_available": 0
    }

    # 8. Mutating target of Asset 1 invalidates its authorization -> authorized_to_scan decrements to 1
    client.put(
        f"/api/assets/{asset_1_id}",
        json={"target_value": "one-mutated.example.com"},
        headers=auth_headers_tenant_a_admin
    )
    stats_after_mutation = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
    assert stats_after_mutation["authorized_to_scan"] == 1 # Only Asset 3 remains authorized
    assert stats_after_mutation["reachable_by_scout"] == 1 # Asset 1 reachability was reset to unverified on mutation

def test_reachable_by_scout_requires_compatible_verification_source(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    # 1. Create internet asset with verified reachability but NULL verification_source
    res_null_src = client.post(
        "/api/assets",
        json={
            "name": "Internet Asset Null Source",
            "asset_type": "web_app",
            "target_type": "domain",
            "target_value": "null-src.example.com",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_null_id = res_null_src.json()["id"]

    # 2. Create internet asset with verified reachability but incompatible verification_source ('internal_probe')
    res_incompat_src = client.post(
        "/api/assets",
        json={
            "name": "Internet Asset Incompatible Source",
            "asset_type": "web_app",
            "target_type": "domain",
            "target_value": "incompat-src.example.com",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_incompat_id = res_incompat_src.json()["id"]

    # 3. Create internet asset with verified reachability and compatible 'tempris_cloud' source
    res_compat = client.post(
        "/api/assets",
        json={
            "name": "Internet Asset Compatible Source",
            "asset_type": "web_app",
            "target_type": "domain",
            "target_value": "compat-src.example.com",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_compat_id = res_compat.json()["id"]

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE assets SET reachability_status = 'verified', verification_source = NULL WHERE id = %s;", (asset_null_id,))
            cur.execute("UPDATE assets SET reachability_status = 'verified', verification_source = 'internal_probe' WHERE id = %s;", (asset_incompat_id,))
            cur.execute("UPDATE assets SET reachability_status = 'verified', verification_source = 'tempris_cloud' WHERE id = %s;", (asset_compat_id,))
        conn.commit()

    stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
    assert stats["total_assets"] == 3
    # Only the asset with compatible verification_source = 'tempris_cloud' is counted
    assert stats["reachable_by_scout"] == 1


TENANT_A = "11111111-1111-1111-1111-111111111111"

from app.collector_registry import collector_registry


def _insert_collector(collector_id, tenant_id, enrollment_status="enrolled", operator_status="active"):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collectors (id, tenant_id, name, description,
                    enrollment_status, operator_status, public_key)
                VALUES (%s, %s, %s, 'scanner-metric test collector', %s, %s, 'dGVzdC1rZXk=');
                """,
                (str(collector_id), str(tenant_id), f"collector-{collector_id.hex[:8]}",
                 enrollment_status, operator_status),
            )
        conn.commit()


def _delete_collector(collector_id):
    collector_registry.unregister_session(collector_id, reason="test teardown")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM collectors WHERE id = %s;", (str(collector_id),))
        conn.commit()


class _FakeSocket:
    def send_text(self, payload):
        pass

    async def receive_text(self):
        return ""


def _connect_collector(collector_id, tenant_id, nmap_available=True):
    session = collector_registry.register_session(
        collector_id=collector_id,
        tenant_id=tenant_id,
        websocket=_FakeSocket(),
        operator_status="active",
    )
    session.capabilities = {"nmap": {"available": nmap_available, "version": "7.99"}}
    return session


def _create_internal_asset(client, headers, collector_id=None, target="10.60.0.1"):
    res = client.post(
        "/api/assets",
        json={
            "name": f"Internal Asset {target}",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": target,
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high",
            **({"collector_id": str(collector_id)} if collector_id else {}),
        },
        headers=headers,
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def test_connected_capable_collector_satisfies_internal_asset(
    client,
    auth_headers_tenant_a_admin,
):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id, TENANT_A)
    try:
        _connect_collector(collector_id, uuid.UUID(TENANT_A), nmap_available=True)
        _create_internal_asset(client, auth_headers_tenant_a_admin, collector_id=collector_id)
        stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
        assert stats["no_scanner_available"] == 0
    finally:
        _delete_collector(collector_id)


def test_disconnected_collector_leaves_internal_asset_uncovered(
    client,
    auth_headers_tenant_a_admin,
):
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    collector_id = uuid.uuid4()
    _insert_collector(collector_id, TENANT_A)
    try:
        session = _connect_collector(collector_id, uuid.UUID(TENANT_A))
        session.last_heartbeat_at = _dt.now(_tz.utc) - _td(seconds=120)
        _create_internal_asset(client, auth_headers_tenant_a_admin, collector_id=collector_id)
        stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
        assert stats["no_scanner_available"] == 1
    finally:
        _delete_collector(collector_id)


def test_missing_collector_assignment_counts_as_no_scanner(
    client,
    auth_headers_tenant_a_admin,
):
    _create_internal_asset(client, auth_headers_tenant_a_admin)
    stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
    assert stats["no_scanner_available"] == 1


def test_collector_without_nmap_capability_is_incompatible(
    client,
    auth_headers_tenant_a_admin,
):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id, TENANT_A)
    try:
        _connect_collector(collector_id, uuid.UUID(TENANT_A), nmap_available=False)
        _create_internal_asset(client, auth_headers_tenant_a_admin, collector_id=collector_id)
        stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
        assert stats["no_scanner_available"] == 1
    finally:
        _delete_collector(collector_id)


def test_paused_collector_does_not_satisfy_internal_asset(
    client,
    auth_headers_tenant_a_admin,
):
    collector_id = uuid.uuid4()
    _insert_collector(collector_id, TENANT_A, operator_status="paused")
    try:
        _connect_collector(collector_id, uuid.UUID(TENANT_A))
        _create_internal_asset(client, auth_headers_tenant_a_admin, collector_id=collector_id)
        stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
        assert stats["no_scanner_available"] == 1
    finally:
        _delete_collector(collector_id)


def test_foreign_tenant_collector_never_satisfies_internal_asset(
    client,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_b_admin,
):
    # Cross-tenant routing must be refused at creation (existence disclosure guard)...
    res = client.post(
        "/api/assets",
        json={
            "name": "Internal Asset Cross Tenant",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.70.0.1",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high",
            "collector_id": str(uuid.uuid4()),
        },
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 404

    # ...and even a hand-crafted cross-tenant assignment never satisfies the metric,
    # even though that collector is connected and capable in tenant B.
    foreign_collector_id = uuid.uuid4()
    _insert_collector(foreign_collector_id, "22222222-2222-2222-2222-222222222222")
    try:
        _connect_collector(foreign_collector_id, uuid.UUID("22222222-2222-2222-2222-222222222222"))
        asset_id = _create_internal_asset(
            client, auth_headers_tenant_b_admin, collector_id=foreign_collector_id
        )
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE assets SET collector_id = %s, tenant_id = %s WHERE id = %s;",
                    (str(foreign_collector_id), TENANT_A, asset_id),
                )
            conn.commit()
        stats = client.get("/api/assets/stats", headers=auth_headers_tenant_a_admin).json()
        assert stats["no_scanner_available"] == 1
    finally:
        _delete_collector(foreign_collector_id)
