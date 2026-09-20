import asyncio
import json
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from app.auth import create_test_token
from app.collector_registry import collector_registry, CollectorSession
from app.db import get_db_connection
from app.exposure.models import ExposureConfirm, FindingCreate
from app.exposure.service import confirm_exposure, create_finding
from app.scout import (
    NMAP_TIMEOUT,
    NUCLEI_TIMEOUT,
    AuthorizationInvalid,
    ToolProbe,
    _execute_collector_job,
    _job_row,
    _normalize_nuclei_observation,
    _validate_locked,
    execute_job,
)
from migrations.runner import run_migrations
from tests.conftest import TENANT_A, TENANT_B
from tests.test_scout_sprint01 import fixture
from tests.test_scout_sprint02 import CVE_ID, nuclei_event, seed_canonical

_TARGET_COUNTER = 100


def next_target():
    global _TARGET_COUNTER
    _TARGET_COUNTER += 1
    return f"10.0.1.{_TARGET_COUNTER}"


class MockCollectorWebSocket:
    def __init__(
        self,
        col_id: uuid.UUID,
        tenant_id: uuid.UUID,
        mode: str = "success",
        caps: dict = None,
        nuclei_stdout: str = None,
    ):
        self.col_id = col_id
        self.tenant_id = tenant_id
        self.mode = mode
        self.caps = caps or {
            "nmap": {"available": True, "version": "7.94", "templates_version": None},
            "nuclei": {"available": True, "version": "3.8.0", "templates_version": "10.2.0"},
        }
        self.nuclei_stdout = nuclei_stdout or json.dumps(nuclei_event(CVE_ID))
        self.sent_frames: list[dict] = []
        self.on_frame_received = None

    async def send_text(self, text: str):
        data = json.loads(text)
        self.sent_frames.append(data)
        if self.on_frame_received:
            self.on_frame_received(data)

        frame_type = data.get("type")
        if frame_type == "SCOUT_JOB":
            job_id = data["job_id"]
            engine = data["engine"]

            if self.mode == "success":
                now_str = datetime.now(timezone.utc).isoformat()
                if engine == "nmap":
                    stdout = fixture("nmap_valid.xml").decode("utf-8")
                else:
                    stdout = self.nuclei_stdout
                res = {
                    "type": "SCOUT_JOB_RESULT",
                    "job_id": job_id,
                    "engine": engine,
                    "status": "completed",
                    "exit_code": 0,
                    "stdout": stdout,
                    "stderr": "",
                    "stdout_bytes": len(stdout),
                    "stderr_bytes": 0,
                    "started_at": now_str,
                    "completed_at": now_str,
                    "error_message": None,
                }
                collector_registry.handle_scout_job_result(self.col_id, res)

            elif self.mode == "nmap_success_nuclei_failure":
                now_str = datetime.now(timezone.utc).isoformat()
                if engine == "nmap":
                    stdout = fixture("nmap_valid.xml").decode("utf-8")
                    res = {
                        "type": "SCOUT_JOB_RESULT",
                        "job_id": job_id,
                        "engine": engine,
                        "status": "completed",
                        "exit_code": 0,
                        "stdout": stdout,
                        "stderr": "",
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": 0,
                        "started_at": now_str,
                        "completed_at": now_str,
                        "error_message": None,
                    }
                else:
                    res = {
                        "type": "SCOUT_JOB_RESULT",
                        "job_id": job_id,
                        "engine": engine,
                        "status": "failed",
                        "exit_code": 1,
                        "stdout": "",
                        "stderr": "nuclei runner error",
                        "stdout_bytes": 0,
                        "stderr_bytes": 19,
                        "started_at": now_str,
                        "completed_at": now_str,
                        "error_message": "nuclei execution failed with exit code 1",
                    }
                collector_registry.handle_scout_job_result(self.col_id, res)

            elif self.mode == "tool_failed":
                now_str = datetime.now(timezone.utc).isoformat()
                res = {
                    "type": "SCOUT_JOB_RESULT",
                    "job_id": job_id,
                    "engine": engine,
                    "status": "failed",
                    "exit_code": 2,
                    "stdout": "",
                    "stderr": f"{engine} process failed",
                    "stdout_bytes": 0,
                    "stderr_bytes": len(engine) + 15,
                    "started_at": now_str,
                    "completed_at": now_str,
                    "error_message": f"{engine} scan failed with exit code 2",
                }
                collector_registry.handle_scout_job_result(self.col_id, res)

            elif self.mode == "parse_failed":
                now_str = datetime.now(timezone.utc).isoformat()
                res = {
                    "type": "SCOUT_JOB_RESULT",
                    "job_id": job_id,
                    "engine": engine,
                    "status": "completed",
                    "exit_code": 0,
                    "stdout": "<malformed-xml-or-json",
                    "stderr": "",
                    "stdout_bytes": 22,
                    "stderr_bytes": 0,
                    "started_at": now_str,
                    "completed_at": now_str,
                    "error_message": None,
                }
                collector_registry.handle_scout_job_result(self.col_id, res)

            elif self.mode == "timeout":
                pass  # do not reply

            elif self.mode == "disconnect":
                collector_registry.unregister_session(self.col_id, reason="Simulated disconnect")

            elif self.mode == "rejected_concurrency":
                now_str = datetime.now(timezone.utc).isoformat()
                res = {
                    "type": "SCOUT_JOB_RESULT",
                    "job_id": job_id,
                    "engine": engine,
                    "status": "rejected",
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                    "started_at": now_str,
                    "completed_at": now_str,
                    "error_message": "concurrency_limit_exceeded",
                }
                collector_registry.handle_scout_job_result(self.col_id, res)

    async def close(self, code=1000, reason=""):
        pass


def create_collector_and_internal_asset(
    tenant_id=TENANT_A,
    target=None,
    col_name="Test Collector",
    operator_status="active",
    enrollment_status="enrolled",
    auth_status="approved",
    auth_expires_delta=timedelta(hours=1),
):
    if target is None:
        target = next_target()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collectors (tenant_id, name, enrollment_status, operator_status)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (str(tenant_id), col_name, enrollment_status, operator_status),
            )
            collector_id = cur.fetchone()["id"]

            cur.execute(
                """
                INSERT INTO assets (
                    tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, collector_id
                ) VALUES (%s, 'Internal Asset', 'server', 'ip', %s, %s,
                          'internal', 'test', 'high', %s)
                RETURNING id
                """,
                (str(tenant_id), target, target, str(collector_id)),
            )
            asset_id = cur.fetchone()["id"]

            expires_at = datetime.now(timezone.utc) + auth_expires_delta
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    tenant_id, asset_id, target_type, normalized_target, network_scope,
                    status, requested_by, approved_by, approved_at, expires_at
                ) VALUES (%s, %s, 'ip', %s, 'internal', %s,
                          'fixture', 'fixture', now(), %s)
                RETURNING id
                """,
                (str(tenant_id), str(asset_id), target, auth_status, expires_at),
            )
            authorization_id = cur.fetchone()["id"]
        conn.commit()

    return collector_id, asset_id, authorization_id


def setup_connected_collector(
    tenant_id=TENANT_A,
    target=None,
    mode="success",
    caps=None,
    operator_status="active",
    enrollment_status="enrolled",
    auth_expires_delta=timedelta(hours=1),
):
    col_id, asset_id, auth_id = create_collector_and_internal_asset(
        tenant_id=tenant_id,
        target=target,
        operator_status=operator_status,
        enrollment_status=enrollment_status,
        auth_expires_delta=auth_expires_delta,
    )
    ws = MockCollectorWebSocket(col_id, tenant_id, mode=mode, caps=caps)
    session = collector_registry.register_session(
        col_id, tenant_id, ws, operator_status=operator_status
    )
    session.capabilities = ws.caps
    return col_id, asset_id, auth_id, ws


def test_migration_015_composite_foreign_key_and_checks():
    with get_db_connection() as conn:
        run_migrations(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT conname, contype FROM pg_constraint
                WHERE conrelid = 'scout_jobs'::regclass
                """
            )
            constraints = {row["conname"]: row["contype"] for row in cur.fetchall()}

    assert "fk_scout_job_collector" in constraints
    assert "scout_jobs_route_check" in constraints
    assert "scout_jobs_network_scope_check" in constraints
    assert "scout_jobs_route_scope_collector_check" in constraints

    target = next_target()
    col_id, asset_id, auth_id = create_collector_and_internal_asset(target=target)

    # Valid COLLECTOR_INTERNAL
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scout_jobs (
                    tenant_id, asset_id, authorization_id, profile, route, target_type,
                    normalized_target, network_scope, authorization_approved_at,
                    authorization_expires_at, requested_by, collector_id
                ) VALUES (%s, %s, %s, 'SERVICE_DISCOVERY', 'COLLECTOR_INTERNAL', 'ip',
                          %s, 'internal', now(), now() + interval '1 hour', 'fixture', %s)
                RETURNING id
                """,
                (str(TENANT_A), str(asset_id), str(auth_id), target, str(col_id)),
            )
            job_id = cur.fetchone()["id"]
        conn.commit()

    # Immutable collector_id trigger verification
    other_col_id, _, _ = create_collector_and_internal_asset(col_name="Other Col")
    with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scout_jobs SET collector_id = %s WHERE id = %s",
                    (str(other_col_id), str(job_id)),
                )

    # Inconsistent route / scope / collector_id check violation
    with pytest.raises(psycopg.errors.CheckViolation):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scout_jobs (
                        tenant_id, asset_id, authorization_id, profile, route, target_type,
                        normalized_target, network_scope, authorization_approved_at,
                        authorization_expires_at, requested_by, collector_id
                    ) VALUES (%s, %s, %s, 'SERVICE_DISCOVERY', 'CENTRAL_PUBLIC', 'ip',
                              %s, 'internal', now(), now() + interval '1 hour', 'fixture', NULL)
                    """,
                    (str(TENANT_A), str(asset_id), str(auth_id), target),
                )


def test_scout_capabilities_ingestion_and_readiness_redaction(
    client, auth_headers_tenant_a_admin
):
    col_id, _, _, ws = setup_connected_collector()
    res = client.get("/api/scout/readiness", headers=auth_headers_tenant_a_admin)
    assert res.status_code == 200
    body = res.json()

    assert "collectors_summary" in body
    assert body["collectors_summary"]["total"] >= 1
    assert body["collectors_summary"]["connected"] >= 1
    assert body["collectors_summary"]["capable"] >= 1

    col_entry = next((c for c in body["collectors"] if c["id"] == str(col_id)), None)
    assert col_entry is not None
    assert col_entry["connected"] is True
    assert col_entry["capabilities"]["nmap"]["available"] is True
    assert col_entry["capabilities"]["nmap"]["version"] == "7.94"
    assert col_entry["capabilities"]["nuclei"]["available"] is True
    assert col_entry["capabilities"]["nuclei"]["version"] == "3.8.0"

    raw_json = json.dumps(body)
    # Redaction checks: paths and private stderr must never be exposed
    assert "executable_path" not in raw_json
    assert "C:\\" not in raw_json
    assert "/usr/bin" not in raw_json
    assert "private stderr" not in raw_json


def test_internal_asset_launch_eligibility_and_dispatch_frame(
    client, auth_headers_tenant_a_admin
):
    target = next_target()
    col_id, asset_id, auth_id, ws = setup_connected_collector(target=target, mode="success")

    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 201
    job_data = res.json()
    assert job_data["route"] == "COLLECTOR_INTERNAL"
    assert job_data["network_scope"] == "internal"
    assert job_data["collector_id"] == str(col_id)

    assert len(ws.sent_frames) >= 1
    scout_job_frame = ws.sent_frames[0]
    assert scout_job_frame["type"] == "SCOUT_JOB"
    assert scout_job_frame["engine"] == "nmap"
    assert scout_job_frame["profile"] == "SERVICE_DISCOVERY"
    assert scout_job_frame["target"] == target
    assert scout_job_frame["target_type"] == "ip"
    assert scout_job_frame["network_scope"] == "internal"
    assert scout_job_frame["timeout_seconds"] == NMAP_TIMEOUT
    assert "expires_at" in scout_job_frame

    # Verify no arbitrary execution controls in frame
    assert "flags" not in scout_job_frame
    assert "command" not in scout_job_frame
    assert "proxy" not in scout_job_frame
    assert "custom_templates" not in scout_job_frame


def test_two_phase_nmap_success_nuclei_failure_semantics(
    client, auth_headers_tenant_a_admin
):
    seed_canonical(CVE_ID)
    target = next_target()
    col_id, asset_id, auth_id, ws = setup_connected_collector(
        target=target, mode="nmap_success_nuclei_failure"
    )

    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 201
    job_id = res.json()["id"]

    job = client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "failed"
    assert job["error_code"] == "tool_failed"

    health = job["source_health"]
    assert len(health) == 2
    assert health[0]["engine"] == "nmap" and health[0]["state"] == "succeeded"
    assert health[1]["engine"] == "nuclei" and health[1]["state"] == "failed"

    observations = client.get(
        f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
    ).json()
    assert len(observations) > 0
    assert all(row["scanner"] == "nmap" for row in observations)

    # Zero Findings or Exposures written to Exposure Domain
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) AS count FROM asset_exposures
                WHERE tenant_id = %s AND asset_id = %s
                """,
                (str(TENANT_A), str(asset_id)),
            )
            assert cur.fetchone()["count"] == 0


def test_atomic_in_flight_jobs_pop_replay_guard(client, auth_headers_tenant_a_admin):
    col_id, asset_id, auth_id, ws = setup_connected_collector(mode="timeout")

    session = collector_registry.get_session(col_id)
    assert session is not None

    job_id = uuid.uuid4()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    fut = loop.create_future()
    session.in_flight_jobs[job_id] = fut

    result_payload = {
        "job_id": str(job_id),
        "engine": "nmap",
        "status": "completed",
        "exit_code": 0,
        "stdout": "<valid></valid>",
        "stderr": "",
        "stdout_bytes": 15,
        "stderr_bytes": 0,
    }

    # First pop succeeds
    assert collector_registry.handle_scout_job_result(col_id, result_payload) is True
    assert fut.done() is True

    # Replay is atomically discarded
    assert collector_registry.handle_scout_job_result(col_id, result_payload) is False

    # Unmatched job_id is discarded
    fake_result = dict(result_payload, job_id=str(uuid.uuid4()))
    assert collector_registry.handle_scout_job_result(col_id, fake_result) is False

    loop.close()


def test_pre_ingestion_validate_locked_recheck_fails_with_authorization_invalid(
    client, auth_headers_tenant_a_admin
):
    target = next_target()
    col_id, asset_id, auth_id, ws = setup_connected_collector(target=target, mode="success")

    # When the frame is dispatched, invalidate authorization before the result is handled
    def on_frame(data):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE asset_scan_authorizations SET status = 'revoked' WHERE id = %s",
                    (str(auth_id),),
                )
            conn.commit()

    ws.on_frame_received = on_frame

    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 201
    job_id = res.json()["id"]

    job = client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "failed"
    assert job["error_code"] == "authorization_invalid"

    observations = client.get(
        f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
    ).json()
    assert observations == []


def test_collector_disconnect_and_timeout_fail_closed(
    client, auth_headers_tenant_a_admin, monkeypatch
):
    # Test 1: Disconnect
    target1 = next_target()
    col_id1, asset_id1, auth_id1, ws1 = setup_connected_collector(target=target1, mode="disconnect")
    res1 = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id1), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res1.status_code == 201
    job_id1 = res1.json()["id"]
    job1 = client.get(f"/api/scout/jobs/{job_id1}", headers=auth_headers_tenant_a_admin).json()
    assert job1["status"] == "failed"
    assert job1["error_code"] == "collector_disconnected"

    # Test 2: Timeout (monkeypatched to 0.1s for fast execution)
    monkeypatch.setattr("app.scout.NMAP_TIMEOUT", 0.1)
    target2 = next_target()
    col_id2, asset_id2, auth_id2, ws2 = setup_connected_collector(target=target2, mode="timeout")
    res2 = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id2), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res2.status_code == 201
    job_id2 = res2.json()["id"]
    job2 = client.get(f"/api/scout/jobs/{job_id2}", headers=auth_headers_tenant_a_admin).json()
    assert job2["status"] == "failed"
    assert job2["error_code"] == "collector_timeout"


def test_qualifying_internal_nuclei_observation_normalizes_to_exposure(
    client, auth_headers_tenant_a_admin
):
    seed_canonical(CVE_ID)
    target = next_target()
    col_id, asset_id, auth_id, ws = setup_connected_collector(target=target, mode="success")

    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 201
    job_id = res.json()["id"]

    job = client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "succeeded"

    observations = client.get(
        f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
    ).json()
    vulnerability = next((r for r in observations if r["scanner"] == "nuclei"), None)
    assert vulnerability is not None
    assert vulnerability["normalized_exposure"] is not None
    assert vulnerability["normalized_exposure"]["canonical_cve_id"] == CVE_ID
    assert vulnerability["normalized_exposure"]["status"] == "confirmed"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT f.*, e.id AS exposure_id, e.status AS exposure_status
                FROM findings f
                JOIN asset_exposures e ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
                WHERE f.tenant_id = %s AND e.asset_id = %s AND f.canonical_cve_id = %s
                """,
                (str(TENANT_A), str(asset_id), CVE_ID),
            )
            row = cur.fetchone()
            assert row is not None
            assert row["exposure_status"] == "confirmed"


def test_cross_tenant_isolation_strictly_enforced(
    client, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
):
    col_a, asset_a, auth_a, ws_a = setup_connected_collector(tenant_id=TENANT_A)
    col_b, asset_b, auth_b, ws_b = setup_connected_collector(tenant_id=TENANT_B)

    # Tenant A cannot launch on Tenant B's asset
    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_b), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 404

    # Tenant B cannot launch on Tenant A's asset
    res_b = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_a), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_b_admin,
    )
    assert res_b.status_code == 404


def test_inactive_or_quarantined_collector_launch_rejected(
    client, auth_headers_tenant_a_admin
):
    for status in ("paused", "quarantined", "revoked"):
        col_id, asset_id, auth_id, ws = setup_connected_collector(operator_status=status)
        res = client.post(
            "/api/scout/jobs",
            json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
            headers=auth_headers_tenant_a_admin,
        )
        assert res.status_code == 409
        assert f"Assigned collector is {status}" in res.json()["detail"]


def test_db_state_transitions_guarded_by_where_status_running():
    target = next_target()
    col_id, asset_id, auth_id = create_collector_and_internal_asset(target=target)

    # Insert a job in terminal 'failed' status
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scout_jobs (
                    tenant_id, asset_id, authorization_id, profile, route, target_type,
                    normalized_target, network_scope, authorization_approved_at,
                    authorization_expires_at, requested_by, collector_id, status
                ) VALUES (%s, %s, %s, 'SERVICE_DISCOVERY', 'COLLECTOR_INTERNAL', 'ip',
                          %s, 'internal', now(), now() + interval '1 hour', 'fixture', %s, 'failed')
                RETURNING id
                """,
                (str(TENANT_A), str(asset_id), str(auth_id), target, str(col_id)),
            )
            job_id = cur.fetchone()["id"]
        conn.commit()

    # Attempt to transition terminal job with running guard
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scout_jobs
                SET status = 'succeeded', completed_at = now()
                WHERE id = %s AND tenant_id = %s AND status = 'running'
                """,
                (str(job_id), str(TENANT_A)),
            )
            assert cur.rowcount == 0
        conn.commit()


def test_expired_authorization_and_ssrf_forbidden_targets_rejected(
    client, auth_headers_tenant_a_admin
):
    # Expired authorization on connected collector
    target = next_target()
    col_id, asset_id, auth_id, ws = setup_connected_collector(
        target=target,
        auth_expires_delta=-timedelta(minutes=5),
    )
    res = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 409
    assert "authorization" in res.json()["detail"].lower()


def test_check_update_rbac_enforcement(
    client, auth_headers_tenant_a_admin, auth_headers_tenant_a_analyst, platform_admin_headers
):
    col_id, _, _, _ = setup_connected_collector(tenant_id=TENANT_A)

    # 1. Analyst role is rejected with 403 Forbidden
    res_analyst = client.post(
        f"/api/v1/collectors/{col_id}/check-update",
        headers=auth_headers_tenant_a_analyst,
    )
    assert res_analyst.status_code == 403

    # 2. Platform session token is rejected with 403 Forbidden (cross-boundary / operational tenant required)
    res_platform = client.post(
        f"/api/v1/collectors/{col_id}/check-update",
        headers=platform_admin_headers,
    )
    assert res_platform.status_code == 403

    # 3. Superadmin role succeeds with 200 OK
    token_super = create_test_token(tenant_id=str(TENANT_A), actor_id="superadmin-a", role="superadmin")
    res_super = client.post(
        f"/api/v1/collectors/{col_id}/check-update",
        headers={"Authorization": f"Bearer {token_super}"},
    )
    assert res_super.status_code == 200
    assert res_super.json()["status"] == "checking"

    # 4. Admin role succeeds with 200 OK
    res_admin = client.post(
        f"/api/v1/collectors/{col_id}/check-update",
        headers=auth_headers_tenant_a_admin,
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["status"] == "checking"


def test_check_update_tenant_isolation(
    client, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
):
    col_a, _, _, _ = setup_connected_collector(tenant_id=TENANT_A)
    col_b, _, _, _ = setup_connected_collector(tenant_id=TENANT_B)

    # Tenant A admin cannot trigger check on Tenant B collector (404 Not Found, zero cross-tenant disclosure)
    res_a_on_b = client.post(
        f"/api/v1/collectors/{col_b}/check-update",
        headers=auth_headers_tenant_a_admin,
    )
    assert res_a_on_b.status_code == 404

    # Tenant B admin cannot trigger check on Tenant A collector (404 Not Found)
    res_b_on_a = client.post(
        f"/api/v1/collectors/{col_a}/check-update",
        headers=auth_headers_tenant_b_admin,
    )
    assert res_b_on_a.status_code == 404

    # Non-existent collector ID returns 404 Not Found
    random_id = uuid.uuid4()
    res_nonexistent = client.post(
        f"/api/v1/collectors/{random_id}/check-update",
        headers=auth_headers_tenant_a_admin,
    )
    assert res_nonexistent.status_code == 404


def test_check_update_offline_collector_returns_409_conflict(
    client, auth_headers_tenant_a_admin
):
    # Create collector in DB for Tenant A, but do not connect/register in collector_registry
    col_id, _, _ = create_collector_and_internal_asset(tenant_id=TENANT_A)

    # Invariant F.4: Connected check returns 409 Conflict if collector is offline
    res = client.post(
        f"/api/v1/collectors/{col_id}/check-update",
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 409
    assert "offline" in res.json()["detail"].lower()


def test_check_update_success_dispatches_anti_rce_frame_and_records_audit_log(
    client, auth_headers_tenant_a_admin
):
    col_id, _, _, ws = setup_connected_collector(tenant_id=TENANT_A)

    # Execute check-update via v1 endpoint
    res = client.post(
        f"/api/v1/collectors/{col_id}/check-update",
        headers=auth_headers_tenant_a_admin,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "checking"
    assert body["collector_id"] == str(col_id)
    assert "dispatched successfully" in body["message"]

    # Verify frame dispatched over WebSocket (Category B Anti-RCE)
    check_frames = [f for f in ws.sent_frames if f.get("type") == "CHECK_UPDATE"]
    assert len(check_frames) >= 1
    frame = check_frames[0]
    assert frame["type"] == "CHECK_UPDATE"
    assert frame["force_recheck"] is True
    # check_id must be a valid UUID string
    assert uuid.UUID(frame["check_id"]) is not None

    # Strict Anti-RCE verification: NO arbitrary execution payload fields allowed
    forbidden_rce_fields = [
        "url",
        "download_url",
        "hash",
        "sha256",
        "command",
        "flags",
        "script",
        "binary",
        "payload",
        "exec",
        "templates_url",
        "custom_templates",
    ]
    for field in forbidden_rce_fields:
        assert field not in frame, f"Forbidden remote execution field '{field}' detected in CHECK_UPDATE frame"

    # Verify structured audit event in database (Invariant F.5)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM audit_events
                WHERE tenant_id = %s AND event_name = 'collector.check_update'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (str(TENANT_A),),
            )
            audit_row = cur.fetchone()
            assert audit_row is not None
            assert audit_row["actor_role"] == "admin"
            assert audit_row["details"]["collector_id"] == str(col_id)

    # Also verify legacy alias route /api/collectors/{id}/check-update works identically
    res_legacy = client.post(
        f"/api/collectors/{col_id}/check-update",
        headers=auth_headers_tenant_a_admin,
    )
    assert res_legacy.status_code == 200
    assert res_legacy.json()["status"] == "checking"


def test_collector_details_capabilities_field_and_redaction(
    client, auth_headers_tenant_a_admin
):
    now_iso = datetime.now(timezone.utc).isoformat()
    mock_caps = {
        "nmap": {
            "available": True,
            "version": "7.94",
            "status": "ready",
            "path": "C:\\Program Files\\Nmap\\nmap.exe",
            "prerequisite_health": "detected",
        },
        "nuclei": {
            "available": True,
            "version": "3.8.0",
            "status": "ready",
            "path": "C:\\Tempris\\tools\\nuclei.exe",
        },
        "nuclei_templates": {
            "available": True,
            "version": "10.2.0",
            "status": "ready",
            "path": "C:\\Tempris\\tools\\nuclei-templates",
        },
        "update_status": "up_to_date",
        "last_checked_at": now_iso,
    }
    col_id, _, _, _ = setup_connected_collector(
        tenant_id=TENANT_A,
        caps=mock_caps,
    )

    # 1. GET /api/v1/collectors/{id}
    res_v1 = client.get(f"/api/v1/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert res_v1.status_code == 200
    col_data = res_v1.json()
    assert "capabilities" in col_data
    caps = col_data["capabilities"]
    assert caps["nmap"]["available"] is True
    assert caps["nmap"]["version"] == "7.94"
    assert caps["nuclei"]["available"] is True
    assert caps["nuclei"]["version"] == "3.8.0"
    assert caps["nuclei_templates"]["available"] is True
    assert caps["nuclei_templates"]["version"] == "10.2.0"
    assert caps["update_status"] == "up_to_date"
    assert caps["last_checked_at"] == now_iso

    # 2. GET /api/collectors
    res_list = client.get("/api/collectors", headers=auth_headers_tenant_a_admin)
    assert res_list.status_code == 200
    collectors = res_list.json()
    target_col = next((c for c in collectors if c["id"] == str(col_id)), None)
    assert target_col is not None
    assert target_col["capabilities"] == caps

