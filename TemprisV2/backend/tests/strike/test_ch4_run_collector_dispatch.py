# backend/tests/strike/test_ch4_run_collector_dispatch.py
"""
Chapter 4 acceptance — the collector-executed run (private-network slice).

The unit of execution is the USER-SELECTED collector: the run dispatches
over its authenticated WSS with the server-pinned destinations and returns
with a terminal outcome in the same request. Covers:

  * explicit deterministic selection — the collector_id is persisted in the
    policy snapshot and the runner identity (collector:<uuid>);
  * fail-closed refusal without redirect: an offline/paused collector and a
    collector that has not reported the capability as available (UNKNOWN
    included) all refuse the run visibly, and NO run row is created;
  * cross-tenant collector selection refused;
  * execution-time honesty: a collector 'rejected' result (capability gone
    at execution) and a failed curl result both record truthful failures;
  * a completed result records the bounded inline output and exit code.
"""
from __future__ import annotations

import uuid

import pytest

from app.collector_registry import collector_registry
from app.db import get_db_connection
from tests.conftest import TENANT_A, TENANT_B
from tests.strike.conftest import (
    make_fake_collector,
    remove_fake_collector,
)

from tests.strike.test_ch4_run_curl import create_scope  # shared helpers


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def collector():
    handle = make_fake_collector(TENANT_A, name="dispatch-collector")
    yield handle
    remove_fake_collector(handle)


def create_run(client, analyst_headers, collector_handle, *, target="203.0.113.10", method="GET"):
    return client.post(
        "/api/strike/runs",
        json={
            "capability": "curl",
            "method": method,
            "target": target,
            "collector_id": str(collector_handle["id"]),
        },
        headers=analyst_headers,
    )


def test_selection_persisted_in_snapshot_and_runner_identity(
    strike_client, analyst_headers, admin_headers, collector
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(strike_client, analyst_headers, collector)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["state"] == "completed"
    assert run["policy_snapshot"]["collector_id"] == str(collector["id"])
    assert run["policy_snapshot"]["execution_plane"] == "collector"
    assert run["runner_id"] == f"collector:{collector['id']}"
    # the exact fixed argv traveled: server URL + pinned destinations
    frame = collector["socket"].sent_frames[0]
    assert frame["type"] == "STRIKE_JOB"
    assert frame["method"] == "GET"
    assert frame["url"] == "http://203.0.113.10:80"
    assert frame["pinned_ips"] == ["203.0.113.10"]


def test_offline_collector_refused_without_redirect_and_without_run_row(
    strike_client, analyst_headers, admin_headers, collector
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    collector_registry.unregister_session(collector["id"], reason="simulated disconnect")
    r = create_run(strike_client, analyst_headers, collector)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "collector_not_ready"
    runs = strike_client.get("/api/strike/runs", headers=analyst_headers).json()
    assert runs == []


def test_unknown_capability_report_refused_fail_closed(
    strike_client, analyst_headers, admin_headers, collector
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    # an older collector that never reported STRIKE readiness: UNKNOWN is
    # NOT ready (user decision — never attempt on unknown)
    collector["session"].capabilities = {}
    r = create_run(strike_client, analyst_headers, collector)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "collector_not_ready"
    runs = strike_client.get("/api/strike/runs", headers=analyst_headers).json()
    assert runs == []


def test_cross_tenant_collector_refused(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    other = make_fake_collector(TENANT_B, name="tenant-b-collector")
    try:
        r = create_run(strike_client, analyst_headers, other)
        assert r.status_code == 422
        # a collector of another tenant is not the tenant's collector at all
        assert r.json()["detail"]["code"] == "collector_invalid"
        runs = strike_client.get("/api/strike/runs", headers=analyst_headers).json()
        assert runs == []
    finally:
        remove_fake_collector(other)


def test_execution_time_rejection_records_truthful_failure(
    strike_client, analyst_headers, admin_headers, collector
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    collector["socket"].script.append({
        "status": "rejected",
        "exit_code": None,
        "error_message": "Capability 'curl' is not executable on this collector",
    })
    r = create_run(strike_client, analyst_headers, collector)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["state"] == "failed"
    assert run["error_code"] == "collector_run_failed"
    assert "not executable" in run["inline_result"]


def test_failed_curl_result_records_exit_code_and_detail(
    strike_client, analyst_headers, admin_headers, collector
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    collector["socket"].script.append({
        "status": "completed",
        "exit_code": 7,
        "stdout": "",
        "stderr": "curl: (7) Failed to connect to 203.0.113.10",
    })
    r = create_run(strike_client, analyst_headers, collector)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["state"] == "failed"
    assert run["exit_code"] == 7


def test_unregistered_collector_id_refused(
    strike_client, analyst_headers, admin_headers, collector
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    ghost = uuid.uuid4()
    r = strike_client.post(
        "/api/strike/runs",
        json={
            "capability": "curl",
            "method": "GET",
            "target": "203.0.113.10",
            "collector_id": str(ghost),
        },
        headers=analyst_headers,
    )
    assert r.status_code == 422
    # unregistered → collector_invalid (DB truth), not merely not_ready
    assert r.json()["detail"]["code"] == "collector_invalid"
