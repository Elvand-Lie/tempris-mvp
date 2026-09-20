# backend/tests/strike/test_ch4_strike_execution.py
"""
Chapter 4 acceptance — execution core: workspaces (PATCH-02/03/04),
operations (execution truth + the classifier), artifacts, and discovery
routing (Flow C).

PRD-derived checklist covered here:
  * workspaces: generation reserved DURABLY before any provider call;
    cardinality lock (one live workspace per engagement — replacement needs
    confirmed fencing); provider refusal = truthful provision_failed alarm,
    never silent; UNKNOWN outcome stays provisioning and refuses retry until
    operator reconciliation; confirmed destruction vs destroy_failed alarm;
    egress policy pinned from approved targets, generation bumped on target
    change;
  * operations: fail-closed dispatch gates (active engagement, live
    workspace, approved fresh target, allowlisted active ability); engine
    failure = outcome ERROR (never PREVENTED/NOT_EXECUTED); classifier
    refuses EXPLOITABLE/PREVENTED; cancellation only on CONFIRMED stop —
    unconfirmed stop = cancel_unconfirmed alarm; bounded output;
  * artifacts: SHA-256 server-side, immutable, hash-verified audited read;
  * discovery: STRIKE_DISCOVERY intake record carrying operation/artifact
    references — never a direct finding; replay identity (PATCH-07).
"""
from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.db import get_db_connection
from app.strike import operations as strike_operations
from app.strike import workspaces as strike_workspaces
from app.strike.workspaces import ProvisionUnknownOutcome
from tests.strike.conftest import iso, seed_ability, take_engagement_active


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def active_ids(strike_client, analyst_headers, admin_headers):
    return take_engagement_active(strike_client, analyst_headers, admin_headers)


@pytest.fixture
def ready_workspace(strike_client, analyst_headers, monkeypatch, active_ids):
    """A live workspace on the active engagement (provider stubbed green)."""
    monkeypatch.setattr(
        strike_workspaces, "provider_provision",
        lambda reservation: f"prov://vm/{reservation['workspace_id']}",
    )
    r = strike_client.post(
        f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
        json={}, headers=analyst_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "ready"
    return body


@pytest.fixture
def running_operation(strike_client, analyst_headers, monkeypatch, active_ids, ready_workspace):
    """An operation dispatched to a stubbed-green engine (state=running)."""
    ability_id = seed_ability()
    r = strike_client.post(
        f"/api/strike/workspaces/{ready_workspace['id']}/in-use", headers=analyst_headers,
    )
    assert r.status_code == 200
    monkeypatch.setattr(
        strike_operations, "engine_dispatch",
        lambda operation: f"eng://{operation['id']}",
    )
    r = strike_client.post(
        f"/api/strike/engagements/{active_ids['engagement_id']}/operations",
        json={
            "target_id": active_ids["target_id"],
            "ability_id": str(ability_id),
            "workspace_id": ready_workspace["id"],
            "params": {"profile": "controlled-validation"},
        },
        headers=analyst_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "running"
    return body


# ---------------------------------------------------------------------------
# Workspaces — PATCH-04 recovery safety
# ---------------------------------------------------------------------------


class TestWorkspaceProvisioning:
    def test_no_provider_configured_is_a_truthful_alarm_never_silent(
        self, strike_client, analyst_headers, active_ids
    ):
        """The shipped default has no provider: the reservation is durably
        reserved FIRST, then provision_failed alarms — nothing is fabricated
        as provisioned."""
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["state"] == "provision_failed"
        assert body["last_error"]
        assert body["provider"] is None            # no native ref fabricated
        assert body["provider_workspace_ref"] is None
        assert body["generation"] == 1

    def test_reservation_is_durable_and_pinned_before_provider_call(
        self, strike_client, analyst_headers, monkeypatch, active_ids
    ):
        """PATCH-04: the reservation row (with the compiled egress policy)
        exists and is committed BEFORE the provider is asked for anything."""
        seen = {}

        def spy_provision(reservation):
            seen["reservation"] = dict(reservation)
            return f"prov://vm/{reservation['workspace_id']}"

        monkeypatch.setattr(strike_workspaces, "provider_provision", spy_provision)
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 201
        # the provider received the stable persisted identity
        assert seen["reservation"]["generation"] == 1
        assert seen["reservation"]["workspace_id"]
        # egress pinned from the approved target (PATCH-03)
        egress = seen["reservation"]["egress_policy"]
        assert len(egress) == 1
        assert egress[0]["target_value"] == "10.0.0.60"
        assert egress[0]["authorization_version"] == 1

    def test_unknown_provider_outcome_stays_provisioning_and_refuses_retry(
        self, strike_client, analyst_headers, admin_headers, monkeypatch, active_ids
    ):
        """Accepted-but-response-lost: the workspace STAYS provisioning
        (execution may have occurred), a blind retry is impossible, and only
        operator reconciliation with confirmed fencing releases the lock
        (PATCH-04)."""
        def unknown_provision(reservation):
            raise ProvisionUnknownOutcome("provider accepted; response lost")

        monkeypatch.setattr(strike_workspaces, "provider_provision", unknown_provision)
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["state"] == "provisioning"     # truth preserved
        assert "UNKNOWN" in body["last_error"]

        # blind retry refused while the outcome is unresolved
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 409  # the cardinality lock holds

        # operator reconciliation WITHOUT fencing keeps the lock
        r = strike_client.post(
            f"/api/strike/workspaces/{body['id']}/reconcile",
            json={"confirmed_fenced": False, "note": "provider still querying"},
            headers=admin_headers,
        )
        assert r.status_code == 422
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 409

        # operator confirms NO VM was created → generation retired → lock released
        r = strike_client.post(
            f"/api/strike/workspaces/{body['id']}/reconcile",
            json={"confirmed_fenced": True, "note": "provider logs confirm no VM created"},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "destroyed"
        assert r.json()["reconcile_note"]

        # sequential generation now reservable (never a second live VM)
        monkeypatch.setattr(
            strike_workspaces, "provider_provision",
            lambda reservation: f"prov://vm/{reservation['workspace_id']}",
        )
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        assert r.json()["generation"] == 2
        assert r.json()["state"] == "ready"

    def test_cardinality_lock_one_live_workspace_per_engagement(
        self, strike_client, analyst_headers, monkeypatch, active_ids, ready_workspace
    ):
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 409  # the ready workspace holds the lock

    def test_destroy_unconfirmed_is_an_alarm_never_silent_destroyed(
        self, strike_client, analyst_headers, admin_headers, monkeypatch,
        active_ids, ready_workspace,
    ):
        monkeypatch.setattr(
            strike_workspaces, "provider_terminate",
            lambda workspace: False,
        )
        r = strike_client.post(
            f"/api/strike/workspaces/{ready_workspace['id']}/destroy",
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["state"] == "destroy_failed"   # alarm — operator action
        assert body["last_error"]
        assert body["destroyed_at"] is None

        # reconciliation confirms fencing → retired
        r = strike_client.post(
            f"/api/strike/workspaces/{ready_workspace['id']}/reconcile",
            json={"confirmed_fenced": True, "note": "hypervisor confirms VM gone"},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "destroyed"

    def test_target_change_bumps_live_workspace_egress_generation(
        self, strike_client, analyst_headers, admin_headers, monkeypatch,
        active_ids, ready_workspace,
    ):
        """PATCH-02/03: revoking a target while a workspace is live bumps
        its egress generation immediately — stale policies cannot
        reactivate."""
        r = strike_client.get(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            headers=analyst_headers,
        )
        assert r.json()[0]["egress_generation"] == 1

        r = strike_client.post(
            f"/api/strike/targets/{active_ids['target_id']}/revoke",
            json={"reason": "enforcement check"}, headers=admin_headers,
        )
        assert r.status_code == 200

        r = strike_client.get(
            f"/api/strike/engagements/{active_ids['engagement_id']}/workspaces",
            headers=analyst_headers,
        )
        assert r.json()[0]["egress_generation"] == 2  # enforcement-immediate


# ---------------------------------------------------------------------------
# Operations — execution truth
# ---------------------------------------------------------------------------


class TestOperationDispatchGates:
    def test_dispatch_refused_without_allowlisted_ability(
        self, strike_client, analyst_headers, active_ids, ready_workspace
    ):
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/operations",
            json={
                "target_id": active_ids["target_id"],
                "ability_id": str(uuid.uuid4()),
                "workspace_id": ready_workspace["id"],
                "params": {},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "ability_not_allowlisted"

    def test_dispatch_refused_without_live_workspace(
        self, strike_client, analyst_headers, active_ids
    ):
        ability_id = seed_ability()
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/operations",
            json={
                "target_id": active_ids["target_id"],
                "ability_id": str(ability_id),
                "workspace_id": str(uuid.uuid4()),
                "params": {},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 404  # identical not-found

    def test_dispatch_refused_against_revoked_target(
        self, strike_client, analyst_headers, admin_headers, active_ids, ready_workspace
    ):
        ability_id = seed_ability()
        r = strike_client.post(
            f"/api/strike/targets/{active_ids['target_id']}/revoke",
            json={"reason": "revoke before dispatch"}, headers=admin_headers,
        )
        assert r.status_code == 200
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/operations",
            json={
                "target_id": active_ids["target_id"],
                "ability_id": str(ability_id),
                "workspace_id": ready_workspace["id"],
                "params": {},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "target_state"

    def test_dispatch_refused_against_expired_target(
        self, strike_client, analyst_headers, admin_headers, monkeypatch
    ):
        """Derived expiry is enforcement-immediate at dispatch."""
        import time as _time

        ids = take_engagement_active(
            strike_client, analyst_headers, admin_headers,
            target_ttl=timedelta(seconds=2),
        )
        monkeypatch.setattr(
            strike_workspaces, "provider_provision",
            lambda reservation: f"prov://vm/{reservation['workspace_id']}",
        )
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 201
        workspace_id = r.json()["id"]
        ability_id = seed_ability()
        _time.sleep(2.5)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/operations",
            json={
                "target_id": ids["target_id"],
                "ability_id": str(ability_id),
                "workspace_id": workspace_id,
                "params": {},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "target_expired"


class TestOperationExecutionTruth:
    def test_engine_failure_is_error_never_prevented_or_not_executed(
        self, strike_client, analyst_headers, active_ids, ready_workspace
    ):
        """No engine integrated (shipped default): the operation records
        outcome ERROR — engine/transport failure never translates into
        PREVENTED or NOT_EXECUTED."""
        ability_id = seed_ability()
        r = strike_client.post(
            f"/api/strike/engagements/{active_ids['engagement_id']}/operations",
            json={
                "target_id": active_ids["target_id"],
                "ability_id": str(ability_id),
                "workspace_id": ready_workspace["id"],
                "params": {},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["state"] == "failed"
        assert body["outcome"] == "ERROR"

    def test_classifier_refuses_exploitable_and_prevented(
        self, strike_client, analyst_headers, running_operation
    ):
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/complete",
            json={"outcome": "EXPLOITABLE", "summary": "claimed exploit"},
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "outcome_classification_refused"

        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/complete",
            json={"outcome": "PREVENTED", "summary": "claimed prevention"},
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "outcome_classification_refused"

    def test_completed_with_observed_outcome(
        self, strike_client, analyst_headers, running_operation
    ):
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/complete",
            json={
                "outcome": "OBSERVED",
                "summary": "controlled validation executed; result collected",
                "native_output": {"http": {"status": 200}},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["state"] == "completed"
        assert body["outcome"] == "OBSERVED"
        assert body["completed_at"]

        # a terminal operation cannot complete twice
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/complete",
            json={"outcome": "INCONCLUSIVE"},
            headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_output_bound_enforced(self, strike_client, analyst_headers, running_operation):
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/complete",
            json={"outcome": "OBSERVED", "native_output": {"blob": "x" * 100_000}},
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "output_bound_exceeded"

    def test_cancel_confirmed_is_cancelled(
        self, strike_client, analyst_headers, monkeypatch, running_operation
    ):
        monkeypatch.setattr(strike_operations, "engine_cancel", lambda operation: None)
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/cancel",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["state"] == "cancelled"
        assert body["cancel_confirmed_at"] is not None
        assert body["outcome"] is None  # uncertainty preserved: whether
        # anything executed before the confirmed stop is not established

    def test_cancel_unconfirmed_is_the_alarm_never_a_clean_cancelled(
        self, strike_client, analyst_headers, monkeypatch, running_operation
    ):
        def unconfirmed_stop(operation):
            raise strike_operations.CancelUnconfirmed("engine unreachable")

        monkeypatch.setattr(strike_operations, "engine_cancel", unconfirmed_stop)
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/cancel",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["state"] == "cancel_unconfirmed"   # alarm
        assert body["cancel_confirmed_at"] is None     # never a clean cancelled


# ---------------------------------------------------------------------------
# Artifacts — bounded, hashed, immutable, audited read
# ---------------------------------------------------------------------------


class TestArtifacts:
    def test_store_read_hash_verified_and_immutable(
        self, strike_client, analyst_headers, running_operation
    ):
        content = b"controlled-validation-evidence-bytes\n"
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/artifacts",
            json={
                "name": "result.txt",
                "media_type": "text/plain",
                "content_b64": base64.b64encode(content).decode(),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        stored = r.json()
        assert stored["sha256"] == hashlib.sha256(content).hexdigest()
        assert stored["size_bytes"] == len(content)
        assert "content" not in stored  # bytes never leak in listing shape

        r = strike_client.get(
            f"/api/strike/artifacts/{stored['id']}", headers=analyst_headers
        )
        assert r.status_code == 200, r.text
        fetched = r.json()
        assert base64.b64decode(fetched["content_b64"]) == content
        assert fetched["sha256"] == stored["sha256"]

        # immutable on write (DB trigger)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(Exception, match="immutable"):
                    cur.execute(
                        "UPDATE strike_artifacts SET sha256 = %s WHERE id = %s;",
                        ("0" * 64, stored["id"]),
                    )
                conn.rollback()
                with pytest.raises(Exception, match="immutable"):
                    cur.execute(
                        "DELETE FROM strike_artifacts WHERE id = %s;", (stored["id"],)
                    )
                conn.rollback()

    def test_oversize_artifact_refused(
        self, strike_client, analyst_headers, running_operation
    ):
        big = base64.b64encode(b"x" * (9 * 1024 * 1024)).decode()
        r = strike_client.post(
            f"/api/strike/operations/{running_operation['id']}/artifacts",
            json={"name": "big.bin", "media_type": "application/octet-stream",
                  "content_b64": big},
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "output_bound_exceeded"


# ---------------------------------------------------------------------------
# Discovery (Flow C) — intake, never a finding
# ---------------------------------------------------------------------------


class TestDiscoveryRouting:
    def test_discovery_routes_as_strike_intake_record(
        self, strike_client, analyst_headers, running_operation
    ):
        r = strike_client.post(
            "/api/strike/discoveries",
            json={
                "operation_id": running_operation["id"],
                "title": "Unexpected service on scoped host",
                "severity": "medium",
                "description": "Discovered during controlled validation",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["intake_state"] == "submitted"

        # the intake record carries the operation/artifact references and
        # the STRIKE_DISCOVERY source — Ch.6 owns everything after
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT source, payload, source_registration_id, source_event_id "
                    "FROM intake_records WHERE id = %s;",
                    (body["intake_record_id"],),
                )
                row = cur.fetchone()
        assert row["source"] == "STRIKE_DISCOVERY"
        assert row["payload"]["strike_operation_id"] == running_operation["id"]
        assert row["payload"]["strike_engagement_id"] == running_operation["engagement_id"]
        assert row["source_registration_id"].startswith("strike:")

        # no finding was created (STRIKE cannot create findings — Q2)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM findings WHERE tenant_id = '11111111-1111-1111-1111-111111111111' "
                    "AND title = %s;",
                    ("Unexpected service on scoped host",),
                )
                assert cur.fetchone()["n"] == 0

    def test_discovery_replay_returns_the_original_record(
        self, strike_client, analyst_headers, running_operation
    ):
        payload = {
            "operation_id": running_operation["id"],
            "title": "Same discovery",
            "severity": "low",
        }
        r1 = strike_client.post("/api/strike/discoveries", json=payload, headers=analyst_headers)
        assert r1.status_code == 201
        r2 = strike_client.post("/api/strike/discoveries", json=payload, headers=analyst_headers)
        assert r2.status_code == 201
        assert r1.json()["intake_record_id"] == r2.json()["intake_record_id"]
        assert r2.json()["outcome"] == "replay"
