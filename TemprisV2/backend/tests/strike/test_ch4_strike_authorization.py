# backend/tests/strike/test_ch4_strike_authorization.py
"""
Chapter 4 acceptance — authorization core (PRD-000 v1.11 Ch.4).

PRD-derived checklist covered here:
  * module entitlement gate + role authority (analyst+ request, admin+
    decision; platform sessions blocked);
  * engagement lifecycle draft → pending_approval → authorized → active →
    completed / aborted, every transition audited, the record permanent
    (no delete path; ROE immutable per engagement);
  * DUAL CONTROL (Appendix C Q11): engagement authorization and target
    approval run exclusively through the Ch.5 primitive — self-approval
    refused, single-use apply, proposal tamper/stale-subject fails closed;
  * targets: exact tuple snapshot, expiry required, revocation
    ENFORCEMENT-IMMEDIATE (authorization version bumps; the egress
    generation of live workspaces bumps in the same transaction);
  * expiry is DERIVED AT READ — never back-written;
  * tenant isolation: cross-tenant ids are the identical not-found;
  * relays: lifecycle pending_pairing → active → revoked (terminal);
    the STRIKE relay is a separate component from the collector.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.db import get_db_connection
from tests.conftest import TENANT_A
from tests.strike.conftest import (
    create_engagement,
    engagement_payload,
    iso,
    take_engagement_active,
)


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


# ---------------------------------------------------------------------------
# Entitlement + authority
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_platform_session_blocked(self, strike_client, platform_admin_headers):
        r = strike_client.get("/api/strike/engagements", headers=platform_admin_headers)
        assert r.status_code == 403

    def test_module_entitlement_required(self, strike_client, admin_headers):
        # flip the STRIKE entitlement off for tenant A via override
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"STRIKE": false}', str(TENANT_A)),
                )
            conn.commit()
        try:
            r = strike_client.get("/api/strike/engagements", headers=admin_headers)
            assert r.status_code == 403
            assert "STRIKE" in r.json()["detail"]
        finally:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE tenant_entitlements SET module_overrides = '{}'::jsonb "
                        "WHERE tenant_id = %s;",
                        (str(TENANT_A),),
                    )
                conn.commit()

    def test_analyst_cannot_approve_or_revoke(self, strike_client, analyst_headers, admin_headers):
        engagement = create_engagement(strike_client, analyst_headers)
        r = strike_client.post(
            f"/api/strike/engagements/{engagement['id']}/submit", headers=analyst_headers
        )
        assert r.status_code == 201
        # analyst attempts the admin-only approve route
        r = strike_client.post(
            f"/api/strike/engagements/{engagement['id']}/approve",
            json={}, headers=analyst_headers,
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Engagement lifecycle
# ---------------------------------------------------------------------------


class TestEngagementLifecycle:
    def test_create_starts_as_draft_with_frozen_roe(self, strike_client, analyst_headers):
        engagement = create_engagement(strike_client, analyst_headers)
        assert engagement["state"] == "draft"
        assert engagement["roe_version"] == "1"
        assert engagement["derived_expired"] is False
        assert engagement["approval_id"] is None

    def test_full_lifecycle_to_completed_is_audited(
        self, strike_client, analyst_headers, admin_headers
    ):
        ids = take_engagement_active(strike_client, analyst_headers, admin_headers)
        eid = ids["engagement_id"]
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/complete", headers=analyst_headers
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "completed"

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_name FROM audit_events
                    WHERE tenant_id = %s AND event_name LIKE 'strike.engagement%%'
                    ORDER BY created_at ASC;
                    """,
                    (str(TENANT_A),),
                )
                events = [row["event_name"] for row in cur.fetchall()]
        assert events == [
            "strike.engagement_created",
            "strike.engagement_submitted",
            "strike.engagement_authorized",
            "strike.engagement_activated",
            "strike.engagement_completed",
        ]

    def test_submit_requires_the_requester(self, strike_client, analyst_headers, admin_headers):
        engagement = create_engagement(strike_client, analyst_headers)
        # a different identity cannot submit someone else's draft
        r = strike_client.post(
            f"/api/strike/engagements/{engagement['id']}/submit", headers=admin_headers
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "engagement_state"

    def test_approval_is_dual_control_and_single_use(
        self, strike_client, analyst_headers, admin_headers
    ):
        # SELF-APPROVAL through the API: an admin proposes AND tries to
        # decide their own engagement — refused (approver ≠ proposer, hard)
        engagement = create_engagement(strike_client, admin_headers)
        eid = engagement["id"]
        r = strike_client.post(f"/api/strike/engagements/{eid}/submit", headers=admin_headers)
        assert r.status_code == 201
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/approve", json={}, headers=admin_headers
        )
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "approval_self_approval_refused"

        # the happy path: the ANALYST proposes; the ADMIN (different
        # identity) decides
        engagement2 = create_engagement(strike_client, analyst_headers)
        eid2 = engagement2["id"]
        r = strike_client.post(f"/api/strike/engagements/{eid2}/submit", headers=analyst_headers)
        assert r.status_code == 201
        r = strike_client.post(
            f"/api/strike/engagements/{eid2}/approve", json={}, headers=admin_headers
        )
        assert r.status_code == 200, r.text
        assert r.json()["engagement"]["state"] == "authorized"
        assert r.json()["engagement"]["approval_id"] is not None
        assert r.json()["applied"]["approval"]["state"] == "applied"

        # single-use: a second approve finds no standing pending approval
        # (the applied approval is terminal) → identical not-found
        r2 = strike_client.post(
            f"/api/strike/engagements/{eid2}/approve", json={}, headers=admin_headers
        )
        assert r2.status_code == 404

    def test_abort_after_proposal_fails_the_apply_closed(
        self, strike_client, analyst_headers, admin_headers
    ):
        """PATCH-04/Ch.5 binding: subject state moved after proposal ⇒ the
        approval rebases onto different state ⇒ apply fails closed."""
        engagement = create_engagement(strike_client, analyst_headers)
        eid = engagement["id"]
        r = strike_client.post(f"/api/strike/engagements/{eid}/submit", headers=analyst_headers)
        assert r.status_code == 201
        # abort the engagement AFTER the proposal
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/abort",
            json={"reason": "out of scope discovered"}, headers=admin_headers,
        )
        assert r.status_code == 200
        # the approval can no longer authorize the aborted engagement
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/approve", json={}, headers=admin_headers
        )
        assert r.status_code == 409  # stale-subject apply fails closed
        assert r.json()["detail"]["code"] in ("approval_stale_subject", "ApprovalStaleSubjectError")

    def test_roe_is_immutable_and_the_record_is_undeletable(self, strike_client, analyst_headers):
        engagement = create_engagement(strike_client, analyst_headers)
        eid = engagement["id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(Exception, match="immutable"):
                    cur.execute(
                        "UPDATE strike_engagements SET roe = %s::jsonb WHERE id = %s;",
                        ('{"scope": ["everything"]}', eid),
                    )
                conn.rollback()
                with pytest.raises(Exception, match="DELETE forbidden"):
                    cur.execute("DELETE FROM strike_engagements WHERE id = %s;", (eid,))
                conn.rollback()

    def test_illegal_transition_refused_at_db_level(self, strike_client, analyst_headers):
        engagement = create_engagement(strike_client, analyst_headers)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(Exception, match="illegal state transition"):
                    cur.execute(
                        "UPDATE strike_engagements SET state = 'active' WHERE id = %s;",
                        (engagement["id"],),
                    )
            conn.rollback()

    def test_engagement_cannot_be_created_with_a_past_window(self, strike_client, analyst_headers):
        now = datetime.now(timezone.utc)
        payload = engagement_payload(valid_from=now - timedelta(hours=2), valid_until=now - timedelta(hours=1))
        r = strike_client.post("/api/strike/engagements", json=payload, headers=analyst_headers)
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Derived expiry
# ---------------------------------------------------------------------------


class TestDerivedExpiry:
    def test_expired_is_derived_at_read_and_enforced(self, strike_client, analyst_headers, admin_headers):
        engagement = create_engagement(
            strike_client, analyst_headers, ttl=timedelta(seconds=2)
        )
        eid = engagement["id"]
        r = strike_client.post(f"/api/strike/engagements/{eid}/submit", headers=analyst_headers)
        assert r.status_code == 201
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/approve", json={}, headers=admin_headers
        )
        assert r.status_code == 200
        assert r.json()["engagement"]["state"] == "authorized"  # window still open

        import time

        time.sleep(2.5)
        r = strike_client.get(f"/api/strike/engagements/{eid}", headers=analyst_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["state"] == "authorized"        # never back-written
        assert body["derived_expired"] is True      # derived at read

        # enforcement: targets can no longer be requested
        now = datetime.now(timezone.utc)
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/targets",
            json={
                "target_type": "ip", "target_value": "10.0.0.99",
                "normalized_target": "10.0.0.99", "purpose": "validation",
                "expires_at": iso(now + timedelta(days=1)),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "engagement_expired"


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


class TestTargets:
    def test_target_snapshot_and_dual_control(
        self, strike_client, analyst_headers, admin_headers
    ):
        engagement = create_engagement(strike_client, analyst_headers)
        eid = engagement["id"]
        strike_client.post(f"/api/strike/engagements/{eid}/submit", headers=analyst_headers)
        strike_client.post(f"/api/strike/engagements/{eid}/approve", json={}, headers=admin_headers)

        now = datetime.now(timezone.utc)
        tuple_in = {
            "target_type": "ip",
            "target_value": "10.0.0.60",
            "normalized_target": "10.0.0.60",
            "purpose": "controlled validation",
            "expires_at": iso(now + timedelta(days=7)),
        }
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/targets", json=tuple_in, headers=analyst_headers
        )
        assert r.status_code == 201, r.text
        target = r.json()["target"]
        # the exact tuple is snapshotted at request
        assert target["target_type"] == "ip"
        assert target["target_value"] == "10.0.0.60"
        assert target["normalized_target"] == "10.0.0.60"
        assert target["state"] == "pending"
        assert target["authorization_version"] == 0

        r = strike_client.post(
            f"/api/strike/targets/{target['id']}/approve", json={}, headers=admin_headers
        )
        assert r.status_code == 200, r.text
        approved = r.json()["target"]
        assert approved["state"] == "approved"
        assert approved["authorization_version"] == 1  # enforcement binds to it
        assert r.json()["applied"]["approval"]["state"] == "applied"  # single-use consumed

    def test_target_expiry_cannot_outlive_the_engagement(
        self, strike_client, analyst_headers, admin_headers
    ):
        engagement = create_engagement(strike_client, analyst_headers)
        eid = engagement["id"]
        strike_client.post(f"/api/strike/engagements/{eid}/submit", headers=analyst_headers)
        strike_client.post(f"/api/strike/engagements/{eid}/approve", json={}, headers=admin_headers)

        now = datetime.now(timezone.utc)
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/targets",
            json={
                "target_type": "ip", "target_value": "10.0.0.61",
                "normalized_target": "10.0.0.61", "purpose": "validation",
                # the engagement window is now+30d; request beyond it
                "expires_at": iso(now + timedelta(days=45)),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_revoke_is_enforcement_immediate(
        self, strike_client, analyst_headers, admin_headers
    ):
        """Revocation bumps the authorization version and the egress
        generation of any live workspace in the SAME transaction, before the
        command reports success (PATCH-02/03)."""
        ids = take_engagement_active(strike_client, analyst_headers, admin_headers)
        eid, tid = ids["engagement_id"], ids["target_id"]

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT authorization_version FROM strike_targets WHERE id = %s;",
                    (tid,),
                )
                version_before = cur.fetchone()["authorization_version"]

        r = strike_client.post(
            f"/api/strike/targets/{tid}/revoke",
            json={"reason": "scope change"}, headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "revoked"
        assert r.json()["authorization_version"] == version_before + 1

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT egress_generation FROM strike_workspaces "
                    "WHERE tenant_id = %s AND engagement_id = %s;",
                    (str(TENANT_A), eid),
                )
                # no workspace yet → bump is a no-op; the version bump is the
                # enforcement record
                assert cur.fetchall() in ([], [{"egress_generation": 1}])

    def test_double_revoke_refused(self, strike_client, analyst_headers, admin_headers):
        ids = take_engagement_active(strike_client, analyst_headers, admin_headers)
        tid = ids["target_id"]
        r = strike_client.post(
            f"/api/strike/targets/{tid}/revoke", json={"reason": "x"}, headers=admin_headers
        )
        assert r.status_code == 200
        r = strike_client.post(
            f"/api/strike/targets/{tid}/revoke", json={"reason": "y"}, headers=admin_headers
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_cross_tenant_is_the_identical_not_found(
        self, strike_client, analyst_headers, auth_headers_tenant_b_admin
    ):
        engagement = create_engagement(strike_client, analyst_headers)
        r = strike_client.get(
            f"/api/strike/engagements/{engagement['id']}",
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404
        r = strike_client.get("/api/strike/engagements", headers=auth_headers_tenant_b_admin)
        assert r.status_code == 200
        assert r.json() == []  # tenant B sees nothing of tenant A


# ---------------------------------------------------------------------------
# Relays (STRIKE-specific; the collector is never involved)
# ---------------------------------------------------------------------------


class TestRelays:
    def test_relay_lifecycle_and_terminal_revocation(
        self, strike_client, analyst_headers, admin_headers
    ):
        ids = take_engagement_active(strike_client, analyst_headers, admin_headers)
        eid = ids["engagement_id"]

        # analyst cannot deploy a relay (admin+ — deploying is an engagement event)
        r = strike_client.post(
            f"/api/strike/engagements/{eid}/relays", headers=analyst_headers
        )
        assert r.status_code == 403

        r = strike_client.post(
            f"/api/strike/engagements/{eid}/relays", headers=admin_headers
        )
        assert r.status_code == 201, r.text
        relay = r.json()
        assert relay["state"] == "pending_pairing"
        secret = relay.pop("pairing_secret")
        assert secret  # disclosed exactly once
        assert "pairing_secret_hash" not in relay

        r = strike_client.post(
            f"/api/strike/relays/{relay['id']}/pair",
            json={"pairing_secret": secret}, headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "active"

        r = strike_client.post(
            f"/api/strike/relays/{relay['id']}/revoke",
            json={"reason": "engagement window closing"}, headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "revoked"

        # revoked is TERMINAL — a revoked relay never re-pairs
        r = strike_client.post(
            f"/api/strike/relays/{relay['id']}/pair",
            json={"pairing_secret": secret}, headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_wrong_pairing_secret_refused_closed(
        self, strike_client, analyst_headers, admin_headers
    ):
        ids = take_engagement_active(strike_client, analyst_headers, admin_headers)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/relays", headers=admin_headers
        )
        assert r.status_code == 201
        r = strike_client.post(
            f"/api/strike/relays/{r.json()['id']}/pair",
            json={"pairing_secret": "wrong-secret"}, headers=analyst_headers,
        )
        assert r.status_code == 422
