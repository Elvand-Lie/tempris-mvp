# backend/tests/test_ch8_edip.py
"""
Focused suite for Chapter 8 — EDIP (Remediation & Risk Decisions)
(PRD-000 v1.11 Ch.8; Appendix A Flow D; PATCH-09/10/13; D-16).

PRD-derived checklist (tests/PRD_TEST_CHECKLIST_ch8_ch9.md):

  1.  module entitlement gate; platform blocked; analyst+ authority
  2.  decision creation from the SPECTRUM handoff — Needs-Decision, sealed
      coherent snapshot (§3.3.6 writer, PATCH-13)
  3.  handoff retry correlation (PATCH-09) + one current decision per
      exposure (Q7)
  4.  creation on a non-current exposure fails closed (404)
  5.  the state machine: planned → in_progress → mitigated → verification →
      closed; invalid edges refused
  6.  unified vocabulary remediate|mitigate|accept-risk|defer
  7.  closure without verification evidence refused (the blflaw lesson)
  8.  verified closure = ONE version-checked transaction: the decision
      closes AND the exact episode resolves through the Ch.3 exposure
      service; CAS on both states — a raced refusal rolls everything back
  9.  verification binds revision + exposure row version; a moved exposure
      invalidates it
  10. EDIP never writes scores or workflow status: the exposure stays
      `confirmed` through planning/mitigation/verification (D-16)
  11. accepted risk dual-controlled via the Ch.5 primitive: approver ≠
      proposer, payload-bound, single-use; fresh snapshot per revision
  12/13. mandatory review_due_at; the review-expiry effective-state rule
      materializes Needs-Decision on read — no scheduler
  14. decision-level reopen (exposure still confirmed); closed decisions
      never reopen; recurrence = new episode + new decision linked back
  15. confirmation withdrawal / supersession auto-supersede the open
      decision (`confirmation_withdrawn`) — no orphan decisions (PATCH-10)
  16. snapshots are immutable history; the live score recomputes on
  17. tenant isolation; cross-tenant reads are the identical 404
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.auth import create_test_token
from app.db import get_db_connection
from app.exposure.models import ExposureResolve
from app.exposure.service import resolve_exposure, supersede_exposures_for_asset
from tests.conftest import TENANT_A


# ---------------------------------------------------------------------------
# Helpers — seed a confirmed exposure through the Ch.3 routes
# ---------------------------------------------------------------------------


def create_asset_in_db(
    tenant_id: uuid.UUID = TENANT_A,
    name: str = "edip-anchor-01",
) -> uuid.UUID:
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, %s, 'server', 'ip', '10.0.0.70', '10.0.0.70',
                          'internal', 'production', 'high', 'active');
                """,
                (str(asset_id), str(tenant_id), name),
            )
        conn.commit()
    return asset_id


def seed_cve(cve_id: str = "CVE-2026-80001") -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO canonical_vulnerabilities (cve_id, state, assigner_short_name)
                VALUES (%s, 'PUBLISHED', 'test-cna')
                ON CONFLICT (cve_id) DO NOTHING;
                """,
                (cve_id,),
            )
        conn.commit()
    return cve_id


def seed_cvss(cve_id: str, base: float = 9.0) -> None:
    """An authoritative CVSS row so the sealed snapshot carries a real value."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT cve_id FROM canonical_vulnerabilities WHERE cve_id = %s;
                """,
                (cve_id,),
            )
            if cur.fetchone() is None:
                seed_cve(cve_id)
            # idempotent seed: cvss_assessments is global intel data that no
            # test truncates — insert only when this seed row is absent
            cur.execute(
                """
                SELECT 1 FROM cvss_assessments
                WHERE cve_id = %s AND assessor = 'nvd@nist.gov'
                  AND cvss_version = '3.1' AND scenario = 'GENERAL';
                """,
                (cve_id,),
            )
            if cur.fetchone() is None:
                cur.execute(
                    """
                    INSERT INTO cvss_assessments (
                        cve_id, source, assessor, assessment_type, cvss_version,
                        vector_string, base_score, base_severity, scenario, is_current
                    ) VALUES (%s, 'nvd', 'nvd@nist.gov', 'nvd', '3.1',
                              'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', %s, 'critical',
                              'GENERAL', TRUE);
                    """,
                    (cve_id, base),
                )
        conn.commit()


def _audit_exists(tenant_id, event_name: str, needle: str) -> bool:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT details::text AS d FROM audit_events
                WHERE tenant_id = %s AND event_name = %s;
                """,
                (str(tenant_id), event_name),
            )
            return any(needle in (r["d"] or "") for r in cur.fetchall())


def _exposure_status(exposure_id) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM asset_exposures WHERE id = %s;",
                (str(exposure_id),),
            )
            return cur.fetchone()["status"]


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def superadmin_headers():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="superadmin-a", role="superadmin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def other_analyst_headers():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="analyst-1", role="analyst")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def scored_exposure(client, admin_headers):
    """One confirmed exposure with an authoritative CVSS row."""
    asset_id = create_asset_in_db()
    cve = seed_cve("CVE-2026-80001")
    seed_cvss(cve, 9.0)
    r = client.post(
        "/api/exposure/findings",
        json={"title": "EDIP seeded exposure", "severity": "high", "canonical_cve_id": cve},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    finding_id = r.json()["id"]
    r = client.post(
        "/api/exposure/confirm",
        json={"finding_id": finding_id, "asset_id": str(asset_id),
              "evidence": {"reference": "edip-seed-1"}},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    return {"exposure_id": r.json()["id"], "finding_id": finding_id, "asset_id": asset_id}


def _create_decision(client, headers, exposure_id, **overrides):
    body = {
        "exposure_id": str(exposure_id),
        "decision_type": "remediate",
        "rationale": "patch the host",
    }
    body.update(overrides)
    return client.post("/api/edip/decisions", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_platform_session_blocked(self, client, platform_admin_headers):
        r = client.get("/api/edip/queue", headers=platform_admin_headers)
        assert r.status_code == 403

    def test_module_entitlement_required(self, client, admin_headers):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"EDIP": false}', str(TENANT_A)),
                )
            conn.commit()
        r = client.get("/api/edip/queue", headers=admin_headers)
        assert r.status_code == 403
        assert "EDIP" in r.json()["detail"]

    def test_transitions_require_owner_or_admin(
        self, client, analyst_headers, other_analyst_headers, admin_headers,
        scored_exposure,
    ):
        r = _create_decision(client, analyst_headers, scored_exposure["exposure_id"])
        assert r.status_code == 201, r.text
        decision_id = r.json()["decision"]["id"]

        # a different analyst who is not the owner: refused 403
        r = client.post(
            f"/api/edip/decisions/{decision_id}/transition",
            json={"to": "planned"},
            headers=other_analyst_headers,
        )
        assert r.status_code == 403
        # an admin may transition
        r = client.post(
            f"/api/edip/decisions/{decision_id}/transition",
            json={"to": "planned"},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Handoff + creation (PATCH-09 correlation; Q7 single current decision)
# ---------------------------------------------------------------------------


class TestHandoffAndCreation:
    def test_handoff_seals_snapshot_creates_and_consumes(
        self, client, admin_headers, scored_exposure
    ):
        # The corrected atomic handoff (PATCH-09): the SPECTRUM handoff itself
        # creates the Needs-Decision decision, seals the score snapshot it
        # consumes, and consumes the handoff — one transaction.
        eid = scored_exposure["exposure_id"]
        r = client.post(
            f"/api/spectrum/exposures/{eid}/edip-handoff",
            json={"note": "action required"},
            headers=admin_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        handoff_id = body["edip_handoff"]["id"]
        decision = body["decision"]
        assert body["edip_handoff"]["state"] == "CONSUMED"
        assert decision["state"] == "needs_decision"
        assert decision["revision"] == 1
        assert decision["decision_type"] == "remediate"
        assert decision["handoff_id"] == handoff_id
        # the sealed snapshot (§3.3.6 writer; PATCH-13): one coherent payload
        snapshot = decision["consumed_snapshot"]
        assert snapshot["state"] in {"FINAL", "PROVISIONAL", "UNSCOREABLE"}
        assert snapshot["formula_version"]
        assert "source_view" in snapshot
        assert decision["snapshot_as_of"]

        # PATCH-09: the handoff is consumed and correlated to the decision
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT state, edip_decision_id, consumed_by "
                    "FROM spectrum_edip_handoffs WHERE id = %s;",
                    (str(handoff_id),),
                )
                row = cur.fetchone()
        assert row["state"] == "CONSUMED"
        assert str(row["edip_decision_id"]) == decision["id"]
        assert row["consumed_by"] == "admin-a"
        assert _audit_exists(
            TENANT_A, "edip.decision_created", str(decision["id"])
        )

        # a direct create on the same exposure is the standing-decision refusal
        r = _create_decision(client, admin_headers, eid)
        assert r.status_code == 409

    def test_second_decision_on_one_exposure_refused(
        self, client, admin_headers, scored_exposure
    ):
        r = _create_decision(client, admin_headers, scored_exposure["exposure_id"])
        assert r.status_code == 201
        r = _create_decision(client, admin_headers, scored_exposure["exposure_id"])
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "edip_conflict"

    def test_handoff_retry_never_forks(
        self, client, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = client.post(
            f"/api/spectrum/exposures/{exposure_id}/edip-handoff",
            json={"note": "first"},
            headers=admin_headers,
        )
        assert r.status_code == 201, r.text
        first_id = r.json()["decision"]["id"]

        # the analyst retries the handoff on the still-confirmed exposure:
        # the standing-decision guard refuses 409 and the rolled-back
        # transaction never forks a second decision or handoff row
        r = client.post(
            f"/api/spectrum/exposures/{exposure_id}/edip-handoff",
            json={"note": "retry"},
            headers=admin_headers,
        )
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "edip_conflict"
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM spectrum_edip_handoffs "
                    "WHERE tenant_id = %s AND exposure_id = %s;",
                    (str(TENANT_A), str(exposure_id)),
                )
                assert cur.fetchone()["count"] == 1
                cur.execute(
                    "SELECT count(*) FROM edip_decisions "
                    "WHERE tenant_id = %s AND exposure_id = %s;",
                    (str(TENANT_A), str(exposure_id)),
                )
                assert cur.fetchone()["count"] == 1
        r = client.get(f"/api/edip/decisions/{first_id}", headers=admin_headers)
        assert r.status_code == 200

    def test_creation_on_non_current_exposure_fails_closed(
        self, client, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        # withdraw the exposure through the Ch.3 service (the only writer)
        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, exposure_id,
                ExposureResolve(status="false_positive", resolution_reason="test withdrawal"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        r = _create_decision(client, admin_headers, exposure_id)
        assert r.status_code == 404

    def test_unknown_vocabulary_refused(self, client, admin_headers, scored_exposure):
        r = _create_decision(
            client, admin_headers, scored_exposure["exposure_id"],
            decision_type="ignore",  # the V1 vocabulary is retired
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# State machine + verified closure (PATCH-09)
# ---------------------------------------------------------------------------


class TestStateMachine:
    def _drive_to_mitigated(self, client, headers, decision_id):
        for target in ("planned", "in_progress", "mitigated"):
            r = client.post(
                f"/api/edip/decisions/{decision_id}/transition",
                json={"to": target},
                headers=headers,
            )
            assert r.status_code == 200, (target, r.text)

    def test_happy_path_verified_closure_resolves_the_exact_episode(
        self, client, analyst_headers, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, analyst_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]

        self._drive_to_mitigated(client, analyst_headers, decision_id)

        # the exposure STAYS current through planning/mitigation/verification
        # (D-16: a claimed fix moves nothing until verification succeeds)
        assert _exposure_status(exposure_id) == "confirmed"

        # closure without verification evidence ⇒ refused (fail-closed)
        r = client.post(f"/api/edip/decisions/{decision_id}/close", headers=analyst_headers)
        assert r.status_code == 409
        assert _exposure_status(exposure_id) == "confirmed"

        r = client.post(
            f"/api/edip/decisions/{decision_id}/verifications",
            json={
                "evidence_kind": "analyst_attestation",
                "evidence_ref": {"attestation": "patch confirmed by host re-inspection"},
                "verdict": "pass",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["decision"]["state"] == "verification"
        assert body["verification"]["exposure_version"]

        # PATCH-09: ONE transaction closes the decision and resolves the
        # exact episode through the Ch.3 exposure service
        r = client.post(f"/api/edip/decisions/{decision_id}/close", headers=analyst_headers)
        assert r.status_code == 200, r.text
        assert r.json()["decision"]["state"] == "closed"
        assert _exposure_status(exposure_id) == "resolved"
        assert _audit_exists(TENANT_A, "edip.decision_closed", str(decision_id))
        assert _audit_exists(TENANT_A, "exposure.resolved", str(exposure_id))

    def test_invalid_edges_refused(self, client, analyst_headers, scored_exposure):
        r = _create_decision(client, analyst_headers, scored_exposure["exposure_id"])
        decision_id = r.json()["decision"]["id"]
        # needs_decision → mitigated skips four states
        r = client.post(
            f"/api/edip/decisions/{decision_id}/transition",
            json={"to": "mitigated"},
            headers=analyst_headers,
        )
        assert r.status_code == 409
        # unknown target
        r = client.post(
            f"/api/edip/decisions/{decision_id}/transition",
            json={"to": "resolved"},
            headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_failed_verification_does_not_enable_closure(
        self, client, analyst_headers, scored_exposure
    ):
        r = _create_decision(client, analyst_headers, scored_exposure["exposure_id"])
        decision_id = r.json()["decision"]["id"]
        self._drive_to_mitigated(client, analyst_headers, decision_id)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/verifications",
            json={
                "evidence_kind": "scout_job",
                "evidence_ref": {"scout_job_id": "job-123"},
                "verdict": "fail",
                "note": "still reachable",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201
        assert r.json()["decision"]["state"] == "verification"
        r = client.post(f"/api/edip/decisions/{decision_id}/close", headers=analyst_headers)
        assert r.status_code == 409

    def test_verification_before_mitigation_refused(
        self, client, analyst_headers, scored_exposure
    ):
        r = _create_decision(client, analyst_headers, scored_exposure["exposure_id"])
        decision_id = r.json()["decision"]["id"]
        r = client.post(
            f"/api/edip/decisions/{decision_id}/verifications",
            json={
                "evidence_kind": "analyst_attestation",
                "evidence_ref": {"attestation": "premature"},
                "verdict": "pass",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# EDIP never writes Ch.3 state (rule 4; D-5/D-16)
# ---------------------------------------------------------------------------


class TestNeverWritesCh3:
    def test_lifecycle_leaves_exposure_and_finding_untouched(
        self, client, analyst_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        finding_id = scored_exposure["finding_id"]
        before = (_exposure_status(exposure_id),)
        r = _create_decision(client, analyst_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]
        for target in ("planned", "in_progress", "mitigated"):
            client.post(
                f"/api/edip/decisions/{decision_id}/transition",
                json={"to": target},
                headers=analyst_headers,
            )
        client.post(
            f"/api/edip/decisions/{decision_id}/verifications",
            json={
                "evidence_kind": "analyst_attestation",
                "evidence_ref": {"attestation": "ok"},
                "verdict": "pass",
            },
            headers=analyst_headers,
        )
        assert (_exposure_status(exposure_id),) == before == ("confirmed",)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM findings WHERE id = %s;", (str(finding_id),))
                assert cur.fetchone()["status"] == "open"


# ---------------------------------------------------------------------------
# Accepted risk — dual control via the Ch.5 primitive (rule 8)
# ---------------------------------------------------------------------------


class TestAcceptedRiskDualControl:
    def test_full_dual_control_flow_seals_fresh_snapshot(
        self, client, admin_headers, superadmin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]
        review_due = datetime.now(timezone.utc) + timedelta(days=90)

        # propose (admin-a is the owner)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/accept-risk/propose",
            json={
                "rationale": "compensating controls in place",
                "review_due_at": review_due.isoformat(),
                "mitigation_type": "COMPENSATING_CONTROL",
            },
            headers=admin_headers,
        )
        assert r.status_code == 201, r.text
        r.json()["approval_id"]

        # self-approval refused — HARD dual control (Ch.5)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/accept-risk/decide",
            json={"decision": "approved"},
            headers=admin_headers,
        )
        assert r.status_code == 409
        assert "self-approval" in r.json()["detail"]["message"]

        # a DIFFERENT admin decides and applies — one atomic pair
        r = client.post(
            f"/api/edip/decisions/{decision_id}/accept-risk/decide",
            json={"decision": "approved"},
            headers=superadmin_headers,
        )
        assert r.status_code == 200, r.text
        r = client.post(
            f"/api/edip/decisions/{decision_id}/accept-risk/apply",
            headers=superadmin_headers,
        )
        assert r.status_code == 200, r.text

        # a NEW revision seals its OWN snapshot (PATCH-13)
        r = client.get(f"/api/edip/decisions/{decision_id}", headers=admin_headers)
        detail = r.json()
        current = detail["decision"]
        assert current["state"] == "accepted_risk"
        assert current["decision_type"] == "accept-risk"
        assert current["revision"] == 2
        assert current["review_due_at"]
        assert current["mitigation_type"] == "COMPENSATING_CONTROL"
        assert current["consumed_snapshot"]["source_view"]["as_of"] >= \
            detail["revisions"][0]["consumed_snapshot"]["source_view"]["as_of"]
        # the exposure stays current and visible (active disposition)
        assert _exposure_status(exposure_id) == "confirmed"
        # single-use: a second apply is a visible conflict, never silent
        r = client.post(
            f"/api/edip/decisions/{decision_id}/accept-risk/apply",
            headers=superadmin_headers,
        )
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "approval_already_applied"

    def test_propose_on_terminal_or_branch_state_refused(
        self, client, admin_headers, superadmin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]
        review_due = datetime.now(timezone.utc) + timedelta(days=30)
        # defer first, then a second accept-risk proposal is out of the
        # branch-from set for the SAME (now deferred) revision
        r = client.post(
            f"/api/edip/decisions/{decision_id}/defer",
            json={
                "rationale": "not now",
                "review_due_at": review_due.isoformat(),
            },
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        # the deferred revision is the current one; accept-risk from a
        # deferred revision is not an allowed branch edge
        r = client.post(
            f"/api/edip/decisions/{decision_id}/accept-risk/propose",
            json={
                "rationale": "double branch",
                "review_due_at": review_due.isoformat(),
            },
            headers=admin_headers,
        )
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# Defer + the review-expiry effective-state rule (rule 2)
# ---------------------------------------------------------------------------


class TestDeferAndReviewExpiry:
    def test_defer_requires_future_review_date(self, client, admin_headers, scored_exposure):
        r = _create_decision(client, admin_headers, scored_exposure["exposure_id"])
        decision_id = r.json()["decision"]["id"]
        past = datetime.now(timezone.utc) - timedelta(days=1)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/defer",
            json={"rationale": "r", "review_due_at": past.isoformat()},
            headers=admin_headers,
        )
        assert r.status_code == 422

    def test_defer_seals_fresh_snapshot_and_stays_visible(
        self, client, admin_headers, analyst_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]
        review_due = datetime.now(timezone.utc) + timedelta(days=14)
        # transitions by owner or admin — the owner defers here
        r = client.post(
            f"/api/edip/decisions/{decision_id}/defer",
            json={
                "rationale": "scheduled for the next window",
                "review_due_at": review_due.isoformat(),
            },
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        decision = r.json()["decision"]
        assert decision["state"] == "deferred"
        assert decision["revision"] == 2
        assert decision["decision_type"] == "defer"
        # the exposure stays confirmed and in the workbench queue
        assert _exposure_status(exposure_id) == "confirmed"
        r = client.get("/api/spectrum/queue", headers=analyst_headers)
        assert exposure_id in {i["exposure_id"] for i in r.json()["items"]}

    def test_review_expiry_materializes_needs_decision_on_read(
        self, client, admin_headers, analyst_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]
        review_due = datetime.now(timezone.utc) + timedelta(days=14)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/defer",
            json={"rationale": "r", "review_due_at": review_due.isoformat()},
            headers=admin_headers,
        )
        assert r.status_code == 200
        # the defer created a NEW revision — the review date lives there
        current_revision_id = r.json()["decision"]["id"]

        # time passes — no scheduler exists; simulate by moving the date back
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE edip_decisions SET review_due_at = %s "
                    "WHERE id = %s;",
                    (datetime.now(timezone.utc) - timedelta(minutes=1),
                     str(current_revision_id)),
                )
            conn.commit()

        # the FIRST observation materializes the transition and audits it
        r = client.get(f"/api/edip/decisions/{decision_id}", headers=analyst_headers)
        assert r.status_code == 200
        assert r.json()["decision"]["state"] == "needs_decision"
        assert _audit_exists(
            TENANT_A, "edip.review_expired", str(current_revision_id)
        )

        # the queue renders it as Needs-Decision too
        r = client.get("/api/edip/queue", headers=admin_headers)
        row = next(
            i for i in r.json()["items"] if i["decision_id"] == current_revision_id
        )
        assert row["state"] == "needs_decision"


# ---------------------------------------------------------------------------
# Reopen + recurrence (rule 9; D-16)
# ---------------------------------------------------------------------------


class TestReopenAndRecurrence:
    def test_decision_level_reopen_and_terminal_discipline(
        self, client, analyst_headers, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, analyst_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]
        review_due = datetime.now(timezone.utc) + timedelta(days=10)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/defer",
            json={"rationale": "r", "review_due_at": review_due.isoformat()},
            headers=analyst_headers,
        )
        assert r.status_code == 200
        # dispute: the same decision reopens (exposure still confirmed)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/reopen",
            json={"reason": "verification of the deferral rationale disputed"},
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        reopened_id = r.json()["decision"]["id"]
        assert r.json()["decision"]["state"] == "needs_decision"
        assert _audit_exists(TENANT_A, "edip.decision_reopened", str(reopened_id))

    def test_recurrence_creates_new_decision_linked_back(
        self, client, analyst_headers, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, analyst_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]

        # drive to verified closure (the old episode resolves)
        for target in ("planned", "in_progress", "mitigated"):
            client.post(
                f"/api/edip/decisions/{decision_id}/transition",
                json={"to": target}, headers=analyst_headers,
            )
        client.post(
            f"/api/edip/decisions/{decision_id}/verifications",
            json={
                "evidence_kind": "analyst_attestation",
                "evidence_ref": {"attestation": "fixed"},
                "verdict": "pass",
            },
            headers=analyst_headers,
        )
        r = client.post(f"/api/edip/decisions/{decision_id}/close", headers=analyst_headers)
        assert r.status_code == 200

        # closed decisions never reopen
        r = client.post(
            f"/api/edip/decisions/{decision_id}/reopen",
            json={"reason": "second thoughts"},
            headers=analyst_headers,
        )
        assert r.status_code == 409

        # recurrence: a NEW episode on the SAME finding (Ch.3 reuses it)
        r = client.post(
            "/api/exposure/confirm",
            json={
                "finding_id": scored_exposure["finding_id"],
                "asset_id": str(scored_exposure["asset_id"]),
                "evidence": {"reference": "recurrence-scan"},
            },
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        new_exposure_id = r.json()["id"]
        assert new_exposure_id != str(exposure_id)

        # the NEW decision links back to the old one for history
        r = _create_decision(
            client, analyst_headers, new_exposure_id,
            previous_decision_id=decision_id,
        )
        assert r.status_code == 201
        new_decision = r.json()["decision"]
        assert new_decision["previous_decision_id"] == decision_id

        # a recurrence link against a non-resolved prior episode is refused
        r = _create_decision(
            client, analyst_headers, new_exposure_id,
            previous_decision_id=new_decision["id"],
        )
        assert r.status_code == 409  # decision already exists for the episode


# ---------------------------------------------------------------------------
# Supersession (rule 10; PATCH-10) — no orphan decisions
# ---------------------------------------------------------------------------


class TestSupersession:
    def test_confirmation_withdrawal_supersedes_the_open_decision(
        self, client, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]

        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, exposure_id,
                ExposureResolve(status="false_positive", resolution_reason="not applicable"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()

        r = client.get(f"/api/edip/decisions/{decision_id}", headers=admin_headers)
        assert r.status_code == 200
        decision = r.json()["decision"]
        assert decision["state"] == "superseded"
        assert decision["superseded_reason"] == "confirmation_withdrawn"
        assert _audit_exists(TENANT_A, "edip.decision_superseded", str(decision_id))

    def test_asset_decommission_supersedes_the_open_decision(
        self, client, admin_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        asset_id = scored_exposure["asset_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision_id = r.json()["decision"]["id"]

        with get_db_connection() as conn:
            supersede_exposures_for_asset(
                conn, TENANT_A, asset_id,
                actor_id="admin-a", actor_role="admin",
                reason="asset decommissioned",
            )
            conn.commit()

        r = client.get(f"/api/edip/decisions/{decision_id}", headers=admin_headers)
        decision = r.json()["decision"]
        assert decision["state"] == "superseded"
        assert decision["superseded_reason"] == "exposure_superseded"

        # superseded decisions leave the queue — no orphan rows
        r = client.get("/api/edip/queue", headers=admin_headers)
        assert decision_id not in {i["decision_id"] for i in r.json()["items"]}


# ---------------------------------------------------------------------------
# Snapshot sealing (rule 3; §3.3.6; PATCH-13)
# ---------------------------------------------------------------------------


class TestSnapshotSealing:
    def test_snapshot_is_immutable_history_while_live_score_recomputes(
        self, client, admin_headers, analyst_headers, scored_exposure
    ):
        exposure_id = scored_exposure["exposure_id"]
        r = _create_decision(client, admin_headers, exposure_id)
        decision = r.json()["decision"]
        decision_id = decision["id"]
        sealed_value = decision["consumed_snapshot"].get("value")

        # a new scoring input changes the LIVE recompute...
        r = client.post(
            f"/api/exposure/{exposure_id}/business-impact",
            json={"value": 9, "reason": "crown-jewel"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text

        # ...but never the sealed snapshot (immutable history)
        r = client.get(f"/api/edip/decisions/{decision_id}", headers=admin_headers)
        current = r.json()["decision"]
        assert current["consumed_snapshot"] == decision["consumed_snapshot"]
        assert current["consumed_snapshot"].get("value") == sealed_value

        # a score-consuming branch action seals a FRESH payload, never reuses
        review_due = datetime.now(timezone.utc) + timedelta(days=30)
        r = client.post(
            f"/api/edip/decisions/{decision_id}/defer",
            json={"rationale": "r", "review_due_at": review_due.isoformat()},
            headers=admin_headers,
        )
        assert r.status_code == 200
        fresh = r.json()["decision"]
        assert fresh["revision"] == 2
        assert fresh["consumed_snapshot"]["source_view"]["as_of"] > \
            decision["consumed_snapshot"]["source_view"]["as_of"]
        assert fresh["consumed_snapshot"] != decision["consumed_snapshot"]


# ---------------------------------------------------------------------------
# Tenant isolation (Q10)
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_cross_tenant_decision_is_the_identical_404(
        self, client, auth_headers_tenant_b_admin, admin_headers, scored_exposure
    ):
        r = _create_decision(client, admin_headers, scored_exposure["exposure_id"])
        decision_id = r.json()["decision"]["id"]
        r = client.get(f"/api/edip/decisions/{decision_id}", headers=auth_headers_tenant_b_admin)
        assert r.status_code == 404
        r = client.post(
            f"/api/edip/decisions/{decision_id}/transition",
            json={"to": "planned"},
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404
        r = client.get("/api/edip/queue", headers=auth_headers_tenant_b_admin)
        assert decision_id not in {i["decision_id"] for i in r.json()["items"]}
