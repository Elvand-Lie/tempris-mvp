# backend/tests/test_ch9_standard.py
"""
Focused suite for Chapter 9 — STANDARD / GRC (PRD-000 v1.11 Ch.9;
Appendix A Flow E; PATCH-11/12; frozen decision 1).

PRD-derived checklist (tests/PRD_TEST_CHECKLIST_ch8_ch9.md):

  1.  module entitlement gate; platform blocked; analyst+ authority
  2.  the 8 framework catalogs seeded; everything not_assessed by default
  3.  compliance_among_assessed is the only metric and ALWAYS renders with
      its assessment coverage — a bare percentage is forbidden
  4.  assessments: draft → signed (dual sign-off end_user/PIC, distinct
      actors) → archived; one live assessment per control
  5.  policies: draft → active → superseded/archived versioning
  6.  control evidence: typed allowlist store; download is an AUDITED read;
      EDIP remediation evidence maps BY REFERENCE (unknown citation refused)
  7.  incidents: validated, timestamped, deduped on (tenant, source,
      external_event_id); replays create no duplicate obligations
  8.  the obligation clock pins the TRIGGER (event time): due_at =
      event_time + clock (MAS 12.1.5 = 1h); receipt/retry never restarts it
  9.  rule evaluation failure fails VISIBLY on the incident:
      evaluation_error row persisted, no obligation, resolution blocked
  10. PATCH-11: a rule-relevant edit creates a new input revision, re-pends
      ALL expected rules (negatives included), reopens a resolved incident
      with audit; attempt/revision history is retained
  11. reevaluation reuses the STABLE obligation identity, never duplicates;
      corrected trigger facts re-derive the deadline through an audited
      revision that preserves prior values + submission history (PATCH-12)
  12. read-time overdue/breach derivation; breach recorded when first
      observed; completed-late derives separately and survives closure
  13. submission without proof refused; the record is immutable; the
      obligation is never auto-closed
  14. unfinished evaluations/obligations block resolution (commit-time check)
  15. the boundary is structural: no score-ish column in any standard_* table
      and a full incident flow leaves findings/asset_exposures untouched
  16. tenant isolation for every surface
  17. exceptions: requested → approved(admin+) → expired (effective-on-read)
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.auth import create_test_token
from app.db import get_db_connection
from tests.conftest import TENANT_A

MAS_RULE_KEY = "mas_trm_12_1_5_incident_notification"


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def other_admin_headers():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="superadmin-a", role="superadmin")
    return {"Authorization": f"Bearer {token}"}


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


def _framework_with_controls(client, headers):
    r = client.get("/api/standard/frameworks", headers=headers)
    assert r.status_code == 200, r.text
    frameworks = r.json()["frameworks"]
    mas = next(f for f in frameworks if f["framework_code"] == "mas_trm_2024")
    return frameworks, mas


def _create_incident(client, headers, *, event_time=None, inputs=None,
                     source="soc", external_event_id="evt-1", title="Suspected breach"):
    body = {
        "source": source,
        "external_event_id": external_event_id,
        "title": title,
        "event_time": (event_time or datetime.now(timezone.utc)).isoformat(),
        "inputs": inputs if inputs is not None
        else {"incident_kind": "cyber_security_incident"},
    }
    return client.post("/api/standard/incidents", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_platform_session_blocked(self, client, platform_admin_headers):
        r = client.get("/api/standard/frameworks", headers=platform_admin_headers)
        assert r.status_code == 403

    def test_module_entitlement_required(self, client, admin_headers):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"STANDARD": false}', str(TENANT_A)),
                )
            conn.commit()
        r = client.get("/api/standard/frameworks", headers=admin_headers)
        assert r.status_code == 403
        assert "STANDARD" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Frameworks + the only compliance metric
# ---------------------------------------------------------------------------


class TestFrameworks:
    def test_eight_catalogs_seeded_all_not_assessed(self, client, analyst_headers):
        frameworks, mas = _framework_with_controls(client, analyst_headers)
        assert {f["framework_code"] for f in frameworks} == {
            "mas_trm_2024", "pdpa", "iso_27001", "im8a", "nist_csf",
            "soc2", "pci_dss", "csa_cybertrust",
        }
        assert len(mas["controls"]) == 7
        assert all(c["status"] == "not_assessed" for f in frameworks
                   for c in f["controls"])
        compliance = mas["compliance"]
        assert compliance["compliance_among_assessed"] is None
        assert compliance["assessed"] == 0
        # the coverage rendering is mandatory — never a bare percentage
        assert "0/7 assessed" in compliance["rendering"]

    def test_metric_renders_with_coverage(self, client, analyst_headers,
                                          admin_headers):
        _, mas = _framework_with_controls(client, analyst_headers)
        control = mas["controls"][0]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "compliant"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        assessment_id = r.json()["assessment"]["id"]
        client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "end_user"}, headers=analyst_headers,
        )
        r = client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "pic"}, headers=admin_headers,
        )
        assert r.status_code == 200, r.text

        _, mas = _framework_with_controls(client, analyst_headers)
        compliance = mas["compliance"]
        assert compliance["assessed"] == 1
        # _jsonify renders non-int numbers in their exact string form (the
        # Ch.3 wire contract); the value is 100.0 either way
        assert float(compliance["compliance_among_assessed"]) == 100.0
        assert "100.0% among assessed · 1/7 assessed" in compliance["rendering"]


# ---------------------------------------------------------------------------
# Assessments — dual sign-off
# ---------------------------------------------------------------------------


class TestAssessments:
    def _draft(self, client, analyst_headers):
        r = client.get("/api/standard/frameworks", headers=analyst_headers)
        iso = next(f for f in r.json()["frameworks"]
                   if f["framework_code"] == "iso_27001")
        control = iso["controls"][0]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "partial",
                  "notes": "logging partial"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        return r.json()["assessment"]["id"]

    def test_dual_signoff_requires_two_actors(self, client, analyst_headers,
                                              admin_headers):
        assessment_id = self._draft(client, analyst_headers)
        # the same actor cannot hold both capacities
        r = client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "end_user"}, headers=analyst_headers,
        )
        assert r.status_code == 200
        r = client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "pic"}, headers=analyst_headers,
        )
        assert r.status_code == 409
        # a different actor completes the dual sign-off
        r = client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "pic"}, headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["assessment"]["state"] == "signed"

    def test_one_live_assessment_per_control(self, client, analyst_headers):
        assessment_id = self._draft(client, analyst_headers)
        r = client.get("/api/standard/frameworks", headers=analyst_headers)
        iso = next(f for f in r.json()["frameworks"]
                   if f["framework_code"] == "iso_27001")
        control = iso["controls"][0]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "compliant"},
            headers=analyst_headers,
        )
        assert r.status_code == 409
        # archiving frees the control for a fresh assessment
        r = client.post(
            f"/api/standard/assessments/{assessment_id}/archive",
            headers=analyst_headers,
        )
        assert r.status_code == 200
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "compliant"},
            headers=analyst_headers,
        )
        assert r.status_code == 201


# ---------------------------------------------------------------------------
# Policies — registry + archive/supersede versioning
# ---------------------------------------------------------------------------


class TestPolicies:
    def test_versioning_lifecycle(self, client, analyst_headers):
        r = client.post(
            "/api/standard/policies",
            json={"title": "Access Policy", "body": "v1 text"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        v1 = r.json()["policy"]
        r = client.post(
            f"/api/standard/policies/{v1['id']}/activate", headers=analyst_headers
        )
        assert r.status_code == 200
        # v2 supersedes v1 atomically on activation
        r = client.post(
            "/api/standard/policies",
            json={"title": "Access Policy", "body": "v2 text",
                  "supersedes_id": v1["id"]},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        v2 = r.json()["policy"]
        assert v2["version"] == 2
        r = client.post(
            f"/api/standard/policies/{v2['id']}/activate", headers=analyst_headers
        )
        assert r.status_code == 200
        r = client.get("/api/standard/policies", headers=analyst_headers)
        states = {p["id"]: p["state"] for p in r.json()["policies"]}
        assert states[v1["id"]] == "superseded"
        assert states[v2["id"]] == "active"
        # archive
        r = client.post(
            f"/api/standard/policies/{v2['id']}/archive", headers=analyst_headers
        )
        assert r.status_code == 200
        assert r.json()["policy"]["state"] == "archived"


# ---------------------------------------------------------------------------
# Control evidence — typed store, audited download, EDIP by reference
# ---------------------------------------------------------------------------


class TestControlEvidence:
    def test_attach_list_download_audited(self, client, analyst_headers):
        r = client.get("/api/standard/frameworks", headers=analyst_headers)
        control = r.json()["frameworks"][0]["controls"][0]
        content = b"control evidence payload"
        r = client.post(
            "/api/standard/evidence",
            json={
                "control_id": control["control_id"],
                "title": "Q3 scan report",
                "media_type": "text/csv",
                "content_base64": base64.b64encode(content).decode(),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        evidence = r.json()["evidence"]
        assert evidence["sha256"]
        assert evidence["size_bytes"] == len(content)

        # download is an AUDITED read (Q12)
        r = client.get(
            f"/api/standard/evidence/{evidence['id']}/download",
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert r.content == content
        assert _audit_exists(
            TENANT_A, "standard.evidence_downloaded", str(evidence["id"])
        )

    def test_media_type_allowlist_enforced(self, client, analyst_headers):
        r = client.get("/api/standard/frameworks", headers=analyst_headers)
        control = r.json()["frameworks"][0]["controls"][0]
        r = client.post(
            "/api/standard/evidence",
            json={
                "control_id": control["control_id"],
                "title": "exe",
                "media_type": "application/x-msdownload",
                "content_base64": base64.b64encode(b"MZ").decode(),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_edip_evidence_maps_by_reference_only(
        self, client, analyst_headers, scored_edip_verification
    ):
        r = client.get("/api/standard/frameworks", headers=analyst_headers)
        control = r.json()["frameworks"][0]["controls"][0]
        # an unknown EDIP verification citation is refused — never accepted
        r = client.post(
            "/api/standard/evidence",
            json={
                "control_id": control["control_id"],
                "title": "remediation proof",
                "media_type": "application/json",
                "edip_verification_id": str(uuid.uuid4()),
                "content_base64": base64.b64encode(b"{}").decode(),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 404
        # a real Ch.8 verification maps BY REFERENCE
        r = client.post(
            "/api/standard/evidence",
            json={
                "control_id": control["control_id"],
                "title": "remediation proof",
                "media_type": "application/json",
                "edip_verification_id": str(scored_edip_verification),
                "content_base64": base64.b64encode(b"{}").decode(),
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        assert r.json()["evidence"]["edip_verification_id"] == \
            str(scored_edip_verification)


@pytest.fixture
def scored_edip_verification(client, admin_headers):
    """One Ch.8 verification record to map by reference (Ch.9 ⇄ Ch.8)."""
    from tests.test_ch8_edip import (  # reuse the Ch8 seeding helpers
        create_asset_in_db, seed_cve, seed_cvss,
    )
    asset_id = create_asset_in_db(name="standard-edip-link")
    cve = seed_cve("CVE-2026-80002")
    seed_cvss(cve, 8.0)
    r = client.post(
        "/api/exposure/findings",
        json={"title": "edip link", "severity": "high", "canonical_cve_id": cve},
        headers=admin_headers,
    )
    finding_id = r.json()["id"]
    r = client.post(
        "/api/exposure/confirm",
        json={"finding_id": finding_id, "asset_id": str(asset_id),
              "evidence": {"reference": "std-link"}},
        headers=admin_headers,
    )
    exposure_id = r.json()["id"]
    r = client.post(
        "/api/edip/decisions",
        json={"exposure_id": exposure_id, "decision_type": "remediate"},
        headers=admin_headers,
    )
    decision_id = r.json()["decision"]["id"]
    for target in ("planned", "in_progress", "mitigated"):
        client.post(
            f"/api/edip/decisions/{decision_id}/transition",
            json={"to": target}, headers=admin_headers,
        )
    r = client.post(
        f"/api/edip/decisions/{decision_id}/verifications",
        json={
            "evidence_kind": "analyst_attestation",
            "evidence_ref": {"attestation": "remediated"},
            "verdict": "pass",
        },
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["verification"]["id"]


# ---------------------------------------------------------------------------
# Incidents, rules, obligations (Flow E; PATCH-11/12)
# ---------------------------------------------------------------------------


class TestIncidentsAndRules:
    def test_rule_fires_with_pinned_trigger_clock(self, client, analyst_headers):
        # the incident was discovered 2h ago; the post is NOW — the clock
        # pins the EVENT time, so the 1h deadline is already in the past
        event_time = datetime.now(timezone.utc) - timedelta(hours=2)
        r = _create_incident(client, analyst_headers, event_time=event_time)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["outcome"] == "created"
        incident = body["incident"]
        obligation = next(
            o for o in incident["obligations"]
            if o["obligation_key"].endswith(MAS_RULE_KEY)
        )
        assert obligation["state"] == "open"
        due = datetime.fromisoformat(obligation["due_at"])
        trigger = datetime.fromisoformat(obligation["trigger_at"])
        assert due - trigger == timedelta(hours=1)
        assert trigger == event_time

        evaluation = next(
            e for e in incident["evaluations"]
            if e["rule_key"] == MAS_RULE_KEY and e["is_current"]
        )
        assert evaluation["state"] == "evaluated"
        assert evaluation["result"] == "obligation_ready"
        assert evaluation["incident_revision_no"] == 1

    def test_dedup_replay_creates_no_duplicate_obligations(
        self, client, analyst_headers
    ):
        r1 = _create_incident(client, analyst_headers)
        assert r1.status_code == 201
        first = r1.json()["incident"]
        r2 = _create_incident(client, analyst_headers)
        assert r2.status_code == 201
        assert r2.json()["outcome"] == "replay"
        assert r2.json()["incident"]["id"] == first["id"]
        assert len(r2.json()["incident"]["obligations"]) == \
            len(first["obligations"]) == 1

    def test_negative_evaluation_is_recorded_not_silent(
        self, client, analyst_headers
    ):
        r = _create_incident(
            client, analyst_headers,
            inputs={"incident_kind": "facility_fault"},
            external_event_id="evt-neg",
        )
        assert r.status_code == 201
        evaluation = next(
            e for e in r.json()["incident"]["evaluations"]
            if e["rule_key"] == MAS_RULE_KEY and e["is_current"]
        )
        assert evaluation["state"] == "evaluated"
        assert evaluation["result"] == "not_applicable"
        assert evaluation["obligation_id"] is None
        assert r.json()["incident"]["obligations"] == []


# ---------------------------------------------------------------------------
# Rule evaluation failure fails VISIBLY on the incident
# ---------------------------------------------------------------------------


class TestEvaluationFailure:
    @pytest.fixture(autouse=True)
    def broken_rule(self):
        """A catalog rule whose template is unreadable (no kind) — inserted
        for this test class, deactivated afterwards (the catalog is global)."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO standard_rules (
                        rule_key, rule_version, title, is_active, condition,
                        obligation_template, clock_seconds
                    ) VALUES ('test_broken_rule', 1, 'Broken rule', TRUE,
                              '{"incident_kind": "broken_kind"}'::jsonb,
                              '{}'::jsonb, 60)
                    ON CONFLICT (rule_key, rule_version) DO UPDATE
                    SET is_active = TRUE,
                        -- reset what earlier runs may have "fixed"
                        obligation_template = '{}'::jsonb;
                    """
                )
            conn.commit()
        yield
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE standard_rules SET is_active = FALSE "
                    "WHERE rule_key = 'test_broken_rule';"
                )
            conn.commit()

    def test_error_row_blocks_resolution_and_retry_recovers(
        self, client, analyst_headers
    ):
        r = _create_incident(
            client, analyst_headers,
            inputs={"incident_kind": "broken_kind"},
            external_event_id="evt-broken",
        )
        assert r.status_code == 201, r.text
        incident = r.json()["incident"]
        evaluation = next(
            e for e in incident["evaluations"]
            if e["rule_key"] == "test_broken_rule" and e["is_current"]
        )
        # the failure is a visible alarm row — never a clean negative
        assert evaluation["state"] == "evaluation_error"
        assert evaluation["error_detail"]
        # no obligation could be created (it cannot be known)
        assert all(
            "test_broken_rule" not in o["obligation_key"]
            for o in incident["obligations"]
        )
        # resolution is blocked
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/resolve",
            headers=analyst_headers,
        )
        assert r.status_code == 409
        assert "unfinished rule evaluations" in r.json()["detail"]["message"]

        # fix the template, then retry — the attempt history is retained
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE standard_rules
                    SET obligation_template = jsonb_build_object(
                            'kind', 'regulator_notification',
                            'title', 'Fixed notice')
                    WHERE rule_key = 'test_broken_rule';
                    """
                )
            conn.commit()
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/rules/test_broken_rule/reevaluate",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        evaluations = [
            e for e in r.json()["incident"]["evaluations"]
            if e["rule_key"] == "test_broken_rule"
        ]
        assert any(e["state"] == "evaluation_error" for e in evaluations)  # history
        current = next(e for e in evaluations if e["is_current"])
        assert current["state"] == "evaluated"
        assert current["attempt"] == evaluation["attempt"] + 1


# ---------------------------------------------------------------------------
# PATCH-11/12: revisions, stable obligations, reopen-on-edit
# ---------------------------------------------------------------------------


class TestIncidentRevisions:
    def test_edit_creates_revision_repends_rules_and_reopens(
        self, client, analyst_headers
    ):
        event_time = datetime.now(timezone.utc) - timedelta(hours=3)
        r = _create_incident(client, analyst_headers, event_time=event_time,
                             external_event_id="evt-rev")
        incident = r.json()["incident"]
        obligation_before = incident["obligations"][0]

        # fulfil + resolve, then edit — the edit reopens the incident
        r = client.post(
            f"/api/standard/obligations/{obligation_before['id']}/submission",
            json={"channel": "MAS portal", "reference": "MAS-REF-1",
                  "proof": "portal receipt"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/resolve",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text

        corrected = datetime.now(timezone.utc) - timedelta(hours=1)
        r = client.patch(
            f"/api/standard/incidents/{incident['id']}",
            json={
                "event_time": corrected.isoformat(),
                "inputs": {"incident_kind": "cyber_security_incident",
                           "systems": "core-banking"},
                "correction_note": "corrected discovery time after SOC review",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["incident"]["state"] == "acknowledged"  # reopened
        assert body["incident"]["current_revision"] == 2
        assert _audit_exists(
            TENANT_A, "standard.incident_reopened", str(incident["id"])
        )

        # ALL expected rules re-pended on the new revision; revision-1
        # attempts (completed, not just errors) remain as history
        current_evals = [
            e for e in body["incident"]["evaluations"] if e["is_current"]
        ]
        assert {e["rule_key"] for e in current_evals} >= {MAS_RULE_KEY}
        assert all(e["incident_revision_no"] == 2 for e in current_evals)
        old_evals = [
            e for e in body["incident"]["evaluations"] if not e["is_current"]
        ]
        assert old_evals, "prior revision attempts must be retained"
        assert all(e["incident_revision_no"] == 1 for e in old_evals)
        assert any(e["result"] == "obligation_ready" for e in old_evals)

        # the obligation kept its STABLE identity — corrected, not duplicated
        obligations = body["incident"]["obligations"]
        assert len(obligations) == 1
        corrected_obligation = obligations[0]
        assert corrected_obligation["id"] == obligation_before["id"]
        assert corrected_obligation["revision"] == 2
        assert datetime.fromisoformat(corrected_obligation["due_at"]) \
            - datetime.fromisoformat(corrected_obligation["trigger_at"]) \
            == timedelta(hours=1)
        assert _audit_exists(
            TENANT_A, "standard.obligation_corrected", str(corrected_obligation["id"])
        )
        # the submission history survived the correction
        r = client.get(
            f"/api/standard/obligations/{corrected_obligation['id']}/submissions",
            headers=analyst_headers,
        )
        assert len(r.json()["submissions"]) == 1


# ---------------------------------------------------------------------------
# Obligations — deadline state, submissions, closure
# ---------------------------------------------------------------------------


class TestObligationsAndSubmissions:
    def _incident_with_open_obligation(self, client, analyst_headers):
        event_time = datetime.now(timezone.utc) - timedelta(hours=2)
        r = _create_incident(client, analyst_headers, event_time=event_time,
                             external_event_id=f"evt-{uuid.uuid4()}")
        assert r.status_code == 201, r.text
        incident = r.json()["incident"]
        obligation = incident["obligations"][0]
        return incident, obligation

    def test_submission_requires_proof_and_is_immutable(
        self, client, analyst_headers
    ):
        _, obligation = self._incident_with_open_obligation(client, analyst_headers)
        # without proof: refused — the obligation stays open, never auto-closed
        r = client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "MAS portal", "reference": "x", "proof": " "},
            headers=analyst_headers,
        )
        assert r.status_code == 422
        r = client.get(
            f"/api/standard/obligations/{obligation['id']}/submissions",
            headers=analyst_headers,
        )
        assert r.json()["submissions"] == []
        r = client.get("/api/standard/obligations", headers=analyst_headers)
        row = next(o for o in r.json()["items"] if o["id"] == obligation["id"])
        assert row["state"] == "open"

        # with proof: fulfilled; completed-late derives from the pinned clock
        r = client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "MAS portal", "reference": "MAS-REF-2",
                  "proof": "portal receipt"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        assert r.json()["obligation"]["state"] == "fulfilled"
        assert r.json()["completed_late"] is True  # due 1h after a 2h-old event

        # the record is immutable at the DB layer
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM standard_submission_records "
                    "WHERE tenant_id = %s AND obligation_id = %s;",
                    (str(TENANT_A), str(obligation["id"])),
                )
                sub_id = cur.fetchone()["id"]
                try:
                    cur.execute(
                        "UPDATE standard_submission_records SET proof = 'forged' "
                        "WHERE id = %s;",
                        (str(sub_id),),
                    )
                    raised = False
                except Exception:
                    conn.rollback()
                    raised = True
        assert raised, "submission records must be immutable"

        # a second submission is refused (one proof per obligation)
        r = client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "email", "proof": "second"},
            headers=analyst_headers,
        )
        assert r.status_code in (409, 422)

    def test_breach_recorded_on_first_observation_and_late_survives_closure(
        self, client, analyst_headers
    ):
        incident, obligation = self._incident_with_open_obligation(
            client, analyst_headers
        )
        # first observation past due: breach materializes + audits
        r = client.get("/api/standard/obligations", headers=analyst_headers)
        row = next(o for o in r.json()["items"] if o["id"] == obligation["id"])
        assert row["overdue"] is True
        assert row["breached_at"] is not None
        assert _audit_exists(
            TENANT_A, "standard.obligation_breach_recorded", str(obligation["id"])
        )

        # fulfil (late) and close — lateness SURVIVES closure
        client.post(
            f"/api/standard/obligations/{obligation['id']}/transition",
            json={"to": "in_progress"}, headers=analyst_headers,
        )
        client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "MAS portal", "proof": "receipt"},
            headers=analyst_headers,
        )
        r = client.post(
            f"/api/standard/obligations/{obligation['id']}/close",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        closed = r.json()["obligation"]
        assert closed["state"] == "closed"
        assert closed["completed_late"] is True


# ---------------------------------------------------------------------------
# Resolution blocking (PATCH-11 commit-time check)
# ---------------------------------------------------------------------------


class TestResolutionBlocking:
    def test_open_obligation_blocks_resolution(self, client, analyst_headers):
        event_time = datetime.now(timezone.utc) - timedelta(hours=1)
        r = _create_incident(client, analyst_headers, event_time=event_time,
                             external_event_id=f"evt-{uuid.uuid4()}")
        incident = r.json()["incident"]
        obligation = incident["obligations"][0]
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/resolve",
            headers=analyst_headers,
        )
        assert r.status_code == 409
        assert "open obligations" in r.json()["detail"]["message"]
        client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "MAS portal", "proof": "receipt"},
            headers=analyst_headers,
        )
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/resolve",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# The boundary is structural (frozen decision 1; D-3)
# ---------------------------------------------------------------------------


class TestScoringBoundary:
    def test_no_score_columns_in_any_standard_table(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT table_name, column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND (table_name LIKE 'standard_%%' OR table_name = 'grc_exceptions')
                      AND column_name ~* '(^|_)(score|tes|severity|priority)($|_)';
                    """
                )
                hits = cur.fetchall()
        assert hits == [], f"score-bearing columns found: {hits}"

    def test_full_incident_flow_never_touches_exposure_state(
        self, client, analyst_headers, admin_headers
    ):
        from tests.test_ch8_edip import create_asset_in_db, seed_cve
        asset_id = create_asset_in_db(name="standard-boundary")
        cve = seed_cve("CVE-2026-80003")
        r = client.post(
            "/api/exposure/findings",
            json={"title": "boundary probe", "severity": "high",
                  "canonical_cve_id": cve},
            headers=admin_headers,
        )
        finding_id = r.json()["id"]
        r = client.post(
            "/api/exposure/confirm",
            json={"finding_id": finding_id, "asset_id": str(asset_id),
                  "evidence": {"reference": "boundary"}},
            headers=admin_headers,
        )
        exposure_id = r.json()["id"]

        # a full incident → obligation → submission → resolve flow
        event_time = datetime.now(timezone.utc) - timedelta(hours=1)
        r = _create_incident(client, analyst_headers, event_time=event_time,
                             external_event_id=f"evt-{uuid.uuid4()}")
        incident = r.json()["incident"]
        obligation = incident["obligations"][0]
        client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "MAS portal", "proof": "receipt"},
            headers=analyst_headers,
        )
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/resolve",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text

        # Ch.3 state untouched: the exposure is still confirmed, the finding
        # exactly as Ch.3 left it
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status FROM asset_exposures WHERE id = %s;",
                    (str(exposure_id),),
                )
                assert cur.fetchone()["status"] == "confirmed"
                cur.execute(
                    "SELECT status, severity FROM findings WHERE id = %s;",
                    (str(finding_id),),
                )
                row = cur.fetchone()
                assert row["status"] == "open"
                assert row["severity"] == "high"


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_cross_tenant_incident_and_obligations_invisible(
        self, client, analyst_headers, auth_headers_tenant_b_admin
    ):
        event_time = datetime.now(timezone.utc) - timedelta(hours=1)
        r = _create_incident(client, analyst_headers,
                             event_time=event_time,
                             external_event_id=f"evt-{uuid.uuid4()}")
        incident = r.json()["incident"]
        obligation = incident["obligations"][0]

        r = client.get(
            f"/api/standard/incidents/{incident['id']}",
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/resolve",
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404
        r = client.post(
            f"/api/standard/obligations/{obligation['id']}/submission",
            json={"channel": "x", "proof": "y"},
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404
        r = client.get("/api/standard/incidents", headers=auth_headers_tenant_b_admin)
        assert incident["id"] not in {i["id"] for i in r.json()["items"]}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_exception_lifecycle(self, client, analyst_headers, admin_headers):
        expires = datetime.now(timezone.utc) + timedelta(days=30)
        r = client.post(
            "/api/standard/exceptions",
            json={"title": "Legacy system exception",
                  "rationale": "deprecated within the year",
                  "expires_at": expires.isoformat()},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        exception_id = r.json()["exception"]["id"]

        # analysts cannot approve; admin can
        r = client.post(
            f"/api/standard/exceptions/{exception_id}/decide",
            json={"decision": "approved"},
            headers=analyst_headers,
        )
        assert r.status_code == 403
        r = client.post(
            f"/api/standard/exceptions/{exception_id}/decide",
            json={"decision": "approved"},
            headers=admin_headers,
        )
        assert r.status_code == 200
        assert r.json()["exception"]["state"] == "approved"

        # expiry is effective-on-read (no scheduler)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE grc_exceptions SET expires_at = %s WHERE id = %s;",
                    (datetime.now(timezone.utc) - timedelta(minutes=1),
                     str(exception_id)),
                )
            conn.commit()
        r = client.get("/api/standard/exceptions", headers=analyst_headers)
        row = next(e for e in r.json()["exceptions"] if e["id"] == exception_id)
        assert row["state"] == "expired"

    def test_mandatory_future_expiry(self, client, analyst_headers):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        r = client.post(
            "/api/standard/exceptions",
            json={"title": "bad", "rationale": "r", "expires_at": past.isoformat()},
            headers=analyst_headers,
        )
        assert r.status_code == 422
