# backend/tests/test_standard_grc_workbench.py
"""
V1-parity GRC workbench additions (all derived, read-only; no new tables):

  1. GET /api/standard/gap-analysis — derived view: signed = completed,
     draft = in_review, no live assessment = pending; completion_pct from
     the sign-off state only.
  2. GET /api/standard/evidence/{id}/preview — inline-safe preview vs
     attachment fallback; the read is audited under its own event name.
  3. GET /api/standard/advisories — derived from live data (audit chain,
     signed gaps, overdue obligations); never mutates state.
  4. POST /api/standard/incidents/{id}/report-draft — MAS TRM 12.1.5 draft
     derived ONLY from a real recorded incident; nothing stored.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.db import get_db_connection
from tests.conftest import TENANT_A


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


def _controls(client, headers):
    r = client.get("/api/standard/frameworks", headers=headers)
    assert r.status_code == 200, r.text
    mas = next(
        f for f in r.json()["frameworks"] if f["framework_code"] == "mas_trm_2024"
    )
    return mas["controls"]


def _create_incident(client, headers, *, external_event_id="evt-draft-1",
                     event_time=None):
    body = {
        "source": "soc",
        "external_event_id": external_event_id,
        "title": "Suspected breach",
        "event_time": (event_time or datetime.now(timezone.utc)).isoformat(),
        "inputs": {"incident_kind": "cyber_security_incident"},
    }
    r = client.post("/api/standard/incidents", json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["incident"]


class TestGapAnalysis:
    def test_empty_tenant_all_pending(self, client, analyst_headers):
        r = client.get("/api/standard/gap-analysis", headers=analyst_headers)
        assert r.status_code == 200, r.text
        payload = r.json()
        summary = payload["summary"]
        assert summary["completed"] == 0
        assert summary["in_review"] == 0
        assert summary["pending"] == summary["total"]
        assert summary["completion_pct"] == 0
        assert all(c["state"] == "pending" for c in payload["controls"])

    def test_signoff_states_drive_the_derived_view(self, client, analyst_headers,
                                                   admin_headers):
        control = _controls(client, analyst_headers)[0]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "compliant"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        assessment_id = r.json()["assessment"]["id"]

        payload = client.get(
            "/api/standard/gap-analysis", headers=analyst_headers
        ).json()
        row = next(c for c in payload["controls"]
                   if c["control_id"] == control["control_id"])
        assert row["state"] == "in_review"
        assert row["assessment_status"] == "compliant"

        # dual sign-off (two different actors) completes the assessment
        client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "end_user"}, headers=analyst_headers,
        )
        client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "pic"}, headers=admin_headers,
        )
        payload = client.get(
            "/api/standard/gap-analysis", headers=analyst_headers
        ).json()
        row = next(c for c in payload["controls"]
                   if c["control_id"] == control["control_id"])
        assert row["state"] == "completed"
        assert payload["summary"]["completed"] >= 1
        assert payload["summary"]["completion_pct"] > 0

    def test_module_gate_and_tenant_isolation(self, client, analyst_headers,
                                              platform_admin_headers):
        r = client.get("/api/standard/gap-analysis", headers=platform_admin_headers)
        assert r.status_code == 403
        # another tenant sees only its own (empty) view
        other = uuid.uuid4()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM standard_control_assessments "
                    "WHERE tenant_id = %s;",
                    (str(other),),
                )
                assert cur.fetchone()["n"] == 0


class TestEvidencePreview:
    def _attach(self, client, headers, media_type: str):
        control = _controls(client, headers)[0]
        r = client.post(
            "/api/standard/evidence",
            json={
                "control_id": control["control_id"],
                "title": f"preview probe {media_type}",
                "media_type": media_type,
                "content_base64": base64.b64encode(b"preview-payload").decode(),
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text
        return r.json()["evidence"]["id"]

    def test_inline_safe_media_renders_inline(self, client, analyst_headers):
        evidence_id = self._attach(client, analyst_headers, "text/plain")
        r = client.get(
            f"/api/standard/evidence/{evidence_id}/preview",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/plain")
        assert "inline" in r.headers["content-disposition"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "no-store" in r.headers["cache-control"]
        assert r.content == b"preview-payload"

    def test_non_inline_media_forces_attachment(self, client, analyst_headers):
        evidence_id = self._attach(client, analyst_headers, "application/pdf")
        r = client.get(
            f"/api/standard/evidence/{evidence_id}/preview",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        assert "attachment" in r.headers["content-disposition"]
        assert r.headers["content-type"] == "application/octet-stream"

    def test_preview_is_audited(self, client, analyst_headers):
        evidence_id = self._attach(client, analyst_headers, "text/plain")
        r = client.get(
            f"/api/standard/evidence/{evidence_id}/preview",
            headers=analyst_headers,
        )
        assert r.status_code == 200
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM audit_events "
                    "WHERE tenant_id = %s AND event_name = 'standard.evidence_previewed';",
                    (str(TENANT_A),),
                )
                assert cur.fetchone()["n"] >= 1

    def test_unknown_evidence_404(self, client, analyst_headers):
        r = client.get(
            f"/api/standard/evidence/{uuid.uuid4()}/preview",
            headers=analyst_headers,
        )
        assert r.status_code == 404


class TestAdvisories:
    def test_derived_only_no_state_change(self, client, analyst_headers):
        r1 = client.get("/api/standard/advisories", headers=analyst_headers)
        assert r1.status_code == 200, r1.text
        r2 = client.get("/api/standard/advisories", headers=analyst_headers)
        assert r1.json() == r2.json()
        for advisory in r1.json()["advisories"]:
            assert advisory["level"] in ("ok", "warning", "critical")
            assert advisory["control_code"]

    def test_signed_gap_raises_a_warning(self, client, analyst_headers,
                                         admin_headers):
        controls = _controls(client, analyst_headers)
        target = next(c for c in controls if c["control_code"] == "MAS-TRM-11.1.1")
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": target["control_id"], "status": "non_compliant"},
            headers=analyst_headers,
        )
        assessment_id = r.json()["assessment"]["id"]
        client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "end_user"}, headers=analyst_headers,
        )
        client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "pic"}, headers=admin_headers,
        )
        advisories = client.get(
            "/api/standard/advisories", headers=analyst_headers
        ).json()["advisories"]
        gap = [a for a in advisories
               if a["control_code"] == "MAS-TRM-11.1.1" and a["type"] == "signed_gap"]
        assert gap and gap[0]["level"] == "warning"

    def test_overdue_obligation_warns_incident_response_controls(
        self, client, analyst_headers,
    ):
        past = datetime.now(timezone.utc) - timedelta(hours=6)
        _create_incident(client, analyst_headers,
                         external_event_id="evt-overdue-adv",
                         event_time=past)
        advisories = client.get(
            "/api/standard/advisories", headers=analyst_headers
        ).json()["advisories"]
        overdue = [a for a in advisories if a["type"] == "overdue_obligations"]
        assert overdue
        assert {a["control_code"] for a in overdue} == {
            "MAS-TRM-12.1.1", "ISO-A.5.24", "SOC2-CC7.2",
        }


class TestIncidentReportDraft:
    def test_draft_derived_from_real_incident_not_stored(
        self, client, analyst_headers,
    ):
        event_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        incident = _create_incident(
            client, analyst_headers,
            external_event_id="evt-report-1", event_time=event_time,
        )
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/report-draft",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        draft = r.json()["report_draft"]
        assert draft["type"] == "MAS TRM 12.1.5 — 1-Hour Incident Notification"
        assert draft["incident_id"] == incident["id"]
        assert draft["status"].startswith("DRAFT")
        assert draft["incident_summary"]["title"] == "Suspected breach"
        # the clock pins the trigger (event time), not the generation time
        assert datetime.fromisoformat(draft["notification_deadline"]) == (
            event_time + timedelta(hours=1)
        )

    def test_draft_generation_is_audited_but_stores_no_artifact(
        self, client, analyst_headers,
    ):
        incident = _create_incident(
            client, analyst_headers, external_event_id="evt-report-2",
        )
        r = client.post(
            f"/api/standard/incidents/{incident['id']}/report-draft",
            headers=analyst_headers,
        )
        assert r.status_code == 200
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM audit_events "
                    "WHERE tenant_id = %s "
                    "AND event_name = 'standard.incident_report_drafted';",
                    (str(TENANT_A),),
                )
                assert cur.fetchone()["n"] >= 1

    def test_unknown_incident_404(self, client, analyst_headers):
        r = client.post(
            f"/api/standard/incidents/{uuid.uuid4()}/report-draft",
            headers=analyst_headers,
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# STANDARD-01/02/04: draft prefill, evidence lifecycle, atomic reassessment
# ---------------------------------------------------------------------------

def _attach_evidence(client, headers, control_id, *, title="ev1", assessment_id=None):
    body = {
        "control_id": control_id,
        "assessment_id": assessment_id,
        "title": title,
        "media_type": "text/plain",
        "content_base64": base64.b64encode(b"evidence-bytes").decode(),
    }
    r = client.post("/api/standard/evidence", json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["evidence"]


def _find_control(controls, control_id):
    return next(c for c in controls if c["control_id"] == control_id)


class TestDraftPrefill:
    def test_saved_draft_status_and_notes_are_exposed(self, client, analyst_headers):
        control = _controls(client, analyst_headers)[2]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "partial", "notes": "Test"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text

        saved = _find_control(_controls(client, analyst_headers), control["control_id"])
        assert saved["assessment_state"] == "draft"
        assert saved["saved_status"] == "partial"
        assert saved["saved_notes"] == "Test"
        # A pending draft is NOT signed compliance.
        assert saved["status"] == "not_assessed"
        assert saved["signoffs"]["end_user"]["by"] is None
        assert saved["signoffs"]["pic"]["by"] is None


class TestAtomicReassess:
    def test_reassess_replaces_the_live_assessment(self, client, analyst_headers):
        control = _controls(client, analyst_headers)[3]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "partial", "notes": "v1"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        original_id = r.json()["assessment"]["id"]

        r2 = client.post(
            "/api/standard/assessments/reassess",
            json={"control_id": control["control_id"], "status": "compliant", "notes": "v2"},
            headers=analyst_headers,
        )
        assert r2.status_code == 201, r2.text

        saved = _find_control(_controls(client, analyst_headers), control["control_id"])
        assert saved["assessment_state"] == "draft"
        assert saved["saved_status"] == "compliant"
        assert saved["saved_notes"] == "v2"
        assert saved["assessment_id"] != original_id

    def test_failed_reassess_keeps_the_previous_assessment(self, client, analyst_headers):
        control = _controls(client, analyst_headers)[3]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "partial", "notes": "keep-me"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        original_id = r.json()["assessment"]["id"]

        bad = client.post(
            "/api/standard/assessments/reassess",
            json={"control_id": control["control_id"], "status": "excellent"},
            headers=analyst_headers,
        )
        assert bad.status_code == 422

        saved = _find_control(_controls(client, analyst_headers), control["control_id"])
        assert saved["assessment_id"] == original_id
        assert saved["saved_status"] == "partial"
        assert saved["saved_notes"] == "keep-me"

    def test_reassess_without_live_assessment_is_404(self, client, analyst_headers):
        control = _controls(client, analyst_headers)[4]
        r = client.post(
            "/api/standard/assessments/reassess",
            json={"control_id": control["control_id"], "status": "compliant"},
            headers=analyst_headers,
        )
        assert r.status_code == 404


class TestEvidenceLifecycle:
    def test_withdraw_requires_reason_and_tombstones(self, client, analyst_headers):
        control = _controls(client, analyst_headers)[5]
        evidence = _attach_evidence(client, analyst_headers, control["control_id"])

        no_reason = client.post(
            f"/api/standard/evidence/{evidence['id']}/withdraw",
            json={"reason": "  "},
            headers=analyst_headers,
        )
        assert no_reason.status_code == 422

        ok = client.post(
            f"/api/standard/evidence/{evidence['id']}/withdraw",
            json={"reason": "wrong file attached"},
            headers=analyst_headers,
        )
        assert ok.status_code == 200, ok.text

        current = client.get(
            f"/api/standard/evidence?control_id={control['control_id']}",
            headers=analyst_headers,
        ).json()["evidence"]
        assert all(e["id"] != evidence["id"] for e in current)

        audit = client.get(
            f"/api/standard/evidence?control_id={control['control_id']}&include_withdrawn=true",
            headers=analyst_headers,
        ).json()["evidence"]
        row = next(e for e in audit if e["id"] == evidence["id"])
        assert row["withdrawn_by"] is not None
        assert row["withdrawn_reason"] == "wrong file attached"

    def test_replace_creates_versioned_attachment_and_tombstones_old(
        self, client, analyst_headers
    ):
        control = _controls(client, analyst_headers)[5]
        old = _attach_evidence(client, analyst_headers, control["control_id"], title="old")
        r = client.post(
            f"/api/standard/evidence/{old['id']}/replace",
            json={
                "title": "new",
                "media_type": "text/plain",
                "content_base64": base64.b64encode(b"evidence-v2").decode(),
                "reason": "corrected file",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        new = r.json()["evidence"]
        assert new["replaces_evidence_id"] == old["id"]
        assert new["control_id"] == old["control_id"]

        current = client.get(
            f"/api/standard/evidence?control_id={control['control_id']}",
            headers=analyst_headers,
        ).json()["evidence"]
        assert [e["id"] for e in current] == [new["id"]]

    def test_signed_assessment_evidence_is_immutable(self, client, analyst_headers,
                                                     admin_headers):
        control = _controls(client, analyst_headers)[6]
        r = client.post(
            "/api/standard/assessments",
            json={"control_id": control["control_id"], "status": "compliant"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        assessment_id = r.json()["assessment"]["id"]
        evidence = _attach_evidence(
            client, analyst_headers, control["control_id"],
            title="signed-proof", assessment_id=assessment_id,
        )
        s1 = client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "end_user"}, headers=analyst_headers,
        )
        assert s1.status_code == 200, s1.text
        s2 = client.post(
            f"/api/standard/assessments/{assessment_id}/signoff",
            json={"capacity": "pic"}, headers=admin_headers,
        )
        assert s2.status_code == 200, s2.text

        withdraw = client.post(
            f"/api/standard/evidence/{evidence['id']}/withdraw",
            json={"reason": "attempted after sign-off"},
            headers=analyst_headers,
        )
        assert withdraw.status_code == 409
        replace = client.post(
            f"/api/standard/evidence/{evidence['id']}/replace",
            json={
                "title": "try",
                "media_type": "text/plain",
                "content_base64": base64.b64encode(b"x").decode(),
            },
            headers=analyst_headers,
        )
        assert replace.status_code == 409
        # Signed evidence remains downloadable (audited historical proof).
        dl = client.get(
            f"/api/standard/evidence/{evidence['id']}/download",
            headers=analyst_headers,
        )
        assert dl.status_code == 200

    def test_restore_returns_a_withdrawn_attachment_to_current(self, client, analyst_headers):
        control = _controls(client, analyst_headers)[5]
        evidence = _attach_evidence(client, analyst_headers, control["control_id"])
        wd = client.post(
            f"/api/standard/evidence/{evidence['id']}/withdraw",
            json={"reason": "mistake"},
            headers=analyst_headers,
        )
        assert wd.status_code == 200
        current = client.get(
            f"/api/standard/evidence?control_id={control['control_id']}",
            headers=analyst_headers,
        ).json()["evidence"]
        assert current == []

        rs = client.post(
            f"/api/standard/evidence/{evidence['id']}/restore",
            headers=analyst_headers,
        )
        assert rs.status_code == 200, rs.text
        current = client.get(
            f"/api/standard/evidence?control_id={control['control_id']}",
            headers=analyst_headers,
        ).json()["evidence"]
        assert [e["id"] for e in current] == [evidence["id"]]
        assert current[0]["withdrawn_at"] is None

        rs_again = client.post(
            f"/api/standard/evidence/{evidence['id']}/restore",
            headers=analyst_headers,
        )
        assert rs_again.status_code == 409

    def test_tenant_isolation_on_withdraw(self, client, analyst_headers,
                                          auth_headers_tenant_b_admin):
        control = _controls(client, analyst_headers)[5]
        evidence = _attach_evidence(client, analyst_headers, control["control_id"])
        foreign = client.post(
            f"/api/standard/evidence/{evidence['id']}/withdraw",
            json={"reason": "cross-tenant attempt"},
            headers=auth_headers_tenant_b_admin,
        )
        assert foreign.status_code == 404
