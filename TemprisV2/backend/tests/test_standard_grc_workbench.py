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
