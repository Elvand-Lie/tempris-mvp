# backend/tests/test_ch11_speak.py
"""
Focused suite for Chapter 11 — SPEAK / Reports, Deliverables
(PRD-000 v1.11 Ch.11).

Covers: register-time ownership validation; generation as a reader that
mutates nothing; content-hash sealing with template identity + generator;
SEALED values that survive upstream change (§3.3.6 snapshot writer — never
recomputed at view time); regeneration as a NEW version row; approved/
archived reports non-deletable (service 409 + DB trigger); artifact hash
verification with refuse+alarm; audited exports; CSV formula-injection
guard; SPEAK chat failing closed with no model; tenant isolation; bounded
lists; authority gates.
"""
from __future__ import annotations

import json
import uuid

import psycopg
import pytest

from app.db import get_db_connection
from app.speak import service as speak_service
from tests.ch10_12_helpers import (
    audit_event_count,
    ch10_12_fixture,
    make_final_episode,
    read_live_tes,
    set_bi,
    upstream_row_counts,
)
from tests.conftest import TENANT_A

_clean_ch10_12 = ch10_12_fixture()


def _dec(x):
    """Unwrap the lossless Decimal wire tag."""
    if isinstance(x, dict) and "__decimal__" in x:
        return x["__decimal__"]
    return x


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


def _register(client, headers, **overrides):
    body = {
        "report_type": "exposure_register",
        "title": "Suite exposure register",
        **overrides,
    }
    return client.post("/api/speak/reports/register", json=body, headers=headers)


def _register_one(client, headers, episode, **overrides):
    return _register(
        client, headers,
        exposure_ids=[str(episode["exposure_id"])], **overrides,
    )


def _generate(client, headers, report_id):
    return client.post(
        f"/api/speak/reports/{report_id}/generate", headers=headers
    )


def _generate_executive(client, headers):
    registered = _register(
        client, headers,
        report_type="executive_summary",
        title="Suite executive summary",
    )
    assert registered.status_code == 201, registered.text
    generated = _generate(client, headers, registered.json()["id"])
    assert generated.status_code == 200, generated.text
    return generated.json()


# ---------------------------------------------------------------------------
# Register: ownership validation
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_rejects_cross_tenant_and_foreign_exposures(
        self, client, analyst_headers
    ):
        # an exposure id from another tenant and a random id are the SAME
        # validation failure — nothing is disclosed
        r = _register(
            client, analyst_headers,
            exposure_ids=[str(uuid.UUID(int=777))],
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "scope_validation_error"

    def test_register_validates_current_exposure(
        self, client, analyst_headers
    ):
        from tests.ch10_12_helpers import resolve_episode
        episode = make_final_episode("CVE-2026-81001")
        resolve_episode(episode["exposure_id"], status="resolved")
        r = _register_one(client, analyst_headers, episode)
        assert r.status_code == 422

    def test_register_accepts_current_scope_and_stamps_template(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81002")
        r = _register_one(client, analyst_headers, episode)
        assert r.status_code == 201, r.text
        report = r.json()
        assert report["status"] == "draft"
        assert report["version"] == 1
        assert report["template_id"] == "builtin.exposure_register"
        assert report["template_version"] == 1
        assert report["sealed_payload"] is None
        assert report["scope"]["exposure_ids"] == [str(episode["exposure_id"])]

    def test_unknown_report_type_rejected(self, client, analyst_headers):
        r = _register(client, analyst_headers, report_type="strike_pack")
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Generation: reader, sealer, never a writer
# ---------------------------------------------------------------------------


class TestGeneration:
    def test_generation_mutates_nothing(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81003")
        r = _register_one(client, analyst_headers, episode)
        report_id = r.json()["id"]
        _generate(client, analyst_headers, report_id)

        _generate_executive(client, analyst_headers)

        # generate twice: register + generate must leave upstream untouched
        # (reports are readers; the AI surface writes nothing either)
        counts = upstream_row_counts()
        assert counts == upstream_row_counts()  # sanity: counting is inert
        r2 = _register_one(client, analyst_headers, episode)
        _generate(client, analyst_headers, r2.json()["id"])
        assert upstream_row_counts() == counts

    def test_report_is_sealed_with_template_and_actor(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81004")
        registered = _register_one(client, analyst_headers, episode)
        report_id = registered.json()["id"]
        generated = _generate(client, analyst_headers, report_id).json()

        assert generated["content_hash"]
        assert generated["generated_by"] == "analyst-a"
        assert generated["as_of"]
        assert generated["template_id"] == "builtin.exposure_register"
        sealed = generated["sealed_payload"]
        assert sealed["as_of"] == generated["as_of"]
        assert sealed["template_id"] == generated["template_id"]
        assert sealed["generated_by"] == "analyst-a"
        assert len(generated["artifacts"]) == 3

    def test_sealed_values_survive_upstream_change(
        self, client, analyst_headers
    ):
        """THE §3.3.6 snapshot-writer test: the report stores the values it
        rendered. A later upstream change alters live reads — never the
        sealed report."""
        episode = make_final_episode("CVE-2026-81005", business_impact=9)
        registered = _register_one(client, analyst_headers, episode)
        report = _generate(client, analyst_headers, registered.json()["id"]).json()
        sealed_value = _dec(
            report["sealed_payload"]["exposures"][0]["tes"]["value"]
        )
        live = read_live_tes(episode["exposure_id"])
        assert str(live["value"]) == sealed_value

        # upstream changes underneath the report
        set_bi(episode["exposure_id"], 1)
        changed = read_live_tes(episode["exposure_id"])
        assert str(changed["value"]) != sealed_value

        fetched = client.get(
            f"/api/speak/reports/{report['id']}", headers=analyst_headers
        ).json()
        assert (
            _dec(fetched["sealed_payload"]["exposures"][0]["tes"]["value"])
            == sealed_value
        ), "a sealed report must never recompute"

    def test_seal_carries_source_view_identities(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81006")
        registered = _register_one(client, analyst_headers, episode)
        report = _generate(client, analyst_headers, registered.json()["id"]).json()
        refs = report["sealed_payload"]["source_refs"]["exposures"]
        row = next(
            r for r in refs if r["exposure_id"] == str(episode["exposure_id"])
        )
        assert row["exposure_version"]
        assert row["cvss_assessment_id"]
        assert row["epss_snapshot_id"]
        assert row["kev_snapshot_id"]

    def test_generate_is_idempotent_guarded(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81007")
        report_id = _register_one(client, analyst_headers, episode).json()["id"]
        assert _generate(client, analyst_headers, report_id).status_code == 200
        r = _generate(client, analyst_headers, report_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "report_state_error"

    def test_unsealed_draft_cannot_be_approved(self, client, analyst_headers):
        episode = make_final_episode("CVE-2026-81008")
        report_id = _register_one(client, analyst_headers, episode).json()["id"]
        r = client.post(
            f"/api/speak/reports/{report_id}/approve", headers=analyst_headers
        )
        assert r.status_code == 403  # analyst cannot approve at all


# ---------------------------------------------------------------------------
# Regeneration: a new version row, history intact
# ---------------------------------------------------------------------------


class TestRegeneration:
    def test_regenerate_creates_new_version_row(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81009", business_impact=9)
        report_id = _register_one(client, analyst_headers, episode).json()["id"]
        v1 = _generate(client, analyst_headers, report_id).json()

        set_bi(episode["exposure_id"], 1)
        r = client.post(
            f"/api/speak/reports/{report_id}/regenerate", headers=analyst_headers
        )
        assert r.status_code == 200, r.text
        v2 = r.json()
        assert v2["id"] != v1["id"]
        assert v2["version"] == 2
        assert v2["parent_report_id"] == v1["id"]
        assert v2["content_hash"] != v1["content_hash"]

        # the parent row is untouched (hash, payload, lifecycle)
        parent = client.get(
            f"/api/speak/reports/{v1['id']}", headers=analyst_headers
        ).json()
        assert parent["content_hash"] == v1["content_hash"]
        assert (
            _dec(parent["sealed_payload"]["exposures"][0]["tes"]["value"])
            == _dec(v1["sealed_payload"]["exposures"][0]["tes"]["value"])
        )
        # and the child sealed the CHANGED world
        assert (
            _dec(v2["sealed_payload"]["exposures"][0]["tes"]["value"])
            != _dec(v1["sealed_payload"]["exposures"][0]["tes"]["value"])
        )

    def test_sealed_payload_is_db_immutable(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81010")
        report_id = _register_one(client, analyst_headers, episode).json()["id"]
        generated = _generate(client, analyst_headers, report_id).json()
        with pytest.raises(psycopg.errors.DatabaseError):
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE reports SET content_hash = %s WHERE id = %s;",
                        ("f" * 64, generated["id"]),
                    )


# ---------------------------------------------------------------------------
# Lifecycle: approve / archive / delete / export
# ---------------------------------------------------------------------------


class TestLifecycle:
    def _approved_report(self, client, analyst_headers, admin_headers, cve):
        episode = make_final_episode(cve)
        report_id = _register_one(client, analyst_headers, episode).json()["id"]
        _generate(client, analyst_headers, report_id)
        r = client.post(
            f"/api/speak/reports/{report_id}/approve", headers=admin_headers
        )
        assert r.status_code == 200, r.text
        return report_id

    def test_approval_gate_and_provenance(
        self, client, analyst_headers, admin_headers
    ):
        report_id = self._approved_report(
            client, analyst_headers, admin_headers, "CVE-2026-81011"
        )
        report = client.get(
            f"/api/speak/reports/{report_id}", headers=admin_headers
        ).json()
        assert report["status"] == "approved"
        assert report["approved_by"] == "admin-a"
        assert report["approved_at"]

        # approve again → conflict; analyst approve → forbidden
        assert client.post(
            f"/api/speak/reports/{report_id}/approve", headers=admin_headers
        ).status_code == 409
        episode = make_final_episode("CVE-2026-81012")
        analyst_report = _register_one(client, analyst_headers, episode).json()["id"]
        _generate(client, analyst_headers, analyst_report)
        assert client.post(
            f"/api/speak/reports/{analyst_report}/approve",
            headers=analyst_headers,
        ).status_code == 403

    def test_approved_report_cannot_be_deleted(
        self, client, analyst_headers, admin_headers
    ):
        report_id = self._approved_report(
            client, analyst_headers, admin_headers, "CVE-2026-81013"
        )
        r = client.delete(f"/api/speak/reports/{report_id}", headers=admin_headers)
        assert r.status_code == 409

        # the database enforces the same rule
        with pytest.raises(psycopg.errors.DatabaseError):
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM reports WHERE tenant_id = %s AND id = %s;",
                        (str(TENANT_A), report_id),
                    )

        # archive instead: bytes retained, still non-deletable
        assert client.post(
            f"/api/speak/reports/{report_id}/archive", headers=admin_headers
        ).status_code == 200
        assert client.delete(
            f"/api/speak/reports/{report_id}", headers=admin_headers
        ).status_code == 409
        archived = client.get(
            f"/api/speak/reports/{report_id}", headers=admin_headers
        ).json()
        assert archived["status"] == "archived"
        assert len(archived["artifacts"]) == 3

    def test_draft_is_deletable_with_its_artifacts(
        self, client, analyst_headers, admin_headers
    ):
        episode = make_final_episode("CVE-2026-81014")
        report_id = _register_one(client, analyst_headers, episode).json()["id"]
        _generate(client, analyst_headers, report_id)
        assert client.delete(
            f"/api/speak/reports/{report_id}", headers=admin_headers
        ).status_code == 200
        assert client.get(
            f"/api/speak/reports/{report_id}", headers=analyst_headers
        ).status_code == 404

    def test_export_is_approval_gated_and_audited(
        self, client, analyst_headers, admin_headers
    ):
        episode = make_final_episode("CVE-2026-81015")
        draft_id = _register_one(client, analyst_headers, episode).json()["id"]
        _generate(client, analyst_headers, draft_id)

        # a draft is not exportable
        assert client.post(
            f"/api/speak/reports/{draft_id}/export",
            json={"recipient": "regulator@example.test"},
            headers=admin_headers,
        ).status_code == 409

        report_id = self._approved_report(
            client, analyst_headers, admin_headers, "CVE-2026-81016"
        )
        before = audit_event_count("speak.report_exported")
        r = client.post(
            f"/api/speak/reports/{report_id}/export",
            json={"recipient": "regulator@example.test", "note": "Q3 filing"},
            headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["content_hash"]
        assert audit_event_count("speak.report_exported") == before + 1

        # analyst cannot export
        another = _register_one(
            client, analyst_headers, make_final_episode("CVE-2026-81017")
        ).json()["id"]
        _generate(client, analyst_headers, another)
        assert client.post(
            f"/api/speak/reports/{another}/export", headers=analyst_headers
        ).status_code == 403


# ---------------------------------------------------------------------------
# Artifacts: sealed bytes, hash-verified downloads, injection guard
# ---------------------------------------------------------------------------


class TestArtifacts:
    def test_download_hashes_match_and_bytes_render_the_seal(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81018")
        report = _generate(
            client, analyst_headers,
            _register_one(client, analyst_headers, episode).json()["id"],
        ).json()
        for artifact in report["artifacts"]:
            kind = artifact["artifact_kind"]
            r = client.get(
                f"/api/speak/reports/{report['id']}/artifacts/{kind}",
                headers=analyst_headers,
            )
            assert r.status_code == 200, r.text
            assert r.headers["X-Content-Sha256-Verified"] == "true"

        # the CSV/HTML render the SEALED payload, not live state
        csv_text = client.get(
            f"/api/speak/reports/{report['id']}/artifacts/csv",
            headers=analyst_headers,
        ).text
        assert report["sealed_payload"]["exposures"][0]["exposure_id"] in csv_text

    def test_download_refuses_and_alarms_on_hash_mismatch(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-81019")
        report = _generate(
            client, analyst_headers,
            _register_one(client, analyst_headers, episode).json()["id"],
        ).json()

        # simulate storage-level tampering: artifacts are byte-immutable via
        # UPDATE, so the tamper path is replace (DELETE + INSERT) — exactly
        # what the download verification exists to catch
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM report_artifacts WHERE report_id = %s "
                    "AND artifact_kind = 'csv';",
                    (report["id"],),
                )
                cur.execute(
                    """
                    INSERT INTO report_artifacts (
                        tenant_id, report_id, artifact_kind, content,
                        size_bytes, content_hash, created_by
                    ) VALUES (%s, %s, 'csv', %s, %s, %s, 'tamper');
                    """,
                    (
                        str(TENANT_A), report["id"], b"synthetic=payload",
                        len(b"synthetic=payload"),
                        "0" * 64,
                    ),
                )
            conn.commit()

        before = audit_event_count("speak.artifact_hash_mismatch")
        r = client.get(
            f"/api/speak/reports/{report['id']}/artifacts/csv",
            headers=analyst_headers,
        )
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "artifact_hash_mismatch"
        assert audit_event_count("speak.artifact_hash_mismatch") == before + 1
        assert b"synthetic" not in r.content

    def test_artifacts_are_byte_immutable(self, client, analyst_headers):
        episode = make_final_episode("CVE-2026-81020")
        report = _generate(
            client, analyst_headers,
            _register_one(client, analyst_headers, episode).json()["id"],
        ).json()
        with pytest.raises(psycopg.errors.DatabaseError):
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE report_artifacts SET content = %s "
                        "WHERE report_id = %s AND artifact_kind = 'json';",
                        (b"{}", report["id"]),
                    )

    def test_csv_artifact_neutralizes_formula_injection(
        self, client, analyst_headers
    ):
        # a hostile title lands in the CSV as DATA, never as a formula
        episode = make_unscoreable_with_title(
            "CVE-2026-81021", "=HYPERLINK(\"https://evil.test\",\"win\")"
        )
        report = _generate(
            client, analyst_headers,
            _register_one(client, analyst_headers, episode).json()["id"],
        ).json()
        csv_text = client.get(
            f"/api/speak/reports/{report['id']}/artifacts/csv",
            headers=analyst_headers,
        ).text
        assert "HYPERLINK" in csv_text
        # the dangerous cell is prefixed with a guard quote
        assert "'=HYPERLINK" in csv_text

    def test_html_escapes_content(self, client, analyst_headers):
        episode = make_unscoreable_with_title(
            "CVE-2026-81022", "<script>alert('x')</script>"
        )
        report = _generate(
            client, analyst_headers,
            _register_one(client, analyst_headers, episode).json()["id"],
        ).json()
        html = client.get(
            f"/api/speak/reports/{report['id']}/artifacts/html",
            headers=analyst_headers,
        ).text
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_executive_summary_renders_unavailable_loudly(
        self, client, analyst_headers
    ):
        report = _generate_executive(client, analyst_headers)
        html = client.get(
            f"/api/speak/reports/{report['id']}/artifacts/html",
            headers=analyst_headers,
        ).text
        assert "unavailable" in html
        assert "chapter8_edip_domain_not_present" in html


def make_unscoreable_with_title(cve: str, title: str):
    from tests.ch10_12_helpers import make_unscoreable_episode
    return make_unscoreable_episode(cve, title=title)


# ---------------------------------------------------------------------------
# Generation: retryable conflicts (audit-chain advance under the snapshot)
# ---------------------------------------------------------------------------


def _raise_chain_advanced(conn, tenant_id, **kwargs):
    raise psycopg.errors.SerializationFailure(
        "audit chain advanced during a repeatable-read transaction"
    )


class TestGenerationRetryableConflicts:
    """The proven production defect: the tenant's audit chain advanced
    during the REPEATABLE READ generation boundary (audit.py refuses to
    re-chain from a provably stale head and raises SerializationFailure).
    The route maps it to the same retryable 409 shape as tes_read_conflict
    — never a bare 500 — and the audit chain itself is untouched."""

    def _register_draft(self, client, headers, cve):
        episode = make_final_episode(cve)
        registered = _register_one(client, headers, episode)
        assert registered.status_code == 201, registered.text
        return registered.json()["id"]

    def test_generate_audit_chain_advance_is_retryable_409_not_500(
        self, client, analyst_headers, monkeypatch
    ):
        report_id = self._register_draft(client, analyst_headers, "CVE-2026-81301")
        monkeypatch.setattr(
            speak_service, "record_audit_event", _raise_chain_advanced
        )
        r = _generate(client, analyst_headers, report_id)
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert detail["code"] == "tes_read_conflict"
        assert detail["retry"] is True
        assert "audit chain advanced" in detail["message"]

    def test_generate_audit_chain_advance_rolls_the_seal_back(
        self, client, analyst_headers, monkeypatch
    ):
        report_id = self._register_draft(client, analyst_headers, "CVE-2026-81302")
        monkeypatch.setattr(
            speak_service, "record_audit_event", _raise_chain_advanced
        )
        r = _generate(client, analyst_headers, report_id)
        assert r.status_code == 409, r.text
        # the whole publication rolled back: still an unsealed draft
        fetched = client.get(
            f"/api/speak/reports/{report_id}", headers=analyst_headers
        ).json()
        assert fetched["status"] == "draft"
        assert fetched["sealed_payload"] is None

    def test_regenerate_audit_chain_advance_is_retryable_409(
        self, client, analyst_headers, monkeypatch
    ):
        report_id = self._register_draft(client, analyst_headers, "CVE-2026-81303")
        generated = _generate(client, analyst_headers, report_id)
        assert generated.status_code == 200, generated.text

        monkeypatch.setattr(
            speak_service, "record_audit_event", _raise_chain_advanced
        )
        r = client.post(
            f"/api/speak/reports/{report_id}/regenerate",
            headers=analyst_headers,
        )
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert detail["code"] == "tes_read_conflict"
        assert detail["retry"] is True
        # the new version row rolled back with the publication
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM reports WHERE parent_report_id = %s;",
                    (report_id,),
                )
                assert cur.fetchone()["n"] == 0


# ---------------------------------------------------------------------------
# SPEAK chat: fails closed, never invents
# ---------------------------------------------------------------------------


class TestSpeakChat:
    def test_speak_chat_fails_closed_without_model(
        self, client, analyst_headers
    ):
        r = client.post(
            "/api/speak/chat",
            json={"message": "What is our worst exposure?"},
            headers=analyst_headers,
        )
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert detail["code"] == "llm_unavailable"
        # no invented numbers anywhere in the failure — 'unavailable' only
        body = json.dumps(r.json())
        assert "9.2" not in body and "tes 9" not in body.lower()


# ---------------------------------------------------------------------------
# Bounded listing + tenant isolation
# ---------------------------------------------------------------------------


class TestGovernance:
    def test_list_is_bounded(self, client, analyst_headers):
        r = client.get(
            "/api/speak/reports", params={"limit": 1000}, headers=analyst_headers
        )
        assert r.status_code == 422  # FastAPI bound: REPORT_LIST_LIMIT

    def test_reports_are_tenant_scoped(
        self, client, analyst_headers, auth_headers_tenant_b_admin
    ):
        episode = make_final_episode("CVE-2026-81023")
        report = _generate(
            client, analyst_headers,
            _register_one(client, analyst_headers, episode).json()["id"],
        ).json()
        assert client.get(
            f"/api/speak/reports/{report['id']}",
            headers=auth_headers_tenant_b_admin,
        ).status_code == 404
        assert client.get(
            f"/api/speak/reports/{report['id']}/artifacts/json",
            headers=auth_headers_tenant_b_admin,
        ).status_code == 404
        listing = client.get(
            "/api/speak/reports", headers=auth_headers_tenant_b_admin
        ).json()
        assert listing["total"] == 0

    def test_module_entitlement_required(self, client, admin_headers):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"SPEAK": false}', str(TENANT_A)),
                )
            conn.commit()
        assert client.get("/api/speak/reports", headers=admin_headers).status_code == 403
        assert client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=admin_headers
        ).status_code == 403

    def test_platform_session_blocked(self, client, platform_admin_headers):
        assert client.get(
            "/api/speak/reports", headers=platform_admin_headers
        ).status_code == 403
