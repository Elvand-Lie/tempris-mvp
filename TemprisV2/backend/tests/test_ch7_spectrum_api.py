# backend/tests/test_ch7_spectrum_api.py
"""
Focused suite for Chapter 7 — SPECTRUM (Confirmed-Exposure Workbench)
(PRD-000 v1.11 Ch.7).

Covers: the module entitlement gate; the queue over CURRENT exposures with
read-through TES (no stored scores — a changed input re-renders on the next
read); workbench detail (decomposition + workflow + history + BI); exposure-
grain assignment and analysis_state (never named 'status', never gating the
Ch.3 lifecycle); notes/journal; the STRIKE engagement draft; the manual EDIP
handoff into Needs-Decision; analyst+ authority and tenant isolation.
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from app.auth import create_test_token
from app.db import get_db_connection
from tests.conftest import TENANT_A


def _dec(x):
    """Unwrap the lossless Decimal tag (same wire contract as Ch.3 reads)."""
    if isinstance(x, dict) and "__decimal__" in x:
        return Decimal(x["__decimal__"])
    return x


# ---------------------------------------------------------------------------
# Helpers — seed a confirmed exposure through the Ch.3 routes
# ---------------------------------------------------------------------------


def create_asset_in_db(
    tenant_id: uuid.UUID = TENANT_A,
    name: str = "spectrum-anchor-01",
) -> uuid.UUID:
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, %s, 'server', 'ip', '10.0.0.60', '10.0.0.60',
                          'internal', 'production', 'high', 'active');
                """,
                (str(asset_id), str(tenant_id), name),
            )
        conn.commit()
    return asset_id


def seed_cve(cve_id: str = "CVE-2026-70001") -> str:
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


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def confirmed_exposure(client, admin_headers):
    """One confirmed exposure on an active asset (created via Ch.3 routes)."""
    asset_id = create_asset_in_db()
    cve = seed_cve()
    r = client.post(
        "/api/exposure/findings",
        json={"title": "Spectrum seeded exposure", "severity": "high", "canonical_cve_id": cve},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    finding_id = r.json()["id"]
    r = client.post(
        "/api/exposure/confirm",
        json={"finding_id": finding_id, "asset_id": str(asset_id),
              "evidence": {"reference": "seed-1"}},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    return {"exposure_id": r.json()["id"], "finding_id": finding_id, "asset_id": asset_id}


# ---------------------------------------------------------------------------
# Module entitlement + authority
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_platform_session_blocked(self, client, platform_admin_headers):
        r = client.get("/api/spectrum/queue", headers=platform_admin_headers)
        assert r.status_code == 403

    def test_module_entitlement_required(self, client, admin_headers):
        # turn the SPECTRUM module off for tenant A via override; cleanup restores
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"SPECTRUM": false}', str(TENANT_A)),
                )
            conn.commit()
        r = client.get("/api/spectrum/queue", headers=admin_headers)
        assert r.status_code == 403
        assert "SPECTRUM" in r.json()["detail"]

    def test_cross_tenant_exposure_is_the_same_404(self, client, auth_headers_tenant_b_admin):
        asset_id = create_asset_in_db()
        cve = seed_cve("CVE-2026-70002")
        token = create_test_token(tenant_id=str(TENANT_A), actor_id="admin-a", role="admin")
        a_headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/api/exposure/findings",
            json={"title": "Tenant A only", "severity": "medium", "canonical_cve_id": cve},
            headers=a_headers,
        )
        finding_id = r.json()["id"]
        r = client.post(
            "/api/exposure/confirm",
            json={"finding_id": finding_id, "asset_id": str(asset_id),
                  "evidence": {"reference": "t-a"}},
            headers=a_headers,
        )
        exposure_id = r.json()["id"]

        # tenant B workbench view of a tenant A exposure: the fail-closed 404
        r = client.get(f"/api/spectrum/exposures/{exposure_id}", headers=auth_headers_tenant_b_admin)
        assert r.status_code == 404
        r = client.get("/api/spectrum/queue", headers=auth_headers_tenant_b_admin)
        assert exposure_id not in {i["exposure_id"] for i in r.json()["items"]}


# ---------------------------------------------------------------------------
# Queue + read-through
# ---------------------------------------------------------------------------


class TestQueue:
    def test_queue_lists_current_exposures_with_tes_and_defaults(
        self, client, analyst_headers, confirmed_exposure
    ):
        r = client.get("/api/spectrum/queue", headers=analyst_headers)
        assert r.status_code == 200, r.text
        items = r.json()["items"]
        row = next(i for i in items if i["exposure_id"] == confirmed_exposure["exposure_id"])
        assert row["canonical_cve_id"] == "CVE-2026-70001"
        assert row["analysis_state"] == "new"  # synthesized default before any action
        assert row["assigned_to"] is None
        assert row["business_impact"] is None
        # read-through TES: a state is always rendered explicitly — even when
        # UNSCOREABLE it is counted/visible, never hidden
        assert row["tes"]["state"] in {"FINAL", "PROVISIONAL", "UNSCOREABLE"}
        assert "formula_version" in row["tes"]

    def test_queue_is_read_through_not_stored(
        self, client, analyst_headers, confirmed_exposure
    ):
        eid = confirmed_exposure["exposure_id"]

        # a NEW scoring input (Business Impact) changes the next read — with no
        # refresh machinery: SPECTRUM has no score storage to invalidate
        r = client.post(
            f"/api/exposure/{eid}/business-impact",
            json={"value": 9, "reason": "crown-jewel data"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text

        row = next(
            i for i in client.get("/api/spectrum/queue", headers=analyst_headers).json()["items"]
            if i["exposure_id"] == eid
        )
        detail = client.get(f"/api/spectrum/exposures/{eid}", headers=analyst_headers).json()

        # queue and detail agree with each other — one recomputed truth, and
        # the authoritative Ch.3 read agrees too (read-through, not a copy)
        ch3 = client.get(f"/api/exposure/{eid}/tes", headers=analyst_headers).json()
        assert row["tes"]["state"] == detail["tes"]["state"] == ch3["state"]
        assert _dec(row["tes"]["value"]) == _dec(detail["tes"]["value"]) == _dec(ch3["value"])
        # the fresh BI assessment surfaces on the row and in the decomposition
        assert _dec(row["business_impact"]["value"]) == Decimal("9.0000")
        bi_row = next(
            r for r in detail["tes"]["decomposition"] if r["axis"] == "business_impact"
        )
        assert bi_row["state"] == "known"
        assert _dec(bi_row["raw_value"]) == Decimal("9.0000")

    def test_resolved_exposures_leave_the_operational_queue(
        self, client, admin_headers, analyst_headers, confirmed_exposure
    ):
        # drive the exposure terminal through the Ch.3-internal command
        from app.exposure.models import ExposureResolve
        from app.exposure.service import resolve_exposure
        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, uuid.UUID(confirmed_exposure["exposure_id"]),
                ExposureResolve(status="resolved", resolution_reason="closed"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        items = client.get("/api/spectrum/queue", headers=analyst_headers).json()["items"]
        assert confirmed_exposure["exposure_id"] not in {i["exposure_id"] for i in items}

    def test_filters_by_analysis_state_and_assignee(
        self, client, analyst_headers, confirmed_exposure
    ):
        eid = confirmed_exposure["exposure_id"]
        client.post(
            f"/api/spectrum/exposures/{eid}/assign",
            json={"assignee": "analyst-a"},
            headers=analyst_headers,
        )
        rows = client.get(
            "/api/spectrum/queue",
            params={"analysis_state": "assigned", "assigned_to": "analyst-a"},
            headers=analyst_headers,
        ).json()["items"]
        assert eid in {i["exposure_id"] for i in rows}
        rows = client.get(
            "/api/spectrum/queue", params={"analysis_state": "new"},
            headers=analyst_headers,
        ).json()["items"]
        assert eid not in {i["exposure_id"] for i in rows}

    def test_unknown_analysis_state_filter_rejected(self, client, analyst_headers):
        r = client.get(
            "/api/spectrum/queue", params={"analysis_state": "closed"},
            headers=analyst_headers,
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Workflow: assignment, analysis_state, notes, journal
# ---------------------------------------------------------------------------


class TestWorkflow:
    def test_assign_bootstraps_new_to_assigned(self, client, analyst_headers, confirmed_exposure):
        eid = confirmed_exposure["exposure_id"]
        r = client.post(
            f"/api/spectrum/exposures/{eid}/assign",
            json={"assignee": "analyst-b"},
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        workflow = r.json()["workflow"]
        assert workflow["assigned_to"] == "analyst-b"
        assert workflow["assigned_by"] == "analyst-a"
        assert workflow["analysis_state"] == "assigned"

        # Ch.3 lifecycle untouched by SPECTRUM workflow writes
        detail = client.get(f"/api/spectrum/exposures/{eid}", headers=analyst_headers).json()
        assert detail["tes"]["source_view"]["exposure_status"] == "confirmed"

    def test_analysis_state_lifecycle_and_journal(self, client, analyst_headers, confirmed_exposure):
        eid = confirmed_exposure["exposure_id"]
        for state in ("in_analysis", "action_required", "in_analysis"):
            r = client.post(
                f"/api/spectrum/exposures/{eid}/analysis-state",
                json={"analysis_state": state, "note": f"moving to {state}"},
                headers=analyst_headers,
            )
            assert r.status_code == 200, r.text
            assert r.json()["workflow"]["analysis_state"] == state

        r = client.post(
            f"/api/spectrum/exposures/{eid}/notes",
            json={"note": "waiting on asset owner"},
            headers=analyst_headers,
        )
        assert r.status_code == 201

        history = client.get(
            f"/api/spectrum/exposures/{eid}/history", headers=analyst_headers
        ).json()["history"]
        events = [h["event"] for h in history]
        assert events == ["analysis_state_changed", "analysis_state_changed",
                          "analysis_state_changed", "note_added"]
        # the bootstrap edge is rendered: new → in_analysis
        assert history[0]["detail"] == {"from": "new", "to": "in_analysis"}
        assert history[1]["detail"] == {"from": "in_analysis", "to": "action_required"}

    def test_invalid_analysis_state_rejected(self, client, analyst_headers, confirmed_exposure):
        eid = confirmed_exposure["exposure_id"]
        r = client.post(
            f"/api/spectrum/exposures/{eid}/analysis-state",
            json={"analysis_state": "status"},
            headers=analyst_headers,
        )
        assert r.status_code == 422  # the field is NEVER 'status' — and never invented

    def test_unassign_clears_owner_keeps_state(self, client, analyst_headers, confirmed_exposure):
        eid = confirmed_exposure["exposure_id"]
        client.post(
            f"/api/spectrum/exposures/{eid}/assign",
            json={"assignee": "analyst-b"}, headers=analyst_headers,
        )
        client.post(
            f"/api/spectrum/exposures/{eid}/analysis-state",
            json={"analysis_state": "in_analysis"}, headers=analyst_headers,
        )
        r = client.post(f"/api/spectrum/exposures/{eid}/unassign", headers=analyst_headers)
        assert r.status_code == 200
        workflow = r.json()["workflow"]
        assert workflow["assigned_to"] is None
        assert workflow["analysis_state"] == "in_analysis"  # the two never gate each other

    def test_mutations_fail_closed_on_noncurrent_or_unknown(self, client, analyst_headers):
        r = client.post(
            f"/api/spectrum/exposures/{uuid.uuid4()}/assign",
            json={"assignee": "x"}, headers=analyst_headers,
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# STRIKE draft + EDIP handoff
# ---------------------------------------------------------------------------


class TestHandoffs:
    def test_strike_request_creates_a_draft(self, client, analyst_headers, confirmed_exposure):
        eid = confirmed_exposure["exposure_id"]
        r = client.post(
            f"/api/spectrum/exposures/{eid}/strike-request",
            json={"note": "validate RCE on staging twin"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        draft = r.json()["strike_request"]
        assert draft["state"] == "draft"
        assert draft["exposure_id"] == eid
        assert draft["requested_by"] == "analyst-a"

        history = client.get(
            f"/api/spectrum/exposures/{eid}/history", headers=analyst_headers
        ).json()["history"]
        assert history[-1]["event"] == "strike_requested"

    def test_edip_handoff_is_manual_and_one_open_per_exposure(
        self, client, analyst_headers, confirmed_exposure
    ):
        eid = confirmed_exposure["exposure_id"]
        r = client.post(
            f"/api/spectrum/exposures/{eid}/edip-handoff",
            json={"note": "patch decision needed"},
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["edip_handoff"]["state"] == "NEEDS_DECISION"
        assert body["workflow"]["analysis_state"] == "action_required"
        assert body["workflow"]["edip_handoff_at"] is not None

        # a standing handoff blocks a second — recorded and retryable, never silent
        r = client.post(
            f"/api/spectrum/exposures/{eid}/edip-handoff", json={}, headers=analyst_headers,
        )
        assert r.status_code == 409

        # the marker shows in the queue
        row = next(
            i for i in client.get("/api/spectrum/queue", headers=analyst_headers).json()["items"]
            if i["exposure_id"] == eid
        )
        assert row["analysis_state"] == "action_required"
        assert row["edip_handoff_at"] is not None

    def test_detail_renders_decomposition_workflow_and_bi(
        self, client, analyst_headers, confirmed_exposure
    ):
        eid = confirmed_exposure["exposure_id"]
        client.post(
            f"/api/exposure/{eid}/business-impact",
            json={"value": 7.5, "reason": "payment path"},
            headers=analyst_headers,
        )
        r = client.get(f"/api/spectrum/exposures/{eid}", headers=analyst_headers)
        assert r.status_code == 200, r.text
        detail = r.json()
        assert detail["exposure_id"] == eid
        bi_row = next(
            x for x in detail["tes"]["decomposition"] if x["axis"] == "business_impact"
        )
        assert bi_row["state"] == "known"
        assert _dec(bi_row["raw_value"]) == Decimal("7.5000")
        assert detail["workflow"]["analysis_state"] == "new"
        assert detail["business_impact"]["assessed_by"] == "analyst-a"
        assert _dec(detail["business_impact"]["value"]) == Decimal("7.5000")
        assert detail["history"] == []
