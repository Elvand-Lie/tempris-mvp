# backend/tests/test_ch10_spotlight.py
"""
Focused suite for Chapter 10 — CISO / SPOTLIGHT, Executive View
(PRD-000 v1.11 Ch.10).

Covers: the read-only consumer over upstream state; count+max tiles that
NEVER mean; FINAL/PROVISIONAL rendered separately; no tenant-wide composite
index; "unavailable ≠ zero" for the absent decision domains; feed-health
carried through; append-only snapshots (DB-enforced) with hash + source
refs and audited capture; trend deltas between snapshots; admin+ capture
and analyst+ reads; module gate; tenant isolation.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from decimal import Decimal

import psycopg
import pytest

from app.db import get_db_connection
from tests.ch10_12_helpers import (
    audit_event_count,
    ch10_12_fixture,
    make_final_episode,
    make_provisional_episode,
    make_unscoreable_episode,
)
from tests.conftest import TENANT_A

# the shared per-test cleanup (owned tables + upstream exposure/vuln state)
_clean_ch10_12 = ch10_12_fixture()


def _dec(x):
    if isinstance(x, dict) and "__decimal__" in x:
        return Decimal(x["__decimal__"])
    return x


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_platform_session_blocked(self, client, platform_admin_headers):
        r = client.get("/api/ciso/summary", headers=platform_admin_headers)
        assert r.status_code == 403

    def test_module_entitlement_required(self, client, admin_headers):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"SPOTLIGHT": false}', str(TENANT_A)),
                )
            conn.commit()
        assert client.get("/api/ciso/summary", headers=admin_headers).status_code == 403
        assert client.post("/api/ciso/snapshots", headers=admin_headers).status_code == 403

    def test_capture_is_admin_plus(self, client, analyst_headers, admin_headers):
        assert client.post("/api/ciso/snapshots", headers=analyst_headers).status_code == 403
        assert client.post("/api/ciso/snapshots", headers=admin_headers).status_code == 201

    def test_reads_are_analyst_plus(self, client, analyst_headers):
        assert client.get("/api/ciso/summary", headers=analyst_headers).status_code == 200


# ---------------------------------------------------------------------------
# The executive summary tiles
# ---------------------------------------------------------------------------


class TestSummaryTiles:
    def test_summary_carries_as_of_and_metric_definitions(
        self, client, analyst_headers
    ):
        r = client.get("/api/ciso/summary", headers=analyst_headers)
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["as_of"]
        assert payload["authority"] == "derived_read_only_projection"
        defs = payload["metric_definitions"]
        for key in ("max_final_tes", "max_provisional_tes", "severe_count",
                    "unscoreable_count"):
            assert key in defs and "never a mean" in defs["max_final_tes"]

    def test_no_tenant_wide_composite_index_in_payload(
        self, client, analyst_headers, admin_headers
    ):
        make_final_episode("CVE-2026-80001")
        payload = client.get("/api/ciso/summary", headers=analyst_headers).json()
        text = json.dumps(payload).lower()
        # the retired V1 anti-pattern and any composite index stay retired
        assert "aggregate_tes" not in text
        assert "mean" not in "".join(payload.keys()).lower()
        assert "composite_index" not in text
        assert "risk_index" not in text

    def test_max_never_mean_tile_matches_extreme_exposure(
        self, client, analyst_headers
    ):
        # ONE cve: intel seeding pins the GLOBAL feed generation, so every
        # episode in a test must share it (two episodes, different BI → two
        # distinct FINAL values)
        low = make_final_episode("CVE-2026-80002", business_impact=1)
        high = make_final_episode("CVE-2026-80002", business_impact=9)

        v_low = _dec(read_tile_value(low["exposure_id"]))
        v_high = _dec(read_tile_value(high["exposure_id"]))
        assert v_low != v_high, "fixture must produce two distinct FINAL values"
        assert read_state(low["exposure_id"]) == "FINAL"
        assert read_state(high["exposure_id"]) == "FINAL"

        payload = client.get("/api/ciso/summary", headers=analyst_headers).json()
        tile = payload["severe_exposures"]
        assert tile["status"] == "ok"
        assert tile["final_count"] == 2
        max_final = _dec(tile["max_final_tes"])
        assert max_final == max(v_low, v_high)
        assert max_final != ((v_low + v_high) / 2), "the mean must never appear"

    def test_final_and_provisional_maxima_render_separately(
        self, client, analyst_headers
    ):
        # same cve: the provisional episode shares the FINAL episode's intel
        # generation and differs only by its missing contextual inputs
        make_final_episode("CVE-2026-80004")
        make_provisional_episode("CVE-2026-80004")

        payload = client.get("/api/ciso/summary", headers=analyst_headers).json()
        tile = payload["severe_exposures"]
        assert tile["final_count"] == 1
        assert tile["provisional_count"] == 1
        # two distinct fields — FINAL never stands in for PROVISIONAL
        assert "max_final_tes" in tile and "max_provisional_tes" in tile
        assert _dec(tile["max_final_tes"]) is not None
        # the provisional max is its own number (or an explicit null), never
        # folded into the FINAL maximum
        assert _dec(tile["max_provisional_tes"]) != _dec(tile["max_final_tes"])

    def test_unscoreable_counted_and_visible(self, client, analyst_headers):
        make_unscoreable_episode("CVE-2026-80006")
        tile = client.get("/api/ciso/summary", headers=analyst_headers).json()[
            "severe_exposures"
        ]
        assert tile["unscoreable_count"] == 1
        assert any(
            row["tes_state"] == "UNSCOREABLE"
            for row in tile["severe_exposures"]
        )

    def test_missing_upstream_domains_render_unavailable_not_zero(
        self, client, analyst_headers
    ):
        """EDIP (Ch.8) and STANDARD (Ch.9) are not in the integrated
        baseline: their tiles render 'unavailable' with a reason — a zero
        would read as 'no accepted risks' / 'no overdue obligations'."""
        payload = client.get("/api/ciso/summary", headers=analyst_headers).json()
        for tile_name in (
            "remediation_posture", "accepted_risk_register",
            "regulatory_pressure",
        ):
            tile = payload[tile_name]
            assert tile["status"] == "unavailable", tile_name
            assert tile["reason"], tile_name
            for key, value in tile.items():
                assert not isinstance(value, int), (
                    f"{tile_name} must not carry fabricated counts ({key})"
                )

    def test_severe_tile_carries_source_identities(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-80007")
        payload = client.get("/api/ciso/summary", headers=analyst_headers).json()
        rows = payload["severe_exposures"]["severe_exposures"]
        row = next(
            r for r in rows if r["exposure_id"] == str(episode["exposure_id"])
        )
        # drill-down is identity, not copy
        assert row["finding_id"] == str(episode["finding_id"])
        assert row["asset_id"] == str(episode["asset_id"])
        assert row["tes_state"] == "FINAL"

    def test_feed_health_tile_surfaces_sync_state(
        self, client, analyst_headers
    ):
        # pristine sync_state: never synced → 'unknown', never 'healthy zero'
        coverage = client.get("/api/ciso/summary", headers=analyst_headers).json()[
            "coverage_quality"
        ]
        assert coverage["status"] == "ok"
        assert coverage["feeds_unknown"] >= 3
        by_source = {f["source"]: f for f in coverage["feeds"]}
        assert by_source["epss"]["status"] == "unknown"

        # an unhealthy feed renders STALE, loudly
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE sync_state SET is_healthy = FALSE "
                    "WHERE source = 'kev';"
                )
            conn.commit()
        coverage = client.get("/api/ciso/summary", headers=analyst_headers).json()[
            "coverage_quality"
        ]
        by_source = {f["source"]: f for f in coverage["feeds"]}
        assert by_source["kev"]["status"] == "stale"
        assert by_source["kev"]["is_healthy"] is False

    def test_workflow_posture_reads_ch7_state(self, client, analyst_headers):
        episode = make_final_episode("CVE-2026-80008")
        payload = client.get("/api/ciso/summary", headers=analyst_headers).json()
        workflow = payload["workflow_posture"]
        assert workflow["status"] == "ok"
        assert workflow["current_exposures"] == 1
        assert workflow["analysis_state_new"] == 1
        assert workflow["open_edip_handoffs"] == 0

        # a Ch.7 action moves the tile — read-through, never a copy
        client.post(
            f"/api/spectrum/exposures/{episode['exposure_id']}/assign",
            json={"assignee": "analyst-a"},
            headers=analyst_headers,
        )
        workflow = client.get("/api/ciso/summary", headers=analyst_headers).json()[
            "workflow_posture"
        ]
        assert workflow["analysis_state_new"] == 0
        assert workflow["analysis_state_assigned"] == 1


def read_tile_value(exposure_id: uuid.UUID) -> dict | None:
    """The exposure's own live TES value via the Ch.3 read route contract
    (through the service layer — no second scoring path exists)."""
    from app.exposure.tes_read_model import get_exposure_tes
    from datetime import datetime, timezone
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        tes = get_exposure_tes(
            conn, TENANT_A, exposure_id, as_of=datetime.now(timezone.utc)
        )
        conn.commit()
    return tes["value"]


def read_state(exposure_id: uuid.UUID) -> str:
    from app.exposure.tes_read_model import get_exposure_tes
    from datetime import datetime, timezone
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        tes = get_exposure_tes(
            conn, TENANT_A, exposure_id, as_of=datetime.now(timezone.utc)
        )
        conn.commit()
    return tes["state"]


# ---------------------------------------------------------------------------
# Snapshots: append-only, sealed, audited; trend deltas
# ---------------------------------------------------------------------------


class TestSnapshots:
    def test_snapshot_capture_and_trend_delta(
        self, client, analyst_headers, admin_headers
    ):
        episode = make_final_episode("CVE-2026-80009")
        assert client.get("/api/ciso/trend", headers=analyst_headers).json()[
            "status"
        ] == "insufficient_history"

        first = client.post("/api/ciso/snapshots", headers=admin_headers).json()
        assert first["payload_hash"]
        assert first["captured_by"] == "admin-a"
        assert first["payload"]["as_of"]

        # change upstream state between captures: the assignment moves the
        # workflow tile, so the second snapshot differs and the trend is a
        # COMPUTED delta between the two — never a fabricated zero baseline
        client.post(
            f"/api/spectrum/exposures/{episode['exposure_id']}/assign",
            json={"assignee": "analyst-a"},
            headers=analyst_headers,
        )
        second = client.post("/api/ciso/snapshots", headers=admin_headers).json()

        listing = client.get("/api/ciso/snapshots", headers=analyst_headers).json()
        assert listing["total"] == 2
        assert [i["id"] for i in listing["items"]] == [second["id"], first["id"]]

        trend = client.get("/api/ciso/trend", headers=analyst_headers).json()
        assert trend["status"] == "ok"
        assert trend["older_snapshot_id"] == first["id"]
        assert trend["newer_snapshot_id"] == second["id"]
        assigned = trend["deltas"]["workflow_posture.analysis_state_assigned"]
        assert assigned["previous"] == 0 and assigned["current"] == 1
        assert assigned["delta"] == 1

    def test_snapshot_payload_hash_binds_the_payload(
        self, client, admin_headers
    ):
        snapshot = client.post("/api/ciso/snapshots", headers=admin_headers).json()
        canonical = json.dumps(
            snapshot["payload"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        )
        assert snapshot["payload_hash"] == hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    def test_snapshot_is_append_only(
        self, client, admin_headers, analyst_headers
    ):
        first = client.post("/api/ciso/snapshots", headers=admin_headers).json()
        second = client.post("/api/ciso/snapshots", headers=admin_headers).json()

        # history is never rewritten: row one is untouched by row two
        fetched = client.get(
            f"/api/ciso/snapshots/{first['id']}", headers=analyst_headers
        ).json()
        assert fetched["payload_hash"] == first["payload_hash"]
        assert fetched["payload"] == first["payload"]

        # and the database itself refuses UPDATE/DELETE (migration 034)
        for statement, params in (
            ("UPDATE posture_snapshots SET payload_hash = %s WHERE id = %s;",
             ("0" * 64, first["id"])),
            ("DELETE FROM posture_snapshots WHERE id = %s;", (first["id"],)),
        ):
            with pytest.raises(psycopg.errors.DatabaseError):
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(statement, params)

    def test_snapshot_source_refs_carry_upstream_identities(
        self, client, admin_headers
    ):
        episode = make_final_episode("CVE-2026-80010")
        snapshot = client.post("/api/ciso/snapshots", headers=admin_headers).json()
        refs = snapshot["source_refs"]
        exposure_refs = [r["exposure_id"] for r in refs["exposures"]]
        assert str(episode["exposure_id"]) in exposure_refs
        assert all(r["exposure_version"] for r in refs["exposures"])
        assert any(r["source"] == "kev" for r in refs["feed_health"])

    def test_snapshot_capture_is_audited(self, client, admin_headers):
        before = audit_event_count("spotlight.snapshot_captured")
        client.post("/api/ciso/snapshots", headers=admin_headers)
        assert audit_event_count("spotlight.snapshot_captured") == before + 1

    def test_unknown_snapshot_is_the_same_404(
        self, client, auth_headers_tenant_b_admin
    ):
        r = client.get(
            f"/api/ciso/snapshots/{uuid.uuid4()}",
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_summary_and_snapshots_are_tenant_scoped(
        self, client, admin_headers, auth_headers_tenant_b_admin
    ):
        make_final_episode("CVE-2026-80011")

        summary_a = client.get("/api/ciso/summary", headers=admin_headers).json()
        assert summary_a["severe_exposures"]["total_current_exposures"] == 1
        client.post("/api/ciso/snapshots", headers=admin_headers)

        summary_b = client.get(
            "/api/ciso/summary", headers=auth_headers_tenant_b_admin
        ).json()
        assert summary_b["tenant_id"] != summary_a["tenant_id"]
        assert summary_b["severe_exposures"]["total_current_exposures"] == 0
        assert summary_b["severe_exposures"]["max_final_tes"] is None

        snapshots_b = client.get(
            "/api/ciso/snapshots", headers=auth_headers_tenant_b_admin
        ).json()
        assert snapshots_b["total"] == 0
