# backend/tests/test_ch12_synthesis.py
"""
Focused suite for Chapter 12 — SYNTHESIS, deterministic correlation
(PRD-000 v1.11 Ch.12).

Covers: read-time joins over authoritative state with source links; the
PATCH-14 remediation-recurrence rule (resolved predecessors only —
false_positive and superseded are never recurrence evidence); the
unremediated-serious threshold join with workflow state; coverage gaps
naming UNSCOREABLE reasons and missing evidence; the accepted-risk ⋈
obligation join degrading LOUDLY while Ch.8/Ch.9 are absent; determinism;
queries that write nothing; feed staleness rendering on rows; analyst+
reads, module gate, tenant isolation.
"""
from __future__ import annotations

import uuid

import pytest

from app.db import get_db_connection
from tests.ch10_12_helpers import (
    ch10_12_fixture,
    confirm_finding_on_asset,
    make_final_episode,
    make_unscoreable_episode,
    read_live_tes,
    resolve_episode,
    set_bi,
    upstream_row_counts,
)
from tests.conftest import TENANT_A

_clean_ch10_12 = ch10_12_fixture()


def _STALE_SUCCESS():
    """49 hours ago — beyond the 48-hour EPSS/KEV freshness gate."""
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) - timedelta(hours=49)


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


def _get(client, headers, path, **params):
    return client.get(f"/api/synthesis{path}", params=params or None, headers=headers)


# ---------------------------------------------------------------------------
# Governance: read-only, gated, scoped
# ---------------------------------------------------------------------------


class TestGovernance:
    def test_queries_write_nothing(self, client, analyst_headers):
        episode = make_final_episode("CVE-2026-82001")
        make_unscoreable_episode("CVE-2026-82002")

        before = upstream_row_counts()
        for path in (
            "/unremediated-serious", "/accepted-risks-vs-obligations",
            "/remediation-recurrence", "/coverage-gaps",
            "/weakness-recurrence",
        ):
            assert _get(client, analyst_headers, path).status_code == 200
        assert upstream_row_counts() == before

    def test_module_entitlement_required(self, client, admin_headers):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                    "WHERE tenant_id = %s;",
                    ('{"SYNTHESIS": false}', str(TENANT_A)),
                )
            conn.commit()
        assert _get(client, admin_headers, "/unremediated-serious").status_code == 403

    def test_platform_session_blocked(self, client, platform_admin_headers):
        assert _get(
            client, platform_admin_headers, "/coverage-gaps"
        ).status_code == 403

    def test_analyst_reads_are_allowed(self, client, analyst_headers):
        assert _get(client, analyst_headers, "/coverage-gaps").status_code == 200


# ---------------------------------------------------------------------------
# Unremediated serious exposures
# ---------------------------------------------------------------------------


class TestUnremediatedSerious:
    def test_definition_is_carried_and_deterministic_threshold(
        self, client, analyst_headers
    ):
        r = _get(client, analyst_headers, "/unremediated-serious")
        answer = r.json()
        assert answer["question"] == "unremediated_serious_exposures"
        assert "8.0" in answer["definition"]
        assert answer["authority"] == "read_time_join_over_authoritative_state"

    def test_serious_join_carries_workflow_and_source_links(
        self, client, analyst_headers
    ):
        serious = make_final_episode("CVE-2026-82003", business_impact=9)
        client.post(
            f"/api/spectrum/exposures/{serious['exposure_id']}/assign",
            json={"assignee": "analyst-a"},
            headers=analyst_headers,
        )
        rows = _get(client, analyst_headers, "/unremediated-serious").json()["rows"]
        row = next(
            r for r in rows if r["exposure_id"] == str(serious["exposure_id"])
        )
        assert row["tes_state"] == "FINAL"
        assert row["workflow"]["analysis_state"] == "assigned"
        assert row["workflow"]["assigned_to"] == "analyst-a"
        assert row["workflow"]["open_edip_handoff"] is False
        # links back to every source row
        assert row["finding_id"] == str(serious["finding_id"])
        assert row["asset_id"] == str(serious["asset_id"])

    def test_below_threshold_and_unscoreable_are_not_serious(
        self, client, analyst_headers
    ):
        low = make_final_episode("CVE-2026-82004", business_impact=1)
        live = read_live_tes(low["exposure_id"])
        if live["value"] is not None and live["value"] >= 8:
            pytest.skip("fixture did not produce a sub-threshold FINAL")
        make_unscoreable_episode("CVE-2026-82005")

        rows = _get(client, analyst_headers, "/unremediated-serious").json()["rows"]
        assert str(low["exposure_id"]) not in {r["exposure_id"] for r in rows}
        for row in rows:
            assert row["tes_state"] in ("FINAL", "PROVISIONAL")


# ---------------------------------------------------------------------------
# Accepted risks ⋈ obligations: degrade loudly
# ---------------------------------------------------------------------------


class TestAcceptedRisksDegradeLoudly:
    def test_missing_domains_are_named_loudly(self, client, analyst_headers):
        answer = _get(
            client, analyst_headers, "/accepted-risks-vs-obligations"
        ).json()
        # the missing decision domains are NAMED — never a silent empty join
        assert answer["degraded"] is True
        assert "edip_decisions" in answer["missing_domains"]
        assert "standard_obligations" in answer["missing_domains"]
        assert answer["rows"] == []
        assert answer["availability"]["edip_decisions"]["reason"] == (
            "chapter8_edip_domain_not_present"
        )
        assert answer["availability"]["standard_obligations"]["status"] == (
            "unavailable"
        )
        # the available domains are declared available, not missing
        assert answer["availability"]["exposures_tes"]["status"] == "available"


# ---------------------------------------------------------------------------
# Remediation recurrence (PATCH-14)
# ---------------------------------------------------------------------------


class TestRecurrence:
    def test_recurrence_pairs_resolved_predecessor(
        self, client, analyst_headers
    ):
        # the seeded episode resolves terminal; the re-confirmation is the
        # new episode whose predecessor is RESOLVED → a recurrence
        episode = make_unscoreable_episode("CVE-2026-82006")
        resolve_episode(episode["exposure_id"], status="resolved")
        returned = confirm_finding_on_asset(
            episode["finding_id"], episode["asset_id"]
        )

        rows = _get(client, analyst_headers, "/remediation-recurrence").json()["rows"]
        row = next(
            r for r in rows if r["exposure_id"] == str(returned)
        )
        assert row["predecessor_exposure_id"] == str(episode["exposure_id"])
        assert row["tuple"]["finding_id"] == str(episode["finding_id"])
        assert row["tuple"]["asset_id"] == str(episode["asset_id"])
        assert row["predecessor_resolved_at"]

    def test_false_positive_and_superseded_are_not_recurrences(
        self, client, analyst_headers
    ):
        # false_positive predecessor: a re-appearance is NOT a failed fix
        fp = make_unscoreable_episode("CVE-2026-82007")
        resolve_episode(fp["exposure_id"], status="false_positive")
        fresh_fp = confirm_finding_on_asset(fp["finding_id"], fp["asset_id"])

        # superseded predecessor: identity bookkeeping, not remediation
        sup = make_unscoreable_episode("CVE-2026-82008")
        from app.exposure.service import supersede_exposures_for_asset
        with get_db_connection() as conn:
            supersede_exposures_for_asset(
                conn, TENANT_A, sup["asset_id"],
                actor_id="admin-a", actor_role="admin",
                reason="suite supersession",
            )
            conn.commit()
        after_supersede = confirm_finding_on_asset(
            sup["finding_id"], sup["asset_id"]
        )

        rows = _get(client, analyst_headers, "/remediation-recurrence").json()["rows"]
        ids = {r["exposure_id"] for r in rows}
        assert str(fresh_fp) not in ids
        assert str(after_supersede) not in ids

    def test_open_episode_without_history_is_not_recurrence(
        self, client, analyst_headers
    ):
        episode = make_final_episode("CVE-2026-82009")
        rows = _get(client, analyst_headers, "/remediation-recurrence").json()["rows"]
        assert str(episode["exposure_id"]) not in {r["exposure_id"] for r in rows}


# ---------------------------------------------------------------------------
# Coverage gaps
# ---------------------------------------------------------------------------


class TestCoverageGaps:
    def test_coverage_gap_names_unscoreable_and_missing_evidence(
        self, client, analyst_headers
    ):
        scored = make_final_episode("CVE-2026-82010")
        unscoreable = make_unscoreable_episode("CVE-2026-82011")

        rows = _get(client, analyst_headers, "/coverage-gaps").json()["rows"]
        by_id = {r["exposure_id"]: r for r in rows}

        scored_row = by_id[str(scored["exposure_id"])]
        assert scored_row["tes_state"] == "FINAL"
        assert scored_row["has_exploitation_evidence"] is False
        assert scored_row["has_reachability_evidence"] is True
        assert scored_row["bound_feed_snapshots"]["epss_snapshot_id"]

        unscoreable_row = by_id[str(unscoreable["exposure_id"])]
        assert unscoreable_row["tes_state"] == "UNSCOREABLE"
        # the missing axis is NAMED — the gap is the answer's subject
        assert "intrinsic" in unscoreable_row["missing_axes"][0].lower()

    def test_stale_feed_marks_rows_stale(self, client, analyst_headers):
        """A stale feed must render — the correlated row names the unresolved
        stale source instead of quietly scoring as if inputs were fresh."""
        # EPSS-top-rung shape (KEV not listed): the rung rides on EPSS, so
        # an EPSS-staleness flip MUST be visible in the recompute
        episode = make_final_episode(
            "CVE-2026-82012", kev_listed=False
        )
        live = read_live_tes(episode["exposure_id"])
        assert live["state"] == "FINAL"

        # age the EPSS feed past its 48h freshness gate (Ch.1 semantics)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE sync_state SET last_successful_at = %s "
                    "WHERE source = 'epss';",
                    (_STALE_SUCCESS(),),
                )
            conn.commit()
        recompute = read_live_tes(episode["exposure_id"])
        assert recompute["state"] != "FINAL"
        er_row = next(
            r for r in recompute["decomposition"]
            if r.get("axis") == "exploit_reality"
        )
        names = [n for n, _why in er_row.get("unresolved_higher", []) or []]
        assert any("(stale)" in n for n in names)

        rows = _get(client, analyst_headers, "/unremediated-serious").json()["rows"]
        row = next(
            (r for r in rows if r["exposure_id"] == str(episode["exposure_id"])),
            None,
        )
        if row is not None:
            assert row["feed_freshness"] == "stale"
            assert row["tes_state"] == recompute["state"]
        else:
            # the stale feed knocked the episode out of the serious set —
            # the coverage answer must still render it explicitly
            gaps = _get(client, analyst_headers, "/coverage-gaps").json()["rows"]
            gap_row = next(
                g for g in gaps
                if g["exposure_id"] == str(episode["exposure_id"])
            )
            assert gap_row["tes_state"] == recompute["state"]


# ---------------------------------------------------------------------------
# Weakness recurrence across assets + determinism
# ---------------------------------------------------------------------------


class TestWeaknessRecurrence:
    def test_same_finding_on_multiple_assets_recurs(
        self, client, analyst_headers
    ):
        from tests.test_p05_cve_tes_read_model import _make_asset

        episode = make_final_episode("CVE-2026-82013", business_impact=8)
        asset2 = _make_asset()
        confirm_finding_on_asset(episode["finding_id"], asset2)

        classes = _get(
            client, analyst_headers, "/weakness-recurrence", min_assets=2
        ).json()["rows"]
        cls = next(
            c for c in classes
            if c["finding_id"] == str(episode["finding_id"])
        )
        assert cls["asset_count"] == 2
        assert cls["episode_count"] == 2
        assert cls["max_final_tes"] is not None
        assert len(cls["episodes"]) == 2
        assert {e["asset_id"] for e in cls["episodes"]} == {
            str(episode["asset_id"]), str(asset2),
        }

    def test_max_per_state_never_a_mean(self, client, analyst_headers):
        from tests.test_p05_cve_tes_read_model import _make_asset

        high = make_final_episode("CVE-2026-82014", business_impact=9)
        asset2 = _make_asset()
        confirm_finding_on_asset(high["finding_id"], asset2)
        v_high = read_live_tes(high["exposure_id"])["value"]

        classes = _get(
            client, analyst_headers, "/weakness-recurrence", min_assets=2
        ).json()["rows"]
        cls = next(
            c for c in classes if c["finding_id"] == str(high["finding_id"])
        )
        from decimal import Decimal
        assert Decimal(cls["max_final_tes"]["__decimal__"]) >= v_high


# ---------------------------------------------------------------------------
# Determinism + tenant isolation
# ---------------------------------------------------------------------------


class TestDeterminismAndIsolation:
    def test_answers_are_deterministic(self, client, analyst_headers):
        make_final_episode("CVE-2026-82015", business_impact=8)
        make_unscoreable_episode("CVE-2026-82016")

        def strip(answer):
            answer = dict(answer)
            answer.pop("as_of", None)
            return answer

        first = strip(
            _get(client, analyst_headers, "/unremediated-serious").json()
        )
        second = strip(
            _get(client, analyst_headers, "/unremediated-serious").json()
        )
        assert first == second

        gaps_first = strip(_get(client, analyst_headers, "/coverage-gaps").json())
        gaps_second = strip(_get(client, analyst_headers, "/coverage-gaps").json())
        assert gaps_first == gaps_second

    def test_correlations_are_tenant_scoped(
        self, client, analyst_headers, auth_headers_tenant_b_admin
    ):
        make_final_episode("CVE-2026-82017", business_impact=9)

        answer_a = _get(
            client, analyst_headers, "/unremediated-serious"
        ).json()
        assert answer_a["row_count"] == 1

        answer_b = _get(
            client, auth_headers_tenant_b_admin, "/unremediated-serious"
        ).json()
        assert answer_b["row_count"] == 0
        gaps_b = _get(
            client, auth_headers_tenant_b_admin, "/coverage-gaps"
        ).json()
        assert gaps_b["row_count"] == 0
        recurrence_b = _get(
            client, auth_headers_tenant_b_admin, "/remediation-recurrence"
        ).json()
        assert recurrence_b["row_count"] == 0
