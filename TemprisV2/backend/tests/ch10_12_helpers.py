# backend/tests/ch10_12_helpers.py
"""
Shared seed/cleanup helpers for the Chapter 10-12 suites (test_ch10_*,
test_ch11_*, test_ch12_*).

A plain module, NOT a conftest: the shared tests/conftest.py is a parallel-
edit hotspot, so each suite defines its own autouse fixture that calls the
factory here. Seeding reuses the established P0-03/P0-05 helpers
(``seed_cve_intel`` et al.) so Chapters 10-12 construct score states exactly
the way the Ch.3 authority's own suite does — never a second scoring path.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.db import get_db_connection
from app.exposure.models import ExposureConfirm, ExposureResolve
from app.exposure.scoring_inputs import (
    BusinessImpactIn,
    ReachabilityEvidenceIn,
    record_reachability_evidence,
    set_business_impact,
)
from app.exposure.service import (
    allocate_finding_for_cve,
    confirm_exposure,
    resolve_exposure,
)
from tests.conftest import TENANT_A
from tests.test_p03_cve_intelligence_resolvers import _VULN_TABLE_CLEANUP_SQL
from tests.test_p05_cve_tes_read_model import seed_cve_intel

# The three suites' owned tables (migrations 034/035) — cleared per test.
CH10_12_TABLES = (
    "posture_snapshots",
    "report_artifacts",
    "reports",
)


def clean_ch10_12():
    """Clear the Ch.10-12 owned tables + the upstream exposure/vuln state,
    and restore sync_state to its pristine never-synced defaults (the
    feed-health tile's factual baseline)."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "TRUNCATE posture_snapshots, report_artifacts, reports;"
            )
            cur.execute(_VULN_TABLE_CLEANUP_SQL)
            for table in (
                "exposure_exploitation_evidence",
                "exposure_business_impact",
                "exposure_reachability_evidence",
                "asset_exposures",
                "asset_applicability_reviews",
                "findings",
                "assets",
            ):
                cur.execute(
                    f"DELETE FROM {table} WHERE tenant_id IN "
                    "('11111111-1111-1111-1111-111111111111', "
                    "'22222222-2222-2222-2222-222222222222');"
                )
            cur.execute(
                """
                UPDATE sync_state SET
                    is_healthy = TRUE,
                    last_successful_at = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    last_error = NULL,
                    consecutive_failures = 0;
                """
            )
        conn.commit()


def ch10_12_fixture():
    """The autouse per-test cleanup fixture shared by the three suites."""

    @pytest.fixture(autouse=True)
    def _clean_ch10_12():
        clean_ch10_12()
        yield
        clean_ch10_12()

    return _clean_ch10_12


# ---------------------------------------------------------------------------
# Score-state construction (through the Ch.3 authority only)
# ---------------------------------------------------------------------------


def make_final_episode(
    cve: str, *, business_impact: int = 7, kev_listed: bool = True,
):
    """All five axes known and fresh → FINAL. ``business_impact`` moves the
    value deterministically (BI is a ledger input, not a score). With
    ``kev_listed=False`` the Exploit-Reality rung rides on EPSS alone (the
    lever the stale-feed test flips)."""
    seed = seed_cve_intel(cve, epss_score="0.90", kev_listed=kev_listed)
    exposure_id, finding_id, asset_id = _make_cve_episode(cve)
    with get_db_connection() as conn:
        record_reachability_evidence(
            conn, TENANT_A, exposure_id,
            ReachabilityEvidenceIn(vantage="internal", evidence={"path": "svc"}),
            actor_id="analyst-a", actor_role="analyst",
        )
        set_business_impact(
            conn, TENANT_A, exposure_id,
            BusinessImpactIn(value=business_impact),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return {
        "exposure_id": exposure_id,
        "finding_id": finding_id,
        "asset_id": asset_id,
        **seed,
    }


def _make_cve_episode(cve: str):
    """A confirmed episode on a fresh active asset, with its finding
    allocated for an already-seeded CVE (default fixture tenant)."""
    with get_db_connection() as conn:
        finding_id = allocate_finding_for_cve(
            conn, TENANT_A, cve,
            default_title=f"Finding {cve}", default_severity="high",
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    from tests.test_p05_cve_tes_read_model import _make_asset, _confirm
    asset_id = _make_asset()
    exposure_id = _confirm(finding_id, asset_id)
    return exposure_id, finding_id, asset_id


def make_provisional_episode(cve: str):
    """A PROVISIONAL episode of an ALREADY-SEEDED CVE (intel generation
    pinned with observations — e.g. by make_final_episode of the same cve):
    the episode lacks the contextual inputs (reachability, Business Impact),
    so the kernel renormalizes PROVISIONAL. NEVER re-seed a second CVE in
    one test: seeding re-pins the GLOBAL feed generation and would strip
    earlier episodes of their EPSS/KEV observations."""
    exposure_id, finding_id, asset_id = _make_cve_episode(cve)
    return {
        "exposure_id": exposure_id,
        "finding_id": finding_id,
        "asset_id": asset_id,
    }


def make_unscoreable_episode(
    cve: str, *, title: str = "Unscoreable finding",
):
    """A confirmed finding with NO authoritative intrinsic (no CVSS / no
    SSS): the kernel fails closed UNSCOREABLE."""
    from tests.test_p03_cve_intelligence_resolvers import _canon
    token = uuid.uuid4().int
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, %s, 'server', 'ip', %s, %s,
                          'internal', 'production', 'high', 'active');
                """,
                (
                    str(asset_id), str(TENANT_A), f"asset-{uuid.uuid4().hex[:8]}",
                    f"10.70.{token % 250}.{(token >> 8) % 250}",
                    f"10.70.{token % 250}.{(token >> 8) % 250}",
                ),
            )
        _canon(conn, cve)
        finding_id = allocate_finding_for_cve(
            conn, TENANT_A, cve, default_title=title,
            default_severity="critical", actor_id="analyst-a",
            actor_role="analyst",
        )
        result = confirm_exposure(
            conn, TENANT_A,
            ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                            evidence={"seed": True}),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return {
        "exposure_id": result.exposure.id,
        "finding_id": finding_id,
        "asset_id": asset_id,
    }


def confirm_finding_on_asset(
    finding_id: uuid.UUID, asset_id: uuid.UUID, tenant_id=None
) -> uuid.UUID:
    """One more current episode of an EXISTING finding (recurrence shape)."""
    with get_db_connection() as conn:
        result = confirm_exposure(
            conn, tenant_id or TENANT_A,
            ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                            evidence={"seed": True}),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return result.exposure.id


def resolve_episode(
    exposure_id: uuid.UUID, status: str = "resolved", tenant_id=None
) -> None:
    with get_db_connection() as conn:
        resolve_exposure(
            conn, tenant_id or TENANT_A, exposure_id,
            ExposureResolve(status=status, resolution_reason="suite"),
            actor_id="admin-a", actor_role="admin",
        )
        conn.commit()


def set_bi(exposure_id: uuid.UUID, value: int) -> None:
    """Move the Business Impact ledger input (the test lever for changing a
    score honestly — through the Ch.3 authority, never directly)."""
    with get_db_connection() as conn:
        set_business_impact(
            conn, TENANT_A, exposure_id,
            BusinessImpactIn(value=value),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()


def read_live_tes(exposure_id: uuid.UUID, tenant_id=None) -> dict:
    from app.exposure.tes_read_model import get_exposure_tes
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        return get_exposure_tes(
            conn, tenant_id or TENANT_A, exposure_id,
            as_of=datetime.now(timezone.utc),
        )


def upstream_row_counts() -> dict:
    """Row counts of the authoritative upstream tables — the write-guard
    baseline the tests diff reads against."""
    counts = {}
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for table in (
                "asset_exposures", "findings", "assets",
                "exposure_business_impact", "exposure_exploitation_evidence",
                "exposure_reachability_evidence",
                "spectrum_exposure_workflow", "spectrum_workflow_history",
                "spectrum_edip_handoffs", "spectrum_strike_requests",
            ):
                cur.execute(f"SELECT COUNT(*) AS n FROM {table};")
                counts[table] = cur.fetchone()["n"]
    return counts


def audit_event_count(event_name: str) -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM audit_events WHERE event_name = %s;",
                (event_name,),
            )
            return cur.fetchone()["n"]
