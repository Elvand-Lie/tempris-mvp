# backend/tests/test_p05_cve_tes_read_model.py
"""
P0-05 — CVE TES read model (PRD-000 v1.11 §3.3.1–§3.3.6; §3.5 #2/#3/#6/#7;
Appendix C Q17; Appendix D PATCH-13; ticket P0-05).

Covers: FINAL / PROVISIONAL / UNSCOREABLE API payloads; every missing
contextual input; the six-field finding summary over a mixed-state set
(max, never mean; no cross-state max); recurrence isolation; finding-status
independence; tenant/IDOR negatives including source ids; resolver/feed
failure; BI / evidence / feed generation changing during the read (one
coherent REPEATABLE READ source view); supersession during the read;
side-effect-free GETs (no score persistence, no snapshot rows, no audit
rows); exact Decimal serialization.

Fixture note: one authoritative CVSS row exists per (cve, assessor, version,
scenario) and the authoritative EPSS/KEV generation is a single sync_state
pointer — intel is seeded once per CVE (``seed_cve_intel``) and episodes are
then created against it. A single CVE therefore cannot be FINAL and
UNSCOREABLE inside one coherent snapshot; the summary's mixed-state fixture
is FINAL + PROVISIONAL, and the UNSCOREABLE count is covered by an
all-UNSCOREABLE finding.
"""
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from app.db import get_db_connection
from app.exposure.exceptions import ExposureNotFoundError
from app.exposure.models import ExposureResolve
from app.exposure.scoring_inputs import (
    BusinessImpactIn,
    ExploitationEvidenceIn,
    ReachabilityEvidenceIn,
    record_exploitation_evidence,
    record_reachability_evidence,
    revoke_evidence,
    set_business_impact,
)
from app.exposure.service import (
    allocate_finding_for_cve,
    resolve_exposure,
    supersede_exposures_for_asset,
)
from app.exposure.tes_read_model import get_exposure_tes, get_finding_tes_summary
from app.vuln_intelligence.repository import (
    complete_sync_snapshot,
    create_sync_snapshot,
)
from tests.conftest import TENANT_A, TENANT_B
from tests.test_p03_cve_intelligence_resolvers import (
    _VULN_TABLE_CLEANUP_SQL,
    _assess,
    _canon,
    _epss_observation,
    _kev_observation,
)

# Captured once at module import (P05 fixture time-bomb fix): every
# freshness relationship in this file is relative to AS_OF, so anchoring it
# at "now" keeps the direct service read and the API route's live-clock read
# inside the same 48-hour freshness window on any run date.
AS_OF = datetime.now(timezone.utc)
_STALE_SUCCESS = AS_OF - timedelta(hours=49)
_FRESH_SUCCESS = AS_OF - timedelta(hours=1)

_EXPOSURE_TABLES = (
    "exposure_exploitation_evidence",
    "exposure_business_impact",
    "exposure_reachability_evidence",
    "asset_exposures",
    "asset_applicability_reviews",
    "findings",
    "assets",
)


@pytest.fixture(autouse=True)
def _clean_tes_env():
    """Vuln-intel + exposure cleanup for isolation (mirrors sibling suites)."""
    def _clean():
        tenants = [str(TENANT_A), str(TENANT_B)]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(_VULN_TABLE_CLEANUP_SQL)
                # attestations are append-only (migration 022 trigger rejects
                # DELETE) — clear via TRUNCATE like tests/conftest.py (test
                # DB only; TRUNCATE does not fire row triggers).
                cur.execute("TRUNCATE exposure_non_exploitation_attestations;")
                for table in _EXPOSURE_TABLES:
                    cur.execute(
                        f"DELETE FROM {table} WHERE tenant_id = ANY(%s::uuid[]);",
                        (tenants,),
                    )
            conn.commit()
    _clean()
    yield
    _clean()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _new_snapshot(conn, source: str) -> str:
    """A real completed sync snapshot (sync_state.last_snapshot_id has an FK
    to sync_snapshots, so pinned states must reference actual rows)."""
    snap = create_sync_snapshot(conn, type("S", (), {
        "source": source, "sync_mode": "incremental", "status": "running",
        "cursor_before": None, "metadata": None,
    })())
    complete_sync_snapshot(conn, snap.id, status="completed")
    return snap.id


def _pin_feed_state(conn, source: str, *, healthy: bool = True,
                    last_success=_FRESH_SUCCESS) -> str:
    """Pin the feed's sync_state to a fresh real snapshot; returns the
    last-good snapshot id."""
    snapshot_id = _new_snapshot(conn, source)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_state SET
                is_healthy = %s,
                last_successful_at = %s,
                last_snapshot_id = %s,
                last_good_snapshot_id = %s,
                last_error = NULL,
                consecutive_failures = 0
            WHERE source = %s;
            """,
            (healthy, last_success, snapshot_id, snapshot_id, source),
        )
        if cur.rowcount == 0:
            cur.execute(
                """
                INSERT INTO sync_state (source, is_healthy, last_successful_at,
                                        last_snapshot_id, last_good_snapshot_id)
                VALUES (%s, %s, %s, %s, %s);
                """,
                (source, healthy, last_success, snapshot_id, snapshot_id),
            )
    return snapshot_id


def seed_cve_intel(
    cve: str,
    *,
    epss_score: str = "0.70",
    epss_present: bool = True,
    kev_ransomware: str = "Known",
    kev_listed: bool = True,
    cvss_score: str = "9.8",
    cvss_present: bool = True,
) -> dict:
    """Seed canonical + authoritative CVSS + one fresh EPSS/KEV generation.

    Idempotent per CVE for CVSS (the schema permits exactly one current row
    per (cve, assessor, version, scenario)); feeds are re-pinned to a NEW
    generation per call — the resolver always binds to the latest one."""
    with get_db_connection() as conn:
        _canon(conn, cve)
        if cvss_present:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM cvss_assessments
                    WHERE cve_id = %s AND is_current = TRUE
                      AND assessor = 'cna-a' AND cvss_version = '3.1';
                    """,
                    (cve,),
                )
                if cur.fetchone() is None:
                    _assess(conn, cve, role="cna", version="3.1",
                            score=cvss_score, assessor="cna-a")
        epss_snap = _pin_feed_state(conn, "epss")
        kev_snap = _pin_feed_state(conn, "kev")
        epss_rec = kev_rec = None
        if epss_present:
            ledger_id = _epss_observation(conn, cve, epss_snap, score=epss_score)
            epss_rec = _source_record_of(conn, "epss_scores", ledger_id)
        if kev_listed:
            ledger_id = _kev_observation(conn, cve, kev_snap, ransomware=kev_ransomware)
            kev_rec = _source_record_of(conn, "kev_entries", ledger_id)
        conn.commit()
    return {
        "epss_snapshot_id": epss_snap,
        "kev_snapshot_id": kev_snap,
        "epss_source_record_id": epss_rec,
        "kev_source_record_id": kev_rec,
    }


def _source_record_of(conn, table: str, ledger_id: str) -> str:
    """The vuln_source_records identity behind a ledger row (what the P0-03
    resolvers bind and what PATCH-13 wants in the source view)."""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT source_record_id FROM {table} WHERE id = %s;", (ledger_id,)
        )
        return str(cur.fetchone()["source_record_id"])


def _make_asset(criticality: str = "critical", network_scope: str = "internal"):
    token = uuid.uuid4().int
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (
                    %s, %s, %s, 'server', 'ip', %s, %s, %s, 'production', %s, 'active'
                );
                """,
                (
                    str(asset_id), str(TENANT_A), f"asset-{uuid.uuid4().hex[:8]}",
                    f"10.66.{token % 250}.{(token >> 8) % 250}",
                    f"10.66.{token % 250}.{(token >> 8) % 250}",
                    network_scope, criticality,
                ),
            )
        conn.commit()
    return asset_id


def _confirm(finding_id, asset_id):
    from app.exposure.models import ExposureConfirm
    from app.exposure.service import confirm_exposure
    with get_db_connection() as conn:
        result = confirm_exposure(
            conn, TENANT_A,
            ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                            evidence={"seed": True}),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return result.exposure.id


def make_cve_episode(cve: str, *, finding_id=None,
                     criticality: str = "critical"):
    """A confirmed episode on a fresh active asset. Intel must be seeded
    separately (seed_cve_intel) — one generation per CVE.
    Returns (exposure_id, finding_id, asset_id)."""
    if finding_id is None:
        with get_db_connection() as conn:
            finding_id = allocate_finding_for_cve(
                conn, TENANT_A, cve,
                default_title=f"Finding {cve}", default_severity="high",
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
    asset_id = _make_asset(criticality=criticality)
    exposure_id = _confirm(finding_id, asset_id)
    return exposure_id, finding_id, asset_id


def make_final_episode(cve: str, *, finding_id=None):
    """All five axes known and fresh → FINAL. Returns
    (exposure_id, finding_id, asset_id, epss_record_id, kev_record_id)."""
    seed = seed_cve_intel(cve, epss_score="0.90")
    exposure_id, finding_id, asset_id = make_cve_episode(
        cve, finding_id=finding_id
    )
    with get_db_connection() as conn:
        record_reachability_evidence(
            conn, TENANT_A, exposure_id,
            ReachabilityEvidenceIn(vantage="internal", evidence={"path": "svc"}),
            actor_id="analyst-a", actor_role="analyst",
        )
        set_business_impact(
            conn, TENANT_A, exposure_id,
            BusinessImpactIn(value=7),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return (exposure_id, finding_id, asset_id,
            seed["epss_source_record_id"], seed["kev_source_record_id"])


def read_tes(exposure_id, tenant_id=TENANT_A, as_of=AS_OF):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        return get_exposure_tes(conn, tenant_id, exposure_id, as_of=as_of)


def read_summary(finding_id, tenant_id=TENANT_A, as_of=AS_OF):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        return get_finding_tes_summary(conn, tenant_id, finding_id, as_of=as_of)


def _row_version(exposure_id) -> str:
    """The row's native xmin version token, read directly from the table."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT xmin::text AS token FROM asset_exposures WHERE id = %s;",
                (str(exposure_id),),
            )
            row = cur.fetchone()
    if row is None:
        return None
    return row["token"] if isinstance(row, dict) else row[0]


def _row_confirmed_at(exposure_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT confirmed_at FROM asset_exposures WHERE id = %s;",
                (str(exposure_id),),
            )
            row = cur.fetchone()
    if row is None:
        return None
    return row["confirmed_at"] if isinstance(row, dict) else row[0]


def er_row(payload):
    for r in payload["decomposition"]:
        if r["axis"] == "exploit_reality":
            return r
    raise AssertionError("no ER row")


def _dec(x):
    """Unwrap the lossless Decimal tag (decomposition rows are pre-tagged by
    the service; top-level scalars stay Decimal until the route boundary)."""
    if isinstance(x, dict) and "__decimal__" in x:
        return Decimal(x["__decimal__"])
    return x


def ax_row(payload, axis):
    for r in payload["decomposition"]:
        if r["axis"] == axis:
            return r
    raise AssertionError(f"no {axis} row")


# ===========================================================================
# State examples
# ===========================================================================


class TestStateExamples:
    def test_final_atomic_payload_with_full_decomposition_and_bindings(self):
        cve = "CVE-2026-5001"
        exposure_id, finding_id, asset_id, epss_rec, kev_rec = make_final_episode(cve)
        payload = read_tes(exposure_id)
        assert payload["state"] == "FINAL"
        # 0.40*9.8 + 0.30*9 + 0.15*10 + 0.10*8 + 0.05*7 = 9.27 exactly
        assert payload["value"] == Decimal("9.27")
        assert payload["display_value"] == Decimal("9.27")
        assert payload["formula_version"] == "tes-v1"
        assert payload["known_axes"] == "5/5"
        assert payload["known_weight"] == Decimal("1.00")
        assert payload["missing_inputs"] == []
        assert [r["axis"] for r in payload["decomposition"]] == [
            "intrinsic", "exploit_reality", "criticality", "reachability",
            "business_impact",
        ]
        assert all(r["state"] == "known" for r in payload["decomposition"])
        # PATCH-13 bindings: episode identity, coherent as_of, status/version
        # reference, CVSS assessment identity, EPSS/KEV last-good snapshots,
        # exact ledger row identities.
        sv = payload["source_view"]
        assert sv["exposure_id"] == str(exposure_id)
        assert sv["exposure_status"] == "confirmed"
        assert sv["finding_id"] == str(finding_id)
        assert sv["asset_id"] == str(asset_id)
        assert sv["as_of"] == AS_OF
        assert sv["cvss_assessment_id"] is not None
        assert sv["epss_snapshot_id"] is not None
        assert sv["epss_source_record_id"] == str(epss_rec)
        assert sv["kev_snapshot_id"] is not None
        assert sv["kev_source_record_id"] == str(kev_rec)
        assert sv["reachability_record_id"] is not None
        assert sv["business_impact_record_id"] is not None
        # feed-health provenance rides the decomposition (P0-04 contract)
        assert er_row(payload)["epss_feed_health"]["source"] == "epss"
        assert er_row(payload)["kev_feed_health"]["source"] == "kev"
        assert er_row(payload)["kev_state"] == "listed"
        assert er_row(payload)["selected_rung"] == "kev_listed+ransomware"

    def test_provisional_renormalized_coverage_and_missing_reasons(self):
        cve = "CVE-2026-5002"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)  # no BI, no reachability
        payload = read_tes(exposure_id)
        assert payload["state"] == "PROVISIONAL"
        assert payload["value"] is not None
        assert payload["known_axes"] == "3/5"
        assert payload["known_weight"] == Decimal("0.85")
        assert payload["missing_inputs"], "PROVISIONAL must name missing inputs"
        assert any("business impact" in m.lower() for m in payload["missing_inputs"])
        assert any("reachability" in m.lower() for m in payload["missing_inputs"])
        unknown = [r for r in payload["decomposition"] if r["state"] != "known"]
        assert {r["axis"] for r in unknown} == {"reachability", "business_impact"}
        for r in unknown:
            assert r["contribution"] is None and r["effective_weight"] is None
        # renormalization: (0.40*9.8 + 0.30*9 + 0.15*10)/0.85 at full precision
        with localcontext() as ctx:
            ctx.prec = 50
            expected = (Decimal("0.40") * Decimal("9.8") + Decimal("0.30") * Decimal("9")
                        + Decimal("0.15") * Decimal("10")) / Decimal("0.85")
        assert payload["value"] == expected
        # display_value is the two-decimal quantization, never the raw value
        assert payload["display_value"] == expected.quantize(Decimal("0.01"))

    def test_unscoreable_when_no_authoritative_cvss(self):
        cve = "CVE-2026-5003"
        seed_cve_intel(cve, cvss_present=False, epss_present=False,
                       kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)
        payload = read_tes(exposure_id)
        assert payload["state"] == "UNSCOREABLE"
        assert payload["value"] is None and payload["display_value"] is None
        assert payload["known_axes"] == "0/5"
        assert len(payload["decomposition"]) == 5
        assert any("UNSCOREABLE" in m for m in payload["missing_inputs"])

    def test_missing_cvss_reason_code_surfaces_in_source_view(self):
        cve = "CVE-2026-5004"
        seed_cve_intel(cve, cvss_present=False, epss_present=False,
                       kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)
        payload = read_tes(exposure_id)
        code = payload["source_view"]["cvss_unscoreable_reason_code"]
        assert code is not None and code.startswith("cvss_")


# ===========================================================================
# Every missing contextual input
# ===========================================================================


class TestMissingContextualInputs:
    def test_missing_business_impact_renders_unknown_row(self):
        cve = "CVE-2026-5010"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)
        payload = read_tes(exposure_id)
        row = ax_row(payload, "business_impact")
        assert row["state"] == "unknown" and row["raw_value"] is None
        assert row["contribution"] is None and row["reason"]
        assert payload["source_view"]["business_impact_record_id"] is None

    def test_missing_reachability_renders_unknown_row(self):
        cve = "CVE-2026-5011"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)
        payload = read_tes(exposure_id)
        row = ax_row(payload, "reachability")
        assert row["state"] == "unknown" and row["raw_value"] is None
        assert payload["source_view"]["reachability_record_id"] is None

    def test_missing_feeds_leave_er_unknown_and_provisional(self):
        cve = "CVE-2026-5012"
        # No EPSS record at all. KEV "absence" resolves authoritatively to
        # not_listed (P0-03: absence inside a fresh canonical generation is
        # definitive), so the genuinely unresolved feed here is EPSS.
        seed_cve_intel(cve, epss_present=False, kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)
        payload = read_tes(exposure_id)
        er = er_row(payload)
        assert _dec(er["raw_value"]) is None
        assert er["selected_rung"] is None
        names = [n for n, _ in er["unresolved_higher"]]
        assert names == ["epss(unknown)"]
        assert any("epss" in m.lower() for m in payload["missing_inputs"])

    def test_expired_evidence_is_stale_higher_not_a_rung(self):
        cve = "CVE-2026-5013"
        # EPSS 0.30 → band 6 (edges 0.5/0.1/0.02/0.002); KEV not listed so
        # the exact-evidence slot is what is under test.
        seed_cve_intel(cve, epss_score="0.30", kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)
        # 400-day-old observed exploitation: expired (365d TTL) — persists,
        # keeps the stale-higher row auditable, never establishes ER 10.
        with get_db_connection() as conn:
            record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(
                    basis="observed", result="succeeded",
                    evidence={"ref": "old-campaign"},
                    observed_at=AS_OF - timedelta(days=400),
                ),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        payload = read_tes(exposure_id)
        er = er_row(payload)
        assert _dec(er["raw_value"]) == Decimal("6")  # EPSS 0.30 → band 6, fresh
        assert payload["state"] == "PROVISIONAL"
        assert any("exact_exposure" in n for n, _ in er["unresolved_higher"])
        assert er["exact_exposure_stale_state"] == "stale"
        assert er["selected_sources"] == ["epss"]

    def test_revoked_evidence_excluded_entirely(self):
        cve = "CVE-2026-5014"
        seed_cve_intel(cve, epss_score="0.30", kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)
        with get_db_connection() as conn:
            res = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(
                    basis="observed", result="succeeded", evidence={"ref": "x"},
                    observed_at=AS_OF - timedelta(days=1),
                ),
                actor_id="analyst-a", actor_role="analyst",
            )
            revoke_evidence(
                conn, TENANT_A, exposure_id, res.record.id, "exploitation",
                "retracted", actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        payload = read_tes(exposure_id)
        er = er_row(payload)
        assert _dec(er["raw_value"]) == Decimal("6")  # EPSS 0.30 → band 6, fresh
        assert all("exact_exposure" not in n for n, _ in er["unresolved_higher"])
        assert payload["source_view"]["exploitation_evidence_ids"] == ()


# ===========================================================================
# Six-field finding summary
# ===========================================================================


class TestFindingSummary:
    def test_mixed_state_six_field_summary_max_never_mean(self):
        cve = "CVE-2026-5100"
        final_id, finding_id, _, _, _ = make_final_episode(cve)
        prov_a, _, _ = make_cve_episode(cve, finding_id=finding_id)
        prov_b, _, _ = make_cve_episode(cve, finding_id=finding_id)
        with get_db_connection() as conn:
            record_reachability_evidence(
                conn, TENANT_A, prov_b,
                ReachabilityEvidenceIn(vantage="external", evidence={"r": 1}),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        summary = read_summary(finding_id)
        # EXACT six-field contract (bounded correction 1): these keys and
        # nothing else — finding_id and as_of are not in the body; the route
        # already identifies the finding.
        assert set(summary) == {
            "max_final_tes", "max_provisional_tes", "final_count",
            "provisional_count", "unscoreable_count", "total_current_exposures",
        }
        assert summary["final_count"] == 1
        assert summary["provisional_count"] == 2
        assert summary["unscoreable_count"] == 0
        assert summary["total_current_exposures"] == 3
        assert summary["max_final_tes"] == read_tes(final_id)["value"] == Decimal("9.27")
        va, vb = read_tes(prov_a)["value"], read_tes(prov_b)["value"]
        assert summary["max_provisional_tes"] == max(va, vb)

    def test_all_unscoreable_finding_counts_every_exposure(self):
        cve = "CVE-2026-5101"
        seed_cve_intel(cve, cvss_present=False, epss_present=False,
                       kev_listed=False)
        _, finding_id, _ = make_cve_episode(cve)
        make_cve_episode(cve, finding_id=finding_id)
        summary = read_summary(finding_id)
        assert summary["unscoreable_count"] == 2
        assert summary["final_count"] == 0 and summary["provisional_count"] == 0
        assert summary["total_current_exposures"] == 2
        assert summary["max_final_tes"] is None
        assert summary["max_provisional_tes"] is None

    def test_summary_excludes_resolved_and_superseded_history(self):
        cve = "CVE-2026-5102"
        seed_cve_intel(cve)
        _, finding_id, _ = make_cve_episode(cve)
        # a second current episode, then resolved → recurrence history
        resolved_id, _, _ = make_cve_episode(cve, finding_id=finding_id)
        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, resolved_id,
                ExposureResolve(status="resolved", resolution_reason="fixed"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        # a third current episode, then superseded (asset decommission)
        sup_id, _, sup_asset = make_cve_episode(cve, finding_id=finding_id)
        with get_db_connection() as conn:
            supersede_exposures_for_asset(
                conn, TENANT_A, sup_asset, actor_id="admin-a",
                actor_role="admin", reason="decommission",
            )
            conn.commit()
        summary = read_summary(finding_id)
        assert summary["total_current_exposures"] == 1
        assert summary["provisional_count"] == 1
        assert summary["final_count"] == 0 and summary["unscoreable_count"] == 0
        assert summary["max_final_tes"] is None

    def test_no_cross_state_max_final_and_provisional_never_blend(self):
        """A PROVISIONAL above the FINAL must not raise the FINAL max and the
        FINAL must never stand in for the PROVISIONAL max: two numbers."""
        cve = "CVE-2026-5103"
        _, finding_id, _, _, _ = make_final_episode(cve)  # FINAL 9.27
        make_cve_episode(cve, finding_id=finding_id)      # PROVISIONAL 9.55…
        summary = read_summary(finding_id)
        assert summary["max_final_tes"] == Decimal("9.27")
        with localcontext() as ctx:
            ctx.prec = 50
            expected = (Decimal("0.40") * Decimal("9.8") + Decimal("0.30") * Decimal("9")
                        + Decimal("0.15") * Decimal("10")) / Decimal("0.85")
        assert summary["max_provisional_tes"] == expected
        assert summary["max_provisional_tes"] > summary["max_final_tes"]
        # the FINAL max did NOT blend upward
        assert summary["max_final_tes"] != summary["max_provisional_tes"]

    def test_recurrence_prior_episode_has_no_current_tes(self):
        cve = "CVE-2026-5104"
        seed_cve_intel(cve)
        first_id, finding_id, asset_id = make_cve_episode(cve)
        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, first_id,
                ExposureResolve(status="resolved", resolution_reason="fixed"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        # recurrence: NEW episode on the SAME finding + asset
        with get_db_connection() as conn:
            from app.exposure.models import ExposureConfirm
            from app.exposure.service import confirm_exposure
            result = confirm_exposure(
                conn, TENANT_A,
                ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                                evidence={"recurrence": True}),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        assert result.exposure.id != first_id
        with pytest.raises(ExposureNotFoundError):
            read_tes(first_id)
        payload = read_tes(result.exposure.id)
        assert payload["state"] == "PROVISIONAL"
        assert payload["source_view"]["exposure_id"] == str(result.exposure.id)
        # prior-episode contextual inputs never leak into the new episode
        assert payload["source_view"]["business_impact_record_id"] is None
        assert payload["source_view"]["reachability_record_id"] is None

    def test_finding_status_is_not_an_input(self):
        cve = "CVE-2026-5105"
        exposure_id, finding_id, _, _, _ = make_final_episode(cve)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE findings SET status = 'closed' WHERE id = %s;",
                    (str(finding_id),),
                )
            conn.commit()
        payload = read_tes(exposure_id)
        assert payload["state"] == "FINAL"
        summary = read_summary(finding_id)
        assert summary["total_current_exposures"] == 1
        assert summary["final_count"] == 1


# ===========================================================================
# Tenant / IDOR negatives
# ===========================================================================


class TestTenantIsolation:
    def test_cross_tenant_exposure_and_summary_are_404(self, client, auth_headers_tenant_b_admin):
        cve = "CVE-2026-5200"
        exposure_id, finding_id, _, _, _ = make_final_episode(cve)
        res = client.get(
            f"/api/exposure/{exposure_id}/tes", headers=auth_headers_tenant_b_admin
        )
        assert res.status_code == 404
        res = client.get(
            f"/api/exposure/findings/{finding_id}/tes-summary",
            headers=auth_headers_tenant_b_admin,
        )
        assert res.status_code == 404
        assert "detail" in res.json()

    def test_unknown_ids_are_404(self, client, auth_headers_tenant_a_admin):
        res = client.get(
            f"/api/exposure/{uuid.uuid4()}/tes", headers=auth_headers_tenant_a_admin
        )
        assert res.status_code == 404
        res = client.get(
            f"/api/exposure/findings/{uuid.uuid4()}/tes-summary",
            headers=auth_headers_tenant_a_admin,
        )
        assert res.status_code == 404

    def test_cross_tenant_source_ids_do_not_leak_state(self, client, auth_headers_tenant_b_admin):
        """A cross-tenant exposure id must not disclose anything — same 404,
        no TES fields in the body."""
        cve = "CVE-2026-5201"
        exposure_id, _, _, _, _ = make_final_episode(cve)
        res = client.get(
            f"/api/exposure/{exposure_id}/tes", headers=auth_headers_tenant_b_admin
        )
        body = res.json()
        assert res.status_code == 404
        assert "value" not in body and "decomposition" not in body

    def test_unauthenticated_request_is_401(self, client):
        res = client.get(f"/api/exposure/{uuid.uuid4()}/tes")
        assert res.status_code == 401

    def test_lookup_queries_are_tenant_scoped_in_sql(self):
        """Correction-2 evidence: both initial lookup SELECTs bind the
        AuthContext tenant directly into the WHERE clause (tenant_id AND
        object id) — another tenant's row is excluded by the database, never
        fetched and rejected afterwards in Python."""
        from app.exposure import tes_read_model as _trm
        src = Path(_trm.__file__).read_text(encoding="utf-8")
        # (a) the exposure lookup is tenant-scoped
        m_exp = re.search(
            r"def _load_exposure_for_tes\(.*?raise ExposureNotFoundError",
            src, re.S,
        )
        assert m_exp, "exposure loader not found"
        assert (
            re.search(r"WHERE\s+e\.tenant_id\s*=\s*%s\s+AND\s+e\.id\s*=\s*%s", m_exp.group(0))
        ), "exposure lookup must scope by tenant_id AND id in SQL"
        # (b) the finding lookup is tenant-scoped
        m_fnd = re.search(
            r"def _load_finding_for_summary\(.*?raise FindingNotFoundError",
            src, re.S,
        )
        assert m_fnd, "finding loader not found"
        assert (
            re.search(r"WHERE\s+tenant_id\s*=\s*%s\s+AND\s+id\s*=\s*%s", m_fnd.group(0))
        ), "finding lookup must scope by tenant_id AND id in SQL"
        # (c) no post-fetch tenant comparison remains in either loader
        assert "!= str(tenant_id)" not in m_exp.group(0)
        assert "!= str(tenant_id)" not in m_fnd.group(0)
        # (d) composite tenant joins are preserved on the exposure lookup
        assert (
            "ON e.tenant_id = f.tenant_id" in m_exp.group(0)
            and "ON e.tenant_id = a.tenant_id" in m_exp.group(0)
        )
        # (e) behavioral proof with a live row: a same-UUID cross-tenant
        # lookup is the same 404 as an unknown id — the SQL predicate (not a
        # Python comparison) excluded the foreign row.
        cve = "CVE-2026-5202"
        exposure_id, finding_id, _, _, _ = make_final_episode(cve)
        with pytest.raises(ExposureNotFoundError):
            read_tes(exposure_id, tenant_id=TENANT_B)
        with pytest.raises(Exception):
            read_summary(finding_id, tenant_id=TENANT_B)


# ===========================================================================
# Resolver / feed failure — never FINAL
# ===========================================================================


class TestFeedFailure:
    @pytest.mark.parametrize("healthy,last_success,names", [
        (False, _FRESH_SUCCESS, ("epss(unknown)", "kev(unknown)")),
        (True, _STALE_SUCCESS, ("epss(stale)", "kev(stale)")),
    ])
    def test_feed_failure_never_final(self, healthy, last_success, names):
        cve = "CVE-2026-5300"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE sync_state SET is_healthy = %s, last_successful_at = %s
                    WHERE source IN ('epss', 'kev');
                    """,
                    (healthy, last_success),
                )
            conn.commit()
        payload = read_tes(exposure_id)
        assert payload["state"] == "PROVISIONAL"  # never FINAL, never UNSCOREABLE
        er = er_row(payload)
        assert er["raw_value"] is None            # no fresh rung stands
        got = [n for n, _ in er["unresolved_higher"]]
        assert got == list(names)                 # STALE and UNKNOWN render distinctly
        # feed-health provenance is still complete in the payload
        assert er["epss_feed_health"]["source"] == "epss"
        assert er["epss_feed_health"]["is_healthy"] is healthy
        assert er["epss_feed_health"]["freshness_age_seconds"] is not None

    def test_missing_sync_state_is_unknown_never_final(self):
        cve = "CVE-2026-5301"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE sync_state SET last_successful_at = NULL, "
                    "last_good_snapshot_id = NULL, is_healthy = FALSE "
                    "WHERE source IN ('epss', 'kev');"
                )
            conn.commit()
        payload = read_tes(exposure_id)
        assert payload["state"] == "PROVISIONAL"
        assert any("epss" in m.lower() for m in payload["missing_inputs"])


# ===========================================================================
# One coherent REPEATABLE READ source view (PATCH-13)
# ===========================================================================


class _SnapshotConn:
    """A connection inside an established REPEATABLE READ snapshot."""

    def __enter__(self):
        self._cm = get_db_connection()
        self.conn = self._cm.__enter__()
        cur = self.conn.cursor()
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        cur.execute("SELECT 1;")
        cur.fetchone()
        cur.close()
        return self.conn

    def __exit__(self, *exc):
        try:
            self.conn.rollback()
        finally:
            return self._cm.__exit__(*exc)


class TestCoherentReadSnapshot:
    def test_business_impact_change_during_read_is_not_mixed(self):
        cve = "CVE-2026-5400"
        exposure_id, _, _, _, _ = make_final_episode(cve)
        with _SnapshotConn() as conn:
            # concurrent BI re-rate commits AFTER the snapshot was established
            with get_db_connection() as wconn:
                set_business_impact(
                    wconn, TENANT_A, exposure_id,
                    BusinessImpactIn(value=2, reason="re-rated"),
                    actor_id="analyst-b", actor_role="analyst",
                )
                wconn.commit()
            payload = get_exposure_tes(conn, TENANT_A, exposure_id, as_of=AS_OF)
            assert _dec(ax_row(payload, "business_impact")["raw_value"]) == Decimal("7")
            assert payload["state"] == "FINAL"
        # later reads see the new version
        after = read_tes(exposure_id)
        assert _dec(ax_row(after, "business_impact")["raw_value"]) == Decimal("2")

    def test_feed_generation_change_during_read_is_not_mixed(self):
        cve = "CVE-2026-5401"
        seed = seed_cve_intel(cve, epss_score="0.70")
        old_rec = seed["epss_source_record_id"]
        exposure_id, _, _ = make_cve_episode(cve)
        with _SnapshotConn() as conn:
            # a NEW EPSS generation lands mid-read
            with get_db_connection() as wconn:
                new_snap = _pin_feed_state(wconn, "epss")
                ledger_id = _epss_observation(wconn, cve, new_snap, score="0.99")
                new_rec = _source_record_of(wconn, "epss_scores", ledger_id)
                wconn.commit()
            payload = get_exposure_tes(conn, TENANT_A, exposure_id, as_of=AS_OF)
            assert payload["source_view"]["epss_source_record_id"] == str(old_rec)
            assert _dec(er_row(payload)["epss_value"]) == Decimal("0.70")
        # a fresh read sees the new generation
        after = read_tes(exposure_id)
        assert after["source_view"]["epss_source_record_id"] == str(new_rec)
        assert _dec(er_row(after)["epss_value"]) == Decimal("0.99")

    def test_exploitation_evidence_generation_during_read_is_not_mixed(self):
        cve = "CVE-2026-5402"
        seed_cve_intel(cve, epss_score="0.30", kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)
        with _SnapshotConn() as conn:
            with get_db_connection() as wconn:
                record_exploitation_evidence(
                    wconn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(
                        basis="observed", result="succeeded",
                        evidence={"ref": "mid-read"}, observed_at=AS_OF - timedelta(days=1),
                    ),
                    actor_id="analyst-a", actor_role="analyst",
                )
                wconn.commit()
            payload = get_exposure_tes(conn, TENANT_A, exposure_id, as_of=AS_OF)
            # evidence committed after the snapshot is not in this view
            assert _dec(er_row(payload)["raw_value"]) == Decimal("6")  # EPSS band 6
            assert payload["source_view"]["exploitation_evidence_ids"] == ()
        after = read_tes(exposure_id)
        assert _dec(er_row(after)["raw_value"]) == Decimal("10")  # now in view
        assert len(after["source_view"]["exploitation_evidence_ids"]) == 1

    def test_supersession_during_read_is_bound_to_coherent_view(self):
        cve = "CVE-2026-5403"
        exposure_id, _, asset_id, _, _ = make_final_episode(cve)
        # the pre-supersession row-version token (correction 3: xmin binding)
        pre_version = _row_version(exposure_id)
        assert pre_version is not None
        with _SnapshotConn() as conn:
            # the supersession commits AFTER the snapshot: the read stays
            # bound to the coherent pre-supersession view, never mixed
            with get_db_connection() as wconn:
                supersede_exposures_for_asset(
                    wconn, TENANT_A, asset_id, actor_id="admin-a",
                    actor_role="admin", reason="decommission mid-read",
                )
                wconn.commit()
            payload = get_exposure_tes(conn, TENANT_A, exposure_id, as_of=AS_OF)
            assert payload["source_view"]["exposure_status"] == "confirmed"
            assert payload["state"] == "FINAL"
            # the in-snapshot response retains the PRE-supersession version
            # token (the snapshot predates the superseding commit)
            assert payload["source_view"]["exposure_version"] == pre_version
        # the database row has a DIFFERENT version after supersession
        post_version = _row_version(exposure_id)
        assert post_version is not None and post_version != pre_version
        # and the response remained explicitly bound to the version it read
        assert payload["source_view"]["exposure_version"] == pre_version
        # after the read: the episode is history — no current TES
        with pytest.raises(ExposureNotFoundError):
            read_tes(exposure_id)

    def test_exposure_version_token_changes_on_lifecycle_change(self):
        """xmin changes when the lifecycle row changes (unlike confirmed_at,
        which never moves on supersession) — it is a real version binding."""
        cve = "CVE-2026-5404"
        exposure_id, _, asset_id, _, _ = make_final_episode(cve)
        before = _row_version(exposure_id)
        confirmed_at_before = _row_confirmed_at(exposure_id)
        with get_db_connection() as wconn:
            supersede_exposures_for_asset(
                wconn, TENANT_A, asset_id, actor_id="admin-a",
                actor_role="admin", reason="decommission",
            )
            wconn.commit()
        after = _row_version(exposure_id)
        assert after != before
        # the old token can never be confused with the new row state
        assert confirmed_at_before == _row_confirmed_at(exposure_id)


# ===========================================================================
# Side-effect-free GETs
# ===========================================================================


class TestNoSideEffects:
    def test_repeated_gets_create_no_rows_and_no_tes_tables(
        self, client, auth_headers_tenant_a_admin
    ):
        cve = "CVE-2026-5500"
        exposure_id, finding_id, _, _, _ = make_final_episode(cve)

        def audit_count():
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT count(*) AS c FROM audit_events WHERE tenant_id = %s;",
                        (str(TENANT_A),),
                    )
                    return cur.fetchone()["c"]

        def tes_like_tables():
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT table_name FROM information_schema.tables
                        WHERE table_schema = 'public'
                          AND (table_name LIKE 'tes_%' OR table_name LIKE '%\\_tes'
                               OR table_name LIKE '%score\\_%')
                        """
                    )
                    return {r["table_name"] for r in cur.fetchall()}

        before_audit = audit_count()
        before_tables = tes_like_tables()
        for _ in range(3):
            res = client.get(
                f"/api/exposure/{exposure_id}/tes", headers=auth_headers_tenant_a_admin
            )
            assert res.status_code == 200
            res = client.get(
                f"/api/exposure/findings/{finding_id}/tes-summary",
                headers=auth_headers_tenant_a_admin,
            )
            assert res.status_code == 200
        assert audit_count() == before_audit, "reads must not audit"
        assert tes_like_tables() == before_tables, (
            "no score persistence, no snapshot rows"
        )

    def test_failed_read_leaves_no_trace(self, client, auth_headers_tenant_a_admin):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM audit_events WHERE tenant_id = %s;",
                    (str(TENANT_A),),
                )
                before = cur.fetchone()["c"]
        res = client.get(
            f"/api/exposure/{uuid.uuid4()}/tes", headers=auth_headers_tenant_a_admin
        )
        assert res.status_code == 404
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM audit_events WHERE tenant_id = %s;",
                    (str(TENANT_A),),
                )
                assert cur.fetchone()["c"] == before


# ===========================================================================
# Exact Decimal serialization
# ===========================================================================


class TestDecimalSerialization:
    def test_full_precision_values_are_lossless_tagged_strings(
        self, client, auth_headers_tenant_a_admin
    ):
        cve = "CVE-2026-5600"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)  # PROVISIONAL 3/5
        res = client.get(
            f"/api/exposure/{exposure_id}/tes", headers=auth_headers_tenant_a_admin
        )
        assert res.status_code == 200
        body = res.json()
        svc = read_tes(exposure_id)
        # renormalized repeating expansion — the wire string must decode to
        # exactly the service-computed Decimal (no float hop, no rounding)
        assert isinstance(body["value"], dict) and "__decimal__" in body["value"]
        assert Decimal(body["value"]["__decimal__"]) == svc["value"]
        assert Decimal(body["display_value"]["__decimal__"]) == svc["display_value"]
        assert Decimal(body["known_weight"]["__decimal__"]) == Decimal("0.85")
        svc_contrib = svc["decomposition"][0]["contribution"]
        assert Decimal(body["decomposition"][0]["contribution"]["__decimal__"]) == (
            _dec(svc_contrib)
        )
        # the wire carries the full renormalized precision — far beyond float
        # (and beyond a 28-digit default Decimal context)
        frac_digits = body["value"]["__decimal__"].split(".")[1]
        assert len(frac_digits) >= 40

    def test_summary_decimals_are_tagged_and_exact(
        self, client, auth_headers_tenant_a_admin
    ):
        cve = "CVE-2026-5601"
        _, finding_id, _, _, _ = make_final_episode(cve)
        res = client.get(
            f"/api/exposure/findings/{finding_id}/tes-summary",
            headers=auth_headers_tenant_a_admin,
        )
        assert res.status_code == 200
        body = res.json()
        assert isinstance(body["max_final_tes"], dict)
        assert "__decimal__" in body["max_final_tes"]
        # numeric equality over the exact wire string (the kernel emits its
        # natural scale — e.g. "9.270" — never a float)
        assert Decimal(body["max_final_tes"]["__decimal__"]) == Decimal("9.27")

    def test_no_float_rounding_of_any_decimal_field(
        self, client, auth_headers_tenant_a_admin
    ):
        """BI 7.3333 must ride the payload as the exact string '7.3333'."""
        cve = "CVE-2026-5602"
        seed_cve_intel(cve)
        exposure_id, _, _ = make_cve_episode(cve)
        with get_db_connection() as conn:
            set_business_impact(
                conn, TENANT_A, exposure_id,
                BusinessImpactIn(value=Decimal("7.3333")),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        res = client.get(
            f"/api/exposure/{exposure_id}/tes", headers=auth_headers_tenant_a_admin
        )
        body = res.json()
        svc = read_tes(exposure_id)
        assert _dec(ax_row(body, "business_impact")["raw_value"]) == Decimal("7.3333")
        # wire decodes EXACTLY to the service-computed Decimal (kernel
        # renormalizes weights first — replicating its rounding order here
        # would test the kernel, not the serialization)
        assert Decimal(body["value"]["__decimal__"]) == svc["value"]
        assert Decimal(body["display_value"]["__decimal__"]) == svc["display_value"]
        # the repeating expansion survived the wire far beyond float precision
        assert len(body["value"]["__decimal__"].split(".")[1]) >= 40


# ===========================================================================
# P0-08a — structural containment of the attested_no_exploitation slot:
# the rung is non-CVE-only (§3.6.6 #5). The CVE-path ER factory cannot set
# it (by construction), a populated slot arriving on the CVE path fails
# closed (defense-in-depth), and the CVE producer never resolves
# attestation-shaped data even when such a row exists in storage against a
# CVE-linked episode.
# ===========================================================================


class TestAttestationSlotCveContainment:
    def test_cve_path_factory_cannot_carry_attestation(self):
        import inspect

        from app.exposure import tes_read_model as rm
        from app.exposure.exceptions import EvidencePolicyError
        from app.exposure.tes_kernel import (
            ExactExposureEvidence,
            ExactExposureEvidenceState,
            EvidenceKind,
            ExploitRealityInput,
            ProvenanceClass,
        )

        # 1) by construction: the CVE factory's signature has no attestation
        #    parameter and its output always carries None
        params = inspect.signature(rm._build_er_input).parameters
        assert "attested_no_exploitation" not in params
        er = rm._build_er_input(None, None, None, None)
        assert er.attested_no_exploitation is None

        # 2) defense-in-depth: a populated slot arriving from a CVE-path
        #    producer raises fail-closed — a CVE must never reach FINAL on
        #    ER 1.0 without fresh intel (§3.3.3)
        populated = ExploitRealityInput(
            attested_no_exploitation=ExactExposureEvidence(
                ExactExposureEvidenceState.FRESH_QUALIFYING,
                kind=EvidenceKind.OBSERVED_EXPLOITATION,
                observed_at=AS_OF,
                source="attestation:smuggled",
                provenance_class=ProvenanceClass.ANALYST_ENTERED,
            )
        )
        with pytest.raises(EvidencePolicyError, match="non-CVE-only"):
            rm._assert_cve_path_er_input(populated)

    def test_cve_episode_never_resolves_attestation_shaped_data(self):
        """Producer test: the service refuses CVE attestations at the API
        (EvidencePolicyError), and even when an attestation-shaped row
        EXISTS in storage against the CVE episode (raw insert bypassing the
        service — the DB permits the row), the CVE ER derivation never
        resolves it: the slot stays None and, with no fresh intel seeded,
        the CVE ER establishes NO rung at all — ER 1.0 on the CVE path is
        reachable ONLY through fresh EPSS < 0.002 AND fresh KEV not-listed
        (§3.3.3 bottom rung)."""
        from app.exposure.exceptions import EvidencePolicyError
        from app.exposure.scoring_inputs import record_non_exploitation_attestation

        cve = f"CVE-2026-{9100 + uuid.uuid4().int % 800}"
        seed_cve_intel(cve, epss_present=False, kev_listed=False)
        exposure_id, finding_id, asset_id = make_cve_episode(cve)
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="non-CVE"):
                record_non_exploitation_attestation(
                    conn, TENANT_A, exposure_id,
                    evidence_ref="cve-assertion", actor_id="analyst-a",
                    actor_role="analyst")
            conn.rollback()
        # attestation-shaped data in storage anyway
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO exposure_non_exploitation_attestations (
                        tenant_id, exposure_id, attested_by, attested_at,
                        evidence_ref
                    ) VALUES (%s, %s, 'analyst-a', now(), 'raw-cve-probe');
                    """,
                    (str(TENANT_A), str(exposure_id)))
            conn.commit()
        payload = read_tes(exposure_id)
        # the CVE reader structurally never resolves the ledger
        assert payload["source_view"]["attestation_state"] is None
        er_row = [r for r in payload["decomposition"]
                  if r["axis"] == "exploit_reality"][0]
        assert er_row["attestation_state"] is None
        assert er_row["selected_rung"] is None   # no fresh intel ⇒ NO rung, not ER 1
        assert er_row["raw_value"] is None
        # everything else known + ER unknown ⇒ renormalized PROVISIONAL —
        # never FINAL-on-ER-1 via the smuggled record
        assert payload["state"] == "PROVISIONAL"
