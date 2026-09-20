# backend/tests/test_p03_cve_intelligence_resolvers.py
"""
P0-03 — CVE intelligence resolvers (PRD-000 v1.8 §3.5 #2, §3.3.3).

Focused PostgreSQL test file covering:

  CVSS authority resolver (resolve_cvss_authority)
    - complete version priority matrix (4.0 > 3.1 > 3.0 > 2.0)
    - complete role priority matrix (CNA > NVD > ADP)
    - 4.0 ADP beats 3.1 CNA (version wins before role)
    - single winner succeeds with full provenance
    - two winners across assessors / across scenarios are ambiguous
    - ambiguity does not fall back; numerical maximum never wins
    - inactive rows ignored; missing structural role fails closed
    - missing CVE vs missing assessment have distinct reason codes

  EPSS freshness resolver (resolve_epss_freshness)
    - exact 48h boundary (fresh at exactly 48h, unknown at 48h + 1s)
    - healthy/unhealthy, missing success timestamp, missing last-good pointer
    - last-good generation match; newer failed-snapshot row ignored (the
      intact last-good observation still resolves fresh)
    - no observation inside the authoritative generation is unknown
    - structured provenance distinguishing last attempt vs last good

  KEV ternary resolver (resolve_kev_status)
    - listed / fresh not_listed / stale-absence unknown / unhealthy unknown
    - missing last-good pointer unknown; reconciled delist is not_listed
    - old-snapshot membership ignored; ransomware provenance retained
    - failed import keeps last-good pointer and data intact; unhealthy after
      failure is unknown

  Race / failure semantics
    - resolver/import coherence under REPEATABLE READ (mid-commit snapshot
      does not mix generations; retry sees the later generation)
    - failed snapshot rows never become authoritative; partial writes cannot
      advance sync_state.last_snapshot_id; prior last-good stays authoritative
    - retry of the same import does not create a second current generation

  Migration 018
    - index exists and covers all four supported versions (EXPLAIN evidence)
    - existing assessment rows preserved (no provenance rewrite)

  Catalog/API anti-TES contract
    - no tes_score / tes_severity / tes_resolution anywhere in the payloads
    - replacement CVSS fields carry authority provenance; list and detail agree
"""
from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

import psycopg
import pytest

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    CanonicalVulnerability,
    CvssAssessment,
    EpssScore,
    FEED_FRESHNESS_WINDOW,
    KevEntry,
    SourceRecord,
    CVSS_AUTHORITY_AMBIGUOUS,
    CVSS_MISSING_CVE,
    CVSS_NO_AUTHORITATIVE_ASSESSMENT,
    EPSS_MISSING_SNAPSHOT,
    EPSS_MISSING_SYNC_STATE,
    EPSS_NEVER_IMPORTED,
    EPSS_NO_OBSERVATION,
    EPSS_STALE,
    EPSS_UNHEALTHY,
    KEV_MISSING_SNAPSHOT,
    KEV_MISSING_SYNC_STATE,
    KEV_NEVER_IMPORTED,
    KEV_STALE,
    KEV_UNHEALTHY,
)
from app.vuln_intelligence.repository import (
    create_sync_snapshot,
    complete_sync_snapshot,
    get_composed_cve_detail,
    get_sync_snapshot,
    get_sync_state,
    resolve_cvss_authority,
    resolve_epss_freshness,
    resolve_kev_status,
    search_vulnerabilities,
    update_sync_state,
    upsert_canonical_vulnerability,
    upsert_cvss_assessment,
    upsert_epss_score,
    upsert_kev_entry,
    upsert_source_record,
)

V31_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V30_VECTOR = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
V20_VECTOR = "AV:N/AC:L/Au:N/C:C/I:C/A:N"

# Fixed deterministic evaluation instant shared by freshness tests.
AS_OF = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)

# Prefix for the bulk CVSS catalog used by the migration-018 EXPLAIN tests.
BULK_CVE_PREFIX = "CVE-2026-99"


def _canon(conn, cve_id: str) -> None:
    upsert_canonical_vulnerability(conn, CanonicalVulnerability(
        cve_id=cve_id, state="PUBLISHED",
        assigner_org_id="org", assigner_short_name="cna",
    ))


def _assess(conn, cve_id: str, *, role: Optional[str], version: str, score: str,
            assessor: str, scenario: str = "GENERAL", source: str = "cve",
            current: bool = True, provider_org_id: Optional[str] = None) -> None:
    """Insert a raw assessment row (bypasses retire-on-upsert for dup rows)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cvss_assessments
                (cve_id, source, assessor, container_role, cvss_version,
                 vector_string, base_score, base_severity, scenario, is_current,
                 provider_org_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (cve_id, source, assessor, role, version, V31_VECTOR if version == "3.1"
             else V40_VECTOR if version == "4.0" else V30_VECTOR if version == "3.0"
             else V20_VECTOR, Decimal(score), "HIGH", scenario, current,
             provider_org_id),
        )


def _set_epss_state(conn, *, snapshot_id: Optional[str], healthy: bool = True,
                    last_success: Optional[datetime] = AS_OF - timedelta(hours=1),
                    success: bool = True) -> None:
    """Pin EPSS sync_state. ``snapshot_id`` sets the operational last-attempt
    pointer; the authoritative last-good pointer follows it by default (pass
    ``good_snapshot_id`` explicitly to diverge them, e.g. after a failure)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_state SET
                is_healthy = %s,
                last_successful_at = %s,
                last_snapshot_id = %s,
                last_good_snapshot_id = %s,
                last_error = %s,
                consecutive_failures = %s
            WHERE source = 'epss';
            """,
            (healthy, last_success,
             snapshot_id,
             snapshot_id,
             None if success else "boom",
             0 if success else 2),
        )


def _set_kev_state(conn, *, snapshot_id: Optional[str], healthy: bool = True,
                   last_success: Optional[datetime] = AS_OF - timedelta(hours=1),
                   success: bool = True) -> None:
    """Pin KEV sync_state. ``snapshot_id`` sets the operational last-attempt
    pointer; the authoritative last-good pointer follows it by default (pass
    ``good_snapshot_id`` explicitly to diverge them, e.g. after a failure)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_state SET
                is_healthy = %s,
                last_successful_at = %s,
                last_snapshot_id = %s,
                last_good_snapshot_id = %s,
                last_error = %s,
                consecutive_failures = %s
            WHERE source = 'kev';
            """,
            (healthy, last_success,
             snapshot_id,
             snapshot_id,
             None if success else "boom",
             0 if success else 2),
        )


def _epss_observation(conn, cve_id: str, snapshot_id: str, *, score: str = "0.12345",
                      score_date: str = "2026-09-16") -> str:
    """Create an epss_scores row whose source record belongs to snapshot_id."""
    rec, _ = upsert_source_record(conn, SourceRecord(
        source="epss", source_id=f"epss-{cve_id}-{score_date}-{snapshot_id}",
        raw_payload={"cve": cve_id, "epss": score}, snapshot_id=snapshot_id,
    ))
    ep = upsert_epss_score(conn, EpssScore(
        cve_id=cve_id, score=Decimal(score), percentile=Decimal("0.55555"),
        model_version="v2026.01.01", score_date=score_date,
        source_record_id=rec.id,
    ))
    return ep.id


def _kev_observation(conn, cve_id: str, snapshot_id: str, *,
                     ransomware: str = "Known") -> str:
    # KEV is enrichment: cve_id FK attaches only when the canonical row exists.
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM canonical_vulnerabilities WHERE cve_id = %s;", (cve_id,))
        canonical = cur.fetchone() is not None
    rec, _ = upsert_source_record(conn, SourceRecord(
        source="kev", source_id=f"kev-{cve_id}-{snapshot_id}",
        raw_payload={"cveID": cve_id}, snapshot_id=snapshot_id,
    ))
    kev = upsert_kev_entry(conn, KevEntry(
        cve_id=cve_id if canonical else None, declared_cve_id=cve_id,
        vendor_project="Vendor", product="Product", vulnerability_name="Vuln",
        date_added="2026-01-01", required_action="Patch",
        known_ransomware=ransomware, source_record_id=rec.id,
        is_active=True,
    ))
    return kev.id


def _failed_snapshot(conn, source: str) -> str:
    """Create a real FAILED snapshot row (exists in sync_snapshots, but is
    never the last successful generation)."""
    snap = create_sync_snapshot(conn, type("S", (), {
        "source": source, "sync_mode": "incremental", "status": "running",
        "cursor_before": None, "metadata": None,
    })())
    complete_sync_snapshot(conn, snap.id, status="failed", error_message="boom")
    conn.commit()
    return snap.id


def _fresh_snapshot(conn, source: str) -> str:
    """Create a real snapshot that exists but is NOT the last successful
    generation (never referenced from sync_state)."""
    snap = create_sync_snapshot(conn, type("S", (), {
        "source": source, "sync_mode": "incremental", "status": "running",
        "cursor_before": None, "metadata": None,
    })())
    complete_sync_snapshot(conn, snap.id, status="completed")
    conn.commit()
    return snap.id


_VULN_TABLE_CLEANUP_SQL = """
    DELETE FROM cve_weaknesses;
    DELETE FROM cve_references;
    DELETE FROM cve_relationships;
    DELETE FROM cve_adp_entries;
    DELETE FROM cve_affected;
    DELETE FROM osv_aliases;
    DELETE FROM osv_records;
    DELETE FROM epss_scores;
    DELETE FROM kev_entries;
    DELETE FROM cvss_assessments;
    DELETE FROM source_artifacts;
    DELETE FROM vuln_source_records;
    DELETE FROM canonical_vulnerabilities;
    UPDATE sync_state SET
        cursor_value = NULL, last_successful_at = NULL,
        last_attempted_at = NULL, last_error = NULL,
        last_snapshot_id = NULL, last_good_snapshot_id = NULL,
        last_sync_duration_ms = NULL, active_record_count = 0,
        consecutive_failures = 0, is_healthy = TRUE,
        sync_enabled = FALSE, next_sync_at = NULL;
    DELETE FROM sync_snapshots;
"""


@pytest.fixture(autouse=True)
def _clean_vuln_tables():
    """Reset vulnerability intelligence tables and sync state for isolation.
    Enrichment children are removed before the canonical spine so rows left
    by other suites' fixtures (which have no teardown) cannot block cleanup.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(_VULN_TABLE_CLEANUP_SQL)
    conn.commit()
    yield
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(_VULN_TABLE_CLEANUP_SQL)
    conn.commit()


# ===========================================================================
# CVSS AUTHORITY RESOLVER
# ===========================================================================


class TestCvssVersionPriorityMatrix:
    """Version wins before role: newest supported generation present wins."""

    def _only_version(self, conn, version: str, score: str):
        cve = f"CVE-2026-100{version.replace('.', '')}"
        _canon(conn, cve)
        _assess(conn, cve, role="cna", version=version, score=score, assessor="cna-a")
        conn.commit()
        res = resolve_cvss_authority(conn, cve)
        assert res.is_scoreable
        assert res.version == version
        assert res.score == Decimal(score)
        return res

    def test_40_wins(self):
        with get_db_connection() as conn:
            res = self._only_version(conn, "4.0", "9.3")

    def test_31_wins(self):
        with get_db_connection() as conn:
            self._only_version(conn, "3.1", "9.8")

    def test_30_wins(self):
        with get_db_connection() as conn:
            self._only_version(conn, "3.0", "9.0")

    def test_20_wins(self):
        with get_db_connection() as conn:
            self._only_version(conn, "2.0", "9.4")

    def test_full_matrix_ordering(self):
        """Each version beats every lower version regardless of role."""
        pairs = [
            (("4.0", "adp"), ("3.1", "cna")),
            (("4.0", "adp"), ("3.0", "cna")),
            (("4.0", "adp"), ("2.0", "cna")),
            (("3.1", "adp"), ("3.0", "cna")),
            (("3.1", "adp"), ("2.0", "cna")),
            (("3.0", "adp"), ("2.0", "cna")),
        ]
        for i, (high, low) in enumerate(pairs):
            with get_db_connection() as conn:
                cve = f"CVE-2026-200{i}"
                _canon(conn, cve)
                _assess(conn, cve, role=low[1], version=low[0], score="10.0", assessor="low")
                _assess(conn, cve, role=high[1], version=high[0], score="1.0", assessor="high")
                conn.commit()
                res = resolve_cvss_authority(conn, cve)
                assert res.version == high[0], pairs
                assert res.role == high[1], pairs
                assert res.score == Decimal("1.0"), pairs


class TestCvssRolePriorityMatrix:
    """Within the winning version, structural role CNA > NVD > ADP."""

    def _role_matrix(self, conn, version: str, cve: str):
        _canon(conn, cve)
        for role, score in (("adp", "3.0"), ("nvd", "5.0"), ("cna", "7.0")):
            _assess(conn, cve, role=role, version=version, score=score,
                    assessor=f"a-{role}", source="nvd" if role == "nvd" else "cve")
        conn.commit()

    def test_cna_beats_nvd_and_adp_31(self):
        with get_db_connection() as conn:
            self._role_matrix(conn, "3.1", "CVE-2026-3000")
            res = resolve_cvss_authority(conn, "CVE-2026-3000")
            assert res.role == "cna"
            assert res.score == Decimal("7.0")

    def test_cna_beats_nvd_and_adp_40(self):
        with get_db_connection() as conn:
            self._role_matrix(conn, "4.0", "CVE-2026-3001")
            res = resolve_cvss_authority(conn, "CVE-2026-3001")
            assert res.role == "cna"
            assert res.score == Decimal("7.0")

    def test_nvd_beats_adp(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-3002"
            _canon(conn, cve)
            _assess(conn, cve, role="adp", version="3.1", score="9.9", assessor="adp-a")
            _assess(conn, cve, role="nvd", version="3.1", score="4.0", assessor="nvd-a",
                    source="nvd")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert res.role == "nvd"
            assert res.score == Decimal("4.0")

    def test_adp_only_wins_when_alone(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-3003"
            _canon(conn, cve)
            _assess(conn, cve, role="adp", version="3.1", score="6.1", assessor="adp-a")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert res.role == "adp"
            assert res.score == Decimal("6.1")

    def test_40_adp_beats_31_cna(self):
        """The PRD's explicit example: version wins before role."""
        with get_db_connection() as conn:
            cve = "CVE-2026-3004"
            _canon(conn, cve)
            _assess(conn, cve, role="adp", version="4.0", score="8.2", assessor="cisa-adp")
            _assess(conn, cve, role="cna", version="3.1", score="9.8", assessor="vendor-cna")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert res.version == "4.0"
            assert res.role == "adp"
            assert res.score == Decimal("8.2")


class TestCvssAmbiguity:
    """More than one surviving winning row fails closed — no tie-break."""

    def test_single_winner_succeeds_with_provenance(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-3100"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="9.8",
                    assessor="vendor-cna", scenario="GENERAL",
                    provider_org_id="cna-org-uuid")
            _assess(conn, cve, role="nvd", version="3.1", score="9.1",
                    assessor="nvd@nist.gov", source="nvd")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert res.is_scoreable
            assert res.assessment_id is not None
            assert res.version == "3.1" and res.role == "cna"
            assert res.assessor == "vendor-cna"
            assert res.provider_org_id == "cna-org-uuid"
            assert res.scenario == "GENERAL"
            assert res.score == Decimal("9.8")
            assert res.severity == "HIGH"
            assert res.vector == V31_VECTOR
            assert res.source == "cve"
            assert res.source_record_id is None  # no source record in this fixture
            assert res.created_at is not None
            assert res.is_current is True

    def test_two_winners_across_assessors_ambiguous(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-3101"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="9.8", assessor="cna-one")
            _assess(conn, cve, role="cna", version="3.1", score="7.5", assessor="cna-two")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert not res.is_scoreable
            assert res.reason_code == CVSS_AUTHORITY_AMBIGUOUS
            assert res.score is None
            assert res.ambiguous_rows is not None and len(res.ambiguous_rows) == 2
            {row["assessor"] for row in res.ambiguous_rows} == {"cna-one", "cna-two"}

    def test_two_winners_across_scenarios_ambiguous(self):
        """Different scenarios legitimately create the tie; no GENERAL filter."""
        with get_db_connection() as conn:
            cve = "CVE-2026-3102"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="9.8",
                    assessor="same-cna", scenario="GENERAL")
            _assess(conn, cve, role="cna", version="3.1", score="6.5",
                    assessor="same-cna", scenario="SPECIALIZED")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert not res.is_scoreable
            assert res.reason_code == CVSS_AUTHORITY_AMBIGUOUS

    def test_ambiguity_does_not_fall_back(self):
        """Ambiguous winners must not fall back to the lower role/version."""
        with get_db_connection() as conn:
            cve = "CVE-2026-3103"
            _canon(conn, cve)
            # Two ambiguous 4.0 CNA winners plus a perfectly clean 3.1 CNA row.
            _assess(conn, cve, role="cna", version="4.0", score="8.0", assessor="a1")
            _assess(conn, cve, role="cna", version="4.0", score="8.5", assessor="a2")
            _assess(conn, cve, role="cna", version="3.1", score="9.8", assessor="clean")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert not res.is_scoreable
            assert res.reason_code == CVSS_AUTHORITY_AMBIGUOUS
            assert res.version == "4.0"  # the winning (ambiguous) generation

    def test_numerical_maximum_never_overrides_authority(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-3104"
            _canon(conn, cve)
            _assess(conn, cve, role="nvd", version="3.1", score="10.0",
                    assessor="nvd@nist.gov", source="nvd")
            _assess(conn, cve, role="cna", version="3.1", score="1.0", assessor="cna-a")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert res.role == "cna"
            assert res.score == Decimal("1.0")

    def test_inactive_rows_ignored(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-3105"
            _canon(conn, cve)
            # A superseded (is_current = FALSE) 4.0 row must not beat the
            # current 3.1 row.
            _assess(conn, cve, role="cna", version="4.0", score="9.9",
                    assessor="old-cna", current=False)
            _assess(conn, cve, role="cna", version="3.1", score="7.2", assessor="new-cna")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert res.version == "3.1"
            assert res.score == Decimal("7.2")

    def test_missing_structural_role_fails_closed(self):
        """No container_role → authority is never inferred from source strings."""
        with get_db_connection() as conn:
            cve = "CVE-2026-3106"
            _canon(conn, cve)
            _assess(conn, cve, role=None, version="3.1", score="9.8",
                    assessor="definitely-a-cna-string", source="cve")
            conn.commit()
            res = resolve_cvss_authority(conn, cve)
            assert not res.is_scoreable
            assert res.reason_code == CVSS_NO_AUTHORITATIVE_ASSESSMENT

    def test_missing_cve_reason_code(self):
        with get_db_connection() as conn:
            res = resolve_cvss_authority(conn, "CVE-9999-0001")
            assert not res.is_scoreable
            assert res.reason_code == CVSS_MISSING_CVE

    def test_missing_assessment_reason_code_is_distinct(self):
        with get_db_connection() as conn:
            _canon(conn, "CVE-2026-3107")
            res = resolve_cvss_authority(conn, "CVE-2026-3107")
            assert not res.is_scoreable
            assert res.reason_code == CVSS_NO_AUTHORITATIVE_ASSESSMENT
            assert res.reason_code != CVSS_MISSING_CVE


# ===========================================================================
# EPSS FRESHNESS RESOLVER
# ===========================================================================


class TestEpssFreshnessResolver:
    def _snapshot(self, conn) -> str:
        snap = create_sync_snapshot(conn, type("S", (), {
            "source": "epss", "sync_mode": "bootstrap", "status": "running",
            "cursor_before": None, "metadata": None,
        })())
        conn.commit()
        return snap.id

    def test_fresh_latest_good_match(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid)
            _epss_observation(conn, "CVE-2026-4000", sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4000", as_of=AS_OF)
            assert res.is_fresh
            assert res.reason_code is None
            assert res.score == Decimal("0.12345")
            assert res.percentile == Decimal("0.55555")
            assert res.model_version == "v2026.01.01"
            assert res.score_date is not None
            assert res.source_record_id is not None
            assert res.snapshot_id == sid
            prov = res.provenance
            assert prov.source == "epss"
            assert prov.is_healthy is True
            assert prov.last_successful_at is not None
            assert prov.last_snapshot_id == sid
            assert prov.freshness_age_seconds == pytest.approx(3600.0)

    def test_boundary_exactly_48h_is_fresh(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid,
                            last_success=AS_OF - FEED_FRESHNESS_WINDOW)
            _epss_observation(conn, "CVE-2026-4001", sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4001", as_of=AS_OF)
            assert res.is_fresh

    def test_boundary_48h_plus_one_second_is_stale(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid,
                            last_success=AS_OF - FEED_FRESHNESS_WINDOW - timedelta(seconds=1))
            _epss_observation(conn, "CVE-2026-4002", sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4002", as_of=AS_OF)
            assert not res.is_fresh
            assert res.reason_code == EPSS_STALE

    def test_unhealthy_is_unknown(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid, healthy=False)
            _epss_observation(conn, "CVE-2026-4003", sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4003", as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == EPSS_UNHEALTHY

    def test_missing_success_timestamp_is_unknown(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid, last_success=None)
            _epss_observation(conn, "CVE-2026-4004", sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4004", as_of=AS_OF)
            assert res.reason_code == EPSS_NEVER_IMPORTED

    def test_missing_snapshot_is_unknown(self):
        with get_db_connection() as conn:
            # A real snapshot exists but sync_state has no last-good pointer:
            # the resolver cannot establish fresh authoritative data.
            orphan = _fresh_snapshot(conn, "epss")
            _set_epss_state(conn, snapshot_id=None)
            _epss_observation(conn, "CVE-2026-4005", orphan)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4005", as_of=AS_OF)
            assert res.reason_code == EPSS_MISSING_SNAPSHOT

    def test_missing_sync_state_is_unknown(self):
        with get_db_connection() as conn:
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4006", as_of=AS_OF)
            # epss row is seeded by migrations; only absent if removed.
            assert res.reason_code in (EPSS_MISSING_SYNC_STATE, EPSS_NEVER_IMPORTED)

    def test_no_observation_is_unknown(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4007", as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == EPSS_NO_OBSERVATION

    def test_newer_failed_row_is_not_authoritative(self):
        """Required regression: the intact last-good observation must survive
        a newer failed snapshot's row. The failed generation's 0.99999 is
        filtered out BEFORE ordering; the resolver returns fresh 0.11111
        bound to the good snapshot. The operational last-attempt pointer may
        diverge from the last-good pointer; authority stays with last-good."""
        with get_db_connection() as conn:
            good_sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=good_sid)
            _epss_observation(conn, "CVE-2026-4008", good_sid, score="0.11111")
            # A newer row written during a failed snapshot; the sync engine
            # advances last_snapshot_id to the failed attempt but preserves
            # last_good_snapshot_id and marks the feed unhealthy.
            failed_sid = _failed_snapshot(conn, "epss")
            _epss_observation(conn, "CVE-2026-4008", failed_sid,
                              score="0.99999", score_date="2026-09-17")
            _set_epss_state(
                conn, snapshot_id=failed_sid, healthy=False, success=False,
                last_success=AS_OF - timedelta(hours=25),
            )
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE sync_state SET last_good_snapshot_id = %s
                    WHERE source = 'epss';
                    """,
                    (good_sid,),
                )
            conn.commit()

            # While unhealthy the retained last-good data is NOT fresh.
            unhealthy_res = resolve_epss_freshness(conn, "CVE-2026-4008", as_of=AS_OF)
            assert unhealthy_res.state == "unknown"
            assert unhealthy_res.reason_code == EPSS_UNHEALTHY

            # Recovery: health restored, pointers still diverged — the good
            # generation is authoritative and its intact observation wins.
            _set_epss_state(
                conn, snapshot_id=failed_sid, healthy=True,
                last_success=AS_OF - timedelta(minutes=1),
            )
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE sync_state SET last_good_snapshot_id = %s
                    WHERE source = 'epss';
                    """,
                    (good_sid,),
                )
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4008", as_of=AS_OF)
            assert res.is_fresh
            assert res.score == Decimal("0.11111")
            assert res.snapshot_id == good_sid
            assert res.provenance.last_good_snapshot_id == good_sid
            assert res.provenance.last_snapshot_id == failed_sid

    def test_no_observation_in_authoritative_generation_is_unknown(self):
        """A newer non-authoritative row existing does NOT by itself make the
        feed unknown via mismatch: no observation inside the last-good
        generation is epss_no_observation."""
        with get_db_connection() as conn:
            good_sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=good_sid)
            # An observation from an unrelated generation only.
            other_sid = _fresh_snapshot(conn, "epss")
            _epss_observation(conn, "CVE-2026-4009", other_sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4009", as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == EPSS_NO_OBSERVATION

    def test_no_ladder_value_assigned(self):
        """P0-04 owns the EPSS ladder; this resolver returns no rung value."""
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_epss_state(conn, snapshot_id=sid)
            _epss_observation(conn, "CVE-2026-4010", sid)
            conn.commit()
            res = resolve_epss_freshness(conn, "CVE-2026-4010", as_of=AS_OF)
            assert not hasattr(res, "rung_value")
            assert not hasattr(res, "ladder_value")


# ===========================================================================
# KEV TERNARY RESOLVER
# ===========================================================================


class TestKevTernaryResolver:
    def _snapshot(self, conn) -> str:
        snap = create_sync_snapshot(conn, type("S", (), {
            "source": "kev", "sync_mode": "bootstrap", "status": "running",
            "cursor_before": None, "metadata": None,
        })())
        conn.commit()
        return snap.id

    def test_listed(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid)
            _kev_observation(conn, "CVE-2026-5000", sid, ransomware="Known")
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5000", as_of=AS_OF)
            assert res.state == "listed"
            assert res.entry_id is not None
            assert res.declared_cve_id == "CVE-2026-5000"
            assert res.resolved_cve_id == "CVE-2026-5000"
            assert res.known_ransomware == "Known"
            assert res.date_added is not None
            assert res.source_record_id is not None
            assert res.snapshot_id == sid
            assert res.provenance.is_healthy is True
            assert res.provenance.last_successful_at is not None
            assert res.provenance.last_snapshot_id == sid
            assert res.provenance.freshness_age_seconds == pytest.approx(3600.0)

    def test_fresh_absence_is_not_listed(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid)
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5001", as_of=AS_OF)
            assert res.state == "not_listed"

    def test_stale_absence_is_unknown(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid,
                           last_success=AS_OF - FEED_FRESHNESS_WINDOW - timedelta(seconds=1))
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5002", as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == KEV_STALE

    def test_unhealthy_absence_is_unknown(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid, healthy=False)
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5003", as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == KEV_UNHEALTHY

    def test_missing_snapshot_is_unknown(self):
        with get_db_connection() as conn:
            _set_kev_state(conn, snapshot_id=None)
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5004", as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == KEV_MISSING_SNAPSHOT

    def test_never_imported_is_unknown(self):
        with get_db_connection() as conn:
            _set_kev_state(conn, snapshot_id=None, last_success=None)
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5005", as_of=AS_OF)
            assert res.reason_code == KEV_NEVER_IMPORTED

    def test_old_snapshot_entry_does_not_establish_listing(self):
        """Old-snapshot membership is not current-membership evidence: the
        newer successful generation omits the CVE, so the fresh feed's
        absence is a definitive not_listed (normal delist)."""
        with get_db_connection() as conn:
            old_sid = self._snapshot(conn)
            _kev_observation(conn, "CVE-2026-5006", old_sid)
            conn.commit()
            # Newer successful generation without this CVE (delisted upstream).
            new_sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=new_sid)
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5006", as_of=AS_OF)
            assert res.state == "not_listed"
            assert res.snapshot_id == new_sid

    def test_real_delist_via_reconciliation_is_not_listed(self):
        """Required regression: exercise the REAL sync savepoint path.

        A successful full-snapshot generation lists the CVE; a later
        successful sync of a full snapshot that omits it runs the real
        absence reconciliation (which marks the historical row inactive while
        retaining its old-generation source record) inside sync_source's
        savepoint/commit flow. The resolver must return not_listed — the
        retained old-generation row must not turn the fresh delist into
        unknown. (Nine survivor entries keep the delist below the 20%
        mass-withdrawal guard, as a real catalog would.)"""
        from app.vuln_intelligence.sync_engine import FetchResult, sync_source
        from app.vuln_intelligence.sync_adapters import KevSyncAdapter

        target = "CVE-2026-5010"
        survivors = [f"CVE-2026-50{i:02d}" for i in range(20, 29)]

        class _KevFullSnapshotAdapter:
            """Real KevSyncAdapter processing; only fetch is stubbed."""
            source_name = "kev"

            def __init__(self, cve_ids):
                self._records = [
                    {
                        "cveID": c,
                        "vendorProject": "Vendor",
                        "product": "Product",
                        "vulnerabilityName": "Vuln",
                        "dateAdded": "2026-01-01",
                        "requiredAction": "Patch",
                        "knownRansomwareCampaignUse": "Known",
                    }
                    for c in cve_ids
                ]

            def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                return FetchResult(
                    records=self._records,
                    cursor_after="batch-1",
                    is_bootstrap=cursor is None,
                    is_exhausted=True,
                    seen_ids=list(self._records and [r["cveID"] for r in self._records]),
                )

            def validate_batch(self, records):
                return KevSyncAdapter().validate_batch(records)

            def process_record(self, conn, record, snapshot_id):
                return KevSyncAdapter().process_record(conn, record, snapshot_id)

        with get_db_connection() as conn:
            # Generation 1 (real sync_source path): target listed.
            outcome1 = sync_source(conn, _KevFullSnapshotAdapter([target] + survivors))
            assert outcome1.success
            state1 = get_sync_state(conn, "kev")
            good_sid = state1.last_good_snapshot_id
            assert good_sid == outcome1.snapshot_id
            first = resolve_kev_status(conn, target, as_of=AS_OF)
            assert first.state == "listed"
            assert first.source_record_id is not None

        with get_db_connection() as conn:
            # Generation 2 (real sync_source path): full snapshot omits the
            # target -> reconciliation deactivates the historical row, which
            # retains its old-generation source record.
            outcome2 = sync_source(conn, _KevFullSnapshotAdapter(survivors))
            assert outcome2.success

            # Reconciliation really marked the historical entry inactive while
            # keeping its old-generation source record.
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT k.is_active, k.withdrawn_at, sr.snapshot_id
                    FROM kev_entries k
                    JOIN vuln_source_records sr ON sr.id = k.source_record_id
                    WHERE k.declared_cve_id = %s;
                    """,
                    (target,),
                )
                hist = cur.fetchone()
            assert hist is not None
            assert hist["is_active"] is False
            assert hist["withdrawn_at"] is not None
            assert str(hist["snapshot_id"]) == good_sid

            # Last-good advanced to the new generation; feed healthy.
            state2 = get_sync_state(conn, "kev")
            assert state2.last_good_snapshot_id == outcome2.snapshot_id
            assert state2.last_good_snapshot_id != good_sid
            assert state2.is_healthy is True

            # The fresh delist reads as not_listed — NOT unknown.
            res = resolve_kev_status(conn, target, as_of=AS_OF)
            assert res.state == "not_listed"
            assert res.snapshot_id == state2.last_good_snapshot_id
            assert res.provenance.last_good_snapshot_id == state2.last_good_snapshot_id

    def test_ransomware_provenance_retained(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid)
            _kev_observation(conn, "CVE-2026-5007", sid, ransomware="Unknown")
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5007", as_of=AS_OF)
            assert res.state == "listed"
            assert res.known_ransomware == "Unknown"

    def test_withdrawn_in_current_generation_is_not_listed(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid)
            entry_id = _kev_observation(conn, "CVE-2026-5008", sid)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE kev_entries SET is_active = FALSE, withdrawn_at = now() WHERE id = %s;",
                    (entry_id,),
                )
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5008", as_of=AS_OF)
            assert res.state == "not_listed"

    def test_no_ladder_value_assigned(self):
        with get_db_connection() as conn:
            sid = self._snapshot(conn)
            _set_kev_state(conn, snapshot_id=sid)
            _kev_observation(conn, "CVE-2026-5009", sid)
            conn.commit()
            res = resolve_kev_status(conn, "CVE-2026-5009", as_of=AS_OF)
            assert not hasattr(res, "rung_value")
            assert not hasattr(res, "ladder_value")


# ===========================================================================
# RACE / FAILURE EVIDENCE
# ===========================================================================


class TestCoherentGenerationRace:
    """Resolver reads one coherent committed generation while imports commit."""

    def test_resolver_import_coherence_repeatable_read(self):
        """A resolver inside REPEATABLE READ established BEFORE its first
        query never mixes generations with a commit that lands midway; a
        retry after the transaction ends sees the later committed generation."""
        cve = "CVE-2026-6000"

        # Baseline: one successful KEV generation listing the CVE.
        with get_db_connection() as conn:
            sid1 = create_sync_snapshot(conn, type("S", (), {
                "source": "kev", "sync_mode": "bootstrap", "status": "running",
                "cursor_before": None, "metadata": None,
            })())
            conn.commit()
            _set_kev_state(conn, snapshot_id=sid1.id)
            _kev_observation(conn, cve, sid1.id)
            conn.commit()
            before = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert before.state == "listed"
            assert before.snapshot_id == sid1.id

        # REPEATABLE READ established BEFORE the first resolver query — the
        # transaction snapshot pins generation sid1.
        with get_db_connection() as conn:
            conn.set_isolation_level(psycopg.IsolationLevel.REPEATABLE_READ)
            first = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert first.state == "listed"
            assert first.snapshot_id == sid1.id

            # A NEW successful generation (sid2) commits MIDWAY through the
            # open resolver transaction — the committed rows are not visible
            # to this snapshot.
            with get_db_connection() as other:
                sid2 = create_sync_snapshot(other, type("S", (), {
                    "source": "kev", "sync_mode": "incremental", "status": "running",
                    "cursor_before": None, "metadata": None,
                })())
                other.commit()
                _kev_observation(other, cve, sid2.id)
                complete_sync_snapshot(other, sid2.id, status="completed")
                update_sync_state(other, "kev", last_snapshot_id=sid2.id, success=True)
                other.commit()

            # The ongoing resolver read still uses ONE coherent committed
            # generation — the pre-commit one (sid1), never a mixture.
            second = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert second.state == "listed"
            assert second.snapshot_id == sid1.id
            conn.rollback()  # end the read-only RR transaction

        # A fresh resolver (retry) sees the later committed generation (sid2).
        with get_db_connection() as conn:
            after = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert after.state == "listed"
            assert after.snapshot_id == sid2.id


class TestFailedAndPartialImports:
    """Failed snapshots never become authoritative; retries stay idempotent."""

    def _bootstrap_good(self, conn, cve: str) -> str:
        snap = create_sync_snapshot(conn, type("S", (), {
            "source": "kev", "sync_mode": "bootstrap", "status": "running",
            "cursor_before": None, "metadata": None,
        })())
        conn.commit()
        _kev_observation(conn, cve, snap.id)
        complete_sync_snapshot(conn, snap.id, status="completed")
        update_sync_state(conn, "kev", last_snapshot_id=snap.id, success=True)
        conn.commit()
        return snap.id

    def test_failed_snapshot_rows_cannot_become_authoritative(self):
        """A failed import advances the operational last-attempt pointer but
        never last_good_snapshot_id; while unhealthy the feed is unknown even
        though the last-good generation and its data remain intact.

        The failure is driven through the REAL sync_source savepoint/rollback
        path: a record that raises mid-processing rolls the attempted row
        writes back to the savepoint, so no new source record survives, the
        failure metadata commits cleanly, and the prior last-good generation
        stays authoritative."""
        from app.vuln_intelligence.sync_engine import FetchResult, sync_source
        from app.vuln_intelligence.sync_adapters import KevSyncAdapter

        cve = "CVE-2026-6100"

        class _ExplodingKevAdapter:
            """Real KEV processing whose second record raises mid-write."""
            source_name = "kev"

            def __init__(self, records):
                self._records = records

            def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                return FetchResult(
                    records=self._records,
                    cursor_after="batch-1",
                    is_bootstrap=cursor is None,
                    is_exhausted=True,
                    seen_ids=[r["cveID"] for r in self._records],
                )

            def validate_batch(self, records):
                return KevSyncAdapter().validate_batch(records)

            def process_record(self, conn, record, snapshot_id):
                if record["cveID"] == cve:
                    raise RuntimeError("boom")
                return KevSyncAdapter().process_record(conn, record, snapshot_id)

        with get_db_connection() as conn:
            # Establish the last-good generation through the real engine.
            good_sid = self._bootstrap_good(conn, cve)

        with get_db_connection() as conn:
            # A failed import: the attempted record raises, sync_source rolls
            # back to the savepoint, records failure metadata, and commits.
            outcome = sync_source(conn, _ExplodingKevAdapter([
                {"cveID": cve},
                {"cveID": "CVE-2026-6199"},
            ]))
            assert not outcome.success
            failed_sid = outcome.snapshot_id

            # The engine's failure semantics: operational pointer advanced,
            # last-good preserved, unhealthy.
            state = get_sync_state(conn, "kev")
            assert state.last_snapshot_id == failed_sid
            assert state.last_good_snapshot_id == good_sid
            assert state.is_healthy is False
            assert failed_sid != good_sid

            # No row from the failed attempt survived the savepoint rollback.
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS n FROM vuln_source_records
                    WHERE source = 'kev' AND snapshot_id = %s;
                    """,
                    (failed_sid,),
                )
                assert cur.fetchone()["n"] == 0

            # Unhealthy: unknown, even though a last-good snapshot exists.
            res = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert res.state == "unknown"
            assert res.reason_code == KEV_UNHEALTHY

            # The last-good pointer and its data remain intact and distinct
            # from the operational last attempt.
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS n FROM kev_entries k
                    JOIN vuln_source_records sr ON sr.id = k.source_record_id
                    WHERE k.declared_cve_id = %s AND sr.snapshot_id = %s;
                    """,
                    (cve, good_sid),
                )
                assert cur.fetchone()["n"] == 1

        # Recovery: a successful retry restores health with diverged pointers
        # — the last-good generation re-advances and the CVE is listed again.
        class _RealKevAdapter:
            source_name = "kev"

            def __init__(self, records):
                self._records = records

            def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                return FetchResult(
                    records=self._records,
                    cursor_after="batch-2",
                    is_bootstrap=cursor is None,
                    is_exhausted=True,
                    seen_ids=[r["cveID"] for r in self._records],
                )

            def validate_batch(self, records):
                return KevSyncAdapter().validate_batch(records)

            def process_record(self, conn, record, snapshot_id):
                return KevSyncAdapter().process_record(conn, record, snapshot_id)

        with get_db_connection() as conn:
            outcome2 = sync_source(conn, _RealKevAdapter([
                {"cveID": cve},
                {"cveID": "CVE-2026-6199"},
            ]))
            assert outcome2.success
            state = get_sync_state(conn, "kev")
            assert state.is_healthy is True
            assert state.last_good_snapshot_id == outcome2.snapshot_id
            assert state.last_snapshot_id == outcome2.snapshot_id
            recovered = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert recovered.state == "listed"
            assert recovered.snapshot_id == outcome2.snapshot_id

    def test_partial_writes_cannot_advance_last_snapshot_id(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-6101"
            good_sid = self._bootstrap_good(conn, cve)
            state = get_sync_state(conn, "kev")
            assert state.last_snapshot_id == good_sid
            # Simulate partial writes: rows inserted for a snapshot whose
            # completion never happened — last_snapshot_id cannot move.
            partial_sid = create_sync_snapshot(conn, type("S", (), {
                "source": "kev", "sync_mode": "incremental", "status": "running",
                "cursor_before": None, "metadata": None,
            })())
            conn.commit()
            _kev_observation(conn, cve, partial_sid.id)
            conn.commit()
            # No complete_sync_snapshot / update_sync_state(success) here.
            state = get_sync_state(conn, "kev")
            assert state.last_snapshot_id == good_sid
            snap = get_sync_snapshot(conn, partial_sid.id)
            assert snap.status == "running"

    def test_retry_does_not_create_second_current_generation(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-6102"
            snap = create_sync_snapshot(conn, type("S", (), {
                "source": "kev", "sync_mode": "bootstrap", "status": "running",
                "cursor_before": None, "metadata": None,
            })())
            conn.commit()
            # First import of the same snapshot content.
            _kev_observation(conn, cve, snap.id)
            complete_sync_snapshot(conn, snap.id, status="completed")
            update_sync_state(conn, "kev", last_snapshot_id=snap.id, success=True)
            conn.commit()

            # Retry of the SAME snapshot/import: content-addressed dedup means
            # no new revision rows and the state points at the SAME snapshot.
            _kev_observation(conn, cve, snap.id)
            complete_sync_snapshot(conn, snap.id, status="completed")
            update_sync_state(conn, "kev", last_snapshot_id=snap.id, success=True)
            conn.commit()

            state = get_sync_state(conn, "kev")
            assert state.last_snapshot_id == snap.id
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM sync_snapshots WHERE source = 'kev';"
                )
                assert cur.fetchone()["n"] == 1
                cur.execute(
                    """
                    SELECT COUNT(*) AS n FROM vuln_source_records
                    WHERE source = 'kev';
                    """
                )
                assert cur.fetchone()["n"] == 1  # one logical record, not two

            # Provenance uncorrupted: the entry still traces to the snapshot.
            res = resolve_kev_status(conn, cve, as_of=AS_OF)
            assert res.state == "listed"
            assert res.snapshot_id == snap.id


# ===========================================================================
# MIGRATION 018 — GENERATION-AWARE INDEX
# ===========================================================================


class TestMigration018Index:
    @pytest.fixture(autouse=True)
    def _reapply_migration_018(self):
        """Idempotently re-apply migration 018 before each index test.

        Other suites in this repository replay migrations 007-012 directly
        (idempotency gates). Migration 012's ``CREATE INDEX IF NOT EXISTS
        idx_cvss_tes_lookup`` resurrects the superseded 3.1-pinned index in
        that scenario. In production ordering 018 always runs after 012, so
        the same idempotent re-application here keeps these tests truthful
        regardless of which suites ran earlier in the session."""
        from pathlib import Path

        sql_path = (
            Path(__file__).resolve().parent.parent
            / "migrations" / "018_cve_intelligence_resolvers.sql"
        )
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql_path.read_text(encoding="utf-8"))
            conn.commit()
        yield

    def test_index_exists_and_012_index_superseded(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT indexname, indexdef FROM pg_indexes
                    WHERE tablename = 'cvss_assessments'
                      AND indexname IN ('idx_cvss_authority_lookup', 'idx_cvss_tes_lookup');
                    """
                )
                rows = {r["indexname"]: r["indexdef"] for r in cur.fetchall()}
            assert "idx_cvss_authority_lookup" in rows
            assert "idx_cvss_tes_lookup" not in rows  # 012 index superseded
            assert "is_current = true" in rows["idx_cvss_authority_lookup"]
            assert "3.1" not in rows["idx_cvss_authority_lookup"]  # no version pin

    @pytest.fixture()
    def bulk_cvss_catalog(self):
        """Seed a realistically-sized CVSS catalog so the planner's natural
        cost model — with NO enable_* GUC touched anywhere — chooses an index
        for the resolver lookup. On a near-empty table a sequential scan is
        genuinely cheaper, so the representative plan is taken at a catalog
        shape comparable to production: many CVEs, several current versions
        per CVE, plus retired history that the partial index skips."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Idempotent pre-clean of leftovers from any aborted run.
                cur.execute(
                    "DELETE FROM cvss_assessments WHERE cve_id LIKE %s;",
                    (BULK_CVE_PREFIX + "%",),
                )
                cur.execute(
                    "DELETE FROM canonical_vulnerabilities WHERE cve_id LIKE %s;",
                    (BULK_CVE_PREFIX + "%",),
                )
                cur.execute(
                    """
                    INSERT INTO canonical_vulnerabilities
                        (cve_id, state, assigner_org_id, assigner_short_name)
                    SELECT %s || lpad(g::text, 6, '0'), 'PUBLISHED',
                           'bulk-org', 'bulk'
                    FROM generate_series(1, 1200) g
                    ON CONFLICT (cve_id) DO NOTHING;
                    """,
                    (BULK_CVE_PREFIX,),
                )
                cur.execute(
                    """
                    INSERT INTO cvss_assessments
                        (cve_id, source, assessor, container_role, cvss_version,
                         vector_string, base_score, base_severity, scenario,
                         is_current)
                    SELECT %s || lpad(g::text, 6, '0'),
                           'cve',
                           'bulk-' || (ARRAY['cna', 'nvd', 'adp'])[1 + g %% 3],
                           (ARRAY['cna', 'nvd', 'adp'])[1 + g %% 3],
                           (ARRAY['4.0', '3.1', '3.0'])[1 + g %% 3],
                           CASE (ARRAY['4.0', '3.1', '3.0'])[1 + g %% 3]
                               WHEN '4.0' THEN %s
                               WHEN '3.1' THEN %s
                               ELSE %s
                           END,
                           5.0, 'HIGH', 'GENERAL', TRUE
                    FROM generate_series(1, 1200) g;
                    """,
                    (BULK_CVE_PREFIX, V40_VECTOR, V31_VECTOR, V30_VECTOR),
                )
                # Retired history: rows the partial index skips entirely.
                cur.execute(
                    """
                    INSERT INTO cvss_assessments
                        (cve_id, source, assessor, container_role, cvss_version,
                         vector_string, base_score, base_severity, scenario,
                         is_current)
                    SELECT %s || lpad(g::text, 6, '0'), 'nvd', 'bulk-retired',
                           'nvd', '3.1', %s, 7.5, 'HIGH', 'GENERAL', FALSE
                    FROM generate_series(1, 1200) g;
                    """,
                    (BULK_CVE_PREFIX, V31_VECTOR),
                )
                cur.execute("ANALYZE cvss_assessments;")
            conn.commit()
        yield
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM cvss_assessments WHERE cve_id LIKE %s;",
                    (BULK_CVE_PREFIX + "%",),
                )
                cur.execute(
                    "DELETE FROM canonical_vulnerabilities WHERE cve_id LIKE %s;",
                    (BULK_CVE_PREFIX + "%",),
                )
                cur.execute("ANALYZE cvss_assessments;")
            conn.commit()

    @pytest.mark.parametrize("version", ["4.0", "3.1", "3.0", "2.0"])
    def test_resolver_lookup_can_use_index_for_every_version(
        self, version, bulk_cvss_catalog
    ):
        """EXPLAIN evidence: the resolver's lookup shape uses
        idx_cvss_authority_lookup for each supported version.

        The plan is taken with default planner settings against a catalog of
        realistic size (see bulk_cvss_catalog) — no enable_seqscan or other
        GUC is forced, so this is the same plan production takes."""
        with get_db_connection() as conn:
            cve = BULK_CVE_PREFIX + "000500"
            _canon(conn, cve)  # idempotent upsert onto the bulk catalog
            # Ensure a current row exists for the probed version so the
            # lookup is non-empty for every supported version (2.0 included).
            _assess(
                conn, cve, role="cna", version=version, score="5.0",
                assessor=f"bulk-probe-{version}",
            )
            conn.commit()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    EXPLAIN SELECT * FROM cvss_assessments
                    WHERE cve_id = %s AND cvss_version = %s
                      AND is_current = TRUE;
                    """,
                    (cve, version),
                )
                plan = "\n".join(r["QUERY PLAN"] for r in cur.fetchall())
        assert "idx_cvss_authority_lookup" in plan, plan

    def test_existing_rows_preserved(self):
        """Migration 018 adds no columns and rewrites no provenance."""
        with get_db_connection() as conn:
            cve = "CVE-2026-7100"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="9.8", assessor="keeper")
            conn.commit()
            with get_db_connection() as conn2:
                with conn2.cursor() as cur:
                    cur.execute(
                        "SELECT id, cve_id, assessor, container_role, base_score "
                        "FROM cvss_assessments WHERE cve_id = %s;",
                        (cve,),
                    )
                    row = cur.fetchone()
            assert row["assessor"] == "keeper"
            assert row["container_role"] == "cna"
            assert row["base_score"] == Decimal("9.8")


# ===========================================================================
# CATALOG / API — NO FALSE TES NAMING
# ===========================================================================


class TestNoFalseTesNaming:
    """No catalog field or API response may call CVE-level CVSS 'TES'."""

    def test_detail_has_no_tes_fields_and_exposes_authority_provenance(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-8000"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="9.8", assessor="vendor")
            conn.commit()
            detail = get_composed_cve_detail(conn, cve)
            assert detail is not None
            for forbidden in ("tes_score", "tes_severity", "tes_resolution"):
                assert forbidden not in detail
            auth = detail["cvss_authority"]
            assert auth["is_scoreable"] is True
            assert auth["version"] == "3.1"
            assert auth["role"] == "cna"
            assert auth["assessor"] == "vendor"
            assert auth["score"] == 9.8
            assert auth["severity"] == "HIGH"
            assert auth["vector"] == V31_VECTOR
            assert auth["source"] == "cve"
            assert auth["assessment_id"] is not None
            assert auth["created_at"] is not None
            assert auth["is_current"] is True

    def test_list_and_detail_agree(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-8001"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="7.5", assessor="vendor")
            conn.commit()
            listing = search_vulnerabilities(conn, q=cve)
            assert listing["total"] >= 1
            item = next(i for i in listing["items"] if i["cve_id"] == cve)
            assert "tes_score" not in item
            assert "tes_severity" not in item
            assert item["cvss_score"] == 7.5
            assert item["cvss_severity"] == "HIGH"
            detail = get_composed_cve_detail(conn, cve)
            assert detail["cvss_authority"]["score"] == item["cvss_score"]
            assert detail["cvss_authority"]["severity"] == item["cvss_severity"]
            assert detail["cvss_authority"]["role"] == item["cvss_role"]

    def test_list_surfaces_ambiguity_without_tes_fields(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-8002"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="9.8", assessor="a1")
            _assess(conn, cve, role="cna", version="3.1", score="7.5", assessor="a2")
            conn.commit()
            listing = search_vulnerabilities(conn, q=cve)
            item = next(i for i in listing["items"] if i["cve_id"] == cve)
            assert item["is_scoreable"] is False
            assert item["cvss_reason_code"] == CVSS_AUTHORITY_AMBIGUOUS
            assert item["cvss_score"] is None
            assert "tes_score" not in item

    def test_min_max_cvss_filters_use_authority_resolution(self):
        with get_db_connection() as conn:
            cve = "CVE-2026-8003"
            _canon(conn, cve)
            _assess(conn, cve, role="cna", version="3.1", score="7.5", assessor="vendor")
            conn.commit()
            inside = search_vulnerabilities(conn, q=cve, min_cvss=7.0, max_cvss=8.0)
            assert any(i["cve_id"] == cve for i in inside["items"])
            outside = search_vulnerabilities(conn, q=cve, min_cvss=8.0)
            assert not any(i["cve_id"] == cve for i in outside["items"])
