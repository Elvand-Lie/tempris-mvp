# backend/tests/test_044_cvss_scenario_digest_index.py
"""CVE-INTEL-01 — migration 044 bounds the idx_cvss_current_assessment key.

The unique partial index on cvss_assessments previously keyed
COALESCE(scenario, '') directly. A real scenario TEXT exceeding the B-tree
~2704-byte per-entry cap made any such current-row insert fail at the index.
Migration 044 rewrites the expression as a fixed-size raw SHA-256 BYTEA digest
(32 bytes) of the same COALESCE'd value; the full scenario TEXT stays stored
and untruncated.

Covers:
  - the index exists with the digest expression and is_current partial
  - a >3KB scenario inserts as a current row without index-row-size failure
  - a duplicate exact scenario is refused (unique violation)
  - a distinct scenario for the same (cve, assessor, version) is accepted
  - NULL and '' scenario still collide on the same key (COALESCE semantics)
  - repository.upsert_cvss_assessment revision behavior with a >3KB scenario:
    same-key re-upsert retires the previous current row and stores the full
    new scenario text untruncated
"""
import uuid

import pytest
from psycopg.errors import UniqueViolation

from app.db import get_db_connection
from app.vuln_intelligence.repository import resolve_cvss_authority, upsert_cvss_assessment
from app.vuln_intelligence.models import CVSS_NO_AUTHORITATIVE_ASSESSMENT, CvssAssessment
from tests.test_p05_cve_tes_read_model import make_cve_episode, read_tes, seed_cve_intel
from decimal import Decimal

@pytest.fixture()
def test_cve():
    # cve_id CHECK pattern: ^CVE-\d{4}-\d{4,}$
    cve_id = "CVE-2026-" + str(900000 + int(uuid.uuid4().hex[:6], 16) % 99999)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO canonical_vulnerabilities
                    (cve_id, state, assigner_org_id, assigner_short_name)
                VALUES (%s, 'PUBLISHED', 'test-org', 'test')
                ON CONFLICT (cve_id) DO NOTHING;
                """,
                (cve_id,),
            )
        conn.commit()
    yield cve_id
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM cvss_assessments WHERE cve_id = %s;", (cve_id,))
            cur.execute("DELETE FROM canonical_vulnerabilities WHERE cve_id = %s;", (cve_id,))
        conn.commit()


def _big_scenario(seed: str, size: int = 4096) -> str:
    return f"{seed}-" + ("x" * size)


class TestMigration044ScenarioDigestIndex:
    def test_index_keys_digest_expression_and_is_current(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT indexdef FROM pg_indexes
                    WHERE indexname = 'idx_cvss_current_assessment';
                    """
                )
                row = cur.fetchone()
        assert row is not None
        indexdef = row["indexdef"]
        assert "digest" in indexdef
        assert "'sha256'" in indexdef
        assert "is_current" in indexdef

    def test_large_scenario_insert_accepted_duplicate_refused_distinct_accepted(self, test_cve):
        scenario = _big_scenario("a")
        base = dict(
            source="cve",
            assessor="test-assessor",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=Decimal("7.5"),
            base_severity="HIGH",
        )
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cvss_assessments
                        (cve_id, source, assessor, cvss_version, vector_string,
                         base_score, base_severity, scenario, is_current)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE);
                    """,
                    (test_cve, base["source"], base["assessor"], base["cvss_version"],
                     base["vector_string"], base["base_score"], base["base_severity"], scenario),
                )
            conn.commit()

        # Same key + exact same >3KB scenario -> unique violation at execute.
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(UniqueViolation):
                    cur.execute(
                        """
                        INSERT INTO cvss_assessments
                            (cve_id, source, assessor, cvss_version, vector_string,
                             base_score, base_severity, scenario, is_current)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE);
                        """,
                        (test_cve, base["source"], base["assessor"], base["cvss_version"],
                         base["vector_string"], base["base_score"], base["base_severity"], scenario),
                    )
            conn.rollback()

        # Distinct scenario for the same key is accepted.
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cvss_assessments
                        (cve_id, source, assessor, cvss_version, vector_string,
                         base_score, base_severity, scenario, is_current)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE);
                    """,
                    (test_cve, base["source"], base["assessor"], base["cvss_version"],
                     base["vector_string"], base["base_score"], base["base_severity"],
                     _big_scenario("b")),
                )
            conn.commit()

    def test_null_and_empty_scenario_still_collide(self, test_cve):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cvss_assessments
                        (cve_id, source, assessor, cvss_version, vector_string,
                         base_score, base_severity, scenario, is_current)
                    VALUES (%s, 'cve', 'null-assessor', '3.1',
                            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                            7.5, 'HIGH', NULL, TRUE);
                    """,
                    (test_cve,),
                )
                with pytest.raises(UniqueViolation):
                    cur.execute(
                        """
                        INSERT INTO cvss_assessments
                            (cve_id, source, assessor, cvss_version, vector_string,
                             base_score, base_severity, scenario, is_current)
                        VALUES (%s, 'cve', 'null-assessor', '3.1',
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                7.5, 'HIGH', '', TRUE);
                        """,
                        (test_cve,),
                    )
            conn.rollback()

    def test_upsert_revision_behavior_with_large_scenario(self, test_cve):
        scenario = _big_scenario("upsert")
        first = CvssAssessment(
            cve_id=test_cve,
            source="cve",
            assessor="upsert-assessor",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=Decimal("7.5"),
            base_severity="HIGH",
            scenario=scenario,
        )
        with get_db_connection() as conn:
            upsert_cvss_assessment(conn, first)
            conn.commit()

        second = CvssAssessment(
            cve_id=test_cve,
            source="cve",
            assessor="upsert-assessor",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/PR:L/UI:L/S:U/C:L/I:L/A:L",
            base_score=Decimal("4.3"),
            base_severity="MEDIUM",
            scenario=scenario,
        )
        with get_db_connection() as conn:
            upsert_cvss_assessment(conn, second)
            conn.commit()

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scenario, base_severity, is_current
                    FROM cvss_assessments
                    WHERE cve_id = %s AND assessor = 'upsert-assessor'
                    ORDER BY created_at;
                    """,
                    (test_cve,),
                )
                rows = cur.fetchall()
        assert len(rows) == 2
        assert [r["is_current"] for r in rows] == [False, True]
        # Full >3KB scenario text is stored untruncated on both revisions.
        assert rows[0]["scenario"] == scenario
        assert rows[1]["scenario"] == scenario
        assert len(rows[1]["scenario"]) > 4096
        assert rows[1]["base_severity"] == "MEDIUM"

    def test_resolver_yields_no_authoritative_then_recovers_after_large_scenario_upsert(
        self, test_cve
    ):
        """Acceptance: the unmodified resolver read path fails closed with
        cvss_no_authoritative_assessment while no current assessment exists,
        and a >3KB-scenario upsert through the real repository path (which the
        fixed index now permits) makes the same CVE resolve — proving the
        defect was the index key bound, not resolver/TES logic."""
        with get_db_connection() as conn:
            res = resolve_cvss_authority(conn, test_cve)
            assert res.reason_code == CVSS_NO_AUTHORITATIVE_ASSESSMENT

        assessment = CvssAssessment(
            cve_id=test_cve,
            source="cve",
            assessor="acceptance-assessor",
            container_role="cna",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=Decimal("6.5"),
            base_severity="MEDIUM",
            scenario=_big_scenario("acceptance"),
        )
        with get_db_connection() as conn:
            upsert_cvss_assessment(conn, assessment)
            conn.commit()

        with get_db_connection() as conn:
            res = resolve_cvss_authority(conn, test_cve)
            assert res.reason_code is None
            assert res.assessment_id == assessment.id
            assert res.version == "3.1"

    def test_same_exposure_tes_read_transitions_when_large_scenario_cvss_arrives(self):
        """The unmodified TES/SPECTRUM read model shows
        cvss_no_authoritative_assessment for an exposure, and the SAME
        exposure read flips to scoreable once a >3KB-scenario CNA assessment
        arrives through the real upsert path (which the fixed index permits).
        No TES/read-model code change is involved."""
        cve = "CVE-2026-" + str(900000 + int(uuid.uuid4().hex[:6], 16) % 99999)
        seed_cve_intel(cve, cvss_present=False, epss_present=False, kev_listed=False)
        exposure_id, _, _ = make_cve_episode(cve)

        before = read_tes(exposure_id)
        assert (
            before["source_view"]["cvss_unscoreable_reason_code"]
            == CVSS_NO_AUTHORITATIVE_ASSESSMENT
        )

        assessment = CvssAssessment(
            cve_id=cve,
            source="cve",
            assessor="cna-a",
            container_role="cna",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=Decimal("6.5"),
            base_severity="MEDIUM",
            scenario=_big_scenario("transition"),
        )
        with get_db_connection() as conn:
            upsert_cvss_assessment(conn, assessment)
            conn.commit()

        after = read_tes(exposure_id)
        assert after["source_view"]["cvss_unscoreable_reason_code"] is None
        assert after["state"] != "UNSCOREABLE"
        assert after["source_view"]["cvss_assessment_id"] == assessment.id
