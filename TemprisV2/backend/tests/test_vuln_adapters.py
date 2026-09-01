# backend/tests/test_vuln_adapters.py
"""
Contract tests for Sprint 02 — Public-Source Adapters.

Tests cover:
  - CVE adapter: envelope validation, CNA parsing, ADP/SSVC extraction,
    affected/metrics/references/weaknesses, replacement relationships,
    content-addressed dedup, revision handling, malformed rejection
  - NVD adapter: multi-CVSS extraction, weakness mapping, CPE configurations,
    references, assessor authorship from source field
  - KEV adapter: all native fields preserved, exact CVE association,
    idempotent upsert
  - EPSS adapter: FIRST bulk CSV metadata/header parsing, dated history,
    multi-day imports, dedup
  - OSV adapter: native identity, alias/related/upstream separation,
    exact CVE-* alias linking, withdrawn state, no-CVE records
  - TES resolver: exact CNA match (no substring), exact NVD match,
    fail-closed on ambiguity, version exclusion
  - Sprint 01 review corrections: FK enforcement, fixture envelope validation,
    affected-data idempotency

All tests run offline against checked-in fixtures and local PostgreSQL 17.
No network calls.
"""
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    CanonicalVulnerability,
    CvssAssessment,
    CveAffected,
    EpssScore,
    SourceRecord,
    SyncSnapshot,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    get_canonical_vulnerability,
    get_cvss_assessments,
    get_cve_affected,
    get_cve_references,
    get_cve_relationships,
    get_cve_weaknesses,
    get_adp_entries,
    get_epss_scores,
    get_kev_entry,
    get_osv_record,
    get_osv_aliases,
    get_osv_records_by_cve,
    get_current_source_record,
    get_source_record_revisions,
    resolve_tes_cvss,
    create_sync_snapshot,
    upsert_canonical_vulnerability,
    upsert_cvss_assessment,
    upsert_source_record,
)
from app.vuln_intelligence.adapters.cve_adapter import process_cve_record
from app.vuln_intelligence.adapters.nvd_adapter import process_nvd_response, process_nvd_cve
from app.vuln_intelligence.adapters.kev_adapter import process_kev_catalog, process_kev_entry
from app.vuln_intelligence.adapters.epss_adapter import process_epss_csv
from app.vuln_intelligence.adapters.osv_adapter import process_osv_record


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "vuln_intelligence"


def load_json(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_text(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def clean_vuln_tables():
    """Truncate all vuln intelligence tables before each test."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE sync_state SET
                    cursor_value = NULL,
                    last_successful_at = NULL,
                    last_attempted_at = NULL,
                    last_error = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    consecutive_failures = 0,
                    is_healthy = TRUE;
                DELETE FROM cve_weaknesses;
                DELETE FROM cve_references;
                DELETE FROM osv_aliases;
                DELETE FROM osv_records;
                DELETE FROM cve_adp_entries;
                DELETE FROM cve_affected;
                DELETE FROM cve_relationships;
                DELETE FROM cvss_assessments;
                DELETE FROM kev_entries;
                DELETE FROM epss_scores;
                DELETE FROM source_artifacts;
                DELETE FROM vuln_source_records;
                DELETE FROM canonical_vulnerabilities;
                DELETE FROM sync_snapshots;
                INSERT INTO sync_state (source) VALUES
                    ('cve'), ('nvd'), ('kev'), ('epss'), ('osv')
                ON CONFLICT (source) DO UPDATE SET
                    cursor_value = NULL,
                    last_successful_at = NULL,
                    last_attempted_at = NULL,
                    last_error = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    consecutive_failures = 0,
                    is_healthy = TRUE;
            """)
        conn.commit()
    yield


# ===========================================================================
# CVE ADAPTER TESTS
# ===========================================================================

class TestCveAdapter:
    """CVE/cvelistV5 adapter parsing and storage."""

    def test_published_cve_full_extraction(self):
        """Full CVE JSON 5.x envelope is parsed: metadata, CNA, ADP/SSVC."""
        fixture = load_json("cve_published.json")
        with get_db_connection() as conn:
            result = process_cve_record(conn, fixture)
            conn.commit()

        assert result.error is None
        assert result.cve_id == "CVE-2024-1234"
        assert result.is_new_revision is True

        with get_db_connection() as conn:
            # Canonical vulnerability
            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None
            assert vuln.state == "PUBLISHED"
            assert vuln.assigner_org_id == "f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0"
            assert vuln.assigner_short_name == "example-cna"

            # Source record with raw payload
            src = get_current_source_record(conn, "cve", "CVE-2024-1234")
            assert src is not None
            assert src.raw_payload["dataType"] == "CVE_RECORD"
            assert src.raw_payload["dataVersion"] == "5.1"

            # CVSS assessment from CNA
            assessments = get_cvss_assessments(conn, "CVE-2024-1234")
            cna_31 = [a for a in assessments if a.source == "cve" and a.cvss_version == "3.1"]
            assert len(cna_31) == 1
            assert cna_31[0].base_score == Decimal("9.8")
            assert cna_31[0].assessor == "example-cna"
            assert cna_31[0].assessment_type == "cna"
            assert cna_31[0].scenario == "GENERAL"

            # Affected products
            affected = get_cve_affected(conn, "CVE-2024-1234")
            assert len(affected) == 1
            assert affected[0].vendor == "Example Corp"
            assert affected[0].product == "Example Product"
            assert affected[0].default_status == "unaffected"

            # References
            refs = get_cve_references(conn, "CVE-2024-1234")
            assert len(refs) == 1
            assert "example.com" in refs[0]["url"]

            # Weaknesses
            cwes = get_cve_weaknesses(conn, "CVE-2024-1234")
            assert len(cwes) == 1
            assert cwes[0]["cwe_id"] == "CWE-89"

            # ADP / SSVC
            adps = get_adp_entries(conn, "CVE-2024-1234")
            assert len(adps) == 1
            assert adps[0].provider_short_name == "CISA-ADP"
            assert adps[0].provider_org_id == "134c704f-9b21-4f2e-91b3-4a467353bcc0"
            assert adps[0].ssvc_data is not None
            assert adps[0].ssvc_data["role"] == "CISA Coordinator"

    def test_cve_envelope_validation(self):
        """Records without dataType=CVE_RECORD are rejected."""
        bad_record = {"dataType": "NOT_CVE", "cveMetadata": {"cveId": "CVE-2024-1234"}}
        with get_db_connection() as conn:
            result = process_cve_record(conn, bad_record)
        assert result.error is not None
        assert "CVE_RECORD" in result.error

    def test_reserved_cve(self):
        """RESERVED CVE has no containers, just metadata."""
        fixture = load_json("cve_reserved.json")
        with get_db_connection() as conn:
            result = process_cve_record(conn, fixture)
            conn.commit()

        assert result.error is None
        assert result.cve_id == "CVE-2024-9999"
        with get_db_connection() as conn:
            vuln = get_canonical_vulnerability(conn, "CVE-2024-9999")
            assert vuln.state == "RESERVED"
            assert vuln.date_published is None

    def test_rejected_cve_with_replacement(self):
        """REJECTED CVE stores replacedBy relationships."""
        fixture = load_json("cve_rejected.json")
        with get_db_connection() as conn:
            result = process_cve_record(conn, fixture)
            conn.commit()

        assert result.error is None
        with get_db_connection() as conn:
            vuln = get_canonical_vulnerability(conn, "CVE-2023-0001")
            assert vuln.state == "REJECTED"
            rels = get_cve_relationships(conn, "CVE-2023-0001")
            assert len(rels) == 1
            assert rels[0].related_cve_id == "CVE-2023-0002"
            assert rels[0].relationship_type == "replaced_by"

    def test_multi_cvss_versions_preserved(self):
        """CVE with CVSS 3.1 and 4.0 — both preserved, no conversion."""
        fixture = load_json("cve_multi_cvss.json")
        with get_db_connection() as conn:
            result = process_cve_record(conn, fixture)
            conn.commit()

        assert result.error is None
        with get_db_connection() as conn:
            assessments = get_cvss_assessments(conn, "CVE-2024-5678")
            versions = {a.cvss_version for a in assessments}
            assert versions == {"3.1", "4.0"}
            for a in assessments:
                if a.cvss_version == "3.1":
                    assert a.base_score == Decimal("7.5")
                elif a.cvss_version == "4.0":
                    assert a.base_score == Decimal("8.3")

    def test_malformed_cve_rejected(self):
        """Malformed CVE ID rejected by adapter."""
        fixture = load_json("cve_malformed.json")
        with get_db_connection() as conn:
            result = process_cve_record(conn, fixture)
        assert result.error is not None
        assert "Invalid CVE ID" in result.error

    def test_content_dedup_same_record_twice(self):
        """Importing identical CVE record twice → no new revision."""
        fixture = load_json("cve_published.json")
        with get_db_connection() as conn:
            r1 = process_cve_record(conn, fixture)
            conn.commit()
            r2 = process_cve_record(conn, fixture)
            conn.commit()

        assert r1.is_new_revision is True
        assert r2.is_new_revision is False

        with get_db_connection() as conn:
            revisions = get_source_record_revisions(conn, "cve", "CVE-2024-1234")
            assert len(revisions) == 1

    def test_updated_record_creates_revision(self):
        """Changed content creates new revision, moves current pointer."""
        v1 = load_json("cve_published.json")
        v2 = load_json("cve_published_updated.json")
        with get_db_connection() as conn:
            r1 = process_cve_record(conn, v1)
            conn.commit()
            r2 = process_cve_record(conn, v2)
            conn.commit()

        assert r1.is_new_revision is True
        assert r2.is_new_revision is True

        with get_db_connection() as conn:
            revisions = get_source_record_revisions(conn, "cve", "CVE-2024-1234")
            assert len(revisions) == 2
            assert revisions[0].is_current is True  # newest
            assert revisions[1].is_current is False  # prior

    def test_affected_data_idempotent_revision(self):
        """Correction 3: affected-data activation retires prior current rows."""
        v1 = load_json("cve_published.json")
        v2 = load_json("cve_published_updated.json")
        with get_db_connection() as conn:
            process_cve_record(conn, v1)
            conn.commit()

            aff_v1 = get_cve_affected(conn, "CVE-2024-1234")
            assert len(aff_v1) == 1

            process_cve_record(conn, v2)
            conn.commit()

            # Current affected should reflect v2 (updated product data)
            aff_v2 = get_cve_affected(conn, "CVE-2024-1234", current_only=True)
            assert len(aff_v2) == 1  # Still one product entry
            # Historical affected also traceable
            aff_all = get_cve_affected(conn, "CVE-2024-1234", current_only=False)
            assert len(aff_all) == 2  # v1 retired + v2 current

    def test_snapshot_id_linked_to_source_records(self):
        """Correction 2: source records link to sync_snapshots via FK."""
        fixture = load_json("cve_published.json")
        with get_db_connection() as conn:
            snap = create_sync_snapshot(conn, SyncSnapshot(
                source="cve", sync_mode="bootstrap"))
            conn.commit()

            result = process_cve_record(conn, fixture, snapshot_id=snap.id)
            conn.commit()

            src = get_current_source_record(conn, "cve", "CVE-2024-1234")
            assert src.snapshot_id == snap.id

    def test_snapshot_fk_enforced(self):
        """Correction 2: bogus snapshot_id raises FK violation."""
        fixture = load_json("cve_published.json")
        bogus_id = "00000000-0000-0000-0000-000000000000"
        with get_db_connection() as conn:
            with pytest.raises(Exception):  # FK violation
                process_cve_record(conn, fixture, snapshot_id=bogus_id)
            conn.rollback()


# ===========================================================================
# NVD ADAPTER TESTS
# ===========================================================================

class TestNvdAdapter:
    """NVD 2.0 API response parsing and storage."""

    def test_nvd_full_response_extraction(self):
        """NVD response envelope parsed: metrics, weaknesses, configs, refs."""
        fixture = load_json("nvd_response.json")
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED"))
            results = process_nvd_response(conn, fixture)
            conn.commit()

        assert len(results) == 1
        assert results[0].error is None
        assert results[0].is_new_revision is True

        with get_db_connection() as conn:
            # CVSS assessments from NVD
            assessments = get_cvss_assessments(conn, "CVE-2024-1234")
            # NVD has: 2x CVSS 3.1 (Primary + Secondary) + 1x CVSS 2.0
            assert len(assessments) == 3

            # Primary NVD 3.1
            nvd_primary = [a for a in assessments
                           if a.assessor == "nvd@nist.gov" and a.cvss_version == "3.1"]
            assert len(nvd_primary) == 1
            assert nvd_primary[0].base_score == Decimal("9.1")
            assert nvd_primary[0].assessment_type == "Primary"
            assert nvd_primary[0].exploitability_score == Decimal("3.9")

            # Secondary (CNA-originated, carried by NVD)
            secondary = [a for a in assessments if a.assessment_type == "Secondary"]
            assert len(secondary) == 1
            assert secondary[0].assessor == "example-cna@example.com"
            assert secondary[0].base_score == Decimal("9.8")

            # CVSS 2.0
            v2 = [a for a in assessments if a.cvss_version == "2.0"]
            assert len(v2) == 1
            assert v2[0].base_score == Decimal("9.4")

            # Weaknesses
            cwes = get_cve_weaknesses(conn, "CVE-2024-1234")
            assert len(cwes) >= 1
            cwe_ids = [w["cwe_id"] for w in cwes]
            assert "CWE-89" in cwe_ids

            # References
            refs = get_cve_references(conn, "CVE-2024-1234")
            assert len(refs) == 2

            # CPE-based affected
            affected = get_cve_affected(conn, "CVE-2024-1234")
            assert len(affected) >= 1
            assert affected[0].source == "nvd"

    def test_nvd_dedup(self):
        """Same NVD response twice → no new revision."""
        fixture = load_json("nvd_response.json")
        with get_db_connection() as conn:
            r1 = process_nvd_response(conn, fixture)
            conn.commit()
            r2 = process_nvd_response(conn, fixture)
            conn.commit()

        assert r1[0].is_new_revision is True
        assert r2[0].is_new_revision is False

    def test_nvd_assessor_from_source_field(self):
        """NVD assessor comes from the metric's `source` field, not inferred."""
        fixture = load_json("nvd_response.json")
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED"))
            process_nvd_response(conn, fixture)
            conn.commit()
            assessments = get_cvss_assessments(conn, "CVE-2024-1234")
            assessors = {a.assessor for a in assessments}
            # Exact source field values, not substring-inferred
            assert "nvd@nist.gov" in assessors
            assert "example-cna@example.com" in assessors


# ===========================================================================
# KEV ADAPTER TESTS
# ===========================================================================

class TestKevAdapter:
    """CISA KEV catalog parsing and storage."""

    def test_kev_catalog_full_extraction(self):
        """All native KEV fields preserved for both entries."""
        fixture = load_json("kev_catalog.json")
        with get_db_connection() as conn:
            results = process_kev_catalog(conn, fixture)
            conn.commit()

        assert len(results) == 2
        assert all(r.error is None for r in results)

        with get_db_connection() as conn:
            kev1 = get_kev_entry(conn, "CVE-2024-1234")
            assert kev1 is not None
            assert kev1.vendor_project == "Example Corp"
            assert kev1.product == "Example Product"
            assert kev1.vulnerability_name == "Example Product SQL Injection Vulnerability"
            assert kev1.date_added == date(2024, 4, 1)
            assert kev1.due_date == date(2024, 4, 22)
            assert kev1.known_ransomware == "Known"
            assert kev1.required_action is not None
            assert kev1.source_record_id is not None

            kev2 = get_kev_entry(conn, "CVE-2024-5678")
            assert kev2 is not None
            assert kev2.known_ransomware == "Unknown"

    def test_kev_exact_cve_association(self):
        """KEV CVE association is exact cveID match only."""
        entry = {"cveID": "CVE-2024-1234", "vendorProject": "V",
                 "product": "P", "vulnerabilityName": "N",
                 "dateAdded": "2024-04-01"}
        with get_db_connection() as conn:
            result = process_kev_entry(conn, entry)
            conn.commit()
        assert result.error is None
        assert result.cve_id == "CVE-2024-1234"

    def test_kev_invalid_cve_rejected(self):
        """KEV entry with invalid CVE ID is rejected."""
        entry = {"cveID": "INVALID", "vendorProject": "V",
                 "product": "P", "vulnerabilityName": "N",
                 "dateAdded": "2024-04-01"}
        with get_db_connection() as conn:
            result = process_kev_entry(conn, entry)
        assert result.error is not None

    def test_kev_dedup(self):
        """Same KEV entry twice → no new revision."""
        fixture = load_json("kev_catalog.json")
        with get_db_connection() as conn:
            r1 = process_kev_catalog(conn, fixture)
            conn.commit()
            r2 = process_kev_catalog(conn, fixture)
            conn.commit()

        assert r1[0].is_new_revision is True
        assert r2[0].is_new_revision is False

    def test_kev_source_record_linked(self):
        """KEV entries have source_record_id for provenance."""
        fixture = load_json("kev_catalog.json")
        with get_db_connection() as conn:
            process_kev_catalog(conn, fixture)
            conn.commit()
            kev = get_kev_entry(conn, "CVE-2024-1234")
            assert kev.source_record_id is not None
            src = get_current_source_record(conn, "kev", "CVE-2024-1234")
            assert src is not None
            assert src.raw_payload["cveID"] == "CVE-2024-1234"


# ===========================================================================
# EPSS ADAPTER TESTS
# ===========================================================================

class TestEpssAdapter:
    """FIRST EPSS bulk CSV parsing and storage."""

    def test_epss_first_csv_format_parsed(self):
        """Correction 5: actual FIRST bulk CSV with metadata comment header."""
        csv_text = load_text("epss_scores.csv")
        with get_db_connection() as conn:
            result = process_epss_csv(conn, csv_text)
            conn.commit()

        assert result.total == 3
        assert result.stored == 3
        assert result.skipped == 0
        assert len(result.errors) == 0

        with get_db_connection() as conn:
            scores = get_epss_scores(conn, "CVE-2024-1234")
            assert len(scores) == 1
            assert scores[0].score == Decimal("0.95432")
            assert scores[0].percentile == Decimal("0.99100")
            assert scores[0].model_version == "v2024.03.01"
            assert scores[0].score_date == date(2024, 4, 15)

    def test_epss_multi_day_history(self):
        """Two days of EPSS data → dated history per CVE."""
        day1 = load_text("epss_scores.csv")
        day2 = load_text("epss_scores_day2.csv")
        with get_db_connection() as conn:
            process_epss_csv(conn, day1)
            conn.commit()
            process_epss_csv(conn, day2)
            conn.commit()

            history = get_epss_scores(conn, "CVE-2024-1234")
            assert len(history) == 2
            # Most recent first
            assert history[0].score_date == date(2024, 4, 16)
            assert history[0].score == Decimal("0.96000")
            assert history[1].score_date == date(2024, 4, 15)
            assert history[1].score == Decimal("0.95432")

    def test_epss_dedup_same_file(self):
        """Same EPSS CSV file twice → deduped by content hash."""
        csv_text = load_text("epss_scores.csv")
        with get_db_connection() as conn:
            r1 = process_epss_csv(conn, csv_text)
            conn.commit()
            r2 = process_epss_csv(conn, csv_text)
            conn.commit()

        assert r1.stored == 3
        assert r2.stored == 0  # Deduped

    def test_epss_metadata_header_required(self):
        """CSV without metadata header → error (missing score_date)."""
        bad_csv = "cve,epss,percentile\nCVE-2024-1234,0.5,0.5\n"
        with get_db_connection() as conn:
            result = process_epss_csv(conn, bad_csv)
        assert len(result.errors) > 0
        assert "score_date" in result.errors[0].lower()

    def test_epss_source_record_created(self):
        """EPSS adapter creates source records for provenance."""
        csv_text = load_text("epss_scores.csv")
        with get_db_connection() as conn:
            process_epss_csv(conn, csv_text)
            conn.commit()
            src = get_current_source_record(conn, "epss", "epss-2024-04-15")
            assert src is not None
            assert src.raw_payload["format"] == "FIRST_EPSS_CSV"


# ===========================================================================
# OSV ADAPTER TESTS
# ===========================================================================

class TestOsvAdapter:
    """OSV format parsing and storage."""

    def test_osv_ghsa_with_cve_alias(self):
        """GHSA with exact CVE alias → linked to CVE spine."""
        fixture = load_json("osv_ghsa.json")
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED"))
            result = process_osv_record(conn, fixture)
            conn.commit()

        assert result.error is None
        assert result.osv_id == "GHSA-xxxx-yyyy-zzzz"
        assert result.is_new_revision is True
        assert "CVE-2024-1234" in result.linked_cve_ids

        with get_db_connection() as conn:
            osv = get_osv_record(conn, "GHSA-xxxx-yyyy-zzzz")
            assert osv is not None
            assert osv.ecosystem == "PyPI"
            assert osv.package_name == "example-package"
            assert osv.package_purl == "pkg:pypi/example-package"
            assert osv.schema_version == "1.6.0"

            aliases = get_osv_aliases(conn, "GHSA-xxxx-yyyy-zzzz")
            cve_aliases = [a for a in aliases if a.alias_type == "alias" and a.linked_cve_id]
            related = [a for a in aliases if a.alias_type == "related"]
            assert len(cve_aliases) == 1
            assert cve_aliases[0].linked_cve_id == "CVE-2024-1234"
            assert len(related) == 1
            assert related[0].alias == "GHSA-aaaa-bbbb-cccc"
            assert related[0].linked_cve_id is None  # related → no link

            # Reverse lookup
            linked = get_osv_records_by_cve(conn, "CVE-2024-1234")
            assert len(linked) == 1
            assert linked[0].osv_id == "GHSA-xxxx-yyyy-zzzz"

    def test_osv_no_cve_no_spine_link(self):
        """OSV without CVE alias → no CVE spine link."""
        fixture = load_json("osv_no_cve.json")
        with get_db_connection() as conn:
            result = process_osv_record(conn, fixture)
            conn.commit()

        assert result.error is None
        assert len(result.linked_cve_ids) == 0

        with get_db_connection() as conn:
            aliases = get_osv_aliases(conn, fixture["id"])
            cve_linked = [a for a in aliases if a.linked_cve_id is not None]
            assert len(cve_linked) == 0

    def test_osv_withdrawn_state(self):
        """Explicit withdrawn state is preserved."""
        fixture = load_json("osv_withdrawn.json")
        with get_db_connection() as conn:
            result = process_osv_record(conn, fixture)
            conn.commit()

        assert result.error is None
        with get_db_connection() as conn:
            osv = get_osv_record(conn, fixture["id"])
            assert osv.withdrawn is not None

    def test_osv_related_does_not_link(self):
        """related entries do NOT create CVE spine links."""
        fixture = load_json("osv_ghsa.json")
        with get_db_connection() as conn:
            process_osv_record(conn, fixture)
            conn.commit()

            aliases = get_osv_aliases(conn, "GHSA-xxxx-yyyy-zzzz")
            related = [a for a in aliases if a.alias_type == "related"]
            for r in related:
                assert r.linked_cve_id is None

    def test_osv_dedup(self):
        """Same OSV record twice → no new revision."""
        fixture = load_json("osv_ghsa.json")
        with get_db_connection() as conn:
            r1 = process_osv_record(conn, fixture)
            conn.commit()
            r2 = process_osv_record(conn, fixture)
            conn.commit()

        assert r1.is_new_revision is True
        assert r2.is_new_revision is False

    def test_osv_source_record_cve_id_is_null(self):
        """OSV source records have cve_id=NULL (OSV identity is not CVE)."""
        fixture = load_json("osv_ghsa.json")
        with get_db_connection() as conn:
            process_osv_record(conn, fixture)
            conn.commit()
            src = get_current_source_record(conn, "osv", "GHSA-xxxx-yyyy-zzzz")
            assert src is not None
            assert src.cve_id is None  # OSV identity ≠ CVE


# ===========================================================================
# TES RESOLVER TESTS (Sprint 01 correction 1: exact match only)
# ===========================================================================

class TestTesResolverExactMatch:
    """TES resolver uses exact CNA/NVD matching — no substring inference."""

    def test_tier1_exact_cna_org_id_match(self):
        """CNA matched by exact assigner_org_id."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0",
                assigner_short_name="example-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="cve",
                assessor="f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert res.resolution_tier == "cna"
            assert res.resolved_score == Decimal("9.8")

    def test_tier1_exact_cna_short_name_match(self):
        """CNA matched by exact assigner_short_name."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0",
                assigner_short_name="example-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="cve",
                assessor="example-cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert res.resolution_tier == "cna"

    def test_no_substring_matching(self):
        """Correction 1: ADP assessment with container_role='adp' must NOT match CNA tier."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="org-exact-id",
                assigner_short_name="exact-cna",
            ))
            # Assessor is "exact-cna-extended" in ADP container (container_role="adp")
            # Must NOT resolve as CNA tier.
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="cve",
                assessor="exact-cna-extended",
                container_role="adp",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            # Should NOT match CNA tier
            assert res.resolution_tier != "cna"
            # Should be unscoreable (no NVD either)
            assert res.unscoreable_reason is not None

    def test_tier2_exact_nvd_match(self):
        """NVD tier matches exact container_role='nvd' assessor."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="nvd",
                assessor="nvd@nist.gov",
                container_role="nvd",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                base_score=Decimal("9.1"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert res.resolution_tier == "nvd"
            assert res.resolved_score == Decimal("9.1")

    def test_nvd_substring_not_matched(self):
        """Non-NVD assessment containing 'nvd' in assessor must NOT match NVD tier."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            # "custom-nvd-assessor" contains "nvd" but container_role is "adp"
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="cve",
                assessor="custom-nvd-assessor",
                container_role="adp",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                base_score=Decimal("9.1"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert res.resolution_tier is None
            assert res.unscoreable_reason is not None

    def test_fail_closed_no_eligible(self):
        """No eligible CVSS 3.1 GENERAL → unscoreable."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="org", assigner_short_name="cna",
            ))
            # Only CVSS 4.0
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="cve",
                assessor="cna", cvss_version="4.0",
                vector_string="CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                base_score=Decimal("8.3"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert res.resolved_score is None
            assert res.unscoreable_reason is not None

    def test_cna_then_nvd_priority(self):
        """When both CNA and NVD have 3.1 GENERAL, CNA wins."""
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id="CVE-2024-1234", state="PUBLISHED",
                assigner_org_id="cna-org", assigner_short_name="the-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="cve",
                assessor="the-cna", cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"), scenario="GENERAL",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id="CVE-2024-1234", source="nvd",
                assessor="nvd@nist.gov", cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                base_score=Decimal("9.1"), scenario="GENERAL",
            ))
            conn.commit()
            res = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert res.resolution_tier == "cna"
            assert res.resolved_score == Decimal("9.8")


# ===========================================================================
# CROSS-ADAPTER INTEGRATION
# ===========================================================================

class TestCrossAdapterIntegration:
    """End-to-end: CVE + NVD + KEV + EPSS + OSV for the same vulnerability."""

    def test_full_pipeline_cve_2024_1234(self):
        """All five sources enriching CVE-2024-1234."""
        with get_db_connection() as conn:
            # 1. CVE adapter
            cve_fix = load_json("cve_published.json")
            process_cve_record(conn, cve_fix)
            conn.commit()

            # 2. NVD adapter
            nvd_fix = load_json("nvd_response.json")
            process_nvd_response(conn, nvd_fix)
            conn.commit()

            # 3. KEV adapter
            kev_fix = load_json("kev_catalog.json")
            process_kev_catalog(conn, kev_fix)
            conn.commit()

            # 4. EPSS adapter
            epss_fix = load_text("epss_scores.csv")
            process_epss_csv(conn, epss_fix)
            conn.commit()

            # 5. OSV adapter
            osv_fix = load_json("osv_ghsa.json")
            process_osv_record(conn, osv_fix)
            conn.commit()

            # --- Verify composed data ---
            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None
            assert vuln.state == "PUBLISHED"

            # Multiple CVSS assessments from CVE and NVD
            assessments = get_cvss_assessments(conn, "CVE-2024-1234")
            sources = {a.source for a in assessments}
            assert "cve" in sources
            assert "nvd" in sources

            # TES resolves to CNA (exact match, not substring)
            tes = resolve_tes_cvss(conn, "CVE-2024-1234")
            assert tes.resolution_tier == "cna"
            assert tes.resolved_score == Decimal("9.8")

            # KEV enrichment
            kev = get_kev_entry(conn, "CVE-2024-1234")
            assert kev is not None
            assert kev.known_ransomware == "Known"

            # EPSS enrichment
            epss = get_epss_scores(conn, "CVE-2024-1234")
            assert len(epss) >= 1

            # OSV linked via exact alias
            osv_linked = get_osv_records_by_cve(conn, "CVE-2024-1234")
            assert len(osv_linked) == 1
            assert osv_linked[0].osv_id == "GHSA-xxxx-yyyy-zzzz"

            # ADP/SSVC from CVE
            adps = get_adp_entries(conn, "CVE-2024-1234")
            assert len(adps) == 1
            assert adps[0].ssvc_data is not None


# ===========================================================================
# FIXTURE ENVELOPE VALIDATION
# ===========================================================================

class TestFixtureEnvelopeCorrections:
    """Correction 4: all CVE fixtures have proper CVE JSON 5.x root envelope."""

    @pytest.mark.parametrize("fixture_name", [
        "cve_published.json",
        "cve_published_updated.json",
        "cve_reserved.json",
        "cve_rejected.json",
        "cve_multi_cvss.json",
        "cve_malformed.json",
    ])
    def test_cve_fixture_has_envelope(self, fixture_name):
        """Every CVE fixture has dataType and dataVersion root fields."""
        fixture = load_json(fixture_name)
        assert fixture.get("dataType") == "CVE_RECORD", \
            f"{fixture_name} missing dataType=CVE_RECORD"
        assert "dataVersion" in fixture, \
            f"{fixture_name} missing dataVersion"
        assert fixture["dataVersion"].startswith("5."), \
            f"{fixture_name} dataVersion should be 5.x, got {fixture['dataVersion']}"

    def test_epss_fixture_has_first_format(self):
        """Correction 5: EPSS fixture uses actual FIRST bulk CSV format."""
        csv_text = load_text("epss_scores.csv")
        lines = csv_text.strip().split("\n")
        # First line must be a metadata comment
        assert lines[0].startswith("#"), "EPSS fixture must start with # metadata line"
        assert "model_version:" in lines[0]
        assert "score_date:" in lines[0]
        # Second line must be the CSV header
        assert lines[1].strip() == "cve,epss,percentile"
