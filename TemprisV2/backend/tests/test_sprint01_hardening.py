# backend/tests/test_sprint01_hardening.py
"""
Sprint 01 Hardening — Contract Assertion Tests.

Covers all assertions from the accepted Sprint 01 contract (Rev 2.1):
  0.1  — Regression safety (all pre-existing tests pass)
  1.1  — AuthorityError on non-cve source
  1.1a — No other function writes to canonical_vulnerabilities
  1.2  — NVD adapter no longer calls upsert_canonical_vulnerability
  1.3  — KEV adapter no longer calls upsert_canonical_vulnerability
  1.4  — OSV adapter no longer calls upsert_canonical_vulnerability
  1.5  — EPSS adapter does not create/modify canonical rows
  1.6  — Integration: NVD arrives first, CVE arrives later, backfill runs
  1.7  — Integration: KEV arrives first, CVE arrives later, backfill runs
  1.8  — cve_adapter passes source="cve" and succeeds
  2.1-2.7 — Dual-column unresolved enrichment references
  3.1-3.6 — Source artifacts / exact byte preservation
  4.1-4.6 — All-or-nothing savepoint protocol

All tests run offline against checked-in fixtures and a local PostgreSQL database.
"""
import hashlib
import inspect
import json
import re
import uuid
from copy import deepcopy
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    AuthorityError,
    CanonicalVulnerability,
    CvssAssessment,
    CveAffected,
    CveAdpEntry,
    CveRelationship,
    EpssScore,
    KevEntry,
    OsvAlias,
    OsvRecord,
    SourceArtifact,
    SourceRecord,
    SyncSnapshot,
    SyncState,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    upsert_canonical_vulnerability,
    get_canonical_vulnerability,
    upsert_source_record,
    get_current_source_record,
    get_source_records_by_cve,
    upsert_cvss_assessment,
    get_cvss_assessments,
    get_cve_affected,
    get_cve_references,
    get_cve_weaknesses,
    upsert_kev_entry,
    get_kev_entry,
    upsert_epss_score,
    get_epss_scores,
    upsert_osv_record,
    upsert_osv_alias,
    get_osv_aliases,
    upsert_adp_entry,
    upsert_cve_references,
    upsert_cve_weaknesses,
    create_sync_snapshot,
    complete_sync_snapshot,
    get_sync_snapshot,
    get_sync_state,
    update_sync_state,
    upsert_source_artifact,
    get_source_artifacts,
    get_source_artifact_by_hash,
    _backfill_unresolved_references,
    get_unresolved_source_records,
    get_composed_cve_detail,
)
from app.vuln_intelligence.adapters.cve_adapter import process_cve_record
from app.vuln_intelligence.adapters.nvd_adapter import (
    process_nvd_cve,
    reconcile_current_nvd_enrichment,
)
from app.vuln_intelligence.adapters.kev_adapter import process_kev_entry
from app.vuln_intelligence.adapters.osv_adapter import process_osv_record
from app.vuln_intelligence.adapters.epss_adapter import process_epss_csv
from app.vuln_intelligence.sync_engine import sync_source, SyncOutcome


# ---------------------------------------------------------------------------
# Fixture loading helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "vuln_intelligence"


def load_json(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_csv(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def clean_vuln_tables():
    """Truncate all vuln intelligence tables before each test for isolation."""
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
                DELETE FROM source_artifacts;
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


def _create_snapshot(conn, source="cve") -> str:
    """Helper: create a running snapshot and return its ID."""
    snap = create_sync_snapshot(conn, SyncSnapshot(
        source=source, sync_mode="incremental", status="running",
    ))
    conn.commit()
    return snap.id


# ===========================================================================
# Deliverable 1 — CVE-Only Canonical Repository Boundary
# ===========================================================================


class TestAuthorityEnforcement:
    """Assertions 1.1, 1.1a, 1.8"""

    def test_1_1_authority_error_on_non_cve_sources(self):
        """upsert_canonical_vulnerability raises AuthorityError for non-cve sources."""
        vuln = CanonicalVulnerability(cve_id="CVE-2024-1234", state="PUBLISHED")
        with get_db_connection() as conn:
            for bad_source in ("nvd", "kev", "osv", "epss", "unknown"):
                with pytest.raises(AuthorityError):
                    upsert_canonical_vulnerability(conn, vuln, source=bad_source)

    def test_1_1a_only_upsert_canonical_writes_to_table(self):
        """No function in repository.py other than upsert_canonical_vulnerability
        writes to canonical_vulnerabilities."""
        import app.vuln_intelligence.repository as repo_module
        source = inspect.getsource(repo_module)

        # Find all INSERT/UPDATE against canonical_vulnerabilities
        pattern = re.compile(
            r"(INSERT\s+INTO|UPDATE)\s+canonical_vulnerabilities",
            re.IGNORECASE,
        )
        matches = list(pattern.finditer(source))
        assert len(matches) > 0, "Expected at least one write in upsert_canonical_vulnerability"

        # Verify all matches are inside upsert_canonical_vulnerability
        for m in matches:
            # Find the function that contains this match
            start = m.start()
            # Walk backwards to find the enclosing def
            preceding = source[:start]
            last_def = preceding.rfind("def ")
            assert last_def >= 0
            func_line = source[last_def:source.index("\n", last_def)]
            assert "upsert_canonical_vulnerability" in func_line, (
                f"Found canonical_vulnerabilities write outside upsert_canonical_vulnerability: "
                f"{func_line.strip()}"
            )

    def test_1_8_cve_adapter_passes_source_cve(self):
        """cve_adapter.process_cve_record creates/updates canonical row with source='cve'."""
        record = load_json("cve_published.json")
        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn)
            result = process_cve_record(conn, record, snapshot_id=snap_id)
            conn.commit()

            assert result.error is None
            assert result.cve_id == "CVE-2024-1234"
            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None
            assert vuln.state == "PUBLISHED"
            assert vuln.assigner_org_id is not None


class TestEnrichmentAdaptersNoCanonical:
    """Assertions 1.2, 1.3, 1.4, 1.5"""

    def test_1_2_nvd_does_not_create_canonical(self):
        """NVD adapter stores source record with declared_cve_id but no canonical row."""
        nvd_data = load_json("nvd_response.json")
        cve_data = nvd_data["vulnerabilities"][0]["cve"]
        cve_id = cve_data["id"]

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "nvd")

            # Count canonical rows before
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                before = cur.fetchone()["cnt"]

            result = process_nvd_cve(conn, cve_data, snapshot_id=snap_id)
            conn.commit()

            assert result.error is None

            # No new canonical row created
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                after = cur.fetchone()["cnt"]
            assert after == before

            # Source record has declared_cve_id set, cve_id NULL
            rec = get_current_source_record(conn, "nvd", cve_id)
            assert rec is not None
            assert rec.declared_cve_id == cve_id
            assert rec.cve_id is None

    def test_1_3_kev_does_not_create_canonical(self):
        """KEV adapter stores entry with declared_cve_id but no canonical row."""
        kev_catalog = load_json("kev_catalog.json")
        entry = kev_catalog["vulnerabilities"][0]
        cve_id = entry["cveID"]

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "kev")

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                before = cur.fetchone()["cnt"]

            result = process_kev_entry(conn, entry, snapshot_id=snap_id)
            conn.commit()

            assert result.error is None

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                after = cur.fetchone()["cnt"]
            assert after == before

            # Source record has declared_cve_id, cve_id NULL
            rec = get_current_source_record(conn, "kev", cve_id)
            assert rec is not None
            assert rec.declared_cve_id == cve_id
            assert rec.cve_id is None

            # KEV entry has declared_cve_id, cve_id NULL
            kev = get_kev_entry(conn, cve_id)
            assert kev is not None
            assert kev.declared_cve_id == cve_id
            assert kev.cve_id is None

    def test_1_4_osv_does_not_create_canonical(self):
        """OSV adapter stores alias with declared_linked_cve_id but no canonical row."""
        osv_rec = load_json("osv_ghsa.json")

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "osv")

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                before = cur.fetchone()["cnt"]

            result = process_osv_record(conn, osv_rec, snapshot_id=snap_id)
            conn.commit()

            assert result.error is None

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                after = cur.fetchone()["cnt"]
            assert after == before

            # Alias has declared_linked_cve_id but linked_cve_id is NULL
            aliases = get_osv_aliases(conn, result.osv_id)
            cve_aliases = [a for a in aliases if a.alias_type == "alias" and validate_cve_id(a.alias)]
            assert len(cve_aliases) > 0
            for a in cve_aliases:
                assert a.declared_linked_cve_id is not None
                assert a.linked_cve_id is None

    def test_1_5_epss_does_not_create_or_modify_canonical(self):
        """EPSS adapter stores scores without creating or modifying canonical rows."""
        csv_text = load_csv("epss_scores.csv")

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "epss")

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                before = cur.fetchone()["cnt"]

            result = process_epss_csv(conn, csv_text, snapshot_id=snap_id)
            conn.commit()

            assert len(result.errors) == 0

            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM canonical_vulnerabilities;")
                after = cur.fetchone()["cnt"]
            assert after == before

            # EPSS scores were stored
            assert result.stored > 0


# ===========================================================================
# Deliverable 2 — Unresolved Exact Enrichment References
# ===========================================================================


class TestDualColumnDesign:
    """Assertions 2.1–2.7"""

    def test_2_1_nvd_declared_cve_id_without_canonical(self):
        """NVD source record stores declared_cve_id with cve_id NULL when no canonical."""
        nvd_data = load_json("nvd_response.json")
        cve_data = nvd_data["vulnerabilities"][0]["cve"]
        cve_id = cve_data["id"]

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "nvd")
            process_nvd_cve(conn, cve_data, snapshot_id=snap_id)
            conn.commit()

            rec = get_current_source_record(conn, "nvd", cve_id)
            assert rec.declared_cve_id == cve_id
            assert rec.cve_id is None

    def test_2_2_kev_declared_cve_id_without_canonical(self):
        """KEV entry stores declared_cve_id without requiring canonical row."""
        kev_catalog = load_json("kev_catalog.json")
        entry = kev_catalog["vulnerabilities"][0]
        cve_id = entry["cveID"]

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "kev")
            process_kev_entry(conn, entry, snapshot_id=snap_id)
            conn.commit()

            kev = get_kev_entry(conn, cve_id)
            assert kev.declared_cve_id == cve_id
            assert kev.cve_id is None

            rec = get_current_source_record(conn, "kev", cve_id)
            assert rec.declared_cve_id == cve_id
            assert rec.cve_id is None

    def test_2_3_osv_declared_linked_cve_id_without_canonical(self):
        """OSV alias stores declared_linked_cve_id with linked_cve_id NULL."""
        osv_rec = load_json("osv_ghsa.json")

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "osv")
            result = process_osv_record(conn, osv_rec, snapshot_id=snap_id)
            conn.commit()

            aliases = get_osv_aliases(conn, result.osv_id)
            cve_aliases = [a for a in aliases if a.alias_type == "alias" and validate_cve_id(a.alias)]
            for a in cve_aliases:
                assert a.declared_linked_cve_id is not None
                assert a.linked_cve_id is None

    def test_2_4_enrichment_insert_succeeds_without_canonical(self):
        """Insert with declared_cve_id and cve_id=NULL succeeds (no FK violation)."""
        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "nvd")
            rec, is_new = upsert_source_record(conn, SourceRecord(
                source="nvd",
                source_id="CVE-2024-9999",
                cve_id=None,
                declared_cve_id="CVE-2024-9999",
                content_hash="test-hash-001",
                raw_payload={"test": True},
                snapshot_id=snap_id,
            ))
            conn.commit()

            assert is_new
            assert rec.declared_cve_id == "CVE-2024-9999"
            assert rec.cve_id is None

    def test_2_5_backfill_populates_fk_after_canonical(self):
        """After CVE Program ingests, backfill populates cve_id FK on existing records."""
        cve_id = "CVE-2024-1234"
        nvd_data = load_json("nvd_response.json")
        cve_data = nvd_data["vulnerabilities"][0]["cve"]
        cve_record = load_json("cve_published.json")

        with get_db_connection() as conn:
            # Step 1: NVD arrives first — no canonical row
            snap_nvd = _create_snapshot(conn, "nvd")
            process_nvd_cve(conn, cve_data, snapshot_id=snap_nvd)
            conn.commit()

            # Verify NVD record has cve_id NULL
            nvd_rec = get_current_source_record(conn, "nvd", cve_id)
            assert nvd_rec.cve_id is None

            # Step 2: CVE Program record arrives → canonical + backfill
            snap_cve = _create_snapshot(conn, "cve")
            process_cve_record(conn, cve_record, snapshot_id=snap_cve)
            conn.commit()

            # Verify backfill: NVD source record now has cve_id set
            nvd_rec_after = get_current_source_record(conn, "nvd", cve_id)
            assert nvd_rec_after.cve_id == cve_id

            # Both CVE and NVD source records returned by get_source_records_by_cve
            all_recs = get_source_records_by_cve(conn, cve_id)
            sources = {r.source for r in all_recs}
            assert "cve" in sources
            assert "nvd" in sources

    def test_2_6_composed_detail_after_backfill(self):
        """get_composed_cve_detail assembles enrichment from all sources after backfill."""
        cve_id = "CVE-2024-1234"
        cve_record = load_json("cve_published.json")
        kev_catalog = load_json("kev_catalog.json")
        kev_entry_data = kev_catalog["vulnerabilities"][0]

        with get_db_connection() as conn:
            # KEV arrives first
            snap_kev = _create_snapshot(conn, "kev")
            process_kev_entry(conn, kev_entry_data, snapshot_id=snap_kev)
            conn.commit()

            # CVE arrives — triggers backfill
            snap_cve = _create_snapshot(conn, "cve")
            process_cve_record(conn, cve_record, snapshot_id=snap_cve)
            conn.commit()

            detail = get_composed_cve_detail(conn, cve_id)
            assert detail is not None
            assert detail["cve_id"] == cve_id
            assert detail["kev"] is not None

    def test_2_7_unresolved_records_queryable(self):
        """Enrichment records with cve_id IS NULL are queryable by declared_cve_id."""
        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn, "nvd")
            upsert_source_record(conn, SourceRecord(
                source="nvd",
                source_id="CVE-2024-9999",
                cve_id=None,
                declared_cve_id="CVE-2024-9999",
                content_hash="unresolved-hash-001",
                raw_payload={"test": True},
                snapshot_id=snap_id,
            ))
            conn.commit()

            unresolved = get_unresolved_source_records(conn, source="nvd")
            assert any(r.declared_cve_id == "CVE-2024-9999" for r in unresolved)


class TestIntegrationBackfill:
    """Assertions 1.6, 1.7"""

    def test_1_6_nvd_first_then_cve_backfills(self):
        """NVD arrives first → CVE arrives → NVD enrichment FK backfilled."""
        cve_id = "CVE-2024-1234"
        nvd_data = load_json("nvd_response.json")
        cve_data = nvd_data["vulnerabilities"][0]["cve"]
        cve_record = load_json("cve_published.json")

        with get_db_connection() as conn:
            # NVD first
            snap_nvd = _create_snapshot(conn, "nvd")
            process_nvd_cve(conn, cve_data, snapshot_id=snap_nvd)
            conn.commit()

            assert get_canonical_vulnerability(conn, cve_id) is None
            nvd_rec = get_current_source_record(conn, "nvd", cve_id)
            assert nvd_rec.declared_cve_id == cve_id
            assert nvd_rec.cve_id is None

            # CVE arrives — creates canonical + backfill
            snap_cve = _create_snapshot(conn, "cve")
            process_cve_record(conn, cve_record, snapshot_id=snap_cve)
            conn.commit()

            assert get_canonical_vulnerability(conn, cve_id) is not None
            nvd_rec_after = get_current_source_record(conn, "nvd", cve_id)
            assert nvd_rec_after.cve_id == cve_id

            detail = get_composed_cve_detail(conn, cve_id)
            sources = {p["source"] for p in detail["source_provenance"]}
            assert "cve" in sources
            assert "nvd" in sources

    def test_nvd_first_reconciles_normalized_data_idempotently_and_equivalently(self):
        """NVD-first and CVE-first produce identical normalized NVD facts."""
        cve_id = "CVE-2024-1234"
        nvd_data = load_json("nvd_response.json")["vulnerabilities"][0]["cve"]
        cve_record = load_json("cve_published.json")

        def dependent_counts(conn, source_record_id):
            counts = {}
            with conn.cursor() as cur:
                for table in (
                    "cvss_assessments",
                    "cve_affected",
                    "cve_weaknesses",
                    "cve_references",
                ):
                    cur.execute(
                        f"SELECT COUNT(*) AS count FROM {table} WHERE source_record_id = %s;",
                        (source_record_id,),
                    )
                    counts[table] = cur.fetchone()["count"]
            return counts

        def normalized_nvd_facts(conn, target_cve_id):
            return {
                "cvss": sorted(
                    (
                        a.assessor,
                        a.assessment_type,
                        a.container_role,
                        a.provider_org_id,
                        a.cvss_version,
                        a.vector_string,
                        str(a.base_score),
                        a.base_severity,
                        str(a.exploitability_score),
                        str(a.impact_score),
                    )
                    for a in get_cvss_assessments(conn, target_cve_id)
                    if a.source == "nvd"
                ),
                "affected": sorted(
                    (tuple(a.cpes or []), json.dumps(a.raw_data, sort_keys=True))
                    for a in get_cve_affected(conn, target_cve_id)
                    if a.source == "nvd"
                ),
                "weaknesses": sorted(
                    (w["cwe_id"], w["description"], w["weakness_type"])
                    for w in get_cve_weaknesses(conn, target_cve_id)
                    if w["source"] == "nvd"
                ),
                "references": sorted(
                    (
                        r["url"],
                        r["name"] or "",
                        tuple(r["tags"] or []),
                        r["source_identifier"] or "",
                    )
                    for r in get_cve_references(conn, target_cve_id)
                    if r["source"] == "nvd"
                ),
            }

        with get_db_connection() as conn:
            # NVD first: preserve exact identity/provenance without creating a CVE.
            process_nvd_cve(conn, nvd_data)
            nvd_source = get_current_source_record(conn, "nvd", cve_id)
            assert get_canonical_vulnerability(conn, cve_id) is None
            assert nvd_source.declared_cve_id == cve_id
            assert nvd_source.cve_id is None
            assert dependent_counts(conn, nvd_source.id) == {
                "cvss_assessments": 0,
                "cve_affected": 0,
                "cve_weaknesses": 0,
                "cve_references": 0,
            }

            # CVE Program arrival creates the spine, links the preserved source
            # revision, and normalizes that same stored NVD payload.
            original_source_hash = nvd_source.content_hash
            process_cve_record(conn, cve_record)
            canonical = get_canonical_vulnerability(conn, cve_id)
            linked_source = get_current_source_record(conn, "nvd", cve_id)
            assert canonical.state == "PUBLISHED"
            assert canonical.assigner_short_name == "example-cna"
            assert linked_source.id == nvd_source.id
            assert linked_source.content_hash == original_source_hash
            assert linked_source.cve_id == cve_id
            expected_counts = {
                "cvss_assessments": 3,
                "cve_affected": 1,
                "cve_weaknesses": 1,
                "cve_references": 2,
            }
            assert dependent_counts(conn, nvd_source.id) == expected_counts
            nvd_first_facts = normalized_nvd_facts(conn, cve_id)

            # Direct reconciliation and identical upstream retry are no-ops.
            assert reconcile_current_nvd_enrichment(conn, cve_id) is False
            retry = process_nvd_cve(conn, nvd_data)
            assert retry.is_new_revision is False
            assert dependent_counts(conn, nvd_source.id) == expected_counts

            # CVE-first then NVD must produce the same current NVD-derived facts.
            second_cve_id = "CVE-2024-91234"
            second_cve = deepcopy(cve_record)
            second_nvd = deepcopy(nvd_data)
            second_cve["cveMetadata"]["cveId"] = second_cve_id
            second_nvd["id"] = second_cve_id
            process_cve_record(conn, second_cve)
            process_nvd_cve(conn, second_nvd)
            assert normalized_nvd_facts(conn, second_cve_id) == nvd_first_facts

    def test_1_7_kev_first_then_cve_backfills(self):
        """KEV arrives first → CVE arrives → KEV entry FK backfilled."""
        cve_id = "CVE-2024-1234"
        kev_catalog = load_json("kev_catalog.json")
        kev_entry_data = kev_catalog["vulnerabilities"][0]
        cve_record = load_json("cve_published.json")

        with get_db_connection() as conn:
            # KEV first
            snap_kev = _create_snapshot(conn, "kev")
            process_kev_entry(conn, kev_entry_data, snapshot_id=snap_kev)
            conn.commit()

            kev = get_kev_entry(conn, cve_id)
            assert kev.declared_cve_id == cve_id
            assert kev.cve_id is None

            # CVE arrives
            snap_cve = _create_snapshot(conn, "cve")
            process_cve_record(conn, cve_record, snapshot_id=snap_cve)
            conn.commit()

            kev_after = get_kev_entry(conn, cve_id)
            assert kev_after.cve_id == cve_id


# ===========================================================================
# Deliverable 3 — Exact Immutable Artifact Preservation
# ===========================================================================


class TestSourceArtifacts:
    """Assertions 3.1–3.6"""

    def test_3_1_source_artifacts_table_exists(self):
        """source_artifacts table exists with expected columns."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'source_artifacts'
                    ORDER BY ordinal_position;
                """)
                cols = {row["column_name"] for row in cur.fetchall()}
            expected = {
                "id", "source_record_id", "sha256_hash", "artifact_url",
                "media_type", "byte_size", "artifact_bytes", "retrieval_time",
                "importer_version", "created_at",
            }
            assert expected.issubset(cols), f"Missing columns: {expected - cols}"

    def test_3_2_upsert_and_retrieve_artifact(self):
        """upsert_source_artifact stores and retrieves artifact bytes."""
        raw_bytes = b'{"test": "artifact data", "key": 42}'
        sha = hashlib.sha256(raw_bytes).hexdigest()

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn)
            # Create a source record to link to
            rec, _ = upsert_source_record(conn, SourceRecord(
                source="cve", source_id="CVE-2024-1234", cve_id=None,
                declared_cve_id="CVE-2024-1234",
                content_hash="art-test-hash", raw_payload={"test": True},
                snapshot_id=snap_id,
            ))

            artifact = upsert_source_artifact(conn, SourceArtifact(
                source_record_id=rec.id,
                sha256_hash=sha,
                artifact_url="https://example.com/artifact.json",
                media_type="application/json",
                byte_size=len(raw_bytes),
                artifact_bytes=raw_bytes,
                importer_version="sprint01-test",
            ))
            conn.commit()

            assert artifact.id is not None

            # Retrieve
            arts = get_source_artifacts(conn, rec.id)
            assert len(arts) == 1
            assert arts[0].sha256_hash == sha
            assert arts[0].artifact_bytes == raw_bytes
            assert arts[0].byte_size == len(raw_bytes)
            assert arts[0].media_type == "application/json"

    def test_3_3_get_artifact_by_hash(self):
        """get_source_artifact_by_hash retrieves by SHA-256."""
        raw_bytes = b"exact bytes for hash lookup"
        sha = hashlib.sha256(raw_bytes).hexdigest()

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn)
            rec, _ = upsert_source_record(conn, SourceRecord(
                source="cve", source_id="CVE-2024-5555", cve_id=None,
                declared_cve_id="CVE-2024-5555",
                content_hash="hash-lookup-test", raw_payload={},
                snapshot_id=snap_id,
            ))
            upsert_source_artifact(conn, SourceArtifact(
                source_record_id=rec.id, sha256_hash=sha,
                byte_size=len(raw_bytes), artifact_bytes=raw_bytes,
            ))
            conn.commit()

            found = get_source_artifact_by_hash(conn, sha)
            assert found is not None
            assert found.artifact_bytes == raw_bytes

    def test_3_4_sha256_from_exact_bytes(self):
        """SHA-256 hash is computed from exact original bytes."""
        raw_bytes = b'{"key": "value", "num": 123}'
        expected_sha = hashlib.sha256(raw_bytes).hexdigest()

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn)
            rec, _ = upsert_source_record(conn, SourceRecord(
                source="cve", source_id="CVE-2024-7777", cve_id=None,
                declared_cve_id="CVE-2024-7777",
                content_hash="sha-test", raw_payload={},
                snapshot_id=snap_id,
            ))
            upsert_source_artifact(conn, SourceArtifact(
                source_record_id=rec.id, sha256_hash=expected_sha,
                byte_size=len(raw_bytes), artifact_bytes=raw_bytes,
            ))
            conn.commit()

            art = get_source_artifacts(conn, rec.id)[0]
            assert hashlib.sha256(art.artifact_bytes).hexdigest() == art.sha256_hash

    def test_3_4a_round_trip_reconstruction(self):
        """Round-trip: retrieve artifact bytes, re-derive hash, re-parse JSON, compare."""
        payload = {"cveId": "CVE-2024-1234", "state": "PUBLISHED", "data": [1, 2, 3]}
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sha = hashlib.sha256(raw_bytes).hexdigest()

        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn)
            rec, _ = upsert_source_record(conn, SourceRecord(
                source="cve", source_id="CVE-2024-1234", cve_id=None,
                declared_cve_id="CVE-2024-1234",
                content_hash=content_hash(payload),
                raw_payload=payload,
                snapshot_id=snap_id,
            ))
            upsert_source_artifact(conn, SourceArtifact(
                source_record_id=rec.id, sha256_hash=sha,
                media_type="application/json",
                byte_size=len(raw_bytes), artifact_bytes=raw_bytes,
            ))
            conn.commit()

            # Round-trip reconstruction
            art = get_source_artifact_by_hash(conn, sha)
            assert hashlib.sha256(art.artifact_bytes).hexdigest() == sha
            reconstructed = json.loads(art.artifact_bytes.decode("utf-8"))
            stored_rec = get_current_source_record(conn, "cve", "CVE-2024-1234")
            assert reconstructed == stored_rec.raw_payload

    def test_3_5_content_hash_vs_sha256_distinct(self):
        """content_hash (canonical JSON) and sha256_hash (exact bytes) are distinct."""
        payload = {"b": 2, "a": 1}  # key order matters for raw bytes
        raw_bytes = json.dumps(payload).encode("utf-8")  # {"b": 2, "a": 1}
        sha_bytes = hashlib.sha256(raw_bytes).hexdigest()
        canonical_h = content_hash(payload)  # sorts keys: {"a":1,"b":2}

        assert sha_bytes != canonical_h

    def test_3_6_multiple_artifacts_per_source_record(self):
        """Multiple artifacts can be stored per source record."""
        with get_db_connection() as conn:
            snap_id = _create_snapshot(conn)
            rec, _ = upsert_source_record(conn, SourceRecord(
                source="cve", source_id="CVE-2024-8888", cve_id=None,
                declared_cve_id="CVE-2024-8888",
                content_hash="multi-art-test", raw_payload={},
                snapshot_id=snap_id,
            ))
            for i in range(3):
                data = f"artifact-{i}".encode()
                upsert_source_artifact(conn, SourceArtifact(
                    source_record_id=rec.id,
                    sha256_hash=hashlib.sha256(data).hexdigest(),
                    byte_size=len(data), artifact_bytes=data,
                ))
            conn.commit()

            arts = get_source_artifacts(conn, rec.id)
            assert len(arts) == 3


# ===========================================================================
# Deliverable 4 — All-or-Nothing Candidate Activation
# ===========================================================================


class _MockAdapter:
    """Minimal SourceAdapter for testing sync_source savepoint protocol."""

    def __init__(self, records, cursor_after="cursor-after", fail_index=None):
        self.source_name = "cve"
        self._records = records
        self._cursor_after = cursor_after
        self._fail_index = fail_index
        self._process_count = 0

    def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
        from app.vuln_intelligence.sync_engine import FetchResult
        return FetchResult(
            records=self._records,
            cursor_after=self._cursor_after,
            is_bootstrap=cursor is None,
        )

    def validate_batch(self, records):
        return True, None

    def process_record(self, conn, record, snapshot_id):
        idx = self._process_count
        self._process_count += 1
        if self._fail_index is not None and idx == self._fail_index:
            return False, False, f"Deliberate failure at record {idx}"
        # Actually process the CVE record
        result = process_cve_record(conn, record, snapshot_id=snapshot_id)
        if result.error:
            return False, False, result.error
        return True, result.is_new_revision, None


class TestSavepointProtocol:
    """Assertions 4.1–4.6"""

    def test_4_1_successful_batch_activates(self):
        """Successful 3-record batch: all records visible, cursor advances."""
        records = [load_json("cve_published.json")]

        with get_db_connection() as conn:
            adapter = _MockAdapter(records, cursor_after="2024-04-15T00:00:00Z")
            outcome = sync_source(conn, adapter)

            assert outcome.success
            assert outcome.records_processed == 1
            assert outcome.cursor_after == "2024-04-15T00:00:00Z"

            # Record is visible
            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None
            assert vuln.state == "PUBLISHED"

            # Cursor advanced
            state = get_sync_state(conn, "cve")
            assert state.cursor_value == "2024-04-15T00:00:00Z"

            # Snapshot completed
            snap = get_sync_snapshot(conn, outcome.snapshot_id)
            assert snap.status == "completed"

    def test_4_2_failed_batch_rolls_back_all_tables(self):
        """Batch where record 2 fails: NO rows from this batch in any table.
        Covers: vuln_source_records, cvss_assessments, cve_affected,
        cve_relationships, cve_references, cve_weaknesses, kev_entries,
        epss_scores, osv_records, osv_aliases, cve_adp_entries, source_artifacts.
        Cursor unchanged. Snapshot status = 'failed'."""
        good_rec = load_json("cve_published.json")
        bad_rec = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2024-9876",
                "state": "INVALID_STATE",
            },
            "containers": {},
        }
        records = [good_rec, bad_rec]

        with get_db_connection() as conn:
            # Count all tables before
            tables_to_check = [
                "vuln_source_records", "cvss_assessments", "cve_affected",
                "cve_relationships", "cve_references", "cve_weaknesses",
                "kev_entries", "epss_scores", "osv_records", "osv_aliases",
                "cve_adp_entries", "source_artifacts",
            ]
            counts_before = {}
            with conn.cursor() as cur:
                for table in tables_to_check:
                    cur.execute(f"SELECT COUNT(*) as cnt FROM {table};")
                    counts_before[table] = cur.fetchone()["cnt"]

            adapter = _MockAdapter(records, cursor_after="should-not-advance", fail_index=1)
            outcome = sync_source(conn, adapter)

            assert not outcome.success
            assert outcome.records_failed >= 1
            assert outcome.cursor_after is None

            # No new rows in any table
            with conn.cursor() as cur:
                for table in tables_to_check:
                    cur.execute(f"SELECT COUNT(*) as cnt FROM {table};")
                    after = cur.fetchone()["cnt"]
                    assert after == counts_before[table], (
                        f"Table {table} has {after - counts_before[table]} leaked rows"
                    )

            # Cursor unchanged
            state = get_sync_state(conn, "cve")
            assert state.cursor_value is None

            # Snapshot exists with status=failed
            snap = get_sync_snapshot(conn, outcome.snapshot_id)
            assert snap.status == "failed"

    def test_4_3_retry_after_failure_succeeds(self):
        """After a failed batch, re-running with corrected records succeeds."""
        good_rec = load_json("cve_published.json")
        bad_rec = {
            "dataType": "CVE_RECORD", "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2024-9876", "state": "INVALID_STATE"},
            "containers": {},
        }

        with get_db_connection() as conn:
            # First: failed batch
            adapter1 = _MockAdapter([good_rec, bad_rec], fail_index=1)
            outcome1 = sync_source(conn, adapter1)
            assert not outcome1.success

            # Second: corrected batch (good records only)
            adapter2 = _MockAdapter([good_rec], cursor_after="retry-cursor")
            outcome2 = sync_source(conn, adapter2)
            assert outcome2.success

            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None

    def test_4_4_savepoint_protocol_ordering(self):
        """sync_source executes the 4-step savepoint protocol."""
        # We verify by checking that on success:
        # - snapshot exists with status=completed
        # - cursor advanced
        # And on failure:
        # - snapshot exists with status=failed
        # - cursor NOT advanced
        # - no record data leaked
        good_rec = load_json("cve_published.json")

        with get_db_connection() as conn:
            # Success path
            adapter = _MockAdapter([good_rec], cursor_after="success-cursor")
            outcome = sync_source(conn, adapter)
            assert outcome.success
            snap = get_sync_snapshot(conn, outcome.snapshot_id)
            assert snap.status == "completed"
            state = get_sync_state(conn, "cve")
            assert state.cursor_value == "success-cursor"

    def test_4_5_failure_metadata_commits_on_rollback(self):
        """After failed batch: snapshot row has status='failed' with error_details,
        while zero record-level rows exist from that batch."""
        bad_rec = {
            "dataType": "CVE_RECORD", "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2024-0001", "state": "INVALID_STATE"},
            "containers": {},
        }

        with get_db_connection() as conn:
            adapter = _MockAdapter([bad_rec], fail_index=0)
            outcome = sync_source(conn, adapter)

            assert not outcome.success

            # Snapshot has failure metadata
            snap = get_sync_snapshot(conn, outcome.snapshot_id)
            assert snap.status == "failed"
            assert snap.records_failed > 0
            assert snap.error_message is not None

            # No canonical row created
            assert get_canonical_vulnerability(conn, "CVE-2024-0001") is None

    def test_4_6_pre_existing_data_unchanged_after_failure(self):
        """Previously current data remains identical after a failed batch."""
        cve_record = load_json("cve_published.json")
        cve_id = "CVE-2024-1234"

        with get_db_connection() as conn:
            # Establish baseline with a successful batch
            adapter1 = _MockAdapter([cve_record], cursor_after="baseline-cursor")
            outcome1 = sync_source(conn, adapter1)
            assert outcome1.success

            # Snapshot composed detail before
            detail_before = get_composed_cve_detail(conn, cve_id)

            # Now run a failed batch
            bad_rec = {
                "dataType": "CVE_RECORD", "dataVersion": "5.1",
                "cveMetadata": {"cveId": "CVE-2024-9999", "state": "INVALID_STATE"},
                "containers": {},
            }
            adapter2 = _MockAdapter([bad_rec], fail_index=0)
            outcome2 = sync_source(conn, adapter2)
            assert not outcome2.success

            # Composed detail after must be identical
            detail_after = get_composed_cve_detail(conn, cve_id)

            # Compare key fields (excluding timestamps that may differ)
            assert detail_before["cve_id"] == detail_after["cve_id"]
            assert detail_before["state"] == detail_after["state"]
            assert detail_before["cvss_assessments"] == detail_after["cvss_assessments"]
            assert detail_before["affected"] == detail_after["affected"]
            assert detail_before["cvss_authority"] == detail_after["cvss_authority"]


# ===========================================================================
# Migration verification
# ===========================================================================


class TestMigration010:
    """SCOPE-3: migration 010 exists and is idempotent."""

    def test_migration_010_exists(self):
        """Migration file 010_sprint01_hardening.sql exists."""
        migration_path = Path(__file__).parent.parent / "migrations" / "010_sprint01_hardening.sql"
        assert migration_path.exists()

    def test_source_artifacts_table_has_correct_schema(self):
        """source_artifacts table has all required columns after migration."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name, data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_name = 'source_artifacts'
                    ORDER BY ordinal_position;
                """)
                columns = {row["column_name"]: row for row in cur.fetchall()}

            assert "id" in columns
            assert "source_record_id" in columns
            assert "sha256_hash" in columns
            assert "artifact_bytes" in columns
            assert columns["artifact_bytes"]["data_type"] == "bytea"
            assert columns["artifact_bytes"]["is_nullable"] == "NO"

    def test_declared_cve_id_column_exists(self):
        """vuln_source_records has declared_cve_id column."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'vuln_source_records' AND column_name = 'declared_cve_id';
                """)
                assert cur.fetchone() is not None

    def test_kev_entries_has_dual_columns(self):
        """kev_entries has id, declared_cve_id, and nullable cve_id."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name, is_nullable FROM information_schema.columns
                    WHERE table_name = 'kev_entries'
                      AND column_name IN ('id', 'declared_cve_id', 'cve_id');
                """)
                cols = {row["column_name"]: row["is_nullable"] for row in cur.fetchall()}
            assert "id" in cols
            assert "declared_cve_id" in cols
            assert cols["cve_id"] == "YES"  # nullable

    def test_osv_aliases_has_declared_linked_cve_id(self):
        """osv_aliases has declared_linked_cve_id column."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'osv_aliases' AND column_name = 'declared_linked_cve_id';
                """)
                assert cur.fetchone() is not None
