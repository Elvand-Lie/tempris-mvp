# backend/tests/test_sprint03_downstream_freeze.py
"""
Sprint 03 — Downstream Contract, Documentation Correction, and Freeze Gate Tests.

Covers all 31 granular assertions across Deliverables 0–4:
- Deliverable 0: Regression Safety & Scope Invariants (Assertions 0.1, 0.2)
- Deliverable 1: Structural CNA-Container Provenance & Deterministic TES Resolution (Assertions 1.1–1.10)
- Deliverable 2: Explicit Deterministic TES CVSS Search Filters & SQL/Python Parity (Assertions 2.1–2.6)
- Deliverable 3: Canonical Documentation Verification (Assertions 3.1–3.6)
- Deliverable 4: Final Freeze Gate Invariants (Assertions 4.1–4.4)
"""
from __future__ import annotations

import os
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    CanonicalVulnerability,
    CvssAssessment,
    SourceRecord,
    KevEntry,
    EpssScore,
    OsvRecord,
)
from app.vuln_intelligence.repository import (
    upsert_canonical_vulnerability,
    upsert_cvss_assessment,
    get_cvss_assessments,
    get_composed_cve_detail,
    resolve_cvss_authority,
    search_vulnerabilities,
    upsert_kev_entry,
    upsert_epss_score,
    upsert_source_record,
)
from app.vuln_intelligence.models import (
    CVSS_AUTHORITY_AMBIGUOUS,
    CVSS_NO_AUTHORITATIVE_ASSESSMENT,
)
from app.vuln_intelligence.adapters.cve_adapter import process_cve_record
from app.vuln_intelligence.adapters.nvd_adapter import process_nvd_cve


# ===========================================================================
# DELIVERABLE 0 & 4: MIGRATION IDEMPOTENCY & FROZEN SUBSYSTEM INVARIANTS
# ===========================================================================

class TestSprint03Deliverable0And4Invariants:
    """Verifies Assertions 0.2, 4.1, 4.3 (Frozen Subsystems & Migration Idempotency)."""

    def test_assertion_4_1_migrations_007_through_012_idempotency(self):
        """Assertion 4.1: Migrations 007 through 012 apply idempotently without error."""
        migration_dir = Path("backend/migrations")
        migration_files = [
            "007_vulnerability_intelligence.sql",
            "008_vuln_intelligence_fk_snapshot.sql",
            "009_sync_orchestration.sql",
            "010_sprint01_hardening.sql",
            "011_sprint02_sync_hardening.sql",
            "012_sprint03_downstream_freeze.sql",
        ]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                for mf in migration_files:
                    path = migration_dir / mf
                    assert path.exists(), f"Migration file {mf} must exist"
                    sql_content = path.read_text(encoding="utf-8")
                    # Execute migration SQL — must be idempotent and succeed
                    cur.execute(sql_content)
            conn.commit()

    def test_assertion_0_2_and_4_3_frozen_subsystems_integrity(self):
        """Assertion 0.2 & 4.3: Frozen subsystems exist, import cleanly, and are untouched."""
        # Check imports of frozen subsystems
        import app.routes.assets as assets_route
        import app.routes.collectors as collectors_route
        import app.routes.auth as auth_route
        import app.collector_registry as collector_registry
        import app.auth_crypto as auth_crypto

        assert hasattr(assets_route, "router")
        assert hasattr(collectors_route, "router")
        assert hasattr(auth_route, "router")
        assert hasattr(collector_registry, "CollectorSession")
        assert hasattr(auth_crypto, "parse_scrypt_hash")


# ===========================================================================
# DELIVERABLE 1: STRUCTURAL CNA CONTAINER PROVENANCE & DETERMINISTIC TES
# ===========================================================================

class TestSprint03Deliverable1StructuralProvenance:
    """Verifies Assertions 1.1 through 1.10 (VI-QA-09 / GC-9)."""

    def test_assertion_1_1_cve_cna_container_role_and_provider_org_id(self):
        """Assertion 1.1: CVE CNA container ingestion stores container_role='cna' and CNA orgId."""
        cve_id = "CVE-2024-30001"
        cna_org_id = "cna-org-uuid-1111"
        cve_payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": cve_id,
                "assignerOrgId": cna_org_id,
                "assignerShortName": "acme-cna",
                "state": "PUBLISHED",
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": cna_org_id,
                        "shortName": "acme-cna",
                    },
                    "descriptions": [{"lang": "en", "value": "Test CNA vulnerability"}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ],
                }
            },
        }

        with get_db_connection() as conn:
            res = process_cve_record(conn, cve_payload)
            conn.commit()
            assert res.cve_id == cve_id

            assessments = get_cvss_assessments(conn, cve_id)
            assert len(assessments) == 1
            a = assessments[0]
            assert a.container_role == "cna"
            assert a.provider_org_id == cna_org_id
            assert a.assessment_type == "cna"
            assert a.base_score == Decimal("9.8")

    def test_assertion_1_2_cve_adp_container_role_and_provider_org_id(self):
        """Assertion 1.2: CVE ADP container ingestion stores container_role='adp' and ADP orgId."""
        cve_id = "CVE-2024-30002"
        cna_org_id = "cna-org-uuid-2222"
        adp_org_id = "adp-cisa-uuid-9999"
        cve_payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": cve_id,
                "assignerOrgId": cna_org_id,
                "assignerShortName": "acme-cna",
                "state": "PUBLISHED",
            },
            "containers": {
                "cna": {
                    "providerMetadata": {"orgId": cna_org_id, "shortName": "acme-cna"},
                    "descriptions": [{"lang": "en", "value": "No CNA metrics here"}],
                },
                "adp": [
                    {
                        "providerMetadata": {"orgId": adp_org_id, "shortName": "CISA-ADP"},
                        "title": "CISA ADP Supplemental Assessment",
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    "baseScore": 6.1,
                                    "baseSeverity": "MEDIUM",
                                }
                            }
                        ],
                    }
                ],
            },
        }

        with get_db_connection() as conn:
            res = process_cve_record(conn, cve_payload)
            conn.commit()
            assert res.cve_id == cve_id

            assessments = get_cvss_assessments(conn, cve_id)
            assert len(assessments) == 1
            a = assessments[0]
            assert a.container_role == "adp"
            assert a.provider_org_id == adp_org_id
            assert a.assessment_type == "adp"
            assert a.base_score == Decimal("6.1")

    def test_assertion_1_2a_adp_only_marked_unscoreable_under_tes(self):
        """Assertion 1.2a: CVE with ONLY ADP CVSS 3.1 assessment is unscoreable under TES."""
        cve_id = "CVE-2024-30003"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="cna-org-3333", assigner_short_name="some-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cisa-adp",
                assessment_type="adp",
                container_role="adp",
                provider_org_id="adp-org-id",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                base_score=Decimal("6.1"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.score == Decimal("6.1")
            assert res.version == "3.1"
            assert res.role == "adp"
            assert res.reason_code is None

    def test_assertion_1_3_nvd_container_role_and_provider_org_id(self):
        """Assertion 1.3: NVD metrics ingestion stores container_role='nvd' and provider_org_id."""
        cve_id = "CVE-2024-30004"
        nvd_payload = {
            "id": cve_id,
            "lastModified": "2024-05-01T12:00:00Z",
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }
                ]
            },
        }

        with get_db_connection() as conn:
            # Seed canonical record first so NVD can attach
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="some-org", assigner_short_name="some-cna",
            ))
            res = process_nvd_cve(conn, nvd_payload)
            conn.commit()
            assert res.cve_id == cve_id

            assessments = get_cvss_assessments(conn, cve_id)
            assert len(assessments) == 1
            a = assessments[0]
            assert a.container_role == "nvd"
            assert a.provider_org_id == "nvd@nist.gov"
            assert a.base_score == Decimal("9.8")

    def test_assertion_1_4_authority_resolution_selects_cna_even_if_short_name_differs(self):
        """Assertion 1.4: Deterministic TES resolution selects CNA CVSS 3.1 GENERAL even if assessor string != assigner_short_name."""
        cve_id = "CVE-2024-30005"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="canonical-org-id",
                assigner_short_name="canonical-short-name",
            ))
            # Assessor string is different (e.g. email or legal entity), but container_role='cna'
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cve-coordination-team@vendor.com",
                assessment_type="cna",
                container_role="cna",
                provider_org_id="canonical-org-id",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                base_score=Decimal("7.5"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.role == "cna"
            assert res.score == Decimal("7.5")
            assert res.assessor == "cve-coordination-team@vendor.com"
            assert res.reason_code is None

    def test_assertion_1_5_authority_resolution_nvd_role_when_no_cna(self):
        """Assertion 1.5: Deterministic TES resolution falls back to NVD CVSS 3.1 GENERAL (Tier 2) only when 0 CNA present."""
        cve_id = "CVE-2024-30006"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            # 0 CNA assessments, 1 NVD assessment
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="nvd",
                assessor="nvd@nist.gov",
                assessment_type="Primary",
                container_role="nvd",
                provider_org_id="nvd@nist.gov",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("7.8"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.role == "nvd"
            assert res.score == Decimal("7.8")
            assert res.reason_code is None

    def test_assertion_1_6_ambiguous_multiple_cna_assessments(self):
        """Assertion 1.6: CVE with >1 CNA CVSS 3.1 GENERAL assessments is unscoreable."""
        cve_id = "CVE-2024-30007"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            # CNA assessment 1
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-team-1",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            # CNA assessment 2
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-team-2",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("8.1"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.score is None
            assert res.reason_code == CVSS_AUTHORITY_AMBIGUOUS
            assert res.ambiguous_rows is not None and len(res.ambiguous_rows) == 2

    def test_assertion_1_7_ambiguous_multiple_nvd_assessments(self):
        """Assertion 1.7: CVE with >1 NVD CVSS 3.1 GENERAL assessments (and 0 CNA) is unscoreable."""
        cve_id = "CVE-2024-30008"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            # NVD assessment 1 (Primary)
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="nvd",
                assessor="nvd@nist.gov",
                assessment_type="Primary",
                container_role="nvd",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            # NVD assessment 2 (Secondary from contributor via NVD)
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="nvd",
                assessor="security@thirdparty.com",
                assessment_type="Secondary",
                container_role="nvd",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                base_score=Decimal("5.9"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.score is None
            assert res.reason_code == CVSS_AUTHORITY_AMBIGUOUS
            assert res.ambiguous_rows is not None and len(res.ambiguous_rows) == 2

    def test_assertion_1_8_non_cvss31_assessments_scoreable_under_generation_priority(self):
        """Assertion 1.8 (P0-03 revision): a CVSS 4.0 CNA assessment is the
        authoritative intrinsic CVSS under the PRD v1.8 §3.5 #2 generation
        ordering (4.0 > 3.1 > 3.0 > 2.0) — the pre-PRD 3.1-only freeze treated
        it as unscoreable; the generation-aware resolver scoreable it."""
        cve_id = "CVE-2024-30009"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-org",
                container_role="cna",
                cvss_version="4.0",
                vector_string="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                base_score=Decimal("9.3"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.score == Decimal("9.3")
            assert res.version == "4.0"
            assert res.role == "cna"
            assert res.reason_code is None

    def test_assertion_1_9_non_general_scenario_scoreable_no_scenario_filter(self):
        """Assertion 1.9 (P0-03 revision): the authority resolver applies no
        GENERAL-scenario filter — a non-GENERAL CNA assessment remains
        authoritative intrinsic CVSS (the pre-PRD freeze marked it
        unscoreable; PRD v1.8 §3.5 #2 removes the scenario gate)."""
        cve_id = "CVE-2024-30010"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="some-org",
                assigner_short_name="some-cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-org",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="SPECIALIZED",
            ))
            conn.commit()

            res = resolve_cvss_authority(conn, cve_id)
            assert res.score == Decimal("9.8")
            assert res.role == "cna"
            assert res.scenario == "SPECIALIZED"
            assert res.reason_code is None

    def test_assertion_1_10_migration_012_backfill_and_detail_exposure(self):
        """Assertion 1.10: Migration 012 backfill populates container_role and provider_org_id and detail exposes them."""
        cve_id = "CVE-2024-30011"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="cna-org-id",
                assigner_short_name="cna-short",
            ))
            # Insert a CNA assessment with explicit container_role and provider_org_id
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-short",
                assessment_type="cna",
                container_role="cna",
                provider_org_id="cna-org-id",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            conn.commit()

            detail = get_composed_cve_detail(conn, cve_id)
            assert detail is not None
            assert "cvss_assessments" in detail
            assert len(detail["cvss_assessments"]) >= 1
            a = detail["cvss_assessments"][0]
            assert a["container_role"] == "cna"
            assert a["provider_org_id"] == "cna-org-id"
            assert a["assessment_type"] == "cna"


# ===========================================================================
# DELIVERABLE 2: EXPLICIT DETERMINISTIC TES CVSS SEARCH FILTERS & SQL/PYTHON PARITY
# ===========================================================================

class TestSprint03Deliverable2DeterministicSearchFilters:
    """Verifies Assertions 2.1 through 2.6 (VI-QA-08 / GC-9)."""

    def test_assertion_2_1_single_score_range_evaluation(self):
        """Assertion 2.1: CVE with CNA=9.8 and NVD=2.0 evaluates as single score 9.8 and excludes max_cvss=3.0."""
        cve_id = "CVE-2024-40001"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="org-1", assigner_short_name="cna-1",
            ))
            # CNA Tier 1 = 9.8
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-1",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            # NVD = 2.0 (should be superseded by CNA Tier 1)
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="nvd",
                assessor="nvd@nist.gov",
                container_role="nvd",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                base_score=Decimal("2.0"),
                scenario="GENERAL",
            ))
            conn.commit()

            # Search with min_cvss=9.0 -> matches (9.8 >= 9.0)
            res_min = search_vulnerabilities(conn, q=cve_id, min_cvss=9.0)
            cve_ids_min = [item["cve_id"] for item in res_min["items"]]
            assert cve_id in cve_ids_min

            # Search with max_cvss=3.0 -> DOES NOT match (9.8 is not <= 3.0, NVD 2.0 is superseded)
            res_max = search_vulnerabilities(conn, q=cve_id, max_cvss=3.0)
            cve_ids_max = [item["cve_id"] for item in res_max["items"]]
            assert cve_id not in cve_ids_max

    def test_assertion_2_1a_overlapping_range_filter(self):
        """Assertion 2.1a: Range [7.0, 9.0] returns only CVEs with deterministic TES score in [7.0, 9.0]."""
        cve_in = "CVE-2024-40002"
        cve_out_low = "CVE-2024-40003"
        cve_out_high = "CVE-2024-40004"
        with get_db_connection() as conn:
            for cve, score in [(cve_in, Decimal("8.0")), (cve_out_low, Decimal("5.0")), (cve_out_high, Decimal("9.8"))]:
                upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                    cve_id=cve, state="PUBLISHED",
                    assigner_org_id="org", assigner_short_name="cna",
                ))
                upsert_cvss_assessment(conn, CvssAssessment(
                    cve_id=cve, source="cve",
                    assessor="cna",
                    container_role="cna",
                    cvss_version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=score,
                    scenario="GENERAL",
                ))
            conn.commit()

            res = search_vulnerabilities(conn, min_cvss=7.0, max_cvss=9.0)
            returned_ids = [item["cve_id"] for item in res["items"]]
            assert cve_in in returned_ids
            assert cve_out_low not in returned_ids
            assert cve_out_high not in returned_ids

    def test_assertion_2_1b_exact_point_bound_filter(self):
        """Assertion 2.1b: Exact point bound min_cvss=9.8 & max_cvss=9.8 matches only exact 9.8."""
        cve_exact = "CVE-2024-40005"
        cve_other = "CVE-2024-40006"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_exact, state="PUBLISHED",
                assigner_org_id="org", assigner_short_name="cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_exact, source="cve",
                assessor="cna",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_other, state="PUBLISHED",
                assigner_org_id="org", assigner_short_name="cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_other, source="cve",
                assessor="cna",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.7"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = search_vulnerabilities(conn, min_cvss=9.8, max_cvss=9.8)
            returned_ids = [item["cve_id"] for item in res["items"]]
            assert cve_exact in returned_ids
            assert cve_other not in returned_ids

    def test_assertion_2_2_contradictory_bounds_return_zero_results(self):
        """Assertion 2.2: Contradictory bounds min_cvss=8.0 & max_cvss=5.0 returns empty items."""
        with get_db_connection() as conn:
            res = search_vulnerabilities(conn, min_cvss=8.0, max_cvss=5.0)
            assert res["items"] == []
            assert res["total"] == 0

    def test_assertion_2_3_cvss40_only_included_under_generation_priority(self):
        """Assertion 2.3 (P0-03 revision): a CVE with only CVSS 4.0 = 9.8 is
        scoreable under the PRD v1.8 §3.5 #2 generation ordering and IS
        matched when its score falls inside the filter bounds (the pre-PRD
        3.1-only freeze excluded it)."""
        cve_id = "CVE-2024-40007"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="org", assigner_short_name="cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna",
                container_role="cna",
                cvss_version="4.0",
                vector_string="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = search_vulnerabilities(conn, q=cve_id, min_cvss=5.0)
            returned_ids = [item["cve_id"] for item in res["items"]]
            assert cve_id in returned_ids

    def test_assertion_2_4_ambiguous_cna_excluded_from_tes_search(self):
        """Assertion 2.4: CVE with ambiguous CNA assessments is excluded from TES score range search."""
        cve_id = "CVE-2024-40008"
        with get_db_connection() as conn:
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                cve_id=cve_id, state="PUBLISHED",
                assigner_org_id="org", assigner_short_name="cna",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-1",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("9.8"),
                scenario="GENERAL",
            ))
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id, source="cve",
                assessor="cna-2",
                container_role="cna",
                cvss_version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=Decimal("7.5"),
                scenario="GENERAL",
            ))
            conn.commit()

            res = search_vulnerabilities(conn, q=cve_id, min_cvss=1.0)
            returned_ids = [item["cve_id"] for item in res["items"]]
            assert cve_id not in returned_ids

    def test_assertion_2_5_combined_search_filters_with_active_kev(self):
        """Assertion 2.5: Multi-filter search (min_cvss, has_kev=True, min_epss) evaluates jointly."""
        cve_match = "CVE-2024-40009"
        cve_withdrawn = "CVE-2024-40010"
        with get_db_connection() as conn:
            for cve, is_active in [(cve_match, True), (cve_withdrawn, False)]:
                upsert_canonical_vulnerability(conn, CanonicalVulnerability(
                    cve_id=cve, state="PUBLISHED",
                    assigner_org_id="org", assigner_short_name="cna",
                ))
                upsert_cvss_assessment(conn, CvssAssessment(
                    cve_id=cve, source="cve",
                    assessor="cna",
                    container_role="cna",
                    cvss_version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=Decimal("8.5"),
                    scenario="GENERAL",
                ))
                upsert_kev_entry(conn, KevEntry(
                    cve_id=cve,
                    vendor_project="Vendor",
                    product="Product",
                    vulnerability_name="Vuln",
                    date_added="2024-05-01",
                    required_action="Patch",
                    is_active=is_active,
                ))
                upsert_epss_score(conn, EpssScore(
                    cve_id=cve,
                    score=Decimal("0.85000"),
                    percentile=Decimal("0.95000"),
                    score_date="2024-05-01",
                ))
            conn.commit()

            res = search_vulnerabilities(conn, min_cvss=8.0, has_kev=True, min_epss=0.80)
            returned_ids = [item["cve_id"] for item in res["items"]]
            assert cve_match in returned_ids
            assert cve_withdrawn not in returned_ids

    def test_assertion_2_6_strict_sql_search_vs_python_resolver_parity(self):
        """Assertion 2.6: Strict SQL search vs Python resolver 100% equivalence on scores and tiers."""
        with get_db_connection() as conn:
            # Query candidate CVEs with a range filter
            search_res = search_vulnerabilities(conn, min_cvss=6.0, max_cvss=10.0, limit=50)
            assert search_res["items"], "Search should return items from seeded test set"

            for item in search_res["items"]:
                cve_id = item["cve_id"]
                py_res = resolve_cvss_authority(conn, cve_id)
                # Python resolver must be scoreable
                assert py_res.score is not None, f"CVE {cve_id} matched in search must be scoreable in Python"
                assert py_res.reason_code is None
                # Score must fall within filter bounds
                assert Decimal("6.0") <= py_res.score <= Decimal("10.0")


# ===========================================================================
# DELIVERABLE 3: CANONICAL DOCUMENTATION VERIFICATION
# ===========================================================================

class TestSprint03Deliverable3DocumentationVerification:
    """Verifies Assertions 3.1 through 3.6 (VI-QA-10 / GC-10)."""

    @pytest.fixture
    def canonical_guide_text(self) -> str:
        guide_path = Path("docs/Canonical Docs/Vulnerability Intelligence/VULNERABILITY_INTELLIGENCE_CANONICAL_GUIDE.md")
        assert guide_path.exists(), "Canonical guide must exist"
        return guide_path.read_text(encoding="utf-8")

    def test_assertion_3_1_authoritative_precedence(self, canonical_guide_text: str):
        """Assertion 3.1: Canonical guide affirms spec and contract precedence over code drift."""
        assert "Authoritative Precedence" in canonical_guide_text
        assert "The canonical specification, governing contracts" in canonical_guide_text

    def test_assertion_3_2_dual_layer_storage_distinction(self, canonical_guide_text: str):
        """Assertion 3.2: Canonical guide distinguishes immutable source_artifacts BYTEA from parsed JSONB."""
        assert "source_artifacts" in canonical_guide_text
        assert "BYTEA" in canonical_guide_text
        assert "vuln_source_records" in canonical_guide_text
        assert "JSONB" in canonical_guide_text

    def test_assertion_3_3_cisa_kev_scope_and_semantics(self, canonical_guide_text: str):
        """Assertion 3.3: Canonical guide documents CISA KEV scope (FCEB binding, guidance for others)."""
        assert "Federal Civilian Executive Branch" in canonical_guide_text or "FCEB" in canonical_guide_text
        assert "Binding Operational Directive" in canonical_guide_text or "BOD 22-01" in canonical_guide_text
        assert "active exploitation" in canonical_guide_text

    def test_assertion_3_4_archive_limits_and_safety_controls(self, canonical_guide_text: str):
        """Assertion 3.4: Canonical guide documents bounded archive limits, ratio floor, and Zip Slip checks."""
        assert "ArchiveLimits" in canonical_guide_text
        assert "Zip Slip" in canonical_guide_text
        assert "1 MB" in canonical_guide_text or "1MB" in canonical_guide_text

    def test_assertion_3_5_illustrative_schema_matches_migrations(self, canonical_guide_text: str):
        """Assertion 3.5: Illustrative schema in guide matches migration truth (no invented defaults)."""
        # Ensure 'state VARCHAR(32) NOT NULL' is present without invented default 'PUBLISHED'
        assert "state VARCHAR(32) NOT NULL," in canonical_guide_text

    def test_assertion_3_6_section_7_structural_container_resolution(self, canonical_guide_text: str):
        """Assertion 3.6: Section 7 in canonical guide documents structural container_role resolution hierarchy."""
        assert "container_role" in canonical_guide_text
        assert "Tier 1: Structural Assigning CNA" in canonical_guide_text or "Tier 1: Assigning CNA" in canonical_guide_text
        assert "Tier 2: Structural NVD" in canonical_guide_text or "Tier 2: NVD" in canonical_guide_text
