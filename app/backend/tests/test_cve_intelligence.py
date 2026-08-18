"""Tests for Phase 1A Canonical Vulnerability Intelligence Spine.

Validates:
- Normalization and identifier validation
- CISA KEV snapshot ingestion and idempotency
- Multi-version, multi-authority CVSS parsing (v2, v3.0, v3.1, v4.0)
- CVE lifecycle and explicit supersession handling
- Transactional rollback on failure
- Non-regression of existing Finding and AssetExposure tables
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import (
    Asset,
    AssetExposure,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    Finding,
    VulnerabilityCvssAssessment,
)
from services.cve_intelligence import (
    import_cisa_kev_snapshot,
    import_nvd_cve_snapshot,
    validate_and_normalize_cve,
)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'shadow_cve_test.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ── Test Suite A: Identity and Normalization ─────────────────────────────────

def test_cve_normalization_and_validation():
    assert validate_and_normalize_cve("cve-2026-1000") == "CVE-2026-1000"
    assert validate_and_normalize_cve("  CVE-2012-1710  ") == "CVE-2012-1710"
    assert validate_and_normalize_cve("cve-1999-0426") == "CVE-1999-0426"

    with pytest.raises(ValueError, match="Invalid CVE identifier format"):
        validate_and_normalize_cve("INVALID-ID")

    with pytest.raises(ValueError, match="Invalid CVE identifier format"):
        validate_and_normalize_cve("CVE-2026")

    with pytest.raises(ValueError, match="Invalid CVE identifier format"):
        validate_and_normalize_cve("CVE-ABCD-1234")

    with pytest.raises(ValueError, match="non-empty string"):
        validate_and_normalize_cve("")


# ── Test Suite B: CISA KEV Behavior ──────────────────────────────────────────

def test_cisa_kev_import_creates_identity_and_kev_only(db, tmp_path):
    kev_payload = {
        "catalogVersion": "2026.05.22",
        "dateReleased": "2026-05-22T18:00:11Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-9082",
                "vendorProject": "Drupal",
                "product": "Core",
                "vulnerabilityName": "Drupal Core SQL Injection",
                "dateAdded": "2026-05-22",
                "shortDescription": "SQL Injection in Drupal Core",
                "requiredAction": "Apply vendor patch",
                "dueDate": "2026-05-27",
                "knownRansomwareCampaignUse": "Known",
                "notes": "https://nvd.nist.gov/vuln/detail/CVE-2026-9082",
            },
            {
                "cveID": "cve-2025-34291",
                "vendorProject": "Langflow",
                "product": "Langflow",
                "vulnerabilityName": "Langflow Origin Validation Error",
                "dateAdded": "2026-05-21",
                "shortDescription": "Origin Validation Error in Langflow",
                "requiredAction": "Upgrade to v1.9.3",
                "dueDate": "2026-06-04",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "https://nvd.nist.gov/vuln/detail/CVE-2025-34291",
            },
        ],
    }
    kev_file = tmp_path / "cisa_kev_sample.json"
    kev_file.write_text(json.dumps(kev_payload), encoding="utf-8")

    stats = import_cisa_kev_snapshot(kev_file, db)
    assert stats["records_read"] == 2
    assert stats["canonical_created"] == 2
    assert stats["kev_created"] == 2
    assert stats["invalid_records"] == 0

    # Verify zero CVSS assessments, zero findings, zero exposures created
    assert db.query(VulnerabilityCvssAssessment).count() == 0
    assert db.query(Finding).count() == 0
    assert db.query(AssetExposure).count() == 0

    # Verify exact fields preserved
    drupal = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2026-9082").one()
    assert drupal.status == "published"
    assert drupal.description == "SQL Injection in Drupal Core"
    assert drupal.description_source == "CISA-KEV"

    drupal_kev = db.query(CisaKevEntry).filter(CisaKevEntry.cve_id == "CVE-2026-9082").one()
    assert drupal_kev.vendor_project == "Drupal"
    assert drupal_kev.product == "Core"
    assert drupal_kev.known_ransomware_campaign_use == "Known"
    assert drupal_kev.required_action == "Apply vendor patch"

    # Idempotent re-import
    stats_second = import_cisa_kev_snapshot(kev_file, db)
    assert stats_second["canonical_created"] == 0
    assert stats_second["canonical_reused"] == 2
    assert stats_second["kev_created"] == 0
    assert stats_second["kev_unchanged"] == 2
    assert db.query(CanonicalVulnerability).count() == 2
    assert db.query(CisaKevEntry).count() == 2


def test_cisa_kev_update_modifies_existing_without_duplication(db, tmp_path):
    initial_payload = {
        "catalogVersion": "2026.05.22",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1111",
                "vendorProject": "TestVendor",
                "product": "TestProd",
                "vulnerabilityName": "Initial Name",
                "dateAdded": "2026-05-01",
                "dueDate": "2026-05-15",
                "requiredAction": "Initial action",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }
    kev_file = tmp_path / "kev_update.json"
    kev_file.write_text(json.dumps(initial_payload), encoding="utf-8")
    import_cisa_kev_snapshot(kev_file, db)

    entry = db.query(CisaKevEntry).filter(CisaKevEntry.cve_id == "CVE-2026-1111").one()
    assert entry.known_ransomware_campaign_use == "Unknown"

    # Update ransomware status to "Known"
    updated_payload = {
        "catalogVersion": "2026.05.23",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1111",
                "vendorProject": "TestVendor",
                "product": "TestProd",
                "vulnerabilityName": "Updated Name",
                "dateAdded": "2026-05-01",
                "dueDate": "2026-05-15",
                "requiredAction": "Updated action",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
    kev_file.write_text(json.dumps(updated_payload), encoding="utf-8")
    stats = import_cisa_kev_snapshot(kev_file, db)
    assert stats["kev_updated"] == 1
    assert stats["kev_created"] == 0

    db.refresh(entry)
    assert entry.known_ransomware_campaign_use == "Known"
    assert entry.vulnerability_name == "Updated Name"
    assert db.query(CisaKevEntry).count() == 1


# ── Test Suite C: CVSS Behavior ──────────────────────────────────────────────

def test_nvd_import_preserves_multiple_cvss_versions_and_authorities(db, tmp_path):
    nvd_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-5000",
                    "sourceIdentifier": "cve@mitre.org",
                    "published": "2026-06-01T12:00:00Z",
                    "lastModified": "2026-06-02T15:30:00Z",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Multi-authority test vulnerability"}
                    ],
                    "metrics": {
                        "cvssMetricV40": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                    "baseScore": 9.3,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ],
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
                            },
                            {
                                "source": "cna@vendor.com",
                                "type": "Secondary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 8.1,
                                    "baseSeverity": "HIGH",
                                },
                            },
                        ],
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "baseScore": 10.0,
                                },
                                "baseSeverity": "HIGH",
                            }
                        ],
                    },
                }
            }
        ]
    }
    nvd_file = tmp_path / "nvd_multi_cvss.json"
    nvd_file.write_text(json.dumps(nvd_payload), encoding="utf-8")

    stats = import_nvd_cve_snapshot(nvd_file, db)
    assert stats["records_read"] == 1
    assert stats["canonical_created"] == 1
    assert stats["cvss_created"] == 4

    assessments = (
        db.query(VulnerabilityCvssAssessment)
        .filter(VulnerabilityCvssAssessment.cve_id == "CVE-2026-5000")
        .all()
    )
    assert len(assessments) == 4

    versions = {a.cvss_version for a in assessments}
    assert versions == {"4.0", "3.1", "2.0"}

    sources = {(a.source, a.source_role, a.cvss_version, a.base_score) for a in assessments}
    assert ("nvd@nist.gov", "Primary", "4.0", 9.3) in sources
    assert ("nvd@nist.gov", "Primary", "3.1", 9.8) in sources
    assert ("cna@vendor.com", "Secondary", "3.1", 8.1) in sources
    assert ("nvd@nist.gov", "Primary", "2.0", 10.0) in sources

    # Idempotent re-import does not duplicate assessments
    stats_repeat = import_nvd_cve_snapshot(nvd_file, db)
    assert stats_repeat["cvss_created"] == 0
    assert stats_repeat["cvss_unchanged"] == 4
    assert db.query(VulnerabilityCvssAssessment).count() == 4


# ── Test Suite D: CVE Lifecycle and Rejected Status ──────────────────────────

def test_rejected_cve_preserves_status_and_explicit_replacement(db, tmp_path):
    nvd_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "vulnStatus": "Rejected",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2026-1000.",
                        }
                    ],
                }
            }
        ]
    }
    nvd_file = tmp_path / "nvd_rejected.json"
    nvd_file.write_text(json.dumps(nvd_payload), encoding="utf-8")

    # Pre-populate replacement target so FK constraint passes
    db.add(CanonicalVulnerability(cve_id="CVE-2026-1000", status="published"))
    db.commit()

    stats = import_nvd_cve_snapshot(nvd_file, db)
    assert stats["canonical_created"] == 1

    rejected = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2026-9999").one()
    assert rejected.status == "rejected"
    assert rejected.replaced_by_cve_id == "CVE-2026-1000"


def test_rejected_cve_without_explicit_consultid_has_no_inferred_replacement(db, tmp_path):
    nvd_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-8888",
                    "vulnStatus": "Rejected",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "** REJECT ** This candidate was rejected by CNA because it was a duplicate.",
                        }
                    ],
                }
            }
        ]
    }
    nvd_file = tmp_path / "nvd_rejected_no_link.json"
    nvd_file.write_text(json.dumps(nvd_payload), encoding="utf-8")

    import_nvd_cve_snapshot(nvd_file, db)
    rejected = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2026-8888").one()
    assert rejected.status == "rejected"
    assert rejected.replaced_by_cve_id is None


# ── Test Suite E: Transaction Safety ─────────────────────────────────────────

def test_transaction_rolls_back_on_malformed_input(db, tmp_path):
    bad_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "GoodVendor",
                "product": "GoodProd",
                "knownRansomwareCampaignUse": "Unknown",
            },
            # Intentionally corrupt record that causes an unhandled database error
            None,
        ]
    }
    bad_file = tmp_path / "corrupt_kev.json"
    bad_file.write_text(json.dumps(bad_payload), encoding="utf-8")

    with pytest.raises(Exception):
        import_cisa_kev_snapshot(bad_file, db)

    # Confirm complete rollback: CVE-2026-0001 was NOT committed
    assert db.query(CanonicalVulnerability).count() == 0
    assert db.query(CisaKevEntry).count() == 0


# ── Test Suite F: Existing System Non-Regression ─────────────────────────────

def test_existing_findings_and_exposures_are_completely_untouched(db, tmp_path):
    # Set up realistic existing tenant data
    asset = Asset(id="A-PROD", tenant_id="tenant-prod", name="Production Web", criticality="critical", status="active")
    finding = Finding(
        id="F-LEGACY-001",
        tenant_id="tenant-prod",
        title="Oracle Fusion Middleware Remote Code Execution",
        cve="CVE-2012-1710",
        cvss=10.0,
        source="kev",
        status="unmitigated",
        raw_inputs={"cvss": 10.0, "exploitability": 10.0, "business_impact": 5.0, "asset_criticality": 10.0, "threat_actor_activity": 10.0},
    )
    exposure = AssetExposure(
        id="EXP-LEGACY-001",
        tenant_id="tenant-prod",
        finding_id="F-LEGACY-001",
        asset_id="A-PROD",
        status="confirmed",
        evidence="Initial audit evidence",
        match_method="manual",
    )
    db.add_all([asset, finding, exposure])
    db.commit()

    initial_finding_count = db.query(Finding).count()
    initial_exposure_count = db.query(AssetExposure).count()

    # Import CISA KEV snapshot containing CVE-2012-1710
    kev_payload = {
        "catalogVersion": "2026.05.22",
        "vulnerabilities": [
            {
                "cveID": "CVE-2012-1710",
                "vendorProject": "Oracle",
                "product": "Fusion Middleware",
                "vulnerabilityName": "Oracle Fusion Middleware Remote Code Execution",
                "dateAdded": "2022-03-25",
                "requiredAction": "Apply patch per vendor advisory",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
    kev_file = tmp_path / "kev_1710.json"
    kev_file.write_text(json.dumps(kev_payload), encoding="utf-8")
    import_cisa_kev_snapshot(kev_file, db)

    # Assert existing finding and exposure remain 100% unchanged
    assert db.query(Finding).count() == initial_finding_count
    assert db.query(AssetExposure).count() == initial_exposure_count

    refreshed_finding = db.query(Finding).filter(Finding.id == "F-LEGACY-001").one()
    assert refreshed_finding.cvss == 10.0
    assert refreshed_finding.raw_inputs["business_impact"] == 5.0

    refreshed_exposure = db.query(AssetExposure).filter(AssetExposure.id == "EXP-LEGACY-001").one()
    assert refreshed_exposure.status == "confirmed"
    assert refreshed_exposure.evidence == "Initial audit evidence"
