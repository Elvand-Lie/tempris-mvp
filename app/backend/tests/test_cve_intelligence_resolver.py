"""Unit and integration tests for Canonical Vulnerability Intelligence Resolver.

Validates:
- Authoritative resolution of canonical vulnerability intelligence
- Deterministic CVSS selection policy (v4.0 > v3.1 > v3.0 > v2.0; Primary > Secondary; Latest modified timestamp)
- CISA KEV precedence over legacy finding flags
- Graceful, read-only legacy fallback when canonical CVSS is absent
- Rejection/superseded CVE metadata resolution
- Zero pollution of canonical tables by fallback data
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import Base, CanonicalVulnerability, CisaKevEntry, Finding, VulnerabilityCvssAssessment  # noqa: E402
from services.cve_intelligence import (  # noqa: E402
    resolve_vulnerability_intelligence,
    select_preferred_cvss_assessment,
)


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_resolver.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # 1. Fully assessed CVE with multiple CVSS versions and sources
    cve_multiversion = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j2 JNDI RCE vulnerability",
        description_source="NVD",
        published_at=datetime(2021, 12, 10, 10, 0, 0, tzinfo=timezone.utc),
    )
    # v2.0 assessment
    cvss_v2 = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-V2",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="2.0",
        vector_string="AV:N/AC:M/Au:N/C:C/I:C/A:C",
        base_score=9.3,
        base_severity="HIGH",
        source_modified_at=datetime(2021, 12, 10, tzinfo=timezone.utc),
    )
    # v3.1 Secondary assessment
    cvss_v31_sec = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-V31-SEC",
        cve_id="CVE-2021-44228",
        source="security@apache.org",
        source_role="Secondary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
        source_modified_at=datetime(2021, 12, 10, tzinfo=timezone.utc),
    )
    # v3.1 Primary assessment (newer)
    cvss_v31_pri = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-V31-PRI",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
        source_modified_at=datetime(2021, 12, 15, tzinfo=timezone.utc),
    )
    # CISA KEV entry
    kev_log4j = CisaKevEntry(
        id="KEV-CVE-2021-44228",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        date_added="2021-12-10",
        due_date="2021-12-24",
        required_action="Apply patches immediately",
        known_ransomware_campaign_use="Known",
    )
    session.add_all([cve_multiversion, cvss_v2, cvss_v31_sec, cvss_v31_pri, kev_log4j])

    # 2. Canonical CVE with NO CVSS assessments (unassessed canonical)
    cve_unassessed = CanonicalVulnerability(
        cve_id="CVE-2026-0001",
        status="published",
        description="Freshly published zero-day vulnerability",
        description_source="NVD",
    )
    session.add(cve_unassessed)

    # 3. Rejected Canonical CVE with replacement
    cve_rejected = CanonicalVulnerability(
        cve_id="CVE-2022-99999",
        status="rejected",
        description="** REJECT ** DO NOT USE. Consult IDs: CVE-2022-12345.",
        description_source="NVD",
        replaced_by_cve_id="CVE-2022-12345",
    )
    session.add(cve_rejected)

    session.commit()
    yield session
    session.close()
    engine.dispose()


def test_select_preferred_cvss_assessment():
    a_v2 = VulnerabilityCvssAssessment(
        id="A1", cve_id="CVE-2020-0001", cvss_version="2.0", base_score=10.0, source_role="Primary"
    )
    a_v30 = VulnerabilityCvssAssessment(
        id="A2", cve_id="CVE-2020-0001", cvss_version="3.0", base_score=7.5, source_role="Primary"
    )
    a_v31_sec = VulnerabilityCvssAssessment(
        id="A3", cve_id="CVE-2020-0001", cvss_version="3.1", base_score=8.0, source_role="Secondary",
        source_modified_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    a_v31_pri = VulnerabilityCvssAssessment(
        id="A4", cve_id="CVE-2020-0001", cvss_version="3.1", base_score=8.5, source_role="Primary",
        source_modified_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    a_v40 = VulnerabilityCvssAssessment(
        id="A5", cve_id="CVE-2020-0001", cvss_version="4.0", base_score=9.0, source_role="Primary"
    )

    # Version ranking: v4.0 beats all lower versions regardless of scores
    assert select_preferred_cvss_assessment([a_v2, a_v30, a_v31_pri, a_v40]).id == "A5"
    # When v4.0 is absent, v3.1 beats v3.0 and v2.0
    assert select_preferred_cvss_assessment([a_v2, a_v30, a_v31_sec]).id == "A3"
    # When versions match, Primary beats Secondary
    assert select_preferred_cvss_assessment([a_v31_sec, a_v31_pri]).id == "A4"


def test_resolver_canonical_authoritative(db_session):
    finding = Finding(
        id="F-LOG4J",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        cvss=7.0,  # Legacy score that should be superseded by canonical 10.0
        cisa_kev=False,  # Legacy flag that should be superseded by canonical KEV
    )

    intel = resolve_vulnerability_intelligence(finding, db_session)

    assert intel.cve_id == "CVE-2021-44228"
    assert intel.status == "published"
    assert intel.cvss_score == 10.0
    assert intel.cvss_version == "3.1"
    assert intel.cvss_source == "nvd@nist.gov"
    assert intel.cvss_source_role == "Primary"
    assert intel.provenance_classification == "canonical_authoritative"
    assert intel.has_canonical_data is True
    assert intel.used_legacy_fallback is False
    assert intel.is_cisa_kev is True
    assert intel.is_ransomware is True
    assert intel.kev_due_date == "2021-12-24"
    assert intel.kev_required_action == "Apply patches immediately"


def test_resolver_legacy_fallback_when_canonical_unassessed(db_session):
    finding = Finding(
        id="F-UNASSESSED",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2026-0001",
        cve="CVE-2026-0001",
        cvss=8.8,
        cisa_kev=True,
        ransomware=False,
        required_action="Legacy manual mitigation",
    )

    intel = resolve_vulnerability_intelligence(finding, db_session)

    assert intel.cve_id == "CVE-2026-0001"
    assert intel.status == "published"
    assert intel.cvss_score == 8.8
    assert intel.cvss_version == "legacy"
    assert intel.provenance_classification == "legacy_unprovenanced"
    assert intel.has_canonical_data is True
    assert intel.used_legacy_fallback is True
    assert intel.is_cisa_kev is True
    assert intel.kev_required_action == "Legacy manual mitigation"

    # Verify no records were inserted into VulnerabilityCvssAssessment or CisaKevEntry
    count_assessments = (
        db_session.query(VulnerabilityCvssAssessment)
        .filter(VulnerabilityCvssAssessment.cve_id == "CVE-2026-0001")
        .count()
    )
    assert count_assessments == 0


def test_resolver_non_cve_finding(db_session):
    finding = Finding(
        id="F-NON-CVE",
        tenant_id="tenant-alpha",
        title="Custom Internal Security Finding",
        cve="SSS-2026-INTERNAL",
        cvss=6.5,
    )

    intel = resolve_vulnerability_intelligence(finding, db_session)

    assert intel.cve_id is None
    assert intel.provenance_classification == "non_cve"
    assert intel.has_canonical_data is False
    assert intel.cvss_score == 6.5
    assert intel.used_legacy_fallback is True


def test_resolver_rejected_cve_metadata(db_session):
    intel = resolve_vulnerability_intelligence("CVE-2022-99999", db_session)

    assert intel.cve_id == "CVE-2022-99999"
    assert intel.status == "rejected"
    assert intel.replaced_by_cve_id == "CVE-2022-12345"
    assert intel.provenance_classification == "canonical_unassessed"
    assert intel.cvss_score is None
