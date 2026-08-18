"""Unit and integration tests for Finding-to-Canonical link/backfill command.

Validates:
- Exact CVE syntax matching only (CVE-YYYY-NNNN)
- Rejection of malformed/non-CVE identifiers
- Idempotent repeated execution
- Dry-run verification
- Multiple findings linking to the same CanonicalVulnerability without merge/deletion
- Tenant filtering
- Preservation of finding IDs, asset links, and evidence
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import Asset, AssetExposure, Base, CanonicalVulnerability, Finding  # noqa: E402
from services.cve_intelligence import link_findings_to_canonical_cves, validate_and_normalize_cve  # noqa: E402


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_link_cves.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Pre-seed canonical vulnerabilities
    canon1 = CanonicalVulnerability(
        cve_id="CVE-2012-1710",
        status="published",
        description="Oracle RCE in WLS",
        description_source="NVD",
    )
    canon2 = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Log4Shell JNDI RCE",
        description_source="NVD",
    )
    session.add_all([canon1, canon2])

    # Pre-seed assets
    asset1 = Asset(id="A-100", tenant_id="tenant-alpha", name="Alpha Web", asset_type="server", status="active")
    asset2 = Asset(id="A-200", tenant_id="tenant-beta", name="Beta API", asset_type="server", status="active")
    session.add_all([asset1, asset2])

    # Pre-seed diverse findings
    f1 = Finding(
        id="F-001",
        tenant_id="tenant-alpha",
        title="Oracle WLS Vulnerability",
        cve="CVE-2012-1710",
        cve_id="CVE-2012-1710",
        cvss=9.8,
        status="unmitigated",
    )
    f2 = Finding(
        id="F-002",
        tenant_id="tenant-alpha",
        title="Another Oracle WLS instance",
        cve="cve-2012-1710",  # Lowercase to test normalization
        cve_id="CVE-2012-1710",
        cvss=9.8,
        status="unmitigated",
    )
    f3 = Finding(
        id="F-003",
        tenant_id="tenant-beta",
        title="Log4j JNDI RCE",
        cve="CVE-2021-44228",
        cve_id="CVE-2021-44228",
        cvss=10.0,
        status="unmitigated",
    )
    f4_unseen = Finding(
        id="F-004",
        tenant_id="tenant-beta",
        title="New Uncatalogued CVE",
        cve="CVE-2026-9999",
        cve_id="CVE-2026-9999",
        cvss=7.5,
        status="unmitigated",
    )
    f5_non_cve = Finding(
        id="F-005",
        tenant_id="tenant-alpha",
        title="Default Admin Password",
        cve="SSS-2026-PASS",
        cve_id="SSS-2026-PASS",
        cvss=8.0,
        status="unmitigated",
    )
    f6_malformed = Finding(
        id="F-006",
        tenant_id="tenant-alpha",
        title="Malformed CVE string",
        cve="CVE-INVALID-STRING",
        cve_id="CVE-INVALID-STRING",
        cvss=5.0,
        status="unmitigated",
    )
    session.add_all([f1, f2, f3, f4_unseen, f5_non_cve, f6_malformed])

    # Pre-seed asset exposures
    exp1 = AssetExposure(id="EXP-001", tenant_id="tenant-alpha", asset_id="A-100", finding_id="F-001", status="confirmed")
    session.add(exp1)

    session.commit()
    yield session
    session.close()
    engine.dispose()


def test_validate_and_normalize_cve():
    assert validate_and_normalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert validate_and_normalize_cve("  CVE-2012-1710  ") == "CVE-2012-1710"
    with pytest.raises(ValueError):
        validate_and_normalize_cve("NOT-A-CVE")
    with pytest.raises(ValueError):
        validate_and_normalize_cve("")
    with pytest.raises(ValueError):
        validate_and_normalize_cve("CVE-2021")


def test_dry_run_leaves_database_unmodified(db_session):
    result = link_findings_to_canonical_cves(db_session, dry_run=True)
    assert result["dry_run"] is True
    assert result["canonical_links_created"] >= 3
    assert result["malformed_values"] == 1
    assert result["non_cve_findings_skipped"] == 1

    # Verify no links were persisted
    f1 = db_session.query(Finding).filter(Finding.id == "F-001").one()
    assert f1.canonical_cve_id is None


def test_live_backfill_establishes_links_and_creates_unknown_canonical(db_session):
    result = link_findings_to_canonical_cves(db_session, dry_run=False, create_missing_canonical=True)
    assert result["dry_run"] is False
    assert result["canonical_links_created"] == 4  # F-001, F-002, F-003, F-004
    assert result["canonical_identities_created"] == 1  # CVE-2026-9999

    # Verify links
    f1 = db_session.query(Finding).filter(Finding.id == "F-001").one()
    f2 = db_session.query(Finding).filter(Finding.id == "F-002").one()
    f3 = db_session.query(Finding).filter(Finding.id == "F-003").one()
    f4 = db_session.query(Finding).filter(Finding.id == "F-004").one()
    f5 = db_session.query(Finding).filter(Finding.id == "F-005").one()
    f6 = db_session.query(Finding).filter(Finding.id == "F-006").one()

    assert f1.canonical_cve_id == "CVE-2012-1710"
    assert f2.canonical_cve_id == "CVE-2012-1710"  # Coexists with F1 without merge
    assert f3.canonical_cve_id == "CVE-2021-44228"
    assert f4.canonical_cve_id == "CVE-2026-9999"
    assert f5.canonical_cve_id is None  # Non-CVE skipped
    assert f6.canonical_cve_id is None  # Malformed skipped

    # Verify canonical identity created with status='unknown'
    cve_9999 = db_session.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2026-9999").one()
    assert cve_9999.status == "unknown"
    assert cve_9999.description_source == "FINDING_LINKAGE"

    # Verify AssetExposure stability
    exp = db_session.query(AssetExposure).filter(AssetExposure.id == "EXP-001").one()
    assert exp.finding_id == "F-001"
    assert exp.asset_id == "A-100"


def test_idempotent_reexecution(db_session):
    # First execution
    link_findings_to_canonical_cves(db_session, dry_run=False)

    # Second execution
    repeat_result = link_findings_to_canonical_cves(db_session, dry_run=False)
    assert repeat_result["canonical_links_created"] == 0
    assert repeat_result["links_already_present"] == 4
    assert repeat_result["canonical_identities_created"] == 0


def test_tenant_scoping(db_session):
    result = link_findings_to_canonical_cves(db_session, dry_run=False, tenant_id="tenant-alpha")
    assert result["findings_inspected"] == 4  # F-001, F-002, F-005, F-006

    f1 = db_session.query(Finding).filter(Finding.id == "F-001").one()
    f3 = db_session.query(Finding).filter(Finding.id == "F-003").one()

    assert f1.canonical_cve_id == "CVE-2012-1710"
    assert f3.canonical_cve_id is None  # Tenant-beta finding left untouched
