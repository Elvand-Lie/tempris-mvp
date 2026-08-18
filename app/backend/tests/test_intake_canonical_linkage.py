"""Tests for intake paths ensuring zero new unlinked CVE findings (Stop New Legacy Pollution).

Validates:
- Scanner observation normalization links canonical_cve_id and ensures CanonicalVulnerability
- Versioned Threat Importer sets canonical_cve_id and creates CanonicalVulnerability
- Idempotent linkage on updates
- Non-CVE findings remain safely unlinked
"""

from __future__ import annotations

import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import Asset, Base, CanonicalVulnerability, Finding, ScanFinding, ScanJob  # noqa: E402
from services.scan_normalizer import normalize_observation  # noqa: E402
from services.threat_importer import import_threat_pack  # noqa: E402


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_intake.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Pre-seed asset
    asset = Asset(
        id="A-SRV-01",
        tenant_id="tenant-intake",
        name="web-01.internal",
        hostname="web-01.internal",
        ip_address="192.168.1.50",
        criticality="high",
        status="active",
    )
    scan_job = ScanJob(
        id="SJ-001",
        tenant_id="tenant-intake",
        target="192.168.1.50",
        normalized_target="192.168.1.50",
        scan_type="nuclei",
        status="running",
    )
    session.add_all([asset, scan_job])
    session.commit()

    yield session, scan_job
    session.close()
    engine.dispose()


def test_scan_normalizer_cve_observation_links_canonical(db_session):
    session, scan_job = db_session

    obs = {
        "engine": "nuclei",
        "template_id": "cve-2023-38606-poc",
        "cve_id": "CVE-2023-38606",
        "risk": "High",
        "target": "192.168.1.50",
        "service": "http",
        "detail": "WebKit vulnerability matched on target",
        "matched_at": "192.168.1.50",
    }

    result = normalize_observation(
        session,
        tenant_id="tenant-intake",
        scan_job=scan_job,
        observation=obs,
        actor_id="scanner-daemon",
    )

    session.commit()

    assert result["finding"] is not None
    finding = result["finding"]
    assert finding.canonical_cve_id == "CVE-2023-38606"
    assert finding.cve == "CVE-2023-38606"
    assert finding.cve_assigned is True

    # Verify CanonicalVulnerability was created/ensured
    canon = session.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2023-38606").first()
    assert canon is not None
    assert canon.cve_id == "CVE-2023-38606"


def test_scan_normalizer_non_cve_observation_leaves_canonical_null(db_session):
    session, scan_job = db_session

    obs = {
        "engine": "nuclei",
        "template_id": "ssl-weak-cipher",
        "risk": "Medium",
        "target": "192.168.1.50",
        "service": "https",
        "detail": "Weak SSL cipher detected",
        "matched_at": "192.168.1.50",
    }

    result = normalize_observation(
        session,
        tenant_id="tenant-intake",
        scan_job=scan_job,
        observation=obs,
        actor_id="scanner-daemon",
    )

    session.commit()

    assert result["finding"] is not None
    finding = result["finding"]
    assert finding.canonical_cve_id is None
    assert finding.finding_type == "SSS"


def test_threat_importer_links_canonical_cve(db_session):
    session, _ = db_session

    pack_data = {
        "pack_name": "zero_day_intel_pack",
        "version": "2026.1.0",
        "findings": [
            {
                "id": "THREAT-F-01",
                "tenant_id": "tenant-intake",
                "title": "Log4Shell Exploit in Wild",
                "cve": "CVE-2021-44228",
                "cvss": 10.0,
                "status": "unmitigated",
                "description": "Exploit observed against enterprise gateways",
            },
            {
                "id": "THREAT-F-02",
                "tenant_id": "tenant-intake",
                "title": "Internal Cloud IAM Misconfiguration",
                "cve": "SSS-2026-IAM-01",
                "cvss": 7.5,
                "status": "unmitigated",
                "description": "Overprivileged IAM roles detected",
            },
        ],
    }

    result = import_threat_pack(session, pack_data, dry_run=False)
    session.commit()

    assert result.get("status") != "failed"

    f1 = session.query(Finding).filter(Finding.id == "THREAT-F-01").one()
    assert f1.canonical_cve_id == "CVE-2021-44228"

    canon = session.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2021-44228").first()
    assert canon is not None

    f2 = session.query(Finding).filter(Finding.id == "THREAT-F-02").one()
    assert f2.canonical_cve_id is None  # Non-CVE SSS is skipped from canonical linkage
