"""Tests for SCOUT Canonical Vulnerability Catalogue & Reference Separation.

Validates:
- GET /api/scout/vulnerabilities queries only canonical tables
- Filtering by status, search, KEV status, ransomware use, vendor/product
- GET /api/scout/vulnerabilities/{cve_id} returns all assessments + preferred CVSS + KEV
- Strict 400 on malformed CVE, 404 on missing CVE
- GET /api/scout/stats reports both reference catalogue metrics and tenant scan activity
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from index import app  # noqa: E402
from models import (  # noqa: E402
    Asset,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    Finding,
    ScanFinding,
    ScanJob,
    VulnerabilityCvssAssessment,
)
from routers.auth import get_current_user  # noqa: E402
from services.database import get_db  # noqa: E402


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_scout.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Pre-seed canonical vulnerabilities
    cve1 = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j2 JNDI RCE",
        description_source="NVD",
        published_at=datetime(2021, 12, 10, tzinfo=timezone.utc),
    )
    cvss1_v31 = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-V31",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
    )
    kev1 = CisaKevEntry(
        id="KEV-CVE-2021-44228",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        date_added="2021-12-10",
        due_date="2021-12-24",
        required_action="Apply vendor mitigations",
        known_ransomware_campaign_use="Known",
    )

    cve2 = CanonicalVulnerability(
        cve_id="CVE-2023-38606",
        status="published",
        description="Apple iOS WebKit kernel privilege escalation",
        description_source="NVD",
        published_at=datetime(2023, 7, 24, tzinfo=timezone.utc),
    )
    cvss2_v31 = VulnerabilityCvssAssessment(
        id="CVSS-APPLE-V31",
        cve_id="CVE-2023-38606",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        base_score=7.8,
        base_severity="HIGH",
    )
    kev2 = CisaKevEntry(
        id="KEV-CVE-2023-38606",
        cve_id="CVE-2023-38606",
        vendor_project="Apple",
        product="iOS",
        vulnerability_name="Apple iOS WebKit RCE",
        date_added="2023-07-26",
        known_ransomware_campaign_use="Unknown",
    )

    cve3_rejected = CanonicalVulnerability(
        cve_id="CVE-2020-99999",
        status="rejected",
        description="** REJECT ** DO NOT USE. Consult IDs: CVE-2020-11111.",
        description_source="NVD",
        replaced_by_cve_id="CVE-2020-11111",
    )

    session.add_all([cve1, cvss1_v31, kev1, cve2, cvss2_v31, kev2, cve3_rejected])

    # Pre-seed some tenant data to test separation
    asset = Asset(id="A-SCOUT", tenant_id="tenant-scout", name="Scout Target", asset_type="server", status="active")
    finding = Finding(
        id="F-SCOUT-1",
        tenant_id="tenant-scout",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Tenant customer finding",
        cvss=10.0,
    )
    session.add_all([asset, finding])

    session.commit()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    def override_get_current_user():
        return {
            "sub": "analyst@example.test",
            "role": "Analyst",
            "tenant_id": "tenant-scout",
            "tier": "enterprise",
            "is_superadmin": False,
        }

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_get_scout_vulnerabilities_catalogue(client):
    response = client.get("/api/scout/vulnerabilities")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "meta" in data
    assert data["meta"]["total"] == 3

    # Check first item structure
    items = {item["cve_id"]: item for item in data["data"]}
    assert "CVE-2021-44228" in items
    log4j = items["CVE-2021-44228"]
    assert log4j["status"] == "published"
    assert log4j["cvss"]["score"] == 10.0
    assert log4j["cvss"]["version"] == "3.1"
    assert log4j["cisa_kev"]["is_kev"] is True
    assert log4j["cisa_kev"]["is_ransomware"] is True


def test_get_scout_vulnerabilities_filters(client):
    # Filter by ransomware_only
    r_resp = client.get("/api/scout/vulnerabilities?ransomware_only=true")
    assert r_resp.status_code == 200
    r_data = r_resp.json()
    assert r_data["meta"]["total"] == 1
    assert r_data["data"][0]["cve_id"] == "CVE-2021-44228"

    # Filter by status=rejected
    rej_resp = client.get("/api/scout/vulnerabilities?status=rejected")
    assert rej_resp.status_code == 200
    rej_data = rej_resp.json()
    assert rej_data["meta"]["total"] == 1
    assert rej_data["data"][0]["cve_id"] == "CVE-2020-99999"
    assert rej_data["data"][0]["replaced_by_cve_id"] == "CVE-2020-11111"

    # Search filter
    search_resp = client.get("/api/scout/vulnerabilities?search=WebKit")
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert search_data["meta"]["total"] == 1
    assert search_data["data"][0]["cve_id"] == "CVE-2023-38606"


def test_get_scout_vulnerability_by_cve_details(client):
    response = client.get("/api/scout/vulnerabilities/CVE-2021-44228")
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2021-44228"
    assert data["preferred_cvss"]["score"] == 10.0
    assert len(data["all_cvss_assessments"]) == 1
    assert data["cisa_kev"]["is_kev"] is True
    assert data["cisa_kev"]["vendor_project"] == "Apache"


def test_get_scout_vulnerability_by_cve_errors(client):
    # Malformed CVE -> 400
    bad_resp = client.get("/api/scout/vulnerabilities/INVALID_CVE_STRING")
    assert bad_resp.status_code == 400

    # Non-existent CVE -> 404
    missing_resp = client.get("/api/scout/vulnerabilities/CVE-1999-9999")
    assert missing_resp.status_code == 404


def test_get_scout_stats(client):
    response = client.get("/api/scout/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "reference_catalogue" in stats
    assert stats["reference_catalogue"]["canonical_vulnerabilities"] == 3
    assert stats["reference_catalogue"]["cisa_kev_catalog_entries"] == 2
    assert "customer_scan_activity" in stats
