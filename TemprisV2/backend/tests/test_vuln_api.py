# backend/tests/test_vuln_api.py
"""
Integration and contract tests for the Vulnerability Intelligence Read API, Search,
Health/Operational endpoints, Lifespan Scheduler, and Tenant Boundary Isolation.
"""
import asyncio
import json
import pytest
from pathlib import Path
from starlette.testclient import TestClient

from app.main import app
from app.db import get_db_connection
from app.vuln_intelligence.models import (
    CanonicalVulnerability,
    CvssAssessment,
    SourceRecord,
    KevEntry,
    EpssScore,
    OsvRecord,
    OsvAlias,
    CveAffected,
    CveAdpEntry,
    CveRelationship,
    SyncSnapshot,
)
from app.vuln_intelligence.repository import (
    upsert_canonical_vulnerability,
    upsert_source_record,
    upsert_cvss_assessment,
    upsert_cve_affected,
    upsert_adp_entry,
    upsert_kev_entry,
    upsert_epss_score,
    upsert_osv_record,
    upsert_osv_alias,
    create_sync_snapshot,
    complete_sync_snapshot,
    upsert_cve_references,
    upsert_cve_weaknesses,
    upsert_cve_relationship,
)
from app.vuln_intelligence.sync_engine import run_sync_loop
from app.vuln_intelligence.sync_adapters import ALL_ADAPTERS


@pytest.fixture
def seeded_intelligence_data():
    """Seed comprehensive vulnerability intelligence test data across all tables."""
    with get_db_connection() as conn:
        test_cves = ["CVE-2023-99901", "CVE-2023-99902"]
        with conn.cursor() as cur:
            cur.execute("DELETE FROM osv_aliases WHERE linked_cve_id = ANY(%s) OR osv_id = 'GHSA-9990-1111-2222';", (test_cves,))
            cur.execute("DELETE FROM osv_records WHERE osv_id = 'GHSA-9990-1111-2222';")
            cur.execute("DELETE FROM cve_relationships WHERE cve_id = ANY(%s) OR related_cve_id = ANY(%s);", (test_cves, test_cves))
            cur.execute("DELETE FROM cve_weaknesses WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM cve_references WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM cve_adp_entries WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM cve_affected WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM cvss_assessments WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM kev_entries WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM epss_scores WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM source_artifacts WHERE source_record_id IN (SELECT id FROM vuln_source_records WHERE cve_id = ANY(%s));", (test_cves,))
            cur.execute("DELETE FROM vuln_source_records WHERE cve_id = ANY(%s);", (test_cves,))
            cur.execute("DELETE FROM canonical_vulnerabilities WHERE cve_id = ANY(%s);", (test_cves,))
        conn.commit()

        # Create a test snapshot
        snap = create_sync_snapshot(conn, SyncSnapshot(
            source="cve",
            sync_mode="bootstrap",
            status="completed",
        ))
        conn.commit()
        snapshot_id = snap.id

        # 1. Canonical vulnerability 1 (PUBLISHED with rich multi-source data)
        vuln1 = CanonicalVulnerability(
            cve_id="CVE-2023-99901",
            state="PUBLISHED",
            date_published="2023-05-10T10:00:00Z",
            date_updated="2023-06-01T12:00:00Z",
            assigner_org_id="cna-apache@apache.org",
            assigner_short_name="apache",
        )
        upsert_canonical_vulnerability(conn, vuln1)

        # Source record for CVE
        cve_payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2023-99901", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "providerMetadata": {"orgId": "cna-apache@apache.org", "shortName": "apache"},
                    "descriptions": [{"lang": "en", "value": "Remote code execution in Apache Struts sample component"}],
                }
            },
        }
        upsert_source_record(conn, SourceRecord(
            source="cve",
            source_id="CVE-2023-99901",
            cve_id="CVE-2023-99901",
            raw_payload=cve_payload,
            snapshot_id=snapshot_id,
        ))

        # CVSS assessments: CNA Base CVSS 3.1 and NVD Base CVSS 3.1.
        # P0-03: structural container_role is required for authority resolution.
        upsert_cvss_assessment(conn, CvssAssessment(
            cve_id="CVE-2023-99901",
            source="cve",
            assessor="apache",
            assessment_type="cna",
            container_role="cna",
            provider_org_id="cna-apache@apache.org",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            base_severity="CRITICAL",
            scenario="GENERAL",
        ))
        upsert_cvss_assessment(conn, CvssAssessment(
            cve_id="CVE-2023-99901",
            source="nvd",
            assessor="nvd@nist.gov",
            assessment_type="Primary",
            container_role="nvd",
            provider_org_id="nvd@nist.gov",
            cvss_version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            base_severity="CRITICAL",
            scenario="GENERAL",
        ))

        # Affected products
        upsert_cve_affected(conn, CveAffected(
            cve_id="CVE-2023-99901",
            source="cve",
            vendor="Apache Software Foundation",
            product="Struts",
            versions=[{"version": "2.5.0", "status": "affected"}],
            cpes=["cpe:2.3:a:apache:struts:2.5.0:*:*:*:*:*:*:*"],
        ))

        # CWE weakness
        upsert_cve_weaknesses(conn, "CVE-2023-99901", "cve", [{"cwe_id": "CWE-94", "description": "Code Injection", "type": "Primary"}])

        # References
        upsert_cve_references(conn, "CVE-2023-99901", "cve", [{"url": "https://example.com/advisory", "name": "Advisory", "tags": ["vendor-advisory"]}])

        # ADP / SSVC
        upsert_adp_entry(conn, CveAdpEntry(
            cve_id="CVE-2023-99901",
            provider_org_id="cisa-adp-org",
            provider_short_name="cisa",
            title="CISA ADP Decision",
            ssvc_data={"decision": "Act", "exploitation": "active"},
            raw_data={},
        ))

        # KEV entry
        upsert_kev_entry(conn, KevEntry(
            cve_id="CVE-2023-99901",
            vendor_project="Apache",
            product="Struts",
            vulnerability_name="Apache Struts RCE",
            date_added="2023-05-15",
            short_description="Apache Struts contains an RCE flaw.",
            required_action="Apply security updates immediately.",
            due_date="2023-06-05",
            known_ransomware="Known",
            notes="Active in the wild",
        ))

        # EPSS score
        upsert_epss_score(conn, EpssScore(
            cve_id="CVE-2023-99901",
            score=0.95420,
            percentile=0.99850,
            model_version="v2023.03.01",
            score_date="2026-09-01",
        ))

        # OSV record & alias
        upsert_osv_record(conn, OsvRecord(
            osv_id="GHSA-9990-1111-2222",
            ecosystem="Maven",
            package_name="org.apache.struts:struts2-core",
            summary="Remote code execution in Struts2",
            published="2023-05-10T10:00:00Z",
            modified="2023-06-01T12:00:00Z",
            raw_payload={},
        ))
        upsert_osv_alias(conn, OsvAlias(
            osv_id="GHSA-9990-1111-2222",
            alias="CVE-2023-99901",
            alias_type="alias",
            linked_cve_id="CVE-2023-99901",
        ))

        # 2. Canonical vulnerability 2 (REJECTED with relationship)
        vuln2 = CanonicalVulnerability(
            cve_id="CVE-2023-99902",
            state="REJECTED",
            date_rejected="2023-06-10T00:00:00Z",
        )
        upsert_canonical_vulnerability(conn, vuln2)
        upsert_cve_relationship(conn, CveRelationship(
            cve_id="CVE-2023-99902",
            related_cve_id="CVE-2023-99901",
            relationship_type="replaced_by",
            source="cve",
        ))

        conn.commit()

    return {"cve_1": "CVE-2023-99901", "cve_2": "CVE-2023-99902"}


class TestVulnIntelligenceApiRead:
    """Test public intelligence read and exact CVE lookup."""

    def test_cve_lookup_unauthenticated_returns_401(self, client: TestClient):
        resp = client.get("/api/vuln-intelligence/cve/CVE-2023-99901")
        assert resp.status_code == 401

    def test_cve_lookup_invalid_syntax_returns_422(self, client: TestClient, auth_headers_tenant_a_analyst):
        resp = client.get("/api/vuln-intelligence/cve/CVE-INVALID-FORMAT", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 422

    def test_cve_lookup_nonexistent_returns_404(self, client: TestClient, auth_headers_tenant_a_analyst):
        resp = client.get("/api/vuln-intelligence/cve/CVE-2099-0001", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 404

    def test_cve_lookup_composed_detail_success(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_analyst):
        cve_id = seeded_intelligence_data["cve_1"]
        resp = client.get(f"/api/vuln-intelligence/cve/{cve_id}", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 200
        data = resp.json()

        # Canonical spine
        assert data["cve_id"] == "CVE-2023-99901"
        assert data["state"] == "PUBLISHED"
        assert data["assigner_short_name"] == "apache"

        # Provenance
        assert len(data["source_provenance"]) >= 1
        assert data["source_provenance"][0]["source"] == "cve"
        assert data["source_provenance"][0]["content_hash"] is not None

        # Descriptions
        assert len(data["descriptions"]) >= 1
        assert "Apache Struts" in data["descriptions"][0]["value"]

        # CVSS assessments (multiple preserved)
        assert len(data["cvss_assessments"]) == 2
        assessors = [a["assessor"] for a in data["cvss_assessments"]]
        assert "apache" in assessors
        assert "nvd@nist.gov" in assessors

        # CVSS authority resolution (P0-03: intrinsic CVSS is never TES)
        assert "tes_resolution" not in data
        auth = data["cvss_authority"]
        assert auth["is_scoreable"] is True
        assert auth["score"] == 9.8
        assert auth["role"] == "cna"
        assert auth["version"] == "3.1"
        assert auth["assessor"] == "apache"

        # Affected / applicability
        assert len(data["affected"]) == 1
        assert data["affected"][0]["product"] == "Struts"

        # KEV
        assert data["kev"] is not None
        assert data["kev"]["known_ransomware"] == "Known"
        assert data["kev"]["required_action"] == "Apply security updates immediately."

        # EPSS
        assert data["epss"] is not None
        assert data["epss"]["score"] == 0.95420
        assert data["epss"]["percentile"] == 0.99850

        # Linked OSV records
        assert len(data["osv_records"]) == 1
        assert data["osv_records"][0]["osv_id"] == "GHSA-9990-1111-2222"
        assert data["osv_records"][0]["package_name"] == "org.apache.struts:struts2-core"

    def test_cve_lookup_cross_tenant_access(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_b_admin):
        """Any authenticated active V2 user (including Tenant B admin) can read public intelligence."""
        cve_id = seeded_intelligence_data["cve_1"]
        resp = client.get(f"/api/vuln-intelligence/cve/{cve_id}", headers=auth_headers_tenant_b_admin)
        assert resp.status_code == 200
        assert resp.json()["cve_id"] == cve_id

    def test_rejected_cve_with_relationship(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_admin):
        cve_id = seeded_intelligence_data["cve_2"]
        resp = client.get(f"/api/vuln-intelligence/cve/{cve_id}", headers=auth_headers_tenant_a_admin)
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "REJECTED"
        assert len(data["relationships"]) == 1
        assert data["relationships"][0]["relationship_type"] == "replaced_by"
        assert data["relationships"][0]["related_cve_id"] == "CVE-2023-99901"


class TestVulnIntelligenceSearch:
    """Test search and filter capabilities."""

    def test_search_by_keyword(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_analyst):
        resp = client.get("/api/vuln-intelligence/cve?q=Struts", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(item["cve_id"] == "CVE-2023-99901" for item in data["items"])

    def test_search_by_state(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_analyst):
        resp = client.get("/api/vuln-intelligence/cve?state=REJECTED", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 200
        data = resp.json()
        assert all(item["state"] == "REJECTED" for item in data["items"])

    def test_search_by_has_kev(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_analyst):
        resp = client.get("/api/vuln-intelligence/cve?has_kev=true", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 200
        data = resp.json()
        assert all(item["has_kev"] is True for item in data["items"])

    def test_search_by_cvss_score(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_analyst):
        resp = client.get("/api/vuln-intelligence/cve?min_cvss=9.0", headers=auth_headers_tenant_a_analyst)
        assert resp.status_code == 200
        data = resp.json()
        assert any(item["cve_id"] == "CVE-2023-99901" for item in data["items"])


class TestVulnIntelligenceOperationalAndAuth:
    """Test operational endpoints and role-based authority boundaries."""

    def test_health_tenant_user_forbidden(self, client: TestClient, auth_headers_tenant_a_admin):
        """Regular tenant administrator cannot access platform operational health."""
        resp = client.get("/api/vuln-intelligence/health", headers=auth_headers_tenant_a_admin)
        assert resp.status_code == 403
        assert "Platform administrator authority required" in resp.json()["detail"]

    def test_health_platform_admin_allowed(self, client: TestClient, platform_admin_headers):
        """Platform administrator can access source health."""
        resp = client.get("/api/vuln-intelligence/health", headers=platform_admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "sources" in data
        assert len(data["sources"]) == 5
        source_names = [s["source"] for s in data["sources"]]
        assert "cve" in source_names
        assert "nvd" in source_names
        assert "kev" in source_names
        assert "epss" in source_names
        assert "osv" in source_names

    def test_single_source_health_platform_admin(self, client: TestClient, platform_admin_headers):
        resp = client.get("/api/vuln-intelligence/health/cve", headers=platform_admin_headers)
        assert resp.status_code == 200
        assert resp.json()["source"] == "cve"

    def test_snapshots_platform_admin(self, client: TestClient, platform_admin_headers):
        resp = client.get("/api/vuln-intelligence/snapshots", headers=platform_admin_headers)
        assert resp.status_code == 200
        assert "snapshots" in resp.json()

    def test_manual_sync_trigger_tenant_user_forbidden(self, client: TestClient, auth_headers_tenant_a_admin):
        resp = client.post("/api/vuln-intelligence/sync/cve", headers=auth_headers_tenant_a_admin)
        assert resp.status_code == 403

    def test_manual_sync_trigger_platform_admin(self, client: TestClient, platform_admin_headers):
        from unittest.mock import patch
        from app.vuln_intelligence.sync_engine import SyncOutcome
        import uuid

        with patch("app.routes.vuln_intelligence.sync_source") as mock_sync:
            mock_sync.return_value = SyncOutcome(
                source="cve",
                success=True,
                snapshot_id=str(uuid.uuid4()),
                sync_mode="incremental",
                records_processed=1,
                records_created=1,
                records_updated=0,
                records_unchanged=0,
                records_failed=0,
                cursor_before=None,
                cursor_after="2026-09-01T00:00:00Z",
                duration_ms=42,
            )
            resp = client.post("/api/vuln-intelligence/sync/cve", headers=platform_admin_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["source"] == "cve"


class TestNoTenantStateLeakage:
    """Non-negotiable rubric check: Public intelligence must not leak tenant exposure state."""

    def test_no_tenant_state_in_cve_detail(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_admin):
        cve_id = seeded_intelligence_data["cve_1"]
        resp = client.get(f"/api/vuln-intelligence/cve/{cve_id}", headers=auth_headers_tenant_a_admin)
        assert resp.status_code == 200
        raw_json_str = resp.text.lower()

        # Rubric non-negotiable keywords
        forbidden_keys = ["tenant_id", "asset_id", "assetexposure", "finding_id", "scan_id", "membership_id"]
        for key in forbidden_keys:
            assert f'"{key}"' not in raw_json_str, f"Forbidden tenant exposure key '{key}' leaked in response!"

    def test_no_tenant_state_in_search_results(self, client: TestClient, seeded_intelligence_data, auth_headers_tenant_a_admin):
        resp = client.get("/api/vuln-intelligence/cve", headers=auth_headers_tenant_a_admin)
        assert resp.status_code == 200
        raw_json_str = resp.text.lower()

        forbidden_keys = ["tenant_id", "asset_id", "assetexposure", "finding_id", "scan_id"]
        for key in forbidden_keys:
            assert f'"{key}"' not in raw_json_str, f"Forbidden tenant exposure key '{key}' leaked in search response!"


class TestSchedulerLoopLifecycle:
    """Test background async scheduler loop opt-in and clean cancellation."""

    @pytest.mark.asyncio
    async def test_scheduler_loop_cancellation(self):
        shutdown_event = asyncio.Event()

        # Start loop with very fast interval
        task = asyncio.create_task(
            run_sync_loop(
                get_db_connection,
                ALL_ADAPTERS,
                check_interval=1,
                shutdown_event=shutdown_event,
            )
        )

        await asyncio.sleep(0.1)
        # Signal shutdown
        shutdown_event.set()

        # Verify task finishes cleanly without raising unhandled exception
        await asyncio.wait_for(task, timeout=2.0)
        assert task.done()
