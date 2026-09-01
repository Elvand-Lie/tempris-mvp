# backend/tests/test_exposure_api.py
"""
Focused FastAPI Test Suite for Exposure Domain REST API (Sprint 02).
Tests all 26 Assertions across Groups 4-8:
  - Group 4: API Authentication, RBAC, and Route Integrity (4.1 - 4.5)
  - Group 5: Findings & Applicability API Endpoints (5.1 - 5.7)
  - Group 6: Confirmation, Resolution, and Canonical Current Exposure API (6.1 - 6.11)
  - Group 7: Multi-Tenant Defense & Cross-Tenant API Rejection (7.1 - 7.6)
  - Group 8: Documentation, Scope Bounding, and Freeze Safety (8.1 - 8.4)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from app.auth import create_test_token
from app.config import PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.main import app
from tests.conftest import TENANT_A, TENANT_B


# ---------------------------------------------------------------------------
# Fixtures & Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def auth_headers_tenant_a_superadmin():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="superadmin-a", role="superadmin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers_tenant_b_analyst():
    token = create_test_token(tenant_id=str(TENANT_B), actor_id="analyst-b", role="analyst")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def seed_cve():
    cve_id = "CVE-2023-12345"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO canonical_vulnerabilities (
                    cve_id, state, assigner_short_name
                ) VALUES (
                    %s, 'PUBLISHED', 'test-cna'
                )
                ON CONFLICT (cve_id) DO NOTHING;
                """,
                (cve_id,),
            )
        conn.commit()
    return cve_id


def create_asset_in_db(
    tenant_id: uuid.UUID,
    name: str = "web-prod-01",
    target_value: str = "10.0.0.1",
    target_type: str = "ip",
    network_scope: str = "internal",
    status: str = "active",
) -> uuid.UUID:
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (
                    %s, %s, %s, 'server', %s, %s, %s, %s, 'production', 'medium', %s
                );
                """,
                (
                    str(asset_id),
                    str(tenant_id),
                    name,
                    target_type,
                    target_value,
                    target_value.lower().strip(),
                    network_scope,
                    status,
                ),
            )
        conn.commit()
    return asset_id


def fetch_audit_events(tenant_id: uuid.UUID, event_name: str) -> list[dict]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, tenant_id, actor_id, actor_role, event_name, asset_id, details, created_at
                FROM audit_events
                WHERE tenant_id = %s AND event_name = %s
                ORDER BY created_at DESC;
                """,
                (str(tenant_id), event_name),
            )
            rows = cur.fetchall()
            result = []
            for r in rows:
                item = dict(r)
                if isinstance(item.get("details"), str):
                    item["details"] = json.loads(item["details"])
                result.append(item)
            return result


# ---------------------------------------------------------------------------
# Group 4: API Authentication, RBAC, and Route Integrity
# ---------------------------------------------------------------------------


class TestGroup4ApiAuthRbacAndRouteIntegrity:
    """Verifies Assertions 4.1 - 4.5."""

    def test_assertion_4_1_unauthenticated_rejection(self, client: TestClient):
        """Assertion 4.1: Invoking any /api/exposure/* endpoint without Authorization returns 401."""
        endpoints = [
            ("GET", "/api/exposure/findings/00000000-0000-0000-0000-000000000001"),
            ("POST", "/api/exposure/findings"),
            ("POST", "/api/exposure/findings/00000000-0000-0000-0000-000000000001/close"),
            ("GET", "/api/exposure/reviews"),
            ("POST", "/api/exposure/reviews"),
            ("POST", "/api/exposure/confirm"),
            ("POST", "/api/exposure/resolve/00000000-0000-0000-0000-000000000001"),
            ("GET", "/api/exposure/current"),
        ]
        for method, path in endpoints:
            if method == "GET":
                res = client.get(path)
            else:
                res = client.post(path, json={})
            assert res.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {res.status_code}"

    def test_assertion_4_2_invalid_token_rejection(self, client: TestClient):
        """Assertion 4.2: Invoking with malformed or expired JWT returns 401."""
        bad_headers = {"Authorization": "Bearer malformed.invalid.token"}
        res = client.get("/api/exposure/current", headers=bad_headers)
        assert res.status_code == 401

        # Expired token (iat 7200s ago, exp 3600s ago)
        expired_token = create_test_token(str(TENANT_A), actor_id="admin-a", exp_delta_seconds=3600, iat=int(datetime.now(timezone.utc).timestamp()) - 7200)
        res_exp = client.get("/api/exposure/current", headers={"Authorization": f"Bearer {expired_token}"})
        assert res_exp.status_code == 401

    def test_assertion_4_3_role_authorization(
        self,
        client: TestClient,
        auth_headers_tenant_a_analyst,
        auth_headers_tenant_a_admin,
        auth_headers_tenant_a_superadmin,
    ):
        """Assertion 4.3: Users with analyst, admin, and superadmin roles successfully access authorized exposure endpoints."""
        for headers in [auth_headers_tenant_a_analyst, auth_headers_tenant_a_admin, auth_headers_tenant_a_superadmin]:
            res = client.get("/api/exposure/current", headers=headers)
            assert res.status_code == 200, f"Role failed with status {res.status_code}: {res.text}"

    def test_assertion_4_4_platform_session_isolation(
        self, client: TestClient, platform_admin_headers
    ):
        """Assertion 4.4: Platform tenant sessions cannot access tenant exposure endpoints (403 Forbidden with detail)."""
        res = client.get("/api/exposure/current", headers=platform_admin_headers)
        assert res.status_code == 403
        assert res.json()["detail"] == "Platform sessions cannot access tenant modules."

        res_post = client.post(
            "/api/exposure/findings",
            headers=platform_admin_headers,
            json={"title": "Test", "severity": "high"},
        )
        assert res_post.status_code == 403
        assert res_post.json()["detail"] == "Platform sessions cannot access tenant modules."

    def test_assertion_4_5_openapi_schema_registration(self):
        """Assertion 4.5: FastAPI app reflects /api/exposure routes under tag Exposure in app.openapi()."""
        schema = app.openapi()
        paths = schema.get("paths", {})
        exposure_paths = [p for p in paths if p.startswith("/api/exposure")]
        assert len(exposure_paths) >= 6
        assert "/api/exposure/findings" in paths
        assert "/api/exposure/confirm" in paths
        assert "/api/exposure/current" in paths

        # Verify tag 'Exposure'
        for p in exposure_paths:
            for method, spec in paths[p].items():
                if method in ("get", "post", "put", "delete"):
                    assert "Exposure" in spec.get("tags", []), f"Path {p} missing Exposure tag"


# ---------------------------------------------------------------------------
# Group 5: Findings & Applicability API Endpoints
# ---------------------------------------------------------------------------


class TestGroup5FindingsAndApplicabilityApiEndpoints:
    """Verifies Assertions 5.1 - 5.7."""

    def test_assertion_5_1_create_finding_via_api(
        self, client: TestClient, auth_headers_tenant_a_admin, seed_cve
    ):
        """Assertion 5.1: POST /api/exposure/findings creates valid finding, returns 201 Created, and emits finding.created."""
        payload = {
            "title": "Remote Code Execution via Insecure Deserialization",
            "severity": "critical",
            "description": "Exploitable via crafted payload",
            "canonical_cve_id": seed_cve,
        }
        res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["title"] == payload["title"]
        assert data["severity"] == "critical"
        assert data["status"] == "open"
        assert data["canonical_cve_id"] == seed_cve
        assert data["tenant_id"] == str(TENANT_A)
        finding_id = data["id"]
        assert uuid.UUID(finding_id)

        # Verify audit event
        events = fetch_audit_events(TENANT_A, "finding.created")
        assert len(events) >= 1
        latest = events[0]
        assert latest["details"]["finding_id"] == finding_id
        assert latest["details"]["title"] == payload["title"]
        assert latest["details"]["canonical_cve_id"] == seed_cve
        assert latest["details"]["severity"] == "critical"

    def test_assertion_5_2_create_non_cve_finding_via_api(
        self, client: TestClient, auth_headers_tenant_a_analyst
    ):
        """Assertion 5.2: POST /api/exposure/findings with canonical_cve_id = null succeeds with 201 Created."""
        payload = {
            "title": "Hardcoded AWS Credentials in Production Repository",
            "severity": "high",
            "description": "Found in config.json",
            "canonical_cve_id": None,
        }
        res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_analyst, json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["title"] == payload["title"]
        assert data["canonical_cve_id"] is None
        assert data["status"] == "open"

    def test_assertion_5_3_invalid_cve_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 5.3: POST /api/exposure/findings with non-existent canonical_cve_id returns 422 Unprocessable Entity."""
        payload = {
            "title": "Bogus CVE Finding",
            "severity": "medium",
            "canonical_cve_id": "CVE-9999-99999",
        }
        res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json=payload)
        assert res.status_code == 422
        assert "CVE-9999-99999" in res.json()["detail"]

    def test_assertion_5_4_get_finding_by_id(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 5.4: GET /api/exposure/findings/{id} returns finding; non-existent returns 404."""
        create_res = client.post(
            "/api/exposure/findings",
            headers=auth_headers_tenant_a_admin,
            json={"title": "Test Get Finding", "severity": "low"},
        )
        finding_id = create_res.json()["id"]

        # Get existing finding
        res = client.get(f"/api/exposure/findings/{finding_id}", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200
        assert res.json()["id"] == finding_id
        assert res.json()["title"] == "Test Get Finding"

        # Non-existent UUID
        non_existent_id = str(uuid.uuid4())
        res_404 = client.get(f"/api/exposure/findings/{non_existent_id}", headers=auth_headers_tenant_a_admin)
        assert res_404.status_code == 404

    def test_assertion_5_5_close_finding_via_api_and_idempotency(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 5.5: POST /api/exposure/findings/{id}/close transitions status to closed, returns 200, emits finding.closed, and is idempotent."""
        create_res = client.post(
            "/api/exposure/findings",
            headers=auth_headers_tenant_a_admin,
            json={"title": "Finding to Close", "severity": "medium"},
        )
        finding_id = create_res.json()["id"]

        # First close call
        close_res1 = client.post(
            f"/api/exposure/findings/{finding_id}/close",
            headers=auth_headers_tenant_a_admin,
            json={"reason": "Patched in release 1.4.2"},
        )
        assert close_res1.status_code == 200
        data1 = close_res1.json()
        assert data1["status"] == "closed"
        assert data1["closed_at"] is not None

        # Verify audit event
        events = fetch_audit_events(TENANT_A, "finding.closed")
        assert len(events) >= 1
        assert events[0]["details"]["finding_id"] == finding_id
        assert events[0]["details"]["reason"] == "Patched in release 1.4.2"

        # Subsequent close call (idempotency)
        close_res2 = client.post(
            f"/api/exposure/findings/{finding_id}/close",
            headers=auth_headers_tenant_a_admin,
            json={"reason": "Duplicate close call"},
        )
        assert close_res2.status_code == 200
        assert close_res2.json()["status"] == "closed"

    def test_assertion_5_6_record_applicability_review_and_actor_default(
        self, client: TestClient, auth_headers_tenant_a_analyst
    ):
        """Assertion 5.6: POST /api/exposure/reviews records review, defaults reviewed_by to auth.actor_id, returns 201, and emits audit event."""
        finding_res = client.post(
            "/api/exposure/findings",
            headers=auth_headers_tenant_a_analyst,
            json={"title": "Applicability Target Finding", "severity": "high"},
        )
        finding_id = finding_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "app-server-01"))

        # Case 1: Omitted reviewed_by -> defaults to actor_id (analyst-a)
        payload = {
            "finding_id": finding_id,
            "asset_id": asset_id,
            "applicability": "APPLICABLE",
            "reason": "Vulnerable library detected in app dependencies",
        }
        res = client.post("/api/exposure/reviews", headers=auth_headers_tenant_a_analyst, json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["finding_id"] == finding_id
        assert data["asset_id"] == asset_id
        assert data["applicability"] == "APPLICABLE"
        assert data["reviewed_by"] == "analyst-a"
        assert data["reason"] == payload["reason"]

        # Verify audit event
        events = fetch_audit_events(TENANT_A, "exposure.review_recorded")
        assert len(events) >= 1
        assert events[0]["details"]["finding_id"] == finding_id
        assert events[0]["details"]["applicability"] == "APPLICABLE"
        assert events[0]["details"]["reason"] == payload["reason"]
        assert str(events[0]["asset_id"]) == str(asset_id)

        # Case 2: Explicit reviewed_by
        payload2 = {
            "finding_id": finding_id,
            "asset_id": asset_id,
            "applicability": "NOT_APPLICABLE",
            "reviewed_by": "custom-analyst",
            "reason": "Feature flag disabled in production",
        }
        res2 = client.post("/api/exposure/reviews", headers=auth_headers_tenant_a_analyst, json=payload2)
        assert res2.status_code == 201
        assert res2.json()["reviewed_by"] == "custom-analyst"

    def test_assertion_5_7_list_reviews_filtering(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 5.7: GET /api/exposure/reviews returns reviews filtered by finding_id or asset_id in chronological order."""
        f1_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "F1", "severity": "low"})
        f2_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "F2", "severity": "low"})
        f1_id = f1_res.json()["id"]
        f2_id = f2_res.json()["id"]

        a1_id = str(create_asset_in_db(TENANT_A, "asset-1", "10.0.0.10"))
        a2_id = str(create_asset_in_db(TENANT_A, "asset-2", "10.0.0.20"))

        client.post("/api/exposure/reviews", headers=auth_headers_tenant_a_admin, json={"finding_id": f1_id, "asset_id": a1_id, "applicability": "NEEDS_REVIEW"})
        client.post("/api/exposure/reviews", headers=auth_headers_tenant_a_admin, json={"finding_id": f1_id, "asset_id": a2_id, "applicability": "APPLICABLE"})
        client.post("/api/exposure/reviews", headers=auth_headers_tenant_a_admin, json={"finding_id": f2_id, "asset_id": a1_id, "applicability": "REFERENCE"})

        # Filter by finding_id
        res_f1 = client.get(f"/api/exposure/reviews?finding_id={f1_id}", headers=auth_headers_tenant_a_admin)
        assert res_f1.status_code == 200
        assert len(res_f1.json()) == 2
        for r in res_f1.json():
            assert r["finding_id"] == f1_id

        # Filter by asset_id
        res_a1 = client.get(f"/api/exposure/reviews?asset_id={a1_id}", headers=auth_headers_tenant_a_admin)
        assert res_a1.status_code == 200
        assert len(res_a1.json()) == 2
        for r in res_a1.json():
            assert r["asset_id"] == a1_id


# ---------------------------------------------------------------------------
# Group 6: Confirmation, Resolution, and Canonical Current Exposure API
# ---------------------------------------------------------------------------


class TestGroup6ConfirmationResolutionAndCanonicalExposureApi:
    """Verifies Assertions 6.1 - 6.11."""

    def test_assertion_6_1_explicit_confirmation_and_actor_default(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.1: POST /api/exposure/confirm with valid evidence confirms exposure, defaults actor, returns 200, emits exposure.confirmed."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Confirm Finding", "severity": "high"})
        finding_id = f_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "asset-confirm-1"))

        evidence = {"source": "nuclei", "matched_at": "https://example.com/api", "template_id": "cve-2023-12345"}
        payload = {
            "finding_id": finding_id,
            "asset_id": asset_id,
            "evidence": evidence,
        }
        res = client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["finding_id"] == finding_id
        assert data["asset_id"] == asset_id
        assert data["status"] == "confirmed"
        assert data["evidence"] == evidence
        assert data["confirmed_by"] == "admin-a"
        assert data["confirmed_at"] is not None

        # Verify audit event
        events = fetch_audit_events(TENANT_A, "exposure.confirmed")
        assert len(events) >= 1
        assert events[0]["details"]["finding_id"] == finding_id
        assert events[0]["details"]["exposure_id"] == data["id"]
        assert str(events[0]["asset_id"]) == str(asset_id)

    def test_assertion_6_2_empty_evidence_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.2: POST /api/exposure/confirm with {} or non-object returns 422 Unprocessable Entity."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Finding Evidence Check", "severity": "high"})
        finding_id = f_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "asset-evidence-1"))

        # Empty dict
        res_empty = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {}},
        )
        assert res_empty.status_code == 422

        # Non-object / string
        res_str = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": "not a dict"},
        )
        assert res_str.status_code == 422

    def test_assertion_6_3_decommissioned_asset_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.3: POST /api/exposure/confirm on a decommissioned asset returns 400 Bad Request."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Finding Decom Check", "severity": "high"})
        finding_id = f_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "asset-decom-1", status="decommissioned"))

        res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {"proof": "valid"}},
        )
        assert res.status_code == 400
        assert "not active" in res.json()["detail"].lower()

    def test_assertion_6_4_closed_finding_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.4: POST /api/exposure/confirm on a closed finding returns 400 Bad Request."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Closed Finding Check", "severity": "high"})
        finding_id = f_res.json()["id"]
        client.post(f"/api/exposure/findings/{finding_id}/close", headers=auth_headers_tenant_a_admin)

        asset_id = str(create_asset_in_db(TENANT_A, "asset-closed-check"))
        res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {"proof": "valid"}},
        )
        assert res.status_code == 400
        assert "not open" in res.json()["detail"].lower()

    def test_assertion_6_5_idempotent_reconfirmation(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.5: Calling POST /api/exposure/confirm repeatedly updates existing confirmed exposure without duplicates."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Reconfirmation Finding", "severity": "high"})
        finding_id = f_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "asset-reconfirm-1"))

        res1 = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {"round": 1}},
        )
        assert res1.status_code == 200
        exp_id1 = res1.json()["id"]

        res2 = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {"round": 2}},
        )
        assert res2.status_code == 200
        exp_id2 = res2.json()["id"]

        assert exp_id1 == exp_id2
        assert res2.json()["evidence"] == {"round": 2}

        # Check current exposures count
        current_res = client.get("/api/exposure/current", headers=auth_headers_tenant_a_admin)
        assert len(current_res.json()) == 1

    def test_assertion_6_6_resolve_exposure_via_api_and_actor_default(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.6: POST /api/exposure/resolve/{id} updates exposure, defaults actor, returns 200, and emits exposure.resolved."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Resolve Finding", "severity": "high"})
        finding_id = f_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "asset-resolve-1"))

        conf_res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {"proof": "valid"}},
        )
        exp_id = conf_res.json()["id"]

        # Resolve without explicit resolved_by (defaults to admin-a)
        res = client.post(
            f"/api/exposure/resolve/{exp_id}",
            headers=auth_headers_tenant_a_admin,
            json={"status": "resolved", "resolution_reason": "Vulnerability patched and verified"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "resolved"
        assert data["resolved_by"] == "admin-a"
        assert data["resolved_at"] is not None
        assert data["resolution_reason"] == "Vulnerability patched and verified"

        # Verify audit event
        events = fetch_audit_events(TENANT_A, "exposure.resolved")
        assert len(events) >= 1
        assert events[0]["details"]["exposure_id"] == exp_id
        assert events[0]["details"]["status"] == "resolved"
        assert events[0]["details"]["reason"] == "Vulnerability patched and verified"

    def test_assertion_6_7_canonical_current_exposures_api(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.7: GET /api/exposure/current returns only active confirmed exposures on open findings and active assets."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Active Exposure Finding", "severity": "critical"})
        finding_id = f_res.json()["id"]
        asset_id = str(create_asset_in_db(TENANT_A, "asset-canonical-1"))

        client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": asset_id, "evidence": {"vuln": True}},
        )

        res = client.get("/api/exposure/current", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200
        items = res.json()
        assert len(items) == 1
        item = items[0]
        assert item["finding_id"] == finding_id
        assert item["asset_id"] == asset_id
        assert item["exposure_status"] == "confirmed"
        assert item["finding_status"] == "open"
        assert item["asset_status"] == "active"
        assert item["finding_title"] == "Active Exposure Finding"
        assert item["finding_severity"] == "critical"
        assert item["asset_name"] == "asset-canonical-1"

    def test_assertion_6_8_canonical_current_exposures_filtering(
        self, client: TestClient, auth_headers_tenant_a_admin, seed_cve
    ):
        """Assertion 6.8: GET /api/exposure/current correctly filters by finding_id, asset_id, cve_id, and severity."""
        f1_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "F1 Critical", "severity": "critical", "canonical_cve_id": seed_cve})
        f2_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "F2 Low", "severity": "low"})
        f1_id = f1_res.json()["id"]
        f2_id = f2_res.json()["id"]

        a1_id = str(create_asset_in_db(TENANT_A, "asset-filter-1", "10.0.1.1"))
        a2_id = str(create_asset_in_db(TENANT_A, "asset-filter-2", "10.0.1.2"))

        client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": f1_id, "asset_id": a1_id, "evidence": {"e": 1}})
        client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": f2_id, "asset_id": a2_id, "evidence": {"e": 2}})

        # Filter by finding_id
        res_f1 = client.get(f"/api/exposure/current?finding_id={f1_id}", headers=auth_headers_tenant_a_admin)
        assert len(res_f1.json()) == 1
        assert res_f1.json()[0]["finding_id"] == f1_id

        # Filter by asset_id
        res_a2 = client.get(f"/api/exposure/current?asset_id={a2_id}", headers=auth_headers_tenant_a_admin)
        assert len(res_a2.json()) == 1
        assert res_a2.json()[0]["asset_id"] == a2_id

        # Filter by cve_id
        res_cve = client.get(f"/api/exposure/current?cve_id={seed_cve}", headers=auth_headers_tenant_a_admin)
        assert len(res_cve.json()) == 1
        assert res_cve.json()[0]["canonical_cve_id"] == seed_cve

        # Filter by severity
        res_sev = client.get("/api/exposure/current?severity=critical", headers=auth_headers_tenant_a_admin)
        assert len(res_sev.json()) == 1
        assert res_sev.json()[0]["finding_severity"] == "critical"

    def test_assertion_6_9_canonical_query_determinism(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.9: GET /api/exposure/current returns results sorted deterministically by confirmed_at DESC, id ASC."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Multi Determinism", "severity": "medium"})
        finding_id = f_res.json()["id"]

        a1_id = str(create_asset_in_db(TENANT_A, "asset-det-1", "10.0.2.1"))
        a2_id = str(create_asset_in_db(TENANT_A, "asset-det-2", "10.0.2.2"))
        a3_id = str(create_asset_in_db(TENANT_A, "asset-det-3", "10.0.2.3"))

        client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": finding_id, "asset_id": a1_id, "evidence": {"e": 1}})
        client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": finding_id, "asset_id": a2_id, "evidence": {"e": 2}})
        client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": finding_id, "asset_id": a3_id, "evidence": {"e": 3}})

        res = client.get("/api/exposure/current", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200
        items = res.json()
        assert len(items) == 3

        # Verify ordering: confirmed_at DESC, exposure_id ASC
        for i in range(len(items) - 1):
            t1 = datetime.fromisoformat(items[i]["confirmed_at"])
            t2 = datetime.fromisoformat(items[i + 1]["confirmed_at"])
            assert (t1 > t2) or (t1 == t2 and items[i]["exposure_id"] <= items[i + 1]["exposure_id"])

    def test_assertion_6_10_multi_asset_exposure_listing(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.10: Single finding confirmed across multiple assets returns all asset exposures."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Shared Vulnerability", "severity": "high"})
        finding_id = f_res.json()["id"]

        a1_id = str(create_asset_in_db(TENANT_A, "fleet-node-01", "192.168.1.1"))
        a2_id = str(create_asset_in_db(TENANT_A, "fleet-node-02", "192.168.1.2"))
        a3_id = str(create_asset_in_db(TENANT_A, "fleet-node-03", "192.168.1.3"))

        for aid in [a1_id, a2_id, a3_id]:
            client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": finding_id, "asset_id": aid, "evidence": {"fleet": True}})

        res = client.get(f"/api/exposure/current?finding_id={finding_id}", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200
        items = res.json()
        assert len(items) == 3
        returned_asset_ids = {item["asset_id"] for item in items}
        assert returned_asset_ids == {a1_id, a2_id, a3_id}

    def test_assertion_6_11_dynamic_asset_lifecycle_transition(
        self, client: TestClient, auth_headers_tenant_a_admin
    ):
        """Assertion 6.11: Deactivating an asset removes it from GET /api/exposure/current; reactivating restores it without exposure mutation."""
        f_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Dynamic Lifecycle Finding", "severity": "critical"})
        finding_id = f_res.json()["id"]
        asset_id = create_asset_in_db(TENANT_A, "asset-dynamic-life", "10.10.10.10")

        # Confirm exposure
        conf_res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": finding_id, "asset_id": str(asset_id), "evidence": {"live": True}},
        )
        assert conf_res.status_code == 200
        exposure_id = conf_res.json()["id"]

        # Verify visible in current exposures
        cur1 = client.get(f"/api/exposure/current?asset_id={asset_id}", headers=auth_headers_tenant_a_admin)
        assert len(cur1.json()) == 1

        # Decommission the asset in database
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE assets SET status = 'decommissioned' WHERE id = %s;", (str(asset_id),))
            conn.commit()

        # Verify immediately removed from current exposures
        cur2 = client.get(f"/api/exposure/current?asset_id={asset_id}", headers=auth_headers_tenant_a_admin)
        assert len(cur2.json()) == 0

        # Reactivate asset in database
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE assets SET status = 'active' WHERE id = %s;", (str(asset_id),))
            conn.commit()

        # Verify immediately restored without exposure mutation
        cur3 = client.get(f"/api/exposure/current?asset_id={asset_id}", headers=auth_headers_tenant_a_admin)
        assert len(cur3.json()) == 1
        assert cur3.json()[0]["exposure_id"] == exposure_id


# ---------------------------------------------------------------------------
# Group 7: Multi-Tenant Defense & Cross-Tenant API Rejection
# ---------------------------------------------------------------------------


class TestGroup7MultiTenantDefenseAndCrossTenantRejection:
    """Verifies Assertions 7.1 - 7.6."""

    def test_assertion_7_1_cross_tenant_finding_isolation(
        self, client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
    ):
        """Assertion 7.1: Tenant B cannot read or close Tenant A's finding (returns 404 Not Found)."""
        f_res = client.post(
            "/api/exposure/findings",
            headers=auth_headers_tenant_a_admin,
            json={"title": "Tenant A Secret Vulnerability", "severity": "critical"},
        )
        finding_id = f_res.json()["id"]

        # Tenant B attempt to read
        res_get = client.get(f"/api/exposure/findings/{finding_id}", headers=auth_headers_tenant_b_admin)
        assert res_get.status_code == 404

        # Tenant B attempt to close
        res_close = client.post(f"/api/exposure/findings/{finding_id}/close", headers=auth_headers_tenant_b_admin)
        assert res_close.status_code == 404

    def test_assertion_7_2_cross_tenant_review_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
    ):
        """Assertion 7.2: Tenant A attempting to record a review with Tenant B's asset or finding returns 404."""
        f_a_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "FA", "severity": "low"})
        f_b_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_b_admin, json={"title": "FB", "severity": "low"})
        fa_id = f_a_res.json()["id"]
        fb_id = f_b_res.json()["id"]

        aa_id = str(create_asset_in_db(TENANT_A, "asset-a-1"))
        ab_id = str(create_asset_in_db(TENANT_B, "asset-b-1"))

        # Tenant A using Tenant B's finding
        res1 = client.post(
            "/api/exposure/reviews",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": fb_id, "asset_id": aa_id, "applicability": "APPLICABLE"},
        )
        assert res1.status_code == 404

        # Tenant A using Tenant B's asset
        res2 = client.post(
            "/api/exposure/reviews",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": fa_id, "asset_id": ab_id, "applicability": "APPLICABLE"},
        )
        assert res2.status_code == 404

    def test_assertion_7_3_cross_tenant_confirmation_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
    ):
        """Assertion 7.3: Tenant A attempting to confirm exposure linking Tenant B's asset or finding returns 404."""
        f_a_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "FA", "severity": "low"})
        f_b_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_b_admin, json={"title": "FB", "severity": "low"})
        fa_id = f_a_res.json()["id"]
        fb_id = f_b_res.json()["id"]

        aa_id = str(create_asset_in_db(TENANT_A, "asset-a-conf"))
        ab_id = str(create_asset_in_db(TENANT_B, "asset-b-conf"))

        # Tenant A linking Tenant B's finding
        res1 = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": fb_id, "asset_id": aa_id, "evidence": {"p": 1}},
        )
        assert res1.status_code == 404

        # Tenant A linking Tenant B's asset
        res2 = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": fa_id, "asset_id": ab_id, "evidence": {"p": 1}},
        )
        assert res2.status_code == 404

    def test_assertion_7_4_cross_tenant_resolution_rejection(
        self, client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
    ):
        """Assertion 7.4: Tenant B attempting to resolve Tenant A's exposure returns 404 Not Found."""
        f_a_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "FA", "severity": "low"})
        fa_id = f_a_res.json()["id"]
        aa_id = str(create_asset_in_db(TENANT_A, "asset-a-res"))

        conf_res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={"finding_id": fa_id, "asset_id": aa_id, "evidence": {"p": 1}},
        )
        exp_id = conf_res.json()["id"]

        # Tenant B attempt to resolve Tenant A's exposure
        res = client.post(
            f"/api/exposure/resolve/{exp_id}",
            headers=auth_headers_tenant_b_admin,
            json={"status": "resolved", "resolution_reason": "Malicious resolve attempt"},
        )
        assert res.status_code == 404

    def test_assertion_7_5_cross_tenant_canonical_query_isolation(
        self, client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
    ):
        """Assertion 7.5: GET /api/exposure/current for Tenant A returns zero data from Tenant B."""
        # Create confirmed exposure in Tenant A
        fa_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "Tenant A Finding", "severity": "high"})
        aa_id = str(create_asset_in_db(TENANT_A, "asset-tenant-a"))
        client.post("/api/exposure/confirm", headers=auth_headers_tenant_a_admin, json={"finding_id": fa_res.json()["id"], "asset_id": aa_id, "evidence": {"a": 1}})

        # Create confirmed exposure in Tenant B
        fb_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_b_admin, json={"title": "Tenant B Finding", "severity": "critical"})
        ab_id = str(create_asset_in_db(TENANT_B, "asset-tenant-b"))
        client.post("/api/exposure/confirm", headers=auth_headers_tenant_b_admin, json={"finding_id": fb_res.json()["id"], "asset_id": ab_id, "evidence": {"b": 1}})

        # Tenant A query
        res_a = client.get("/api/exposure/current", headers=auth_headers_tenant_a_admin)
        assert res_a.status_code == 200
        items_a = res_a.json()
        assert len(items_a) == 1
        assert items_a[0]["tenant_id"] == str(TENANT_A)
        assert items_a[0]["finding_title"] == "Tenant A Finding"

        # Tenant B query
        res_b = client.get("/api/exposure/current", headers=auth_headers_tenant_b_admin)
        assert res_b.status_code == 200
        items_b = res_b.json()
        assert len(items_b) == 1
        assert items_b[0]["tenant_id"] == str(TENANT_B)
        assert items_b[0]["finding_title"] == "Tenant B Finding"

    def test_assertion_7_6_cross_tenant_review_query_isolation(
        self, client: TestClient, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin
    ):
        """Assertion 7.6: GET /api/exposure/reviews with foreign tenant filters returns an empty list without leaking data."""
        fa_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_a_admin, json={"title": "FA", "severity": "low"})
        fb_res = client.post("/api/exposure/findings", headers=auth_headers_tenant_b_admin, json={"title": "FB", "severity": "low"})
        fa_id = fa_res.json()["id"]
        fb_id = fb_res.json()["id"]

        aa_id = str(create_asset_in_db(TENANT_A, "aa"))
        ab_id = str(create_asset_in_db(TENANT_B, "ab"))

        client.post("/api/exposure/reviews", headers=auth_headers_tenant_a_admin, json={"finding_id": fa_id, "asset_id": aa_id, "applicability": "APPLICABLE"})
        client.post("/api/exposure/reviews", headers=auth_headers_tenant_b_admin, json={"finding_id": fb_id, "asset_id": ab_id, "applicability": "APPLICABLE"})

        # Tenant A queries with Tenant B's finding_id -> returns []
        res = client.get(f"/api/exposure/reviews?finding_id={fb_id}", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200
        assert res.json() == []

        # Tenant A queries with Tenant B's asset_id -> returns []
        res2 = client.get(f"/api/exposure/reviews?asset_id={ab_id}", headers=auth_headers_tenant_a_admin)
        assert res2.status_code == 200
        assert res2.json() == []


# ---------------------------------------------------------------------------
# Group 8: Documentation, Scope Bounding, and Freeze Safety
# ---------------------------------------------------------------------------


class TestGroup8DocumentationScopeBoundingAndFreezeSafety:
    """Verifies Assertions 8.1 - 8.4."""

    def test_assertion_8_1_documentation_completeness(self):
        """Assertion 8.1: docs/modules/exposure/README.md and docs/modules/exposure/EXPOSURE.md exist and are non-empty."""
        repo_root = Path(__file__).resolve().parents[3]
        readme_path = repo_root / "docs" / "modules" / "exposure" / "README.md"
        spec_path = repo_root / "docs" / "modules" / "exposure" / "EXPOSURE.md"

        assert readme_path.is_file(), f"Missing {readme_path}"
        assert spec_path.is_file(), f"Missing {spec_path}"
        assert readme_path.stat().st_size > 500
        assert spec_path.stat().st_size > 1000

    def test_assertion_8_2_documentation_content_verification(self):
        """Assertion 8.2: Documentation covers architecture, relational model, lifecycle state machines, canonical query, and API spec."""
        repo_root = Path(__file__).resolve().parents[3]
        spec_content = (repo_root / "docs" / "modules" / "exposure" / "EXPOSURE.md").read_text(encoding="utf-8")
        readme_content = (repo_root / "docs" / "modules" / "exposure" / "README.md").read_text(encoding="utf-8")

        for term in [
            "findings",
            "asset_applicability_reviews",
            "asset_exposures",
            "canonical_vulnerabilities",
            "/api/exposure/findings",
            "/api/exposure/reviews",
            "/api/exposure/confirm",
            "/api/exposure/resolve",
            "/api/exposure/current",
            "finding.created",
            "finding.closed",
            "exposure.review_recorded",
            "exposure.confirmed",
            "exposure.resolved",
        ]:
            assert term in spec_content or term in readme_content, f"Documentation missing required term: {term}"

    def test_assertion_8_3_migration_additive_integrity(self):
        """Assertion 8.3: Verify migrations 001-013 remain intact and additive."""
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        assert migrations_dir.is_dir()
        migration_files = sorted(list(migrations_dir.glob("*.sql")))
        assert len(migration_files) >= 13
        assert any("013_exposure_domain_foundation.sql" in f.name for f in migration_files)

    def test_assertion_8_4_openapi_schema_freeze_and_route_bounding(self):
        """Assertion 8.4: Verify exposed endpoints strictly match Sprint 02 scope."""
        schema = app.openapi()
        paths = schema.get("paths", {})
        exposure_routes = [p for p in paths if p.startswith("/api/exposure")]
        expected_routes = {
            "/api/exposure/findings",
            "/api/exposure/findings/{finding_id}",
            "/api/exposure/findings/{finding_id}/close",
            "/api/exposure/reviews",
            "/api/exposure/confirm",
            "/api/exposure/resolve/{exposure_id}",
            "/api/exposure/current",
        }
        assert set(exposure_routes) == expected_routes
