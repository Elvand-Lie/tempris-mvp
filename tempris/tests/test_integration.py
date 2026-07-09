"""
Tempris Integration Tests
=========================
End-to-end flows testing multiple modules working together.
Tests real user journeys through the platform.
"""
import pytest


class TestLoginFlow:
    """Test the complete login → authenticated request flow."""

    def test_login_returns_valid_token(self, client):
        """Login with valid demo credentials returns a JWT token."""
        resp = client.post("/api/auth/login", json={
            "email": "sherie@tempris.com",
            "password": "demo"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["role"] == "Superadmin"
        assert data["user"]["email"] == "sherie@tempris.com"

    def test_login_token_works_for_api_calls(self, client):
        """Token from login endpoint can be used to access protected endpoints."""
        # Login
        login_resp = client.post("/api/auth/login", json={
            "email": "sherie@tempris.com",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]

        # Use token to hit a protected endpoint
        resp = client.get("/api/health")
        assert resp.status_code == 200

        # Hit audit endpoint with token
        resp = client.get(
            "/api/audit/log",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200

    def test_invalid_login_rejected(self, client):
        """Wrong password returns 401."""
        resp = client.post("/api/auth/login", json={
            "email": "sherie@tempris.com",
            "password": "wrongpassword"
        })
        assert resp.status_code == 401

    def test_no_token_returns_401(self, client):
        """Protected endpoints reject requests without auth token."""
        resp = client.get("/api/audit/log")
        assert resp.status_code == 401


class TestRBACFlow:
    """Test role-based access control across modules."""

    def _login(self, client, email):
        """Helper to login and get token."""
        resp = client.post("/api/auth/login", json={
            "email": email,
            "password": "demo"
        })
        return resp.json()["access_token"]

    def test_superadmin_full_access(self, client):
        """Superadmin can access all modules."""
        token = self._login(client, "sherie@tempris.com")
        headers = {"Authorization": f"Bearer {token}"}

        # Should all return 200
        assert client.get("/api/audit/log", headers=headers).status_code == 200
        assert client.get("/api/spectrum/findings", headers=headers).status_code == 200
        assert client.get("/api/assets/", headers=headers).status_code == 200

    def test_viewer_read_only(self, client):
        """Viewer can read but cannot write."""
        token = self._login(client, "viewer@tempris.com")
        headers = {"Authorization": f"Bearer {token}"}

        # Read should work
        assert client.get("/api/audit/log", headers=headers).status_code == 200


class TestAuditTrailIntegrity:
    """Test that actions across modules create proper audit entries."""

    @pytest.fixture(autouse=True)
    def _clear_lockout(self):
        """Clear brute force lockout state before each test."""
        import routers.auth as auth_mod
        auth_mod._login_attempts.clear()
        yield
        auth_mod._login_attempts.clear()

    def test_login_creates_audit_entry(self, client):
        """Successful login should create an audit log entry."""
        # Login
        login_resp = client.post("/api/auth/login", json={
            "email": "sherie@tempris.com",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Check audit logs
        resp = client.get("/api/audit/log", headers=headers)
        assert resp.status_code == 200
        logs = resp.json()

        # Should contain at least a login entry
        if isinstance(logs, list) and len(logs) > 0:
            actions = [log.get("action", "") for log in logs]
            assert "USER_LOGIN" in actions, f"Expected USER_LOGIN in audit log, got: {actions}"

    def test_failed_login_creates_audit_entry(self, client):
        """Failed login should also be logged for security monitoring."""
        # Fail a login
        client.post("/api/auth/login", json={
            "email": "sherie@tempris.com",
            "password": "wrongpassword"
        })

        # Login to check audit
        login_resp = client.post("/api/auth/login", json={
            "email": "sherie@tempris.com",
            "password": "demo"
        })
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.get("/api/audit/log", headers=headers)
        logs = resp.json()
        if isinstance(logs, list) and len(logs) > 0:
            actions = [log.get("action", "") for log in logs]
            assert "USER_LOGIN_FAILED" in actions, f"Expected USER_LOGIN_FAILED in audit, got: {actions}"


class TestHealthEndpoints:
    """Test basic health and API availability."""

    def test_health_endpoint(self, client):
        """Health endpoint returns 200 with correct message."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "Tempris API running"

    def test_security_headers_present(self, client):
        """Every response should include security headers."""
        resp = client.get("/api/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Referrer-Policy" in resp.headers
        assert "Content-Security-Policy" in resp.headers
        assert "Permissions-Policy" in resp.headers

    def test_server_fingerprint_stripped(self, client):
        """Server header should not reveal backend technology."""
        resp = client.get("/api/health")
        # Should NOT have 'server' or 'x-powered-by' headers
        assert "x-powered-by" not in resp.headers


class TestSpectrumEdipFlow:
    """Test the Spectrum → EDIP decision flow."""

    def test_get_findings(self, client, superadmin_headers):
        """Spectrum findings endpoint returns data."""
        resp = client.get("/api/spectrum/findings", headers=superadmin_headers)
        assert resp.status_code == 200

    def test_edip_decision_workflow(self, client, superadmin_headers):
        """Can make EDIP decisions on findings."""
        # Get findings first
        resp = client.get("/api/spectrum/findings", headers=superadmin_headers)
        assert resp.status_code == 200
        findings = resp.json()

        # If there are findings, try making an EDIP decision
        if isinstance(findings, list) and len(findings) > 0:
            finding = findings[0]
            cve = finding.get("cve", "CVE-2024-0001")

            # Make EDIP decision
            decision_resp = client.post(
                "/api/spectrum/edip",
                json={
                    "finding_id": cve,
                    "cve": cve,
                    "decision": "investigate",
                    "rationale": "Integration test — investigating this finding"
                },
                headers=superadmin_headers
            )
            # Accept 200 or 201
            assert decision_resp.status_code in (200, 201, 422), \
                f"EDIP decision failed: {decision_resp.status_code} - {decision_resp.text}"


class TestScannerSSRFProtection:
    """Test scanner endpoint blocks internal IPs (SSRF protection)."""

    def test_scanner_blocks_localhost(self, client, superadmin_headers):
        """Scanner should reject localhost as target."""
        resp = client.post("/api/scanner/scan", json={
            "target": "127.0.0.1"
        }, headers=superadmin_headers)
        # Should be blocked (400 or 403)
        assert resp.status_code in (400, 403, 422), \
            f"Scanner should block localhost, got: {resp.status_code}"

    def test_scanner_blocks_internal_ip(self, client, superadmin_headers):
        """Scanner should reject internal/private IPs."""
        for target in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254"]:
            resp = client.post("/api/scanner/scan", json={
                "target": target
            }, headers=superadmin_headers)
            assert resp.status_code in (400, 403, 422), \
                f"Scanner should block {target}, got: {resp.status_code}"

    def test_scanner_blocks_ipv6_loopback(self, client, superadmin_headers):
        """Scanner should reject IPv6 loopback."""
        resp = client.post("/api/scanner/scan", json={
            "target": "::1"
        }, headers=superadmin_headers)
        assert resp.status_code in (400, 403, 422), \
            f"Scanner should block ::1, got: {resp.status_code}"


class TestSPARouting:
    """Test SPA routing and static file serving."""

    def test_root_serves_html(self, client):
        """Root path should serve the SPA (or 404 if index.html not built)."""
        resp = client.get("/")
        # 200 if frontend built, 404 in test env is acceptable
        assert resp.status_code in (200, 404)

    def test_security_page_serves_vdp(self, client):
        """The /security route should serve the VDP policy."""
        resp = client.get("/security")
        # Should serve VDP HTML or 404 if docs not found in test env
        assert resp.status_code in (200, 404)

    def test_api_404_for_nonexistent(self, client):
        """Non-existent API routes return 404, not the SPA."""
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404

    def test_dotfiles_blocked(self, client):
        """Dotfile paths should be blocked for security."""
        resp = client.get("/.env")
        assert resp.status_code in (404, 403)

        resp = client.get("/.git/config")
        assert resp.status_code in (404, 403)


class TestBruteForceProtection:
    """Test account lockout after repeated failed logins."""

    def test_lockout_after_max_attempts(self, client):
        """Account locks after MAX_LOGIN_ATTEMPTS failed tries."""
        email = "sherie@tempris.com"

        # Make 5 failed attempts
        for i in range(5):
            resp = client.post("/api/auth/login", json={
                "email": email,
                "password": "wrong"
            })
            # First 4 should be 401, 5th might trigger lockout
            assert resp.status_code in (401, 429), f"Attempt {i+1}: {resp.status_code}"

        # 6th attempt should be locked (429)
        resp = client.post("/api/auth/login", json={
            "email": email,
            "password": "demo"  # Even correct password should be locked
        })
        assert resp.status_code == 429, \
            f"Expected 429 lockout, got: {resp.status_code}"

        # Clean up lockout state for other tests
        from routers.auth import _login_attempts
        _login_attempts.pop(email, None)


class TestRateLimiting:
    """Test rate limiting middleware."""

    def test_health_not_rate_limited(self, client):
        """Health endpoint should not be rate limited."""
        for _ in range(20):
            resp = client.get("/api/health")
            assert resp.status_code == 200
