import os
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from passlib.hash import bcrypt


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AUDIT_HMAC_KEY", "test_audit_hmac_secret_key_12345678")

from index import app
from routers import auth


def test_spa_bootstrap_is_not_cached_and_uses_token_persisting_bundle():
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    bundle_match = re.search(r'src="(/assets/index-[^"]+\.js(?:\?v=[^"]+)?)"', response.text)
    assert bundle_match, "SPA bootstrap must select a JavaScript bundle"

    bundle = client.get(bundle_match.group(1))

    assert bundle.status_code == 200
    assert "localStorage.setItem(`tempris_token`" in bundle.text
    assert "localStorage.setItem(`tempris_user`" in bundle.text
    assert "JSON.parse(localStorage.getItem(`tempris_user`)" in bundle.text


def test_direct_index_and_spa_fallback_are_not_cached():
    client = TestClient(app)

    assert client.get("/index.html").headers["cache-control"] == "no-store, max-age=0"
    assert client.get("/synthesis").headers["cache-control"] == "no-store, max-age=0"


def test_read_only_standard_page_avoids_forbidden_cross_module_bootstrap(monkeypatch):
    from middleware.rate_limit import _Bucket

    monkeypatch.setattr(_Bucket, "consume", lambda self: True)
    email = "readonly.bootstrap@tempris.test"
    auth.USERS[email] = {
        "password": bcrypt.hash("readonly-bootstrap-password"),
        "role": "Read-only",
        "name": "Read-only Bootstrap",
        "tenant_id": "tenant-readonly-bootstrap",
    }
    try:
        client = TestClient(app)
        login = client.post(
            "/api/auth/login",
            json={"email": email, "password": "readonly-bootstrap-password"},
        )
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        assert client.get("/api/standard/frameworks", headers=headers).status_code == 200
        assert client.get("/api/audit/log", headers=headers).status_code == 200
        assert client.get(
            "/api/scout/findings?limit=5&ransomware_only=true", headers=headers
        ).status_code == 403
        assert client.get("/api/packages/current", headers=headers).status_code == 403

        index = client.get("/").text
        bundle_path = re.search(r'src="(/assets/index-[^"]+\.js(?:\?v=[^"]+)?)"', index).group(1)
        bundle = client.get(bundle_path).text
        extension = client.get("/extensions/tempris-modules.js").text
        assert "e?.role===`Read-only`?Promise.resolve({data:[]})" in bundle
        assert "currentUserRole() === 'Read-only'" in extension
    finally:
        auth.USERS.pop(email, None)


def test_legacy_frontend_serves_native_style_module_extension_and_branding():
    client = TestClient(app)

    index = client.get("/")
    script = client.get("/extensions/tempris-modules.js")
    bootstrap = client.get("/extensions/tempris-bootstrap.js")
    stylesheet = client.get("/extensions/tempris-modules.css")
    logo = client.get("/brand/tempris-logo-light.png")

    assert 'src="/assets/index-DUrFdX-d.js?v=20260810b"' in index.text
    assert 'src="/extensions/tempris-bootstrap.js?v=20260810b"' in index.text
    assert index.text.index('src="/extensions/tempris-bootstrap.js?v=20260810b"') < index.text.index('src="/assets/index-DUrFdX-d.js?v=20260810b"')
    assert 'src="/extensions/tempris-modules.js?v=20260810b"' in index.text
    assert 'href="/extensions/tempris-modules.css?v=20260810b"' in index.text
    assert script.status_code == 200
    assert script.headers["cache-control"] == "no-store, max-age=0"
    assert bootstrap.headers["cache-control"] == "no-store, max-age=0"
    assert stylesheet.headers["cache-control"] == "no-store, max-age=0"
    assert bootstrap.status_code == 200
    assert "url.pathname !== '/api/grc/state'" in bootstrap.text
    assert "normalizeToggleGroup(toggles.agm" in bootstrap.text
    assert "'/api/ciso/summary'" in script.text
    assert "'/packages'" in script.text
    assert "'/api/packages/current'" in script.text
    assert "Business Logic Flaw Intake" in script.text
    assert "Secure online intake" in script.text
    assert "Enabled Modules" in script.text
    assert "'/vdp-queue'" in script.text
    assert "VDP Security Queue" in script.text
    assert "Confirm resolution" in script.text
    assert "Client Report Service" in script.text
    assert "Most Exposed Assets" in script.text
    assert "Priority Remediation Items" in script.text
    assert "Recent Incident Drafts" in script.text
    assert "Edit as new report" in script.text
    assert "96.3% MAPPED" not in script.text
    assert "'/api/reports/poc/generate'" in script.text
    assert "client_consent_for_partner" in script.text
    assert "Vulnerability Exposure Review Queue" in script.text
    assert "Every submitted intake is stored in the shared findings database" in script.text
    assert "view=needs_review" in script.text
    assert "Keep as reference" in script.text
    assert "Not applicable" in script.text
    assert "exposure-classification" in script.text
    assert "data-recent-toggle" in script.text
    assert "method: 'PUT'" in script.text
    assert script.text.index("[data-asset-picker-options]').addEventListener('change'") < script.text.index("[data-asset-picker-confirm]').addEventListener('click'")
    assert "Select at least one affected customer asset" not in script.text
    assert "data-report-format" in script.text
    assert "window.prompt" not in script.text
    assert "Backend package-entitlement enforcement is not implemented" not in script.text
    assert "document.body.append(host)" in script.text
    assert "host.innerHTML" in script.text
    assert "main.innerHTML" not in script.text
    assert "rootObserver.observe(root" in script.text
    assert "observe(document.documentElement" not in script.text
    assert "Use your assigned Tempris credentials." in script.text
    assert "Powered by Codingo Wave 1 Architecture" in script.text
    assert "Tempris Technology Pte. Ltd. · Secure Workspace" in script.text
    assert "button.style.display = 'none'" in script.text
    assert stylesheet.status_code == 200
    assert ".tmx-page" in stylesheet.text
    assert logo.status_code == 200
    assert logo.headers["content-type"] == "image/png"
