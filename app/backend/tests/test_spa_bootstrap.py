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

    assert 'src="/assets/index-DUrFdX-d.js?v=20260816b"' in index.text
    assert 'src="/extensions/tempris-bootstrap.js?v=20260816b"' in index.text
    assert index.text.index('src="/extensions/tempris-bootstrap.js?v=20260816b"') < index.text.index('src="/assets/index-DUrFdX-d.js?v=20260816b"')
    assert 'src="/extensions/tempris-sss-ui.js?v=20260816b"' in index.text
    assert 'src="/extensions/tempris-modules.js?v=20260816b"' in index.text
    assert 'href="/extensions/tempris-modules.css?v=20260816b"' in index.text
    assert script.status_code == 200
    assert script.headers["cache-control"] == "no-store, max-age=0"
    assert bootstrap.headers["cache-control"] == "no-store, max-age=0"
    assert stylesheet.headers["cache-control"] == "no-store, max-age=0"
    assert bootstrap.status_code == 200
    assert "Contextual scoring inputs remain server-side" in bootstrap.text
    assert "normalizeToggleGroup" not in bootstrap.text
    assert "toggles.agm" not in bootstrap.text
    assert "'/api/ciso/summary'" in script.text
    assert "'/packages'" in script.text
    assert "'/api/packages/current'" in script.text
    assert "Business Logic Flaw Intake" in script.text
    assert "Secure online intake" in script.text
    assert "Enabled Modules" in script.text
    assert "'/vdp-queue'" in script.text
    assert "VDP Security Queue" in script.text
    assert "Remove selected" in script.text
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
    assert "Evidence note (required when confirming a catalogue vulnerability)" in script.text
    assert "Optional evidence file" in script.text
    assert "data-asset-picker-file" in script.text
    assert "data-exposure-prev" in script.text
    assert "const data = await loadCiso(true);" in script.text
    assert "Already linked — uncheck to remove this asset from the finding." in script.text
    assert "Describe how you verified that the selected asset is affected (at least 10 characters)." in script.text
    assert "window.addEventListener('focus'" not in script.text
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
    assert "Legacy asset pointer — review required" in script.text
    assert "finding.asset_id ? [assets.find" not in script.text
    assert "Powered by Codingo Wave 1 Architecture" in script.text
    assert "Tempris Technology Pte. Ltd. · Secure Workspace" in script.text
    assert "button.style.display = 'none'" in script.text
    assert stylesheet.status_code == 200
    assert ".tmx-page" in stylesheet.text
    assert logo.status_code == 200
    assert logo.headers["content-type"] == "image/png"


def test_native_module_routes_are_not_extension_takeovers_and_keep_primary_controls():
    frontend = Path(__file__).resolve().parents[2] / "frontend"
    extension = (frontend / "extensions" / "tempris-modules.js").read_text(encoding="utf-8")
    bundle = (frontend / "assets" / "index-DUrFdX-d.js").read_text(encoding="utf-8")

    extension_route_line = next(line for line in extension.splitlines() if "const EXTENSION_ROUTES" in line)
    native_routes = ("/spectrum", "/scout", "/strike", "/standard", "/grc", "/spotlight")
    assert all(route not in extension_route_line for route in native_routes)
    assert all(f"if (path === '{route}')" not in extension for route in native_routes)

    native_controls = {
        "/spectrum": ("SPECTRUM Analysis", "CTEM Lifecycle", "EDIP Engine Recommendation"),
        "/scout": ("Launch Scan", "Scan History", "CISA KEV Intelligence", "explicitly authorised for this SCOUT scan"),
        "/strike": ("Authorization", "MITRE ATT&CK", "Check confidence"),
        "/standard": ("STANDARD Compliance", "Assessment coverage", "Compliance among assessed"),
        "/grc": ("GRC SOP Builder", "Gap Analysis", "Policy Library", "policyArchive", "policySupersede", "policyDelete"),
        "/spotlight": ("Generate Report", "Report History", "Canonical Posture"),
    }
    for route, markers in native_controls.items():
        assert all(marker in bundle for marker in markers), route

    assert "children:e.aggregate_tes==null?`N/A`:e.aggregate_tes.toFixed(1)" in bundle
    assert "strokeDashoffset:e.aggregate_tes==null?502" in bundle
    assert "No confirmed scoreable exposure" in bundle
    assert "scope=confirmed_exposure" in bundle
    assert "window.location.search.includes(`history=1`)?`/api/spectrum/findings?limit=2000`:`/api/spectrum/findings?limit=2000&scope=confirmed_exposure`" in bundle
    assert "$(`window.location.search.includes" not in bundle
    assert "Linked assets and evidence" in bundle
    assert "Current decision — revise if new evidence is recorded" in bundle
    assert "No EDIP decision" in bundle


def test_every_retained_bundle_excludes_tes_internals():
    asset_root = Path(__file__).resolve().parents[2] / "frontend" / "assets"
    bundles = sorted(asset_root.glob("index-*.js"))
    assert len(bundles) == 5
    forbidden = (
        "TES Modifier Impact",
        "Auto-feeds TES modifiers",
        "1.0 compliant · 1.5 non-compliant",
        "tes_modifier:",
        "AGM ↑ if gap",
    )
    for bundle in bundles:
        source = bundle.read_text(encoding="utf-8")
        assert all(value not in source for value in forbidden), bundle.name
