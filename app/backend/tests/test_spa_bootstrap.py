import os
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AUDIT_HMAC_KEY", "test_audit_hmac_secret_key_12345678")

from index import app


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


def test_legacy_frontend_serves_native_style_module_extension_and_branding():
    client = TestClient(app)

    index = client.get("/")
    script = client.get("/extensions/tempris-modules.js")
    bootstrap = client.get("/extensions/tempris-bootstrap.js")
    stylesheet = client.get("/extensions/tempris-modules.css")
    logo = client.get("/brand/tempris-logo-light.png")

    assert 'src="/assets/index-DUrFdX-d.js?v=20260724d"' in index.text
    assert 'src="/extensions/tempris-bootstrap.js?v=20260724d"' in index.text
    assert index.text.index('src="/extensions/tempris-bootstrap.js?v=20260724d"') < index.text.index('src="/assets/index-DUrFdX-d.js?v=20260724d"')
    assert 'src="/extensions/tempris-modules.js?v=20260724d"' in index.text
    assert 'href="/extensions/tempris-modules.css?v=20260724d"' in index.text
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
