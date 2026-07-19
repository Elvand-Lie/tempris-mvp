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
    bundle_match = re.search(r'src="(/assets/index-[^"]+\.js)"', response.text)
    assert bundle_match, "SPA bootstrap must select a JavaScript bundle"

    bundle = client.get(bundle_match.group(1))

    assert bundle.status_code == 200
    assert "localStorage.setItem(`tempris_token`" in bundle.text


def test_direct_index_and_spa_fallback_are_not_cached():
    client = TestClient(app)

    assert client.get("/index.html").headers["cache-control"] == "no-store, max-age=0"
    assert client.get("/synthesis").headers["cache-control"] == "no-store, max-age=0"


def test_legacy_frontend_serves_native_style_module_extension_and_branding():
    client = TestClient(app)

    index = client.get("/")
    script = client.get("/extensions/tempris-modules.js")
    stylesheet = client.get("/extensions/tempris-modules.css")
    logo = client.get("/brand/tempris-logo-light.png")

    assert 'src="/assets/index-DUrFdX-d.js"' in index.text
    assert 'src="/extensions/tempris-modules.js"' in index.text
    assert 'href="/extensions/tempris-modules.css"' in index.text
    assert script.status_code == 200
    assert "'/api/ciso/summary'" in script.text
    assert "'/packages'" in script.text
    assert stylesheet.status_code == 200
    assert ".tmx-page" in stylesheet.text
    assert logo.status_code == 200
    assert logo.headers["content-type"] == "image/png"
