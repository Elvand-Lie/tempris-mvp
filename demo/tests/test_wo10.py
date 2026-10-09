# demo/tests/test_wo10.py — reset integrity + checksum-mismatch rejection.
# Requires the local Postgres (docker compose up db, or terra-demo-pg on 5433).
# Run: DATABASE_URL=... python -m pytest tests/test_wo10.py -q
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys

import pyotp
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "api"))

PACK = pathlib.Path(__file__).resolve().parent.parent / "pack" / "northwind_freight.v1.json"
PACK_SHA256 = hashlib.sha256(PACK.read_bytes()).hexdigest()
os.environ["DEMO_PACK_SHA256"] = PACK_SHA256
os.environ.setdefault("DATABASE_URL", "postgresql://demo:demo@localhost:5433/terra_demo")
os.environ["DEMO_PACK_PATH"] = str(PACK)

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app.auth import seed_user  # noqa: E402
from app.db import connect, init_schema  # noqa: E402

USER = "pytest-presenter"
PASSWORD = "PytestDemo!2026"


@pytest.fixture(scope="module")
def client():
    init_schema()
    info = seed_user(USER, PASSWORD)
    main.PACK_PATH = PACK
    with TestClient(main.app) as c:
        code = pyotp.TOTP(info["totp_provisioning_uri"].split("secret=")[1].split("&")[0]).now()
        r = c.post("/demo/login", json={"username": USER, "password": PASSWORD, "totp_code": code})
        assert r.status_code == 200, r.text
        c.headers.update({"Authorization": f"Bearer {r.json()['token']}"})
        yield c


def test_reset_loads_the_pinned_pack(client):
    r = client.post("/demo/reset")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "reset"
    pack = client.get("/demo/pack").json()
    assert len(pack["assets"]) == 18
    assert sorted(pack["journeys"].keys()) == ["A", "B", "C", "D", "E"]
    assert pack["estate"]["name"] == "Northwind Freight"


def test_reset_restores_drifted_state(client):
    client.post("/demo/reset")
    baseline = client.get("/demo/pack").json()
    # simulate presenter-driven drift directly in the tenant tables
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', 'terra', false)")
            cur.execute(
                "UPDATE pack_findings SET payload = payload || '{\"status\": \"nuked\"}'::jsonb"
            )
    drifted = client.get("/demo/pack").json()
    assert any(f["status"] == "nuked" for f in drifted["findings"])
    r = client.post("/demo/reset")
    assert r.status_code == 200
    restored = client.get("/demo/pack").json()
    assert restored["findings"] == baseline["findings"]


def test_checksum_mismatch_is_rejected(client, monkeypatch):
    monkeypatch.setattr(main, "PACK_SHA256", "0" * 64)
    r = client.post("/demo/reset")
    assert r.status_code == 500
    assert "integrity" in r.json()["detail"]


def test_pack_file_matches_pinned_checksum():
    assert hashlib.sha256(PACK.read_bytes()).hexdigest() == PACK_SHA256


def test_no_secrets_in_pack():
    """Credential records carry names/scopes only — never values."""
    pack = json.loads(PACK.read_text(encoding="utf-8"))
    for asset in pack["assets"]:
        for cred in (asset.get("agent") or {}).get("credentials", []):
            assert set(cred.keys()) <= {"name", "scope"}, cred
    blob = PACK.read_text(encoding="utf-8").lower()
    for marker in ("api_key", "apikey", "bearer ", "password=", "sk-proj", "sk-ant", "secret:"):
        assert marker not in blob, f"possible secret material in pack: {marker}"


def test_journey_e_is_the_approved_card():
    pack = json.loads(PACK.read_text(encoding="utf-8"))
    e = pack["journeys"]["E"]
    assert e["talk_track_source"].startswith("External Journey E card")
    screens = [s["screen"] for s in e["steps"]]
    assert screens == [
        "asset_inventory", "asset_detail", "attack_path", "coverage", "decision_view",
    ]
    joined = " ".join(s["talk"] for s in e["steps"])
    for line in (
        "inventoried, owned and tracked",
        "blast radius is its connections",
        "Declared isn't verified",
        "ordered, accountable decision",
    ):
        assert line in joined, line
