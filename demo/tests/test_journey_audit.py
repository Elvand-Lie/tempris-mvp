# demo/tests/test_journey_audit.py — journey-step audit events are validated
# against the pinned pack; fabricated steps are refused, not recorded.
# Requires the local Postgres (DATABASE_URL). Uses the full API stack.
from __future__ import annotations

import hashlib
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
os.environ.setdefault("DB_APP_PASSWORD", "")  # bootstrap role in tests
os.environ.setdefault("DEMO_INVITE_SECRET", "test-invite-secret-0123456789abcdef")

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app.auth import seed_user  # noqa: E402

USER = "journey-audit-qa"
PASSWORD = "JourneyAudit!2026"


@pytest.fixture(scope="module")
def client():
    from app.db import init_schema

    init_schema()
    info = seed_user(USER, PASSWORD)
    main.PACK_PATH = PACK
    with TestClient(main.app) as c:
        code = pyotp.TOTP(info["totp_provisioning_uri"].split("secret=")[1].split("&")[0]).now()
        r = c.post("/demo/login", json={"username": USER, "password": PASSWORD, "totp_code": code})
        assert r.status_code == 200, r.text
        c.headers.update({"Authorization": f"Bearer {r.json()['token']}"})
        yield c


def _audit_rows(client, journey):
    r = client.get("/demo/audit")
    return [e for e in r.json()["events"] if e["event"] == "demo.journey_step"
            and e["detail"].get("journey") == journey]


def test_valid_journey_step_is_recorded(client):
    assert client.post("/demo/journey-event", json={"journey": "A", "step": 1, "title": "t"}).status_code == 200
    assert len(_audit_rows(client, "A")) >= 1


def test_fabricated_journey_is_refused_and_not_recorded(client):
    before = len(_audit_rows(client, "Z"))
    r = client.post("/demo/journey-event", json={"journey": "Z", "step": 99, "title": "fake"})
    assert r.status_code == 422
    assert len(_audit_rows(client, "Z")) == before


def test_out_of_range_step_is_refused_and_not_recorded(client):
    before = len(_audit_rows(client, "A"))
    r = client.post("/demo/journey-event", json={"journey": "A", "step": 42, "title": "fake"})
    assert r.status_code == 422
    assert len(_audit_rows(client, "A")) == before


def test_explore_navigation_remains_allowed(client):
    r = client.post("/demo/journey-event", json={"journey": "EXPLORE", "step": 1, "title": "Overview"})
    assert r.status_code == 200
    r = client.post("/demo/journey-event", json={"journey": "EXPLORE", "step": 99, "title": "x"})
    assert r.status_code == 422
