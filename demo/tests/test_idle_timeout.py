# demo/tests/test_idle_timeout.py — a session idle for more than
# IDLE_TIMEOUT_MINUTES is rejected and deleted (WO-10 10c; delivery-report
# blocker #11: "no backend test for the 30-minute idle timeout").
from __future__ import annotations

import hashlib
import os
import pathlib
import sys
from datetime import timedelta

import pyotp
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "api"))

PACK = pathlib.Path(__file__).resolve().parent.parent / "pack" / "northwind_freight.v1.json"
os.environ.setdefault("DEMO_PACK_SHA256", hashlib.sha256(PACK.read_bytes()).hexdigest())
os.environ.setdefault("DATABASE_URL", "postgresql://demo:demo@localhost:5433/terra_demo")
os.environ["DEMO_PACK_PATH"] = str(PACK)

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app.auth import IDLE_TIMEOUT_MINUTES, seed_user, utcnow  # noqa: E402
from app.db import connect  # noqa: E402

USER = "idle-timeout-qa"
PASSWORD = "IdleTimeout!2026"


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
        token = r.json()["token"]
        c.headers.update({"Authorization": f"Bearer {token}"})
        yield c, token


def test_fresh_session_passes(client):
    c, _ = client
    assert c.get("/demo/bootstrap").status_code == 200


def test_idle_session_is_rejected_and_deleted(client):
    c, token = client
    stale = utcnow() - timedelta(minutes=IDLE_TIMEOUT_MINUTES + 1)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE sessions SET last_seen = %s WHERE token = %s", (stale, token))
    r = c.get("/demo/bootstrap")
    assert r.status_code == 401
    assert "timed out" in r.json()["detail"]
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM sessions WHERE token = %s", (token,))
            assert cur.fetchone()[0] == 0  # the stale session row is gone
