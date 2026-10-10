# demo/tests/test_wo10_access.py — WO-10 10c access control and acceptance (d)(f)(g).
# Same harness and local Postgres as test_wo10.py:
#   DATABASE_URL=... python -m pytest tests/test_wo10_access.py -q
from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import time
import uuid

import pyotp
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "api"))

PACK = pathlib.Path(__file__).resolve().parent.parent / "pack" / "northwind_freight.v1.json"
os.environ["DEMO_PACK_SHA256"] = hashlib.sha256(PACK.read_bytes()).hexdigest()
os.environ.setdefault("DATABASE_URL", "postgresql://demo:demo@localhost:5433/terra_demo")
os.environ["DEMO_PACK_PATH"] = str(PACK)
os.environ["DEMO_INVITE_SECRET"] = "pytest-invite-secret-" + "k" * 32

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app import enroll  # noqa: E402
from app.auth import seed_user  # noqa: E402
from app.db import connect, init_schema  # noqa: E402

PASSWORD = "PytestDemo!2026"


def _name(prefix: str) -> str:
    return f"pt-{prefix}-{uuid.uuid4().hex[:8]}"


def _code(info: dict) -> str:
    return pyotp.TOTP(info["totp_provisioning_uri"].split("secret=")[1].split("&")[0]).now()


def _sql(stmt: str, params: tuple) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(stmt, params)


def _user_row(username: str):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, totp_secret, revoked, expires_at FROM users WHERE username = %s", (username,))
            return cur.fetchone()


def _login(client, username: str, info: dict, password: str = PASSWORD):
    return client.post("/demo/login", json={"username": username, "password": password, "totp_code": _code(info)})


@pytest.fixture(scope="module")
def client():
    init_schema()
    main.PACK_PATH = PACK
    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def session(client):
    """A fresh named presenter, signed in. Returns (username, info, headers)."""
    username = _name("presenter")
    info = seed_user(username, PASSWORD)
    r = _login(client, username, info)
    assert r.status_code == 200, r.text
    return username, info, {"Authorization": f"Bearer {r.json()['token']}"}


# ---------- acceptance (f): expired and revoked accounts are rejected ----------

def test_expired_account_cannot_sign_in(client):
    username = _name("expired")
    info = seed_user(username, PASSWORD)
    _sql("UPDATE users SET expires_at = now() - interval '1 day' WHERE username = %s", (username,))
    r = _login(client, username, info)
    assert r.status_code == 403, r.text
    assert "expired" in r.json()["detail"].lower()


def test_expired_account_session_is_cut_off(client, session):
    username, _info, headers = session
    assert client.get("/demo/bootstrap", headers=headers).status_code == 200
    _sql("UPDATE users SET expires_at = now() - interval '1 minute' WHERE username = %s", (username,))
    r = client.get("/demo/pack", headers=headers)
    assert r.status_code == 403, r.text
    assert "expired" in r.json()["detail"].lower()


def test_revoked_account_cannot_sign_in(client):
    username = _name("revoked")
    info = seed_user(username, PASSWORD)
    _sql("UPDATE users SET revoked = TRUE WHERE username = %s", (username,))
    r = _login(client, username, info)
    assert r.status_code in (401, 403), r.text


def test_revoked_account_session_is_cut_off_instantly(client, session):
    username, _info, headers = session
    assert client.get("/demo/bootstrap", headers=headers).status_code == 200
    _sql("UPDATE users SET revoked = TRUE WHERE username = %s", (username,))
    r = client.get("/demo/bootstrap", headers=headers)
    assert r.status_code in (401, 403), r.text
    assert client.post("/demo/reset", headers=headers).status_code in (401, 403)


# ---------- 10c: accounts are issued by Tempris; enrollment cannot take over ----------

def test_enrollment_cannot_overwrite_or_unrevoke_an_existing_account(client):
    victim = _name("victim")
    seed_user(victim, PASSWORD)
    _sql("UPDATE users SET revoked = TRUE WHERE username = %s", (victim,))
    before = _user_row(victim)
    r = client.post("/demo/register", json={
        "username": victim, "password": "Attacker!Passw0rd", "invite_code": enroll.mint_invite(victim),
    })
    assert r.status_code == 409, r.text
    after = _user_row(victim)
    assert after == before  # same password hash, TOTP secret, revoked flag and expiry


def test_enrollment_requires_a_tempris_invite_for_that_username(client):
    username = _name("noinvite")
    other = _name("other")
    for code in ("", "garbage", enroll.mint_invite(other), enroll.mint_invite(username)[:-1] + "0"):
        r = client.post("/demo/register", json={"username": username, "password": PASSWORD, "invite_code": code})
        assert r.status_code == 403, (code, r.text)
    expired = enroll.mint_invite(username, ttl_s=60, now=time.time() - 3600)
    r = client.post("/demo/register", json={"username": username, "password": PASSWORD, "invite_code": expired})
    assert r.status_code == 403 and "expired" in r.json()["detail"].lower()
    assert _user_row(username) is None


def test_enrollment_with_invite_creates_one_account_once(client):
    username = _name("enrol")
    code = enroll.mint_invite(username)
    r = client.post("/demo/register", json={"username": username, "password": PASSWORD, "invite_code": code})
    assert r.status_code == 200, r.text
    assert r.json()["qr_svg"].lstrip().startswith("<")
    again = client.post("/demo/register", json={"username": username, "password": "Another!Passw0rd", "invite_code": code})
    assert again.status_code == 409


def test_enrollment_is_disabled_without_the_host_secret(client, monkeypatch):
    monkeypatch.delenv("DEMO_INVITE_SECRET", raising=False)
    username = _name("disabled")
    r = client.post("/demo/register", json={"username": username, "password": PASSWORD, "invite_code": "1.abc"})
    assert r.status_code == 403 and "disabled" in r.json()["detail"].lower()
    assert _user_row(username) is None


def test_lockout_after_five_failed_attempts(client):
    username = _name("lockout")
    info = seed_user(username, PASSWORD)
    wrong = pyotp.TOTP(pyotp.random_base32()).now()
    for _ in range(5):
        r = client.post("/demo/login", json={"username": username, "password": PASSWORD, "totp_code": wrong})
        assert r.status_code != 200
    r = _login(client, username, info)  # correct code, but the account is now locked
    assert r.status_code != 200 and "locked" in r.json()["detail"].lower(), r.text


# ---------- acceptance (d) reset < 60 s, (g) audit trail ----------

def test_reset_completes_within_60_seconds(client, session):
    _username, _info, headers = session
    t0 = time.monotonic()
    r = client.post("/demo/reset", headers=headers)
    assert r.status_code == 200, r.text
    assert time.monotonic() - t0 < 60


def test_audit_records_login_journey_reset_and_export(client, session):
    _username, _info, headers = session
    marker = uuid.uuid4().hex
    assert client.post("/demo/journey-event", headers=headers, json={"journey": "A", "step": 1, "title": marker}).status_code == 200
    assert client.post("/demo/reset", headers=headers).status_code == 200
    assert client.post("/demo/export", headers=headers, json={"kind": f"report.pdf {marker}"}).status_code == 200
    events = client.get("/demo/audit", headers=headers).json()["events"]
    names = {e["event"] for e in events}
    assert {"demo.login", "demo.journey_step", "demo.reset", "demo.export"} <= names, names
    blobs = [str(e["detail"]) for e in events]
    assert any(marker in b for b in blobs if "journey" in b)
    assert any(marker in b for b in blobs if "report.pdf" in b)
