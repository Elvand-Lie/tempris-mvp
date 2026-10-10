# demo/api/app/enroll.py — in-app presenter enrollment, made WO-10 10c compliant.
#
# 10c: "Named users only (one per Terra presenter; no shared logins), issued by
# Tempris." In-app enrollment (c39ca94) is kept, but:
#   * it is DISABLED unless Tempris sets DEMO_INVITE_SECRET on the demo host;
#   * each enrollment needs a Tempris-issued invite (issue_invite.py) that is
#     bound to one username and expires (max 7 days);
#   * the account row is INSERT-only. An existing username — active, expired or
#     revoked — is never overwritten, so enrollment cannot reset another
#     presenter's password/TOTP or lift a revocation (acceptance f).
# Renewal and resets stay an admin action via provision_presenter.py.
from __future__ import annotations

import hashlib
import hmac
import os
import time
from datetime import timedelta

import pyotp
from fastapi import HTTPException

from .auth import ACCOUNT_TTL_DAYS, DEMO_TENANT, _hash_password, utcnow
from .db import connect

INVITE_SECRET_ENV = "DEMO_INVITE_SECRET"
INVITE_DEFAULT_TTL_S = 72 * 3600
INVITE_MAX_TTL_S = 7 * 86400


def _secret() -> bytes:
    value = os.environ.get(INVITE_SECRET_ENV, "")
    if len(value) < 32:
        raise HTTPException(403, "in-app enrollment is disabled — ask Tempris to issue your presenter account")
    return value.encode()


def _sign(username: str, exp: int) -> str:
    return hmac.new(_secret(), f"{username}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]


def mint_invite(username: str, ttl_s: int = INVITE_DEFAULT_TTL_S, *, now: float | None = None) -> str:
    """Tempris-side: an invite for exactly one username, valid for ttl_s seconds."""
    exp = int((time.time() if now is None else now) + min(ttl_s, INVITE_MAX_TTL_S))
    return f"{exp}.{_sign(username, exp)}"


def verify_invite(username: str, code: str, *, now: float | None = None) -> None:
    t = time.time() if now is None else now
    try:
        exp_s, sig = (code or "").strip().split(".", 1)
        exp = int(exp_s)
    except ValueError:
        raise HTTPException(403, "invalid invite code") from None
    if not hmac.compare_digest(_sign(username, exp), sig):
        raise HTTPException(403, "invalid invite code")
    if exp < t:
        raise HTTPException(403, "invite code expired — ask Tempris for a new one")
    if exp - t > INVITE_MAX_TTL_S + 60:
        raise HTTPException(403, "invalid invite code")


def create_presenter(username: str, password: str, *, tenant_id: str = DEMO_TENANT) -> dict:
    """Insert-only account creation. Returns the one-time TOTP provisioning info."""
    secret = pyotp.random_base32()
    expires = utcnow() + timedelta(days=ACCOUNT_TTL_DAYS)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, tenant_id, password_hash, totp_secret, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING
                RETURNING expires_at
                """,
                (username, tenant_id, _hash_password(password), secret, expires),
            )
            row = cur.fetchone()
    if row is None:
        raise HTTPException(409, "this username already has an account — ask Tempris to renew or reset it")
    return {
        "username": username,
        "totp_provisioning_uri": pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, issuer_name="Tempris Demo"
        ),
        "expires_at": expires.isoformat(),
    }
