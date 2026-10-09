# demo/api/app/auth.py — WO-10 access control: named presenters, TOTP MFA,
# 5-attempt lockout, 30-min idle timeout, 90-day expiry, instant revocation.
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .db import connect

MAX_FAILED = 5
LOCKOUT_MINUTES = 15
IDLE_TIMEOUT_MINUTES = 30
ACCOUNT_TTL_DAYS = 90
DEMO_TENANT = "terra"

_bearer = HTTPBearer(auto_error=False)


def _hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2**14, r=8, p=1
    ).hex()
    return f"{salt}${digest}"


def _verify_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$", 1)
    check = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2**14, r=8, p=1
    ).hex()
    return hmac.compare_digest(check, digest)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def seed_user(
    username: str, password: str, *, tenant_id: str = DEMO_TENANT
) -> dict:
    """Create (or reset) a named presenter. Returns the TOTP provisioning
    info for the one-time QR setup; the secret is NOT stored anywhere else."""
    secret = pyotp.random_base32()
    expires = utcnow() + timedelta(days=ACCOUNT_TTL_DAYS)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, tenant_id, password_hash, totp_secret, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (username) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    totp_secret = EXCLUDED.totp_secret,
                    failed_attempts = 0, locked_until = NULL,
                    expires_at = EXCLUDED.expires_at, revoked = FALSE
                RETURNING totp_secret, expires_at
                """,
                (username, tenant_id, _hash_password(password), secret, expires),
            )
    return {
        "username": username,
        "totp_provisioning_uri": pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, issuer_name="Tempris Demo"
        ),
        "expires_at": expires.isoformat(),
    }


def login(username: str, password: str, totp_code: str, *, tenant_id: str = DEMO_TENANT) -> str:
    """Verify credentials + TOTP; enforce lockout/expiry/revocation.
    Returns a session bearer token."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT password_hash, totp_secret, failed_attempts, locked_until,
                       expires_at, revoked, tenant_id
                FROM users WHERE username = %s
                FOR UPDATE
                """,
                (username,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(401, "invalid credentials")
            stored, secret, failed, locked_until, expires_at, revoked, user_tenant = row
            now = utcnow()
            fail = HTTPException(401, "invalid credentials")
            if user_tenant != tenant_id:
                raise fail
            if locked_until is not None and locked_until > now:
                raise HTTPException(
                    423,
                    f"account locked after {MAX_FAILED} failed attempts — "
                    f"retry after {locked_until.isoformat()} or contact Tempris",
                )
            if revoked:
                raise HTTPException(403, "account revoked")
            if expires_at < now:
                raise HTTPException(403, "account expired — contact Tempris to renew")
            if not _verify_password(password, stored) or not pyotp.TOTP(secret).verify(
                totp_code.replace(" ", ""), valid_window=1
            ):
                # Commit the failure on this same connection (the row is locked
                # here) BEFORE raising, so the increment is not rolled back.
                failed += 1
                locked = failed >= MAX_FAILED
                cur.execute(
                    """
                    UPDATE users SET failed_attempts = %s,
                        locked_until = CASE WHEN %s THEN %s ELSE locked_until END
                    WHERE username = %s
                    """,
                    (0 if locked else failed,
                     locked, now + timedelta(minutes=LOCKOUT_MINUTES), username),
                )
                conn.commit()
                raise fail
            cur.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = %s",
                (username,),
            )
            token = secrets.token_urlsafe(32)
            cur.execute(
                """
                INSERT INTO sessions (token, username, tenant_id)
                VALUES (%s, %s, %s)
                """,
                (token, username, user_tenant),
            )
            return token


def audit(tenant_id: str, username: str, event: str, detail: dict | None = None) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_events (tenant_id, username, event, detail) VALUES (%s, %s, %s, %s)",
                (tenant_id, username, event, json.dumps(detail or {})),
            )


def revoke_session(token: str) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token = %s", (token,))


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Session guard: valid token, 30-min idle timeout, expiry, revocation,
    presenter role only (single role — every session is a presenter)."""
    if creds is None:
        raise HTTPException(401, "authentication required")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.token, s.username, s.tenant_id, s.last_seen,
                       u.expires_at, u.revoked, u.locked_until
                FROM sessions s JOIN users u ON u.username = s.username
                WHERE s.token = %s
                """,
                (creds.credentials,),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(401, "session invalid — log in again")
            token, username, tenant_id, last_seen, expires_at, revoked, _locked = row
            now = utcnow()
            if revoked:
                raise HTTPException(403, "account revoked")
            if expires_at < now:
                raise HTTPException(403, "account expired")
            if last_seen < now - timedelta(minutes=IDLE_TIMEOUT_MINUTES):
                cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
                raise HTTPException(
                    401, f"session timed out after {IDLE_TIMEOUT_MINUTES} minutes idle"
                )
            cur.execute(
                "UPDATE sessions SET last_seen = now() WHERE token = %s", (token,)
            )
            return {"username": username, "tenant_id": tenant_id, "role": "presenter"}


def make_jwt_like_token() -> str:  # pragma: no cover
    return uuid.uuid4().hex
