# backend/app/routes/auth.py
import hashlib
import time
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
from app import config
from app.config import (
    JWT_SECRET,
    JWT_ALGORITHM,
    PLATFORM_TENANT_ID,
)
from app.auth import AuthContext, get_auth_context
from app.auth_crypto import verify_password_scrypt, compute_dummy_scrypt
from app.db import get_db_connection
from app.audit import record_audit_event

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# Session lifetime is pinned to the token lifetime (exp - iat = 3600):
# explicit 1-hour re-login — the refresh-vs-relogin decision (PRD Ch.5 open
# decision #1) is decided for v1 as NO refresh tokens; the user_sessions
# store (migration 024) is the extension point if refresh is ever
# productized.
SESSION_LIFETIME_SECONDS = 3600

class LoginRateGuard:
    """
    Minimal stdlib in-memory per-client login attempt rate guard.
    Thread-safe across concurrent worker threads and requests.
    Supports injectable controllable clock for deterministic testing.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: float = 60.0, clock: Callable[[], float] = time.time):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.clock = clock
        self._lock = threading.Lock()
        self._attempts: Dict[str, List[float]] = {}

    def check_and_record(self, client_id: str) -> bool:
        with self._lock:
            now = self.clock()
            cutoff = now - self.window_seconds

            # Prune expired timestamps and delete stale/empty client buckets so keys do not accumulate
            stale_keys = []
            for cid, ts_list in self._attempts.items():
                active = [t for t in ts_list if t > cutoff]
                if not active:
                    stale_keys.append(cid)
                elif len(active) != len(ts_list):
                    self._attempts[cid] = active

            for k in stale_keys:
                del self._attempts[k]

            timestamps = list(self._attempts.get(client_id, []))
            if len(timestamps) >= self.max_attempts:
                return False

            timestamps.append(now)
            self._attempts[client_id] = timestamps
            return True

    def reset(self):
        with self._lock:
            self._attempts.clear()

login_rate_guard = LoginRateGuard()

class LoginRequest(BaseModel):
    email: Optional[str] = Field(None, min_length=1, max_length=128)
    username: Optional[str] = Field(None, min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=1024)

    @model_validator(mode="before")
    @classmethod
    def validate_identifier(cls, values):
        if isinstance(values, dict):
            email = values.get("email")
            username = values.get("username")
            if not email and not username:
                raise ValueError("Field 'email' is required.")
        return values

    @property
    def identifier(self) -> str:
        return (self.email or self.username or "").strip()

class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    tenant_id: str
    role: str

@router.post("/login", response_model=LoginResponse)
def login(creds: LoginRequest, request: Request):
    """
    Verifies database credentials using timing-equivalent scrypt execution,
    derives the user's sole active membership, and issues an authoritative
    1-hour 5-claim HS256 JWT.
    Enforces process-local per-client login attempt rate limit.
    """
    client_ip = "127.0.0.1"
    if request.client and request.client.host:
        client_ip = request.client.host

    if not login_rate_guard.check_and_record(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    identifier = creds.identifier
    if not identifier:
        compute_dummy_scrypt(creds.password)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, password_hash, status, is_platform_admin
                FROM users
                WHERE LOWER(email) = LOWER(%s);
                """,
                (identifier,)
            )
            user = cur.fetchone()

        # User not found, pending (password_hash is NULL), or disabled
        if not user or user["status"] != "active" or not user["password_hash"]:
            compute_dummy_scrypt(creds.password)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        # Verify password using constant-time scrypt comparison
        if not verify_password_scrypt(creds.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        # User authenticated - query active memberships joined with tenants
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    tm.id AS membership_id,
                    tm.tenant_id,
                    tm.role,
                    tm.status AS membership_status,
                    t.status AS tenant_status
                FROM tenant_memberships tm
                JOIN tenants t ON t.id = tm.tenant_id
                WHERE tm.user_id = %s AND tm.status = 'active';
                """,
                (str(user["id"]),)
            )
            memberships = cur.fetchall()

        # Zero active memberships
        if not memberships:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        # Corrupt state: more than 1 active membership found -> fail closed & record audit error
        if len(memberships) > 1:
            record_audit_event(
                conn=conn,
                tenant_id=PLATFORM_TENANT_ID,
                actor_id=str(user["email"]),
                actor_role="unknown",
                event_name="auth.configuration_error",
                details={
                    "reason": "Multiple active memberships encountered for user",
                    "user_id": str(user["id"]),
                    "active_memberships_count": len(memberships),
                }
            )
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        membership = memberships[0]

        # Tenant is not active
        if membership["tenant_status"] != "active":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        # Exactly 1 active membership in an active tenant -> persist a session
        # (per-token revocation, migration 024) and mint the session-bound JWT:
        # `sub` is the user UUID (PRD Ch.5 decision), `jti` names the session
        # (the raw jti is never stored — only its SHA-256).
        tenant_id = str(membership["tenant_id"])
        role = str(membership["role"])
        canonical_email = str(user["email"])

        now_ts = int(time.time())
        jti = str(uuid.uuid4())
        expires_at = datetime.fromtimestamp(now_ts + SESSION_LIFETIME_SECONDS, tz=timezone.utc)

        with conn.cursor() as cur:
            # Opportunistic cleanup: drop this user's already-expired sessions.
            cur.execute(
                "DELETE FROM user_sessions WHERE user_id = %s AND expires_at < now();",
                (str(user["id"]),)
            )
            cur.execute(
                """
                INSERT INTO user_sessions (user_id, tenant_id, jti_hash, issued_at, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (
                    str(user["id"]),
                    tenant_id,
                    hashlib.sha256(jti.encode("utf-8")).hexdigest(),
                    datetime.fromtimestamp(now_ts, tz=timezone.utc),
                    expires_at,
                )
            )
            session_id = cur.fetchone()["id"]

        record_audit_event(
            conn=conn,
            tenant_id=uuid.UUID(tenant_id),
            actor_id=str(user["id"]),
            actor_role=role,
            event_name="auth.login",
            details={
                "email": canonical_email,
                "session_id": str(session_id),
            }
        )
        conn.commit()

        payload = {
            "tenant_id": tenant_id,
            "sub": str(user["id"]),
            "role": role,
            "iat": now_ts,
            "exp": now_ts + SESSION_LIFETIME_SECONDS,
            "jti": jti,
        }

        kid, signing_secret = config.jwt_signing_key()
        headers = {"kid": kid} if kid else None
        token = jwt.encode(payload, signing_secret, algorithm="HS256", headers=headers)

        return LoginResponse(
            token=token,
            token_type="bearer",
            expires_in=SESSION_LIFETIME_SECONDS,
            tenant_id=tenant_id,
            role=role,
        )


@router.post("/logout")
def logout(auth: AuthContext = Depends(get_auth_context)):
    """
    Revoke the caller's current session (per-token revocation). Idempotent:
    a token without a persisted session (legacy transition shape) logs out
    with nothing to revoke.
    """
    revoked = False
    if auth.session_id is not None:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE user_sessions
                    SET revoked_at = now(), revoking_actor = %s, revocation_reason = 'logout'
                    WHERE id = %s AND user_id = %s AND revoked_at IS NULL;
                    """,
                    (auth.actor_id, str(auth.session_id), str(auth.user_id))
                )
                revoked = cur.rowcount > 0
                if revoked:
                    record_audit_event(
                        conn=conn,
                        tenant_id=auth.tenant_id,
                        actor_id=auth.actor_id,
                        actor_role=auth.role,
                        event_name="auth.logout",
                        details={"session_id": str(auth.session_id), "reason": "logout"}
                    )
            conn.commit()
    return {"status": "logged_out", "session_revoked": revoked}


@router.get("/sessions")
def list_sessions(auth: AuthContext = Depends(get_auth_context)):
    """List the caller's active (unrevoked, unexpired) sessions in the
    token's tenant; `current` marks the session the caller's token belongs to."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, issued_at, expires_at
                FROM user_sessions
                WHERE user_id = %s AND tenant_id = %s
                  AND revoked_at IS NULL AND expires_at > now()
                ORDER BY issued_at DESC;
                """,
                (str(auth.user_id), str(auth.tenant_id))
            )
            rows = cur.fetchall()

    return {
        "sessions": [
            {
                "id": str(row["id"]),
                "issued_at": row["issued_at"].isoformat(),
                "expires_at": row["expires_at"].isoformat(),
                "current": auth.session_id is not None and row["id"] == auth.session_id,
            }
            for row in rows
        ]
    }


@router.delete("/sessions/{session_id}")
def revoke_session(session_id: uuid.UUID, auth: AuthContext = Depends(get_auth_context)):
    """Revoke one of the caller's own sessions in the token's tenant. A
    session that does not exist, belongs to another user/tenant, or is
    already revoked is the identical 404 (no existence oracle)."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE user_sessions
                SET revoked_at = now(), revoking_actor = %s, revocation_reason = 'revoked_by_user'
                WHERE id = %s AND user_id = %s AND tenant_id = %s AND revoked_at IS NULL;
                """,
                (auth.actor_id, str(session_id), str(auth.user_id), str(auth.tenant_id))
            )
            if cur.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Session not found or already revoked"
                )
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="auth.session_revoked",
                details={"session_id": str(session_id), "reason": "revoked_by_user"}
            )
        conn.commit()
    return {"status": "revoked", "session_id": str(session_id)}
