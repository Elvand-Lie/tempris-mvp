# backend/app/routes/auth.py
import time
import threading
from typing import Callable, Dict, List, Optional
import jwt
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
from app.config import (
    JWT_SECRET,
    JWT_ALGORITHM,
    PLATFORM_TENANT_ID,
)
from app.auth_crypto import verify_password_scrypt, compute_dummy_scrypt
from app.db import get_db_connection
from app.audit import record_audit_event

router = APIRouter(prefix="/api/auth", tags=["Auth"])

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

        # Exactly 1 active membership in an active tenant -> mint 5-claim JWT
        tenant_id = str(membership["tenant_id"])
        role = str(membership["role"])
        canonical_email = str(user["email"])

        now_ts = int(time.time())
        payload = {
            "tenant_id": tenant_id,
            "sub": canonical_email,
            "role": role,
            "iat": now_ts,
            "exp": now_ts + 3600,
        }

        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

        return LoginResponse(
            token=token,
            token_type="bearer",
            expires_in=3600,
            tenant_id=tenant_id,
            role=role,
        )
