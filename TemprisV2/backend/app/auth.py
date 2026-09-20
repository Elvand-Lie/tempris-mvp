# backend/app/auth.py
import hashlib
import uuid
from typing import Optional, List
import jwt
from fastapi import Header, HTTPException, status, Depends
from pydantic import BaseModel
from app import config
from app.config import JWT_SECRET, JWT_ALGORITHM, PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.services.entitlements import resolve_effective_modules

class AuthContext(BaseModel):
    tenant_id: uuid.UUID
    actor_id: str
    role: str
    is_platform_admin: bool = False
    user_id: Optional[uuid.UUID] = None
    # Session-bound tokens (jti claim): the persisted user_sessions row id.
    session_id: Optional[uuid.UUID] = None

def get_auth_context(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> AuthContext:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'"
        )

    token = parts[1]

    # Key selection by `kid` header (PRD Ch.5: JWT kid + rotation path).
    # Tokens without a kid verify against JWT_SECRET; an unknown kid fails closed.
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}"
        )
    try:
        verification_secret = config.jwt_verification_secret(kid)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token: unknown token key id"
        )

    try:
        payload = jwt.decode(
            token,
            verification_secret,
            algorithms=["HS256"],
            options={"verify_exp": True, "verify_iat": True}
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}"
        )

    raw_exp = payload.get("exp")
    raw_iat = payload.get("iat")
    raw_tenant_id = payload.get("tenant_id")
    actor_id = payload.get("sub")
    role = payload.get("role")

    if raw_exp is None or raw_iat is None or not raw_tenant_id or not actor_id or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing required claims: 'exp', 'iat', 'tenant_id', 'sub', 'role'"
        )

    if not isinstance(raw_exp, int) or not isinstance(raw_iat, int):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Claims 'exp' and 'iat' must be integer timestamps."
        )

    if (raw_exp - raw_iat) != 3600:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token lifetime (exp - iat) must be exactly 3600 seconds. Got {raw_exp - raw_iat} seconds."
        )

    try:
        tenant_uuid = uuid.UUID(str(raw_tenant_id))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Claim 'tenant_id' must be a valid UUID"
        )

    if role not in ("analyst", "admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid role claim '{role}'. Must be analyst, admin, or superadmin."
        )

    # Session-bound token (jti claim — the shape /api/auth/login mints since
    # migration 024): `sub` is the user UUID and the token must resolve to an
    # unrevoked, unexpired persisted session (per-token revocation, PRD Ch.5
    # Target architecture item 2). The point-join still enforces the coarse
    # revocation invariants on top.
    jti = payload.get("jti")
    session_id_val: Optional[uuid.UUID] = None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            if jti is not None:
                if not isinstance(jti, str) or not jti.strip():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session invalid or expired"
                    )
                jti_hash = hashlib.sha256(jti.encode("utf-8")).hexdigest()
                cur.execute(
                    """
                    SELECT
                        u.id AS user_id,
                        u.status AS user_status,
                        u.is_platform_admin,
                        t.status AS tenant_status,
                        m.id AS membership_id,
                        m.status AS membership_status,
                        m.role AS membership_role,
                        s.id AS session_id
                    FROM user_sessions s
                    JOIN users u ON u.id = s.user_id
                    JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = %s
                    JOIN tenants t ON t.id = m.tenant_id
                    WHERE s.jti_hash = %s
                      AND s.tenant_id = %s
                      AND s.revoked_at IS NULL
                      AND s.expires_at > now();
                    """,
                    (str(tenant_uuid), jti_hash, str(tenant_uuid))
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session invalid or expired"
                    )
                # The `sub` claim and the session row must name the same user.
                if str(row["user_id"]) != str(actor_id):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session invalid or expired"
                    )
                session_id_val = row["session_id"] if isinstance(row["session_id"], uuid.UUID) else uuid.UUID(str(row["session_id"]))
            else:
                # Legacy transition shape (no jti): only tokens minted before
                # the session store shipped (<= 1 h of token lifetime) and the
                # test helper. `sub` resolves by user UUID or email — the PRD
                # decision is sub = user UUID; email remains a lookup
                # attribute. Production login never mints this shape.
                cur.execute(
                    """
                    SELECT
                        u.id AS user_id,
                        u.status AS user_status,
                        u.is_platform_admin,
                        t.status AS tenant_status,
                        m.id AS membership_id,
                        m.status AS membership_status,
                        m.role AS membership_role
                    FROM users u
                    JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = %s
                    JOIN tenants t ON t.id = m.tenant_id
                    WHERE u.id::text = %s OR LOWER(u.email) = LOWER(%s);
                    """,
                    (str(tenant_uuid), str(actor_id), str(actor_id))
                )
                row = cur.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired"
        )

    if (
        row["user_status"] != "active"
        or row["tenant_status"] != "active"
        or row["membership_status"] != "active"
        or row["membership_role"] != role
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired"
        )

    user_id_val = row["user_id"] if isinstance(row["user_id"], uuid.UUID) else uuid.UUID(str(row["user_id"]))

    return AuthContext(
        tenant_id=tenant_uuid,
        actor_id=str(actor_id),
        role=role,
        is_platform_admin=bool(row["is_platform_admin"]),
        user_id=user_id_val,
        session_id=session_id_val
    )

def require_roles(allowed_roles: List[str]):
    def dependency(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if auth.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{auth.role}' is not authorized for this operation. Required: {allowed_roles}"
            )
        return auth
    return dependency

def require_module(module_name: str):
    def dependency(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
        # Root defense: sessions in the dedicated platform login-context tenant
        # never access tenant modules, even if an entitlement is accidentally
        # assigned to that tenant. Platform administrators manage platform
        # metadata and entitlements exclusively via /api/platform.
        if auth.tenant_id == PLATFORM_TENANT_ID:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Platform sessions cannot access tenant modules."
            )
        with get_db_connection() as conn:
            effective = resolve_effective_modules(conn, auth.tenant_id)
        if module_name not in effective:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Tenant does not possess active entitlement for module '{module_name}'"
            )
        return auth
    return dependency

def require_platform_admin(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
    if auth.tenant_id != PLATFORM_TENANT_ID or not auth.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform administrator authority required."
        )
    return auth

# Helper for minting test tokens. Deliberately the LEGACY token shape (no
# `jti`, email-or-uuid `sub`): it exercises the transition verification path
# without touching the user_sessions store. Tokens minted by
# /api/auth/login carry `jti` + user-UUID `sub` and are session-bound.
def create_test_token(
    tenant_id: str,
    actor_id: str = "test-user",
    role: str = "admin",
    exp_delta_seconds: int = 3600,
    iat: Optional[int] = None
) -> str:
    import time
    now_ts = int(time.time()) if iat is None else iat
    payload = {
        "tenant_id": str(tenant_id),
        "sub": actor_id,
        "role": role,
        "iat": now_ts,
        "exp": now_ts + exp_delta_seconds
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
