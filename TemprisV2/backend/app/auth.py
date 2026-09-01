# backend/app/auth.py
import uuid
from typing import Optional, List
import jwt
from fastapi import Header, HTTPException, status, Depends
from pydantic import BaseModel
from app.config import JWT_SECRET, JWT_ALGORITHM, PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.services.entitlements import resolve_effective_modules

class AuthContext(BaseModel):
    tenant_id: uuid.UUID
    actor_id: str
    role: str
    is_platform_admin: bool = False
    user_id: Optional[uuid.UUID] = None

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
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
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

    # Execute database point-join query for real-time revocation and role enforcement
    with get_db_connection() as conn:
        with conn.cursor() as cur:
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
                WHERE LOWER(u.email) = LOWER(%s);
                """,
                (str(tenant_uuid), str(actor_id))
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
        user_id=user_id_val
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

# Helper for minting test tokens
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
