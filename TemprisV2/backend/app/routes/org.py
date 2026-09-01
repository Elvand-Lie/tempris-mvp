import uuid
from typing import Literal, Optional

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.audit import record_audit_event
from app.auth import AuthContext, PLATFORM_TENANT_ID, get_auth_context, require_roles
from app.db import get_db_connection
from app.services.entitlements import resolve_effective_modules


router = APIRouter(prefix="/api/org", tags=["Organization"])
LAST_SUPERADMIN_DETAIL = "Cannot remove or demote the last active superadmin of an organization"


def require_superadmin(auth: AuthContext = Depends(require_roles(["superadmin"]))) -> AuthContext:
    """
    Shared dependency for tenant Organization member management.

    Requires the superadmin role AND a tenant workspace session. A session in
    the dedicated Platform Control login-context tenant is never a tenant
    workspace, so platform administrators are rejected even though their
    platform membership carries the superadmin role; platform identities are
    managed exclusively through /api/platform. GET /api/org/tenant deliberately
    stays on get_auth_context because it is the authenticated-session metadata
    endpoint (including the Platform Control login context).
    """
    if auth.tenant_id == PLATFORM_TENANT_ID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform sessions cannot manage tenant organization members.",
        )
    return auth


class MemberCreate(BaseModel):
    email: str = Field(min_length=1, max_length=255)
    role: Literal["analyst", "admin", "superadmin"]


class MemberUpdate(BaseModel):
    role: Optional[Literal["analyst", "admin", "superadmin"]] = None
    status: Optional[Literal["active", "disabled"]] = None


def _email(value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise HTTPException(status_code=422, detail="Email must not be blank")
    return cleaned


def _guard_last_superadmin(cur, tenant_id: uuid.UUID) -> None:
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0));", (str(tenant_id),))
    cur.execute(
        """
        SELECT COUNT(*) AS count
        FROM tenant_memberships
        WHERE tenant_id = %s AND role = 'superadmin' AND status = 'active';
        """,
        (str(tenant_id),),
    )
    if cur.fetchone()["count"] <= 1:
        raise HTTPException(status_code=409, detail=LAST_SUPERADMIN_DETAIL)


@router.get("/tenant")
def get_tenant(auth: AuthContext = Depends(get_auth_context)):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, slug, status, created_at FROM tenants WHERE id = %s;",
                (str(auth.tenant_id),),
            )
            tenant = cur.fetchone()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        tenant["effective_modules"] = sorted(resolve_effective_modules(conn, auth.tenant_id))
        tenant["is_platform_admin"] = auth.is_platform_admin
        return tenant


@router.get("/members")
def list_members(auth: AuthContext = Depends(require_superadmin)):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, u.full_name, u.status AS user_status,
                       m.role, m.status AS membership_status, m.created_at
                FROM tenant_memberships m
                JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = %s
                ORDER BY LOWER(u.email), u.id;
                """,
                (str(auth.tenant_id),),
            )
            return cur.fetchall()


@router.post("/members", status_code=status.HTTP_201_CREATED)
def add_member(payload: MemberCreate, auth: AuthContext = Depends(require_superadmin)):
    email = _email(payload.email)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE LOWER(email) = %s FOR UPDATE;", (email,))
                user = cur.fetchone()
                if user:
                    user_id = user["id"]
                    cur.execute(
                        "SELECT 1 FROM tenant_memberships WHERE user_id = %s AND status = 'active' LIMIT 1;",
                        (str(user_id),),
                    )
                    if cur.fetchone():
                        raise HTTPException(
                            status_code=409,
                            detail="User already has an active organization membership",
                        )
                else:
                    cur.execute(
                        """
                        INSERT INTO users (id, email, status, password_hash)
                        VALUES (gen_random_uuid(), %s, 'pending', NULL)
                        RETURNING id;
                        """,
                        (email,),
                    )
                    user_id = cur.fetchone()["id"]

                cur.execute(
                    """
                    INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                    VALUES (gen_random_uuid(), %s, %s, %s, 'active')
                    ON CONFLICT (tenant_id, user_id) DO UPDATE
                    SET role = EXCLUDED.role, status = 'active', updated_at = now()
                    RETURNING role, status, created_at;
                    """,
                    (str(auth.tenant_id), str(user_id), payload.role),
                )
                membership = cur.fetchone()
                record_audit_event(
                    conn,
                    auth.tenant_id,
                    auth.actor_id,
                    auth.role,
                    "org.member_added",
                    details={"user_id": str(user_id), "email": email, "role": payload.role},
                )
                conn.commit()
                return {"id": user_id, "email": email, **membership}
    except psycopg.errors.UniqueViolation as exc:
        raise HTTPException(
            status_code=409,
            detail="User already has an active organization membership",
        ) from exc


@router.patch("/members/{user_id}")
def update_member(
    user_id: uuid.UUID,
    payload: MemberUpdate,
    auth: AuthContext = Depends(require_superadmin),
):
    if payload.role is None and payload.status is None:
        raise HTTPException(status_code=422, detail="At least one of role or status is required")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT m.role, m.status, u.email
                FROM tenant_memberships m
                JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = %s AND m.user_id = %s
                FOR UPDATE;
                """,
                (str(auth.tenant_id), str(user_id)),
            )
            current = cur.fetchone()
            if not current:
                raise HTTPException(status_code=404, detail="Organization member not found")

            next_role = payload.role or current["role"]
            next_status = payload.status or current["status"]
            if (
                current["role"] == "superadmin"
                and current["status"] == "active"
                and (next_role != "superadmin" or next_status != "active")
            ):
                _guard_last_superadmin(cur, auth.tenant_id)

            try:
                cur.execute(
                    """
                    UPDATE tenant_memberships
                    SET role = %s, status = %s, updated_at = now()
                    WHERE tenant_id = %s AND user_id = %s
                    RETURNING role, status AS membership_status, updated_at;
                    """,
                    (next_role, next_status, str(auth.tenant_id), str(user_id)),
                )
            except psycopg.errors.UniqueViolation as exc:
                if exc.diag.constraint_name == "uq_memberships_user_active":
                    raise HTTPException(
                        status_code=409,
                        detail="User already has an active organization membership",
                    ) from exc
                raise
            updated = cur.fetchone()
            record_audit_event(
                conn,
                auth.tenant_id,
                auth.actor_id,
                auth.role,
                "org.member_updated",
                details={
                    "user_id": str(user_id),
                    "email": current["email"],
                    "role": next_role,
                    "status": next_status,
                },
            )
            conn.commit()
            return {"id": user_id, "email": current["email"], **updated}


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    user_id: uuid.UUID,
    auth: AuthContext = Depends(require_superadmin),
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT m.role, m.status, u.email
                FROM tenant_memberships m
                JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = %s AND m.user_id = %s
                FOR UPDATE;
                """,
                (str(auth.tenant_id), str(user_id)),
            )
            member = cur.fetchone()
            if not member:
                raise HTTPException(status_code=404, detail="Organization member not found")
            if member["role"] == "superadmin" and member["status"] == "active":
                _guard_last_superadmin(cur, auth.tenant_id)

            cur.execute(
                "DELETE FROM tenant_memberships WHERE tenant_id = %s AND user_id = %s;",
                (str(auth.tenant_id), str(user_id)),
            )
            record_audit_event(
                conn,
                auth.tenant_id,
                auth.actor_id,
                auth.role,
                "org.member_removed",
                details={"user_id": str(user_id), "email": member["email"]},
            )
            conn.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
