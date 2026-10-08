import uuid
from typing import Literal, Optional

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.audit import record_audit_event
from app.auth import AuthContext, PLATFORM_TENANT_ID, get_auth_context, require_roles
from app.auth_crypto import generate_scrypt_hash
from app.db import get_db_connection
from app.services.entitlements import resolve_effective_modules
from app.services.membership_lifecycle import (
    PENDING_MEMBERSHIP_DETAIL,
    membership_status_for_account,
)


router = APIRouter(prefix="/api/org", tags=["Organization"])
LAST_SUPERADMIN_DETAIL = "Cannot remove or demote the last active superadmin of an organization"
# ORG-01: a membership may only be enabled for an already-active account.
# Activation itself (pending account + initial password) is the dedicated
# POST /users/{user_id}/activate endpoint below — a tenant Superadmin action
# within their own tenant; Platform Administrators retain the bootstrap and
# cross-tenant path (PRD Ch.5, as amended 2026-09-24).
UNACTIVATED_ACCOUNT_DETAIL = (
    "User account is not active. A Superadmin must activate the account before "
    "its membership can be enabled"
)
TENANT_ADMIN_FORBIDDEN_DETAIL = (
    "Tenant Admins cannot create or modify Superadmin memberships"
)


def _require_tenant_session(auth: AuthContext) -> None:
    if auth.tenant_id == PLATFORM_TENANT_ID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform sessions cannot manage tenant organization members.",
        )


def require_superadmin(auth: AuthContext = Depends(require_roles(["superadmin"]))) -> AuthContext:
    """
    Dependency for full tenant Organization member management.

    Requires the superadmin role AND a tenant workspace session. A session in
    the dedicated Platform Control login-context tenant is never a tenant
    workspace, so platform administrators are rejected even though their
    platform membership carries the superadmin role; platform identities are
    managed exclusively through /api/platform. GET /api/org/tenant deliberately
    stays on get_auth_context because it is the authenticated-session metadata
    endpoint (including the Platform Control login context).
    """
    _require_tenant_session(auth)
    return auth


def require_org_manager(auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))) -> AuthContext:
    """
    Dependency for limited Organization management (Tenant Admin).

    A Tenant Admin may view members and manage ordinary (analyst/admin)
    memberships, but never Superadmin memberships; role-level limits are
    enforced per endpoint. Platform sessions are rejected as above.
    """
    _require_tenant_session(auth)
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
def list_members(auth: AuthContext = Depends(require_org_manager)):
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
def add_member(payload: MemberCreate, auth: AuthContext = Depends(require_org_manager)):
    # ORG-01: a Tenant Admin may invite ordinary users (analyst/admin) only;
    # creating a Superadmin membership is a tenant Superadmin authority.
    if auth.role != "superadmin" and payload.role == "superadmin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=TENANT_ADMIN_FORBIDDEN_DETAIL)
    email = _email(payload.email)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status FROM users WHERE LOWER(email) = %s FOR UPDATE;",
                    (email,),
                )
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
                    cur.execute(
                        "SELECT 1 FROM tenant_memberships WHERE user_id = %s AND status = 'pending' LIMIT 1;",
                        (str(user_id),),
                    )
                    if cur.fetchone():
                        raise HTTPException(
                            status_code=409, detail=PENDING_MEMBERSHIP_DETAIL
                        )
                    new_membership_status = membership_status_for_account(user["status"])
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
                    # ORG-01: a never-activated account gets a PENDING
                    # membership — the invitation exists, but it is not an
                    # active/usable membership until a Platform Administrator
                    # activates the account.
                    new_membership_status = "pending"

                cur.execute(
                    """
                    INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                    VALUES (gen_random_uuid(), %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, user_id) DO UPDATE
                    SET role = EXCLUDED.role, status = EXCLUDED.status, updated_at = now()
                    RETURNING role, status, created_at;
                    """,
                    (str(auth.tenant_id), str(user_id), payload.role, new_membership_status),
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
        if exc.diag.constraint_name == "uq_memberships_user_pending":
            raise HTTPException(status_code=409, detail=PENDING_MEMBERSHIP_DETAIL) from exc
        raise HTTPException(
            status_code=409,
            detail="User already has an active organization membership",
        ) from exc


@router.patch("/members/{user_id}")
def update_member(
    user_id: uuid.UUID,
    payload: MemberUpdate,
    auth: AuthContext = Depends(require_org_manager),
):
    if payload.role is None and payload.status is None:
        raise HTTPException(status_code=422, detail="At least one of role or status is required")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT m.role, m.status, u.email, u.status AS user_status
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

            # ORG-01: a Tenant Admin never modifies a Superadmin membership and
            # never promotes anyone into the Superadmin role — Superadmin
            # retains the highest tenant authority.
            if auth.role != "superadmin":
                if current["role"] == "superadmin" or payload.role == "superadmin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=TENANT_ADMIN_FORBIDDEN_DETAIL,
                    )

            next_role = payload.role or current["role"]
            next_status = payload.status or current["status"]
            # ORG-01: enabling a membership is not the same as activating an
            # account. A membership may only be enabled for an active account;
            # a never-activated account first goes through POST
            # /users/{user_id}/activate (tenant Superadmin, own tenant).
            if next_status == "active" and current["user_status"] != "active":
                raise HTTPException(status_code=409, detail=UNACTIVATED_ACCOUNT_DETAIL)
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


class UserActivation(BaseModel):
    initial_password: str = Field(min_length=1, max_length=1024)


# ORG-02 (PRD Ch.5, as amended 2026-09-24): Platform provisioning bootstraps
# the first Superadmin; from then on a tenant Superadmin activates pending
# accounts within their own tenant. The platform activation endpoint
# (/api/platform/users/{id}/activate) remains for bootstrap repair and
# platform-level administration.
@router.post("/users/{user_id}/activate", status_code=status.HTTP_200_OK)
def activate_user(
    user_id: uuid.UUID,
    payload: UserActivation,
    auth: AuthContext = Depends(require_superadmin),
):
    password_hash = generate_scrypt_hash(payload.initial_password)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Tenant isolation: the account must hold the invitation (pending
            # membership) in the caller's own tenant.
            cur.execute(
                """
                SELECT m.role, u.email, u.status AS user_status
                FROM tenant_memberships m
                JOIN users u ON u.id = m.user_id
                WHERE m.tenant_id = %s AND m.user_id = %s AND m.status = 'pending'
                FOR UPDATE OF u;
                """,
                (str(auth.tenant_id), str(user_id)),
            )
            invitation = cur.fetchone()
            if not invitation:
                raise HTTPException(
                    status_code=404,
                    detail="Pending organization member not found in this tenant",
                )
            if invitation["user_status"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "User account is not pending and cannot be activated here; "
                        "disabled accounts must be restored by a Platform Administrator"
                    ),
                )

            # Activation and membership promotion are one atomic change: the
            # pending invitation becomes the account's in-force membership.
            cur.execute(
                """
                UPDATE users
                SET password_hash = %s, status = 'active', updated_at = now()
                WHERE id = %s AND status = 'pending'
                RETURNING id, email, full_name, status;
                """,
                (password_hash, str(user_id)),
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="Pending user not found")
            try:
                cur.execute(
                    """
                    UPDATE tenant_memberships
                    SET status = 'active', updated_at = now()
                    WHERE tenant_id = %s AND user_id = %s AND status = 'pending'
                    RETURNING role, status AS membership_status;
                    """,
                    (str(auth.tenant_id), str(user_id)),
                )
            except psycopg.errors.UniqueViolation as exc:
                if exc.diag.constraint_name == "uq_memberships_user_active":
                    raise HTTPException(
                        status_code=409,
                        detail="User already has an active organization membership",
                    ) from exc
                raise
            membership = cur.fetchone()
            record_audit_event(
                conn,
                auth.tenant_id,
                auth.actor_id,
                auth.role,
                "org.user_activated",
                details={"user_id": str(user_id), "email": user["email"], "role": membership["role"]},
            )
            conn.commit()
            return {
                **user,
                "membership": {
                    "role": membership["role"],
                    "status": membership["membership_status"],
                },
            }
