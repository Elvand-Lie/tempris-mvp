import json
import re
import unicodedata
import uuid
from typing import Any, Literal, Optional

import psycopg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.audit import record_audit_event
from app.auth import AuthContext, PLATFORM_TENANT_ID, require_platform_admin
from app.auth_crypto import generate_scrypt_hash
from app.collector_registry import collector_registry
from app.db import get_db_connection
from app.services.membership_lifecycle import (
    PENDING_MEMBERSHIP_DETAIL,
    membership_status_for_account,
)


router = APIRouter(prefix="/api/platform", tags=["Platform"])
OCC_DETAIL = "Resource has been modified concurrently. Please reload and retry."
ACTIVE_MEMBERSHIP_DETAIL = "User already has an active organization membership"
# ORG-01: platform tenant provisioning invites the bootstrap Superadmin, and a
# never-activated account must not hold an active membership. The repair
# endpoint is for a tenant with no superadmin at all, so an outstanding
# invitation already occupies that slot; the Platform Administrator completes it
# through POST /users/{id}/activate instead.
PENDING_SUPERADMIN_DETAIL = (
    "Tenant already has a pending superadmin invitation; activate that account instead"
)
# ORG-01: an account in 'disabled' account-state can never be activated (that
# endpoint only accepts pending accounts), so it cannot serve as the tenant's
# activation path — a disabled membership would leave the tenant permanently
# without an activatable bootstrap Superadmin.
DISABLED_ACCOUNT_DETAIL = (
    "User account is disabled and cannot be activated; use a different email "
    "or have a Platform Administrator restore the account first"
)


def _reject_platform_control_target(tenant_id: uuid.UUID) -> None:
    """
    Shared guard: the Platform Control tenant is the platform login context,
    not an administrable tenant. It must never appear as a target of platform
    tenant, entitlement, or member repair operations.
    """
    if tenant_id == PLATFORM_TENANT_ID:
        raise HTTPException(status_code=404, detail="Tenant not found")


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: Optional[str] = Field(default=None, min_length=1, max_length=64)
    initial_superadmin_email: str = Field(min_length=1, max_length=255)
    base_package_id: str = Field(min_length=1, max_length=64)


class TenantUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    status: Optional[Literal["active", "disabled"]] = None
    expected_version: int = Field(ge=1)


class InitialSuperadmin(BaseModel):
    email: str = Field(min_length=1, max_length=255)


class EntitlementUpdate(BaseModel):
    package_id: str = Field(min_length=1, max_length=64)
    module_overrides: Any
    expected_version: int = Field(ge=1)


class UserActivation(BaseModel):
    initial_password: str = Field(min_length=1, max_length=1024)


def _clean(value: str, field: str, *, lower: bool = False) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise HTTPException(status_code=422, detail=f"{field} must not be blank")
    return cleaned.lower() if lower else cleaned


def _generated_slug(cur, name: str) -> str:
    normalized = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    base = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-") or "tenant"
    base = base[:64].rstrip("-") or "tenant"
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s));", (base,))
    cur.execute("SELECT slug FROM tenants WHERE slug = %s OR slug LIKE %s;", (base, f"{base}-%"))
    used = {row["slug"] for row in cur.fetchall()}
    if base not in used:
        return base
    suffix = 2
    while True:
        candidate = f"{base[: 63 - len(str(suffix))].rstrip('-')}-{suffix}"
        if candidate not in used:
            return candidate
        suffix += 1


def _audit(conn, auth: AuthContext, event_name: str, details: dict) -> None:
    record_audit_event(
        conn,
        PLATFORM_TENANT_ID,
        auth.actor_id,
        "platform_admin",
        event_name,
        details=details,
    )


@router.get("/tenants")
def list_tenants(auth: AuthContext = Depends(require_platform_admin)):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.id, t.name, t.slug, t.status, t.version, t.created_at,
                       COUNT(m.id) AS member_count,
                       COUNT(m.id) FILTER (WHERE m.status = 'active') AS active_member_count,
                       COUNT(m.id) FILTER (WHERE m.status = 'pending') AS pending_invitation_count,
                       COUNT(m.id) FILTER (WHERE m.role = 'superadmin' AND m.status = 'active') AS active_superadmin_count,
                       te.package_id, te.module_overrides, te.version AS entitlement_version
                FROM tenants t
                LEFT JOIN tenant_memberships m ON m.tenant_id = t.id
                LEFT JOIN tenant_entitlements te ON te.tenant_id = t.id
                WHERE t.id != %s
                GROUP BY t.id, te.package_id, te.module_overrides, te.version
                ORDER BY LOWER(t.name), t.id;
                """,
                (str(PLATFORM_TENANT_ID),),
            )
            return cur.fetchall()


@router.post("/tenants", status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreate, auth: AuthContext = Depends(require_platform_admin)):
    name = _clean(payload.name, "name")
    email = _clean(payload.initial_superadmin_email, "initial_superadmin_email", lower=True)
    package_id = _clean(payload.base_package_id, "base_package_id")

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                slug = (
                    _clean(payload.slug, "slug", lower=True)
                    if payload.slug is not None
                    else _generated_slug(cur, name)
                )
                cur.execute("SELECT id FROM packages WHERE id = %s;", (package_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=422, detail="Base package does not exist")

                cur.execute(
                    "SELECT id, status FROM users WHERE LOWER(email) = %s FOR UPDATE;",
                    (email,),
                )
                user = cur.fetchone()
                if user:
                    user_id = user["id"]
                    if user["status"] == "disabled":
                        raise HTTPException(status_code=409, detail=DISABLED_ACCOUNT_DETAIL)
                    cur.execute(
                        "SELECT 1 FROM tenant_memberships WHERE user_id = %s AND status = 'active' LIMIT 1;",
                        (str(user_id),),
                    )
                    if cur.fetchone():
                        raise HTTPException(status_code=409, detail=ACTIVE_MEMBERSHIP_DETAIL)
                    # ORG-01: one outstanding invitation per user, because
                    # Platform activation then names exactly one membership
                    # (uq_memberships_user_pending, migration 040).
                    cur.execute(
                        "SELECT 1 FROM tenant_memberships WHERE user_id = %s AND status = 'pending' LIMIT 1;",
                        (str(user_id),),
                    )
                    if cur.fetchone():
                        raise HTTPException(status_code=409, detail=PENDING_MEMBERSHIP_DETAIL)
                else:
                    cur.execute(
                        """
                        INSERT INTO users (id, email, status, password_hash)
                        VALUES (gen_random_uuid(), %s, 'pending', NULL)
                        RETURNING id, status;
                        """,
                        (email,),
                    )
                    user = cur.fetchone()
                    user_id = user["id"]

                # ORG-01: the bootstrap Superadmin invitation is a PENDING
                # membership while the account itself is unactivated — an
                # unusable account must not be represented as active access.
                # Platform activation (POST /users/{id}/activate) sets the
                # initial password and promotes the pending membership in one
                # atomic step; the first Superadmin can log in right after.
                bootstrap_membership_status = membership_status_for_account(user["status"])

                cur.execute(
                    """
                    INSERT INTO tenants (id, name, slug, status, version)
                    VALUES (gen_random_uuid(), %s, %s, 'active', 1)
                    RETURNING id, name, slug, status, version, created_at;
                    """,
                    (name, slug),
                )
                tenant = cur.fetchone()
                cur.execute(
                    """
                    INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                    VALUES (gen_random_uuid(), %s, %s, 'superadmin', %s);
                    """,
                    (str(tenant["id"]), str(user_id), bootstrap_membership_status),
                )
                cur.execute(
                    """
                    INSERT INTO tenant_entitlements
                        (tenant_id, package_id, module_overrides, version, updated_by)
                    VALUES (%s, %s, '{}'::jsonb, 1, %s);
                    """,
                    (str(tenant["id"]), package_id, str(auth.user_id)),
                )
                _audit(
                    conn,
                    auth,
                    "platform.tenant_created",
                    {
                        "target_tenant_id": str(tenant["id"]),
                        "initial_superadmin_user_id": str(user_id),
                        "package_id": package_id,
                    },
                )
                conn.commit()
                return {
                    **tenant,
                    "initial_superadmin": {"id": user_id, "email": email},
                    "entitlement": {
                        "package_id": package_id,
                        "module_overrides": {},
                        "version": 1,
                    },
                }
    except psycopg.errors.UniqueViolation as exc:
        constraint = exc.diag.constraint_name
        if constraint == "uq_memberships_user_pending":
            detail = PENDING_MEMBERSHIP_DETAIL
        elif constraint in {"idx_users_email", "uq_memberships_user_active"}:
            detail = ACTIVE_MEMBERSHIP_DETAIL
        elif constraint == "idx_tenants_slug":
            detail = "Tenant slug already exists"
        else:
            raise
        raise HTTPException(status_code=409, detail=detail) from exc


@router.get("/tenants/{tenant_id}")
def get_tenant(tenant_id: uuid.UUID, auth: AuthContext = Depends(require_platform_admin)):
    _reject_platform_control_target(tenant_id)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.id, t.name, t.slug, t.status, t.version, t.created_at, t.updated_at,
                       te.package_id, te.module_overrides, te.version AS entitlement_version,
                       te.updated_at AS entitlement_updated_at
                FROM tenants t
                LEFT JOIN tenant_entitlements te ON te.tenant_id = t.id
                WHERE t.id = %s;
                """,
                (str(tenant_id),),
            )
            tenant = cur.fetchone()
            if not tenant:
                raise HTTPException(status_code=404, detail="Tenant not found")
            return tenant


@router.patch("/tenants/{tenant_id}")
async def update_tenant(
    tenant_id: uuid.UUID,
    payload: TenantUpdate,
    auth: AuthContext = Depends(require_platform_admin),
):
    _reject_platform_control_target(tenant_id)
    if payload.name is None and payload.status is None:
        raise HTTPException(status_code=422, detail="At least one of name or status is required")
    name = _clean(payload.name, "name") if payload.name is not None else None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM tenants WHERE id = %s;", (str(tenant_id),))
            current = cur.fetchone()
            if not current:
                raise HTTPException(status_code=404, detail="Tenant not found")
            cur.execute(
                """
                UPDATE tenants
                SET name = COALESCE(%s, name), status = COALESCE(%s, status),
                    version = version + 1, updated_at = now()
                WHERE id = %s AND version = %s
                RETURNING id, name, slug, status, version, created_at, updated_at;
                """,
                (name, payload.status, str(tenant_id), payload.expected_version),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=409, detail=OCC_DETAIL)
            _audit(
                conn,
                auth,
                "platform.tenant_updated",
                {
                    "target_tenant_id": str(tenant_id),
                    "name": updated["name"],
                    "status": updated["status"],
                    "version": updated["version"],
                },
            )
            conn.commit()

    if current["status"] != "disabled" and updated["status"] == "disabled":
        await collector_registry.terminate_tenant_sessions(
            tenant_id, close_code=1008, reason="Tenant disabled"
        )
    return updated


@router.put("/tenants/{tenant_id}/initial-superadmin")
def assign_initial_superadmin(
    tenant_id: uuid.UUID,
    payload: InitialSuperadmin,
    auth: AuthContext = Depends(require_platform_admin),
):
    _reject_platform_control_target(tenant_id)
    email = _clean(payload.email, "email", lower=True)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM tenants WHERE id = %s FOR UPDATE;", (str(tenant_id),))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail="Tenant not found")
                cur.execute(
                    """
                    SELECT COUNT(*) AS count FROM tenant_memberships
                    WHERE tenant_id = %s AND role = 'superadmin' AND status = 'active';
                    """,
                    (str(tenant_id),),
                )
                if cur.fetchone()["count"] > 0:
                    raise HTTPException(status_code=409, detail="Tenant already has an active superadmin")

                cur.execute(
                    """
                    SELECT COUNT(*) AS pending_count FROM tenant_memberships
                    WHERE tenant_id = %s AND role = 'superadmin' AND status = 'pending';
                    """,
                    (str(tenant_id),),
                )
                if cur.fetchone()["pending_count"] > 0:
                    raise HTTPException(status_code=409, detail=PENDING_SUPERADMIN_DETAIL)

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
                        raise HTTPException(status_code=409, detail=ACTIVE_MEMBERSHIP_DETAIL)
                    cur.execute(
                        "SELECT 1 FROM tenant_memberships WHERE user_id = %s AND status = 'pending' LIMIT 1;",
                        (str(user_id),),
                    )
                    if cur.fetchone():
                        raise HTTPException(status_code=409, detail=PENDING_MEMBERSHIP_DETAIL)
                else:
                    cur.execute(
                        """
                        INSERT INTO users (id, email, status, password_hash)
                        VALUES (gen_random_uuid(), %s, 'pending', NULL)
                        RETURNING id, status;
                        """,
                        (email,),
                    )
                    user = cur.fetchone()
                    user_id = user["id"]

                # ORG-01: the repair endpoint invites a Superadmin too, so the
                # same account-state rule applies — a never-activated account
                # gets a pending invitation, promoted atomically by platform
                # activation.
                repair_membership_status = membership_status_for_account(user["status"])

                cur.execute(
                    """
                    INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                    VALUES (gen_random_uuid(), %s, %s, 'superadmin', %s)
                    ON CONFLICT (tenant_id, user_id) DO UPDATE
                    SET role = 'superadmin', status = EXCLUDED.status, updated_at = now();
                    """,
                    (str(tenant_id), str(user_id), repair_membership_status),
                )
                _audit(
                    conn,
                    auth,
                    "platform.tenant_initial_superadmin_assigned",
                    {"target_tenant_id": str(tenant_id), "user_id": str(user_id), "email": email},
                )
                conn.commit()
                return {
                    "id": user_id,
                    "email": email,
                    "role": "superadmin",
                    "status": repair_membership_status,
                }
    except psycopg.errors.UniqueViolation as exc:
        if exc.diag.constraint_name == "uq_memberships_user_pending":
            raise HTTPException(status_code=409, detail=PENDING_MEMBERSHIP_DETAIL) from exc
        raise HTTPException(status_code=409, detail=ACTIVE_MEMBERSHIP_DETAIL) from exc


@router.get("/catalogue")
def get_catalogue(auth: AuthContext = Depends(require_platform_admin)):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description, status, created_at FROM modules ORDER BY id;")
            modules = cur.fetchall()
            cur.execute(
                """
                SELECT p.id, p.name, p.description, p.is_default, p.version, p.created_at,
                       COALESCE(array_agg(pm.module_id ORDER BY pm.module_id)
                                FILTER (WHERE pm.module_id IS NOT NULL), '{}') AS modules
                FROM packages p
                LEFT JOIN package_modules pm ON pm.package_id = p.id
                GROUP BY p.id
                ORDER BY p.id;
                """
            )
            return {"modules": modules, "packages": cur.fetchall()}


@router.get("/tenants/{tenant_id}/entitlements")
def get_entitlements(tenant_id: uuid.UUID, auth: AuthContext = Depends(require_platform_admin)):
    _reject_platform_control_target(tenant_id)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT package_id, module_overrides, version, updated_by, updated_at
                FROM tenant_entitlements WHERE tenant_id = %s;
                """,
                (str(tenant_id),),
            )
            entitlement = cur.fetchone()
            if not entitlement:
                raise HTTPException(status_code=404, detail="Tenant entitlement not found")
            return entitlement


@router.put("/tenants/{tenant_id}/entitlements")
def update_entitlements(
    tenant_id: uuid.UUID,
    payload: EntitlementUpdate,
    auth: AuthContext = Depends(require_platform_admin),
):
    _reject_platform_control_target(tenant_id)
    if not isinstance(payload.module_overrides, dict):
        raise HTTPException(status_code=422, detail="module_overrides must be a JSON object")
    package_id = _clean(payload.package_id, "package_id")
    overrides = payload.module_overrides
    for key, value in overrides.items():
        if not isinstance(key, str):
            raise HTTPException(status_code=422, detail="Override module keys must be strings")
        if type(value) is not bool:
            raise HTTPException(
                status_code=422,
                detail=f"Override value for module '{key}' must be a strict boolean",
            )

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT version FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(tenant_id),),
            )
            current = cur.fetchone()
            if not current:
                raise HTTPException(status_code=404, detail="Tenant entitlement not found")
            if current["version"] != payload.expected_version:
                raise HTTPException(status_code=409, detail=OCC_DETAIL)

            cur.execute("SELECT id FROM packages WHERE id = %s;", (package_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=422, detail=f"Unknown or inactive package '{package_id}'")

            if overrides:
                cur.execute("SELECT id FROM modules WHERE id = ANY(%s);", (list(overrides),))
                known = {row["id"] for row in cur.fetchall()}
                for key in overrides:
                    if key not in known:
                        raise HTTPException(status_code=422, detail=f"Unknown module '{key}' in overrides")

            normalized = {key: overrides[key] for key in sorted(overrides)}
            cur.execute(
                """
                UPDATE tenant_entitlements
                SET package_id = %s, module_overrides = %s::jsonb,
                    version = version + 1, updated_by = %s, updated_at = now()
                WHERE tenant_id = %s AND version = %s
                RETURNING package_id, module_overrides, version, updated_by, updated_at;
                """,
                (
                    package_id,
                    json.dumps(normalized),
                    str(auth.user_id),
                    str(tenant_id),
                    payload.expected_version,
                ),
            )
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=409, detail=OCC_DETAIL)
            _audit(
                conn,
                auth,
                "platform.entitlement_updated",
                {
                    "target_tenant_id": str(tenant_id),
                    "package_id": package_id,
                    "module_overrides": normalized,
                    "version": updated["version"],
                },
            )
            conn.commit()
            return updated


@router.get("/users/pending")
def list_pending_users(auth: AuthContext = Depends(require_platform_admin)):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, u.full_name, u.status, u.created_at,
                       t.name AS organization_name, m.role AS organization_role,
                       m.status AS organization_membership_status
                FROM users u
                LEFT JOIN LATERAL (
                    SELECT tm.tenant_id, tm.role, tm.status, tm.created_at
                    FROM tenant_memberships tm
                    WHERE tm.user_id = u.id AND tm.status IN ('active', 'pending')
                    ORDER BY (tm.status = 'active') DESC, tm.created_at, tm.id
                    LIMIT 1
                ) m ON TRUE
                LEFT JOIN tenants t ON t.id = m.tenant_id
                WHERE u.status = 'pending'
                ORDER BY LOWER(u.email), u.id;
                """
            )
            return cur.fetchall()


@router.post("/users/{user_id}/activate")
def activate_user(
    user_id: uuid.UUID,
    payload: UserActivation,
    auth: AuthContext = Depends(require_platform_admin),
):
    password_hash = generate_scrypt_hash(payload.initial_password)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # ORG-01: activation and membership promotion are one atomic change.
            # The invitation created by a tenant Superadmin (or by platform
            # provisioning) is what becomes in force here; leaving it pending
            # would strand an activated account with no usable access.
            cur.execute(
                """
                UPDATE users
                SET password_hash = %s, status = 'active', updated_at = now()
                WHERE id = %s AND status = 'pending'
                RETURNING id, email, full_name, status, updated_at;
                """,
                (password_hash, str(user_id)),
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="Pending user not found")
            cur.execute(
                """
                UPDATE tenant_memberships
                SET status = 'active', updated_at = now()
                WHERE user_id = %s AND status = 'pending'
                RETURNING tenant_id, role, status;
                """,
                (str(user_id),),
            )
            promotions = cur.fetchall()
            _audit(
                conn,
                auth,
                "platform.user_activated",
                {
                    "user_id": str(user_id),
                    "email": user["email"],
                    "promoted_memberships": [
                        {"tenant_id": str(row["tenant_id"]), "role": row["role"]}
                        for row in promotions
                    ],
                },
            )
            conn.commit()
            return {
                **user,
                "memberships": [
                    {
                        "tenant_id": row["tenant_id"],
                        "role": row["role"],
                        "status": row["status"],
                    }
                    for row in promotions
                ],
            }
