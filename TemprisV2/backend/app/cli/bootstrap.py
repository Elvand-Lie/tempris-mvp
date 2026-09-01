# backend/app/cli/bootstrap.py
"""
Standalone, idempotent platform administrator bootstrap CLI for Tempris V2.

Provisions or reconciles the initial Tempris platform superadmin user and
active superadmin membership in the dedicated Tempris Platform Control tenant
(the platform login context). The operational Tempris tenant
(11111111-1111-1111-1111-111111111111) owns Assets/Collectors and is never
touched by this CLI.
"""

import os
import sys
import uuid
import re
import argparse
from pathlib import Path
from typing import Optional, Dict, Any

from dotenv import load_dotenv

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

env_path = backend_dir / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

import psycopg
from psycopg.rows import dict_row

from app.auth_crypto import parse_scrypt_hash
from app.config import PLATFORM_TENANT_ID
from app.db import get_db_connection

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email(email: str) -> str:
    if not email or not isinstance(email, str):
        raise ValueError("ADMIN_USERNAME is required and must not be empty.")
    cleaned = email.strip().lower()
    if not EMAIL_REGEX.match(cleaned):
        raise ValueError(
            f"ADMIN_USERNAME '{email}' is not a valid email address (e.g. admin@tempris.com)."
        )
    return cleaned


def validate_platform_tenant_id(tenant_id_raw: str) -> uuid.UUID:
    if not tenant_id_raw:
        raise ValueError("ADMIN_TENANT_ID is required and must not be empty.")
    try:
        tenant_uuid = uuid.UUID(str(tenant_id_raw).strip())
    except (ValueError, TypeError):
        raise ValueError(f"ADMIN_TENANT_ID '{tenant_id_raw}' is not a valid UUID.")
    if tenant_uuid != PLATFORM_TENANT_ID:
        raise ValueError(
            f"ADMIN_TENANT_ID '{tenant_uuid}' does not match the required Tempris Platform Control tenant UUID ({PLATFORM_TENANT_ID})."
        )
    return tenant_uuid


def validate_password_hash(hash_str: str) -> str:
    if not hash_str or not isinstance(hash_str, str) or not hash_str.strip():
        raise ValueError("ADMIN_PASSWORD_HASH is required and must not be empty.")
    cleaned = hash_str.strip()
    try:
        parse_scrypt_hash(cleaned)
    except Exception as e:
        raise ValueError(f"ADMIN_PASSWORD_HASH is invalid: {e}")
    return cleaned


def bootstrap(
    conn: Optional[psycopg.Connection] = None,
    admin_username: Optional[str] = None,
    admin_password_hash: Optional[str] = None,
    admin_tenant_id: Optional[str] = None,
    force_password_reset: bool = False,
) -> Dict[str, Any]:
    """
    Execute platform administrator bootstrap in a single database transaction.

    Idempotently provisions:
    1. The dedicated Tempris Platform Control tenant (f0000000-0000-4000-8000-000000000001),
       the platform login context. This is NOT the operational Tempris tenant.
    2. The primary platform administrator user (is_platform_admin = TRUE, status = 'active').
    3. The active superadmin membership in the Platform Control tenant.
    4. No module entitlement for the Platform Control tenant; any accidentally
       assigned entitlement row is removed.

    Preserves existing passwords unless force_password_reset is True.
    Refuses conflicting tenant/email/membership states.
    """
    raw_email = admin_username or os.environ.get("ADMIN_USERNAME")
    raw_hash = admin_password_hash or os.environ.get("ADMIN_PASSWORD_HASH")
    raw_tenant_id = admin_tenant_id or os.environ.get("ADMIN_TENANT_ID")

    email = validate_email(raw_email)
    tenant_id = validate_platform_tenant_id(raw_tenant_id)
    password_hash = validate_password_hash(raw_hash)

    def _execute_bootstrap(c: psycopg.Connection) -> Dict[str, Any]:
        with c.cursor(row_factory=dict_row) as cur:
            # 1. Ensure the dedicated Tempris Platform Control tenant exists
            cur.execute(
                """
                INSERT INTO tenants (id, name, slug, status, version)
                VALUES (%s, 'Tempris Platform Control', 'tempris-platform-control', 'active', 1)
                ON CONFLICT (id) DO UPDATE
                SET name = 'Tempris Platform Control', slug = 'tempris-platform-control', status = 'active'
                RETURNING id, name, slug, status;
                """,
                (str(tenant_id),),
            )
            tenant_row = cur.fetchone()

            # 2. Check for conflicting platform admin with different email
            cur.execute(
                """
                SELECT id, email, status, is_platform_admin
                FROM users
                WHERE is_platform_admin = TRUE AND LOWER(email) != %s;
                """,
                (email,),
            )
            conflicting_admins = cur.fetchall()
            if conflicting_admins:
                conflict_emails = [a["email"] for a in conflicting_admins]
                raise RuntimeError(
                    f"Conflicting platform admin user(s) already exist with different email(s): {conflict_emails}"
                )

            # 3. Query or upsert user
            cur.execute(
                """
                SELECT id, email, full_name, password_hash, status, is_platform_admin
                FROM users
                WHERE LOWER(email) = %s;
                """,
                (email,),
            )
            user_row = cur.fetchone()
            password_updated = False

            if user_row is None:
                # Create fresh active platform admin user
                cur.execute(
                    """
                    INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                    VALUES (gen_random_uuid(), %s, 'Tempris Administrator', %s, 'active', TRUE)
                    RETURNING id, email, status, is_platform_admin;
                    """,
                    (email, password_hash),
                )
                user_row = cur.fetchone()
                user_id = user_row["id"]
                password_updated = True
            else:
                user_id = user_row["id"]
                current_status = user_row["status"]

                if current_status == "pending":
                    # Transition pending user to active with provided password
                    cur.execute(
                        """
                        UPDATE users
                        SET status = 'active',
                            password_hash = %s,
                            is_platform_admin = TRUE,
                            updated_at = now()
                        WHERE id = %s
                        RETURNING id, email, status, is_platform_admin;
                        """,
                        (password_hash, str(user_id)),
                    )
                    user_row = cur.fetchone()
                    password_updated = True
                elif current_status == "active":
                    if force_password_reset:
                        cur.execute(
                            """
                            UPDATE users
                            SET password_hash = %s,
                                is_platform_admin = TRUE,
                                updated_at = now()
                            WHERE id = %s
                            RETURNING id, email, status, is_platform_admin;
                            """,
                            (password_hash, str(user_id)),
                        )
                        user_row = cur.fetchone()
                        password_updated = True
                    else:
                        # Preserve existing password hash
                        cur.execute(
                            """
                            UPDATE users
                            SET is_platform_admin = TRUE,
                                updated_at = now()
                            WHERE id = %s
                            RETURNING id, email, status, is_platform_admin;
                            """,
                            (str(user_id),),
                        )
                        user_row = cur.fetchone()
                elif current_status == "disabled":
                    if force_password_reset:
                        cur.execute(
                            """
                            UPDATE users
                            SET status = 'active',
                                password_hash = %s,
                                is_platform_admin = TRUE,
                                updated_at = now()
                            WHERE id = %s
                            RETURNING id, email, status, is_platform_admin;
                            """,
                            (password_hash, str(user_id)),
                        )
                        user_row = cur.fetchone()
                        password_updated = True
                    else:
                        raise RuntimeError(
                            f"User '{email}' is disabled. Pass --force-password-reset to reactivate and update password."
                        )

            # 4. Check memberships for user across any tenant
            cur.execute(
                """
                SELECT id, tenant_id, role, status
                FROM tenant_memberships
                WHERE user_id = %s AND status = 'active';
                """,
                (str(user_id),),
            )
            active_memberships = cur.fetchall()

            for m in active_memberships:
                if str(m["tenant_id"]) != str(tenant_id):
                    raise RuntimeError(
                        f"User '{email}' already has an active membership in a different tenant ({m['tenant_id']}). Cannot bootstrap platform membership."
                    )

            # 5. Upsert active superadmin membership in platform tenant
            cur.execute(
                """
                SELECT id, tenant_id, role, status
                FROM tenant_memberships
                WHERE tenant_id = %s AND user_id = %s;
                """,
                (str(tenant_id), str(user_id)),
            )
            membership_row = cur.fetchone()

            if membership_row is None:
                cur.execute(
                    """
                    INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                    VALUES (gen_random_uuid(), %s, %s, 'superadmin', 'active')
                    RETURNING id, tenant_id, user_id, role, status;
                    """,
                    (str(tenant_id), str(user_id)),
                )
                membership_row = cur.fetchone()
            else:
                cur.execute(
                    """
                    UPDATE tenant_memberships
                    SET role = 'superadmin',
                        status = 'active',
                        updated_at = now()
                    WHERE id = %s
                    RETURNING id, tenant_id, user_id, role, status;
                    """,
                    (membership_row["id"],),
                )
                membership_row = cur.fetchone()

            # 6. Platform Control holds NO module entitlement. Remove any
            # entitlement row that was accidentally assigned so platform
            # sessions remain confined to the platform control plane.
            cur.execute(
                "DELETE FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(tenant_id),),
            )

        c.commit()

        return {
            "status": "success",
            "user_id": str(user_id),
            "email": email,
            "tenant_id": str(tenant_id),
            "tenant_name": tenant_row["name"],
            "role": membership_row["role"],
            "is_platform_admin": user_row["is_platform_admin"],
            "password_updated": password_updated,
        }

    if conn is not None:
        return _execute_bootstrap(conn)
    else:
        with get_db_connection() as c:
            return _execute_bootstrap(c)


def main():
    parser = argparse.ArgumentParser(
        description="Tempris V2 Platform Administrator Bootstrap CLI"
    )
    parser.add_argument(
        "--force-password-reset",
        action="store_true",
        help="Force overwrite of existing administrator password hash with ADMIN_PASSWORD_HASH",
    )
    args = parser.parse_args()

    try:
        result = bootstrap(force_password_reset=args.force_password_reset)
        print("Platform administrator bootstrap succeeded:")
        print(f"  User ID:            {result['user_id']}")
        print(f"  Email:              {result['email']}")
        print(f"  Platform Tenant:    {result['tenant_name']} ({result['tenant_id']})")
        print(f"  Membership Role:    {result['role']}")
        print(f"  Is Platform Admin:  {result['is_platform_admin']}")
        print(f"  Password Updated:   {result['password_updated']}")
        sys.exit(0)
    except Exception as e:
        print(f"Error during platform administrator bootstrap: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
