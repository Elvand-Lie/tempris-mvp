# backend/tests/test_bootstrap_cli.py
import os
import sys
import uuid
import subprocess
import pytest
from psycopg.rows import dict_row

from app.db import get_db_connection
from app.auth_crypto import generate_scrypt_hash
from app.cli.bootstrap import (
    bootstrap,
    validate_email,
    validate_platform_tenant_id,
    validate_password_hash,
    PLATFORM_TENANT_ID,
)

LEGACY_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
VALID_ADMIN_EMAIL = "admin@tempris.com"
VALID_SCRYPT_HASH = "scrypt$16384$8$1$688dbe89a4ffcfe6457beeaf5503ef0a$8329a7eb365132ada7161ce8af1875b7f50a9b442ea5709849f0be7f00b5391f"


@pytest.fixture(autouse=True)
def clean_bootstrap_state():
    """Ensure clean state for platform admin user and membership across tests."""
    def _clean():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tenant_memberships WHERE tenant_id = %s OR user_id IN (SELECT id FROM users WHERE LOWER(email) = %s);",
                    (str(PLATFORM_TENANT_ID), VALID_ADMIN_EMAIL),
                )
                cur.execute("DELETE FROM users WHERE LOWER(email) = %s;", (VALID_ADMIN_EMAIL,))
                cur.execute("DELETE FROM tenant_entitlements WHERE tenant_id = %s;", (str(PLATFORM_TENANT_ID),))
            conn.commit()

    _clean()
    yield
    _clean()


def test_email_validation():
    assert validate_email("admin@tempris.com") == "admin@tempris.com"
    assert validate_email("  SuperAdmin@Tempris.COM ") == "superadmin@tempris.com"

    for invalid in ["", "   ", "admin", "admin@", "@tempris.com", "admin@localhost", "not-an-email"]:
        with pytest.raises(ValueError):
            validate_email(invalid)


def test_platform_tenant_id_validation():
    assert validate_platform_tenant_id(str(PLATFORM_TENANT_ID)) == PLATFORM_TENANT_ID
    assert validate_platform_tenant_id(f" {str(PLATFORM_TENANT_ID)} ") == PLATFORM_TENANT_ID

    # Non-platform UUID rejected
    other_uuid = uuid.uuid4()
    with pytest.raises(ValueError, match="does not match the required Tempris Platform Control tenant UUID"):
        validate_platform_tenant_id(str(other_uuid))

    # Invalid UUID string rejected
    with pytest.raises(ValueError, match="not a valid UUID"):
        validate_platform_tenant_id("invalid-uuid-string")


def test_password_hash_validation():
    assert validate_password_hash(VALID_SCRYPT_HASH) == VALID_SCRYPT_HASH

    for invalid in ["", "  ", "not-a-hash", "scrypt$invalid$params", "md5$12345"]:
        with pytest.raises(ValueError):
            validate_password_hash(invalid)


def test_bootstrap_happy_path_and_idempotency():
    with get_db_connection() as conn:
        # 1. First run: provisions platform admin and membership
        res1 = bootstrap(
            conn=conn,
            admin_username=VALID_ADMIN_EMAIL,
            admin_password_hash=VALID_SCRYPT_HASH,
            admin_tenant_id=str(PLATFORM_TENANT_ID),
            force_password_reset=False,
        )
        assert res1["status"] == "success"
        assert res1["email"] == VALID_ADMIN_EMAIL
        assert res1["is_platform_admin"] is True
        assert res1["role"] == "superadmin"
        assert res1["password_updated"] is True
        assert res1["tenant_name"] == "Tempris Platform Control"

        user_id = res1["user_id"]

        # Verify DB state
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
            user = cur.fetchone()
            assert user["email"] == VALID_ADMIN_EMAIL
            assert user["status"] == "active"
            assert user["is_platform_admin"] is True
            assert user["password_hash"] == VALID_SCRYPT_HASH

            cur.execute("SELECT * FROM tenant_memberships WHERE user_id = %s AND tenant_id = %s;", (user_id, str(PLATFORM_TENANT_ID)))
            membership = cur.fetchone()
            assert membership["role"] == "superadmin"
            assert membership["status"] == "active"

            # Platform Control never receives a module entitlement.
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(PLATFORM_TENANT_ID),),
            )
            assert cur.fetchone()["count"] == 0

        # 2. Second run: idempotent, preserves existing password hash
        # Modify password hash in DB to simulate a user password change
        custom_hash = generate_scrypt_hash("new-custom-password")
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s;", (custom_hash, user_id))
        conn.commit()

        res2 = bootstrap(
            conn=conn,
            admin_username=VALID_ADMIN_EMAIL,
            admin_password_hash=VALID_SCRYPT_HASH,
            admin_tenant_id=str(PLATFORM_TENANT_ID),
            force_password_reset=False,
        )
        assert res2["status"] == "success"
        assert res2["password_updated"] is False

        # Verify password hash was NOT overwritten
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT password_hash FROM users WHERE id = %s;", (user_id,))
            assert cur.fetchone()["password_hash"] == custom_hash

        # 3. Third run with force_password_reset=True: overwrites password hash
        res3 = bootstrap(
            conn=conn,
            admin_username=VALID_ADMIN_EMAIL,
            admin_password_hash=VALID_SCRYPT_HASH,
            admin_tenant_id=str(PLATFORM_TENANT_ID),
            force_password_reset=True,
        )
        assert res3["status"] == "success"
        assert res3["password_updated"] is True

        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT password_hash FROM users WHERE id = %s;", (user_id,))
            assert cur.fetchone()["password_hash"] == VALID_SCRYPT_HASH


def test_bootstrap_activates_pending_user():
    pending_user_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, email, status, password_hash) VALUES (%s, %s, 'pending', NULL);",
                (str(pending_user_id), VALID_ADMIN_EMAIL),
            )
        conn.commit()

        res = bootstrap(
            conn=conn,
            admin_username=VALID_ADMIN_EMAIL,
            admin_password_hash=VALID_SCRYPT_HASH,
            admin_tenant_id=str(PLATFORM_TENANT_ID),
        )
        assert res["status"] == "success"
        assert res["user_id"] == str(pending_user_id)
        assert res["password_updated"] is True

        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT status, password_hash, is_platform_admin FROM users WHERE id = %s;", (str(pending_user_id),))
            u = cur.fetchone()
            assert u["status"] == "active"
            assert u["password_hash"] == VALID_SCRYPT_HASH
            assert u["is_platform_admin"] is True


def test_bootstrap_refuses_conflicting_platform_admin():
    other_admin_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, email, password_hash, status, is_platform_admin) VALUES (%s, 'existing_admin@tempris.com', 'scrypt$hash', 'active', TRUE);",
                (str(other_admin_id),),
            )
        conn.commit()

        with pytest.raises(RuntimeError, match="Conflicting platform admin user"):
            bootstrap(
                conn=conn,
                admin_username=VALID_ADMIN_EMAIL,
                admin_password_hash=VALID_SCRYPT_HASH,
                admin_tenant_id=str(PLATFORM_TENANT_ID),
            )

        # Cleanup
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s;", (str(other_admin_id),))
        conn.commit()


def test_bootstrap_refuses_conflicting_active_membership_in_other_tenant():
    user_id = uuid.uuid4()
    other_tenant_id = uuid.uuid4()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO tenants (id, name, slug) VALUES (%s, 'Other', %s);", (str(other_tenant_id), f"other-{other_tenant_id.hex[:6]}"))
            cur.execute("INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, 'scrypt$hash', 'active');", (str(user_id), VALID_ADMIN_EMAIL))
            cur.execute("INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status) VALUES (gen_random_uuid(), %s, %s, 'admin', 'active');", (str(other_tenant_id), str(user_id)))
        conn.commit()

        with pytest.raises(RuntimeError, match="already has an active membership in a different tenant"):
            bootstrap(
                conn=conn,
                admin_username=VALID_ADMIN_EMAIL,
                admin_password_hash=VALID_SCRYPT_HASH,
                admin_tenant_id=str(PLATFORM_TENANT_ID),
            )

        # Cleanup
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tenant_memberships WHERE user_id = %s;", (str(user_id),))
            cur.execute("DELETE FROM users WHERE id = %s;", (str(user_id),))
            cur.execute("DELETE FROM tenants WHERE id = %s;", (str(other_tenant_id),))
        conn.commit()


def test_bootstrap_leaves_legacy_tenant_with_zero_memberships():
    with get_db_connection() as conn:
        bootstrap(
            conn=conn,
            admin_username=VALID_ADMIN_EMAIL,
            admin_password_hash=VALID_SCRYPT_HASH,
            admin_tenant_id=str(PLATFORM_TENANT_ID),
        )

        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT COUNT(*) AS count FROM tenant_memberships WHERE tenant_id = %s;", (str(LEGACY_TENANT_ID),))
            count = cur.fetchone()["count"]
            assert count == 0


def test_bootstrap_provisions_platform_control_only_and_removes_stray_entitlement():
    """
    Bootstrap targets the dedicated Platform Control tenant (not the operational
    Tempris tenant) and removes any accidentally assigned entitlement so the
    platform login context stays module-free.
    """
    with get_db_connection() as conn:
        # Simulate an accidentally assigned entitlement on the platform tenant.
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version)
                VALUES (%s, 'CORE_ASSETS', '{}'::jsonb, 1)
                ON CONFLICT (tenant_id) DO NOTHING;
                """,
                (str(PLATFORM_TENANT_ID),),
            )
        conn.commit()

        res = bootstrap(
            conn=conn,
            admin_username=VALID_ADMIN_EMAIL,
            admin_password_hash=VALID_SCRYPT_HASH,
            admin_tenant_id=str(PLATFORM_TENANT_ID),
        )
        assert res["status"] == "success"
        assert res["tenant_id"] == str(PLATFORM_TENANT_ID)
        assert res["tenant_name"] == "Tempris Platform Control"

        with conn.cursor(row_factory=dict_row) as cur:
            # Entitlement was removed by bootstrap.
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(PLATFORM_TENANT_ID),),
            )
            assert cur.fetchone()["count"] == 0

            # The operational Tempris tenant is untouched by bootstrap.
            cur.execute(
                "SELECT name, slug FROM tenants WHERE id = %s;",
                ("11111111-1111-1111-1111-111111111111",),
            )
            operational = cur.fetchone()
            assert operational["name"] == "Tempris"
            assert operational["slug"] == "tempris"


def test_bootstrap_cli_subprocess_execution():
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env["ADMIN_USERNAME"] = VALID_ADMIN_EMAIL
    env["ADMIN_TENANT_ID"] = str(PLATFORM_TENANT_ID)
    env["ADMIN_PASSWORD_HASH"] = VALID_SCRYPT_HASH
    env["PYTHONPATH"] = backend_dir

    result = subprocess.run(
        [sys.executable, "-m", "app.cli.bootstrap"],
        cwd=backend_dir,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Bootstrap CLI failed with stdout: {result.stdout}, stderr: {result.stderr}"
    assert "Platform administrator bootstrap succeeded:" in result.stdout
    assert VALID_ADMIN_EMAIL in result.stdout


def test_bootstrap_fails_closed_when_env_vars_missing(monkeypatch):
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_TENANT_ID", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)

    # Missing email
    with pytest.raises(ValueError, match="ADMIN_USERNAME"):
        bootstrap(admin_tenant_id=str(PLATFORM_TENANT_ID), admin_password_hash=VALID_SCRYPT_HASH)

    # Missing tenant id
    with pytest.raises(ValueError, match="ADMIN_TENANT_ID"):
        bootstrap(admin_username=VALID_ADMIN_EMAIL, admin_password_hash=VALID_SCRYPT_HASH)

    # Missing password hash
    with pytest.raises(ValueError, match="ADMIN_PASSWORD_HASH"):
        bootstrap(admin_username=VALID_ADMIN_EMAIL, admin_tenant_id=str(PLATFORM_TENANT_ID))


def test_bootstrap_cli_subprocess_fails_closed_when_admin_vars_missing():
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env.pop("ADMIN_USERNAME", None)
    env.pop("ADMIN_TENANT_ID", None)
    env.pop("ADMIN_PASSWORD_HASH", None)
    env["PYTHONPATH"] = backend_dir

    result = subprocess.run(
        [sys.executable, "-m", "app.cli.bootstrap"],
        cwd=backend_dir,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Error during platform administrator bootstrap" in result.stderr
