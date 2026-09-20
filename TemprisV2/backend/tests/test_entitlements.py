# backend/tests/test_entitlements.py
import uuid
import json
import pytest
from app.db import get_db_connection
from app.services.entitlements import resolve_effective_modules
from tests.conftest import TENANT_A, TENANT_B

CORE_ASSETS_MODULES = {
    "ASSETS", "EDIP", "SPEAK", "SPECTRUM", "SPOTLIGHT", "STANDARD",
    "STRIKE", "SYNTHESIS",
}

def test_resolve_effective_modules_base_package():
    """CORE_ASSETS resolves every module shipped in the package."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET package_id = 'CORE_ASSETS', module_overrides = '{}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

        effective = resolve_effective_modules(conn, TENANT_A)
        assert effective == CORE_ASSETS_MODULES

def test_resolve_effective_modules_explicit_false_override():
    """A false override removes only that module from the package."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenant_entitlements
                SET package_id = 'CORE_ASSETS', module_overrides = '{"ASSETS": false}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

        effective = resolve_effective_modules(conn, TENANT_A)
        assert effective == CORE_ASSETS_MODULES - {"ASSETS"}

def test_resolve_effective_modules_explicit_true_override():
    """Test 3: Tenant with an empty package and {"ASSETS": true} override resolves {'ASSETS'}."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO packages (id, name, description, is_default, version)
                VALUES ('EMPTY_PKG', 'Empty Package', 'No modules', FALSE, 1)
                ON CONFLICT (id) DO NOTHING;
            """)
            cur.execute("""
                UPDATE tenant_entitlements
                SET package_id = 'EMPTY_PKG', module_overrides = '{"ASSETS": true}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

        effective = resolve_effective_modules(conn, TENANT_A)
        assert effective == {"ASSETS"}

def test_resolve_effective_modules_disabled_catalogue_module():
    """Test 4: Inactive module in catalogue is excluded regardless of package or true override."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE modules SET status = 'disabled' WHERE id = 'ASSETS';")
            cur.execute("""
                UPDATE tenant_entitlements
                SET package_id = 'CORE_ASSETS', module_overrides = '{"ASSETS": true}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

        # ASSETS is excluded regardless of package or override; sibling modules remain.
        effective = resolve_effective_modules(conn, TENANT_A)
        assert effective == CORE_ASSETS_MODULES - {"ASSETS"}

def test_resolve_effective_modules_inactive_tenant():
    """Test 5: Disabled tenant resolves set() regardless of entitlement configuration."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenants SET status = 'disabled' WHERE id = %s;", (str(TENANT_A),))
            cur.execute("""
                UPDATE tenant_entitlements
                SET package_id = 'CORE_ASSETS', module_overrides = '{}'::jsonb
                WHERE tenant_id = %s;
            """, (str(TENANT_A),))
        conn.commit()

        effective = resolve_effective_modules(conn, TENANT_A)
        assert effective == set()

def test_resolve_effective_modules_unentitled_tenant():
    """Test 6: Tenant without any row in tenant_entitlements resolves set()."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tenant_entitlements WHERE tenant_id = %s;", (str(TENANT_A),))
        conn.commit()

        effective = resolve_effective_modules(conn, TENANT_A)
        assert effective == set()

def test_resolve_effective_modules_none_or_missing_id():
    """Test 7: None or invalid tenant ID returns empty set."""
    with get_db_connection() as conn:
        assert resolve_effective_modules(conn, None) == set()
        assert resolve_effective_modules(conn, uuid.uuid4()) == set()
