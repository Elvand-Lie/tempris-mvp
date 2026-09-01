# backend/tests/test_migration_004_005.py
import uuid
import pytest
import psycopg
from psycopg.errors import CheckViolation, UniqueViolation, ForeignKeyViolation
from psycopg.rows import dict_row

from app.db import get_db_connection
from app.config import PLATFORM_TENANT_ID
from migrations.runner import MIGRATIONS_DIR

# Operational Tempris tenant — owns Assets/Collectors; NOT the platform tenant.
OPERATIONAL_TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
LEGACY_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def test_migrations_004_005_applied_and_tables_exist():
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # Verify migration runner recorded 004 and 005
            cur.execute("SELECT version FROM schema_migrations WHERE version IN ('004_tenancy_and_auth_foundation.sql', '005_module_catalogue_and_entitlements.sql', '006_platform_control_tenant.sql');")
            versions = {r["version"] for r in cur.fetchall()}
            assert "004_tenancy_and_auth_foundation.sql" in versions
            assert "005_module_catalogue_and_entitlements.sql" in versions
            assert "006_platform_control_tenant.sql" in versions

            # Verify all 7 tables exist
            expected_tables = [
                "tenants",
                "users",
                "tenant_memberships",
                "modules",
                "packages",
                "package_modules",
                "tenant_entitlements",
            ]
            for table in expected_tables:
                cur.execute(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = %s;
                    """,
                    (table,),
                )
                assert cur.fetchone() is not None, f"Table '{table}' does not exist."


def test_migration_006_creates_platform_control_tenant_without_entitlement():
    """
    Migration 006 must create the dedicated platform login-context tenant
    (Tempris Platform Control) as active with NO module entitlement. The
    operational Tempris tenant keeps its identity and its entitlement.
    """
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT version FROM schema_migrations WHERE version = '006_platform_control_tenant.sql';")
            assert cur.fetchone() is not None, "Migration 006 was not recorded."

            cur.execute("SELECT name, slug, status FROM tenants WHERE id = %s;", (str(PLATFORM_TENANT_ID),))
            row = cur.fetchone()
            assert row is not None, "Platform Control tenant does not exist."
            assert row["name"] == "Tempris Platform Control"
            assert row["slug"] == "tempris-platform-control"
            assert row["status"] == "active"

            # Platform Control must hold no module entitlement.
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(PLATFORM_TENANT_ID),),
            )
            assert cur.fetchone()["count"] == 0

            # The operational Tempris tenant remains distinct and entitled.
            assert str(PLATFORM_TENANT_ID) != str(OPERATIONAL_TENANT_ID)
            cur.execute(
                "SELECT COUNT(*) AS count FROM tenant_entitlements WHERE tenant_id = %s;",
                (str(OPERATIONAL_TENANT_ID),),
            )
            assert cur.fetchone()["count"] == 1


def test_known_production_tenants_and_zero_legacy_memberships():
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # 1. Operational Tempris Tenant (11111111-1111-1111-1111-111111111111)
            cur.execute("SELECT * FROM tenants WHERE id = %s;", (str(OPERATIONAL_TENANT_ID),))
            operational_tenant = cur.fetchone()
            assert operational_tenant is not None
            assert operational_tenant["name"] == "Tempris"
            assert operational_tenant["slug"] == "tempris"
            assert operational_tenant["status"] == "active"

            # 2. Legacy Tenant (00000000-0000-0000-0000-000000000001)
            cur.execute("SELECT * FROM tenants WHERE id = %s;", (str(LEGACY_TENANT_ID),))
            legacy_tenant = cur.fetchone()
            assert legacy_tenant is not None
            assert legacy_tenant["name"] == "Legacy Tenant 00000000"
            assert legacy_tenant["slug"] == "legacy-tenant-0000"
            assert legacy_tenant["status"] == "active"

            # 3. Invariant: Legacy tenant MUST have 0 ambient memberships
            cur.execute("SELECT COUNT(*) AS count FROM tenant_memberships WHERE tenant_id = %s;", (str(LEGACY_TENANT_ID),))
            count = cur.fetchone()["count"]
            assert count == 0


def test_on_delete_restrict_foreign_keys_prevent_tenant_deletion():
    test_tenant_id = uuid.uuid4()
    test_asset_id = uuid.uuid4()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Create a test tenant
            cur.execute(
                "INSERT INTO tenants (id, name, slug, status) VALUES (%s, 'Restrict Test Tenant', %s, 'active');",
                (str(test_tenant_id), f"restrict-{test_tenant_id.hex[:8]}"),
            )
            # Create an asset under this tenant
            cur.execute(
                """
                INSERT INTO assets (id, tenant_id, name, asset_type, target_type, target_value, normalized_target, network_scope, environment, criticality)
                VALUES (%s, %s, 'Protected Asset', 'server', 'ip', '10.0.0.99', '10.0.0.99', 'internal', 'test', 'low');
                """,
                (str(test_asset_id), str(test_tenant_id)),
            )
        conn.commit()

        # Attempt to delete the tenant while child asset exists - must fail with ForeignKeyViolation
        with pytest.raises(ForeignKeyViolation):
            with conn.cursor() as cur:
                cur.execute("DELETE FROM tenants WHERE id = %s;", (str(test_tenant_id),))

        conn.rollback()

        # Clean up child asset first, then delete tenant - must succeed
        with conn.cursor() as cur:
            cur.execute("DELETE FROM assets WHERE id = %s;", (str(test_asset_id),))
            cur.execute("DELETE FROM tenants WHERE id = %s;", (str(test_tenant_id),))
        conn.commit()


def test_users_password_state_check_constraint():
    user_id_1 = uuid.uuid4()
    user_id_2 = uuid.uuid4()
    user_id_3 = uuid.uuid4()
    user_id_4 = uuid.uuid4()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # 1. Pending user with NULL password_hash -> SUCCESS
            cur.execute(
                "INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, NULL, 'pending');",
                (str(user_id_1), f"pending-{user_id_1.hex[:6]}@example.com"),
            )

            # 2. Active user with non-null password_hash -> SUCCESS
            cur.execute(
                "INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, 'scrypt$dummy$hash', 'active');",
                (str(user_id_2), f"active-{user_id_2.hex[:6]}@example.com"),
            )

            # 3. Disabled user with non-null password_hash -> SUCCESS
            cur.execute(
                "INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, 'scrypt$dummy$hash', 'disabled');",
                (str(user_id_3), f"disabled-{user_id_3.hex[:6]}@example.com"),
            )
        conn.commit()

        # 4. Pending user with non-null password_hash -> FAILS (chk_users_password_state)
        with pytest.raises(CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, 'some_hash', 'pending');",
                    (str(user_id_4), "invalid-pending@example.com"),
                )
        conn.rollback()

        # 5. Active user with NULL password_hash -> FAILS (chk_users_password_state)
        with pytest.raises(CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, NULL, 'active');",
                    (str(user_id_4), "invalid-active@example.com"),
                )
        conn.rollback()

        # 6. Disabled user with NULL password_hash -> FAILS (chk_users_password_state)
        with pytest.raises(CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, NULL, 'disabled');",
                    (str(user_id_4), "invalid-disabled@example.com"),
                )
        conn.rollback()

        # Cleanup
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id IN (%s, %s, %s);", (str(user_id_1), str(user_id_2), str(user_id_3)))
        conn.commit()


def test_users_case_insensitive_email_uniqueness():
    user_id_1 = uuid.uuid4()
    user_id_2 = uuid.uuid4()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, email, password_hash, status) VALUES (%s, 'UniqueUser@Example.Com', 'scrypt$dummy', 'active');",
                (str(user_id_1),),
            )
        conn.commit()

        # Attempting to insert duplicate email with different case must fail with UniqueViolation
        with pytest.raises(UniqueViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (id, email, password_hash, status) VALUES (%s, 'uniqueuser@example.com', 'scrypt$dummy', 'active');",
                    (str(user_id_2),),
                )
        conn.rollback()

        # Cleanup
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s;", (str(user_id_1),))
        conn.commit()


def test_memberships_single_active_membership_partial_unique_index():
    user_id = uuid.uuid4()
    tenant_1 = uuid.uuid4()
    tenant_2 = uuid.uuid4()
    m1_id = uuid.uuid4()
    m2_id = uuid.uuid4()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO tenants (id, name, slug) VALUES (%s, 'T1', %s);", (str(tenant_1), f"t1-{tenant_1.hex[:6]}"))
            cur.execute("INSERT INTO tenants (id, name, slug) VALUES (%s, 'T2', %s);", (str(tenant_2), f"t2-{tenant_2.hex[:6]}"))
            cur.execute("INSERT INTO users (id, email, password_hash, status) VALUES (%s, %s, 'scrypt$dummy', 'active');", (str(user_id), f"u-{user_id.hex[:6]}@example.com"))

            # 1. Create first active membership in tenant_1 -> SUCCESS
            cur.execute(
                "INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status) VALUES (%s, %s, %s, 'admin', 'active');",
                (str(m1_id), str(tenant_1), str(user_id)),
            )
        conn.commit()

        # 2. Attempt to create second active membership for same user in tenant_2 -> FAILS (uq_memberships_user_active)
        with pytest.raises(UniqueViolation):
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status) VALUES (%s, %s, %s, 'analyst', 'active');",
                    (str(m2_id), str(tenant_2), str(user_id)),
                )
        conn.rollback()

        # 3. Disable the first membership, then create active membership in tenant_2 -> SUCCESS (historical coexistence)
        with conn.cursor() as cur:
            cur.execute("UPDATE tenant_memberships SET status = 'disabled' WHERE id = %s;", (str(m1_id),))
            cur.execute(
                "INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status) VALUES (%s, %s, %s, 'analyst', 'active');",
                (str(m2_id), str(tenant_2), str(user_id)),
            )
        conn.commit()

        # Cleanup
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tenant_memberships WHERE user_id = %s;", (str(user_id),))
            cur.execute("DELETE FROM users WHERE id = %s;", (str(user_id),))
            cur.execute("DELETE FROM tenants WHERE id IN (%s, %s);", (str(tenant_1), str(tenant_2)))
        conn.commit()


def test_module_catalogue_and_core_assets_package_seeding():
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # 1. Verify ASSETS module
            cur.execute("SELECT * FROM modules WHERE id = 'ASSETS';")
            mod = cur.fetchone()
            assert mod is not None
            assert mod["name"] == "Asset Inventory, Scan Authorizations & Reachability Probing"
            assert mod["status"] == "active"

            # 2. Verify CORE_ASSETS package
            cur.execute("SELECT * FROM packages WHERE id = 'CORE_ASSETS';")
            pkg = cur.fetchone()
            assert pkg is not None
            assert pkg["is_default"] is True

            # 3. Verify package_modules mapping
            cur.execute("SELECT * FROM package_modules WHERE package_id = 'CORE_ASSETS' AND module_id = 'ASSETS';")
            mapping = cur.fetchone()
            assert mapping is not None

            # 4. Verify tenant_entitlements for the operational Tempris tenant
            cur.execute("SELECT * FROM tenant_entitlements WHERE tenant_id = %s;", (str(OPERATIONAL_TENANT_ID),))
            ent = cur.fetchone()
            assert ent is not None
            assert ent["package_id"] == "CORE_ASSETS"
            assert ent["module_overrides"] == {}


def test_migration_004_collision_safe_backfill_and_restrict_fks():
    """
    Regression test for fixup 01-collision-safe-backfill:
    Executes Migration 004 against populated pre-migration operational tables containing
    two tenant UUIDs with the same first eight characters (e.g. 00000000-0000-0000-0000-000000000011
    and 00000000-0000-0000-0000-000000000012). Proves that:
    1. Migration 004 executes without UniqueViolation on idx_tenants_slug.
    2. Both tenant rows are dynamically backfilled with deterministic full-UUID slugs ('tenant-<uuid>').
    3. ON DELETE RESTRICT foreign keys are created on all four operational tables and actively block deletion.
    """
    schema_name = f"test_coll_safe_{uuid.uuid4().hex[:12]}"
    tenant_1 = uuid.UUID("00000000-0000-0000-0000-000000000011")
    tenant_2 = uuid.UUID("00000000-0000-0000-0000-000000000012")

    # Assert test precondition: both UUIDs share the first 8 characters
    assert str(tenant_1)[:8] == str(tenant_2)[:8] == "00000000"

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"CREATE SCHEMA {schema_name};")
            cur.execute(f"SET search_path TO {schema_name}, public;")

            try:
                # 1. Apply pre-migration schema: Migrations 001 through 003
                for mig_file in [
                    "001_initial_assets_schema.sql",
                    "002_collectors_and_asset_routing.sql",
                    "003_collector_schema_contract.sql",
                ]:
                    sql_text = (MIGRATIONS_DIR / mig_file).read_text(encoding="utf-8")
                    cur.execute(sql_text)

                # 2. Populate operational tables with pre-existing records under both colliding prefix UUIDs
                asset_1_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO assets (id, tenant_id, name, asset_type, target_type, target_value, normalized_target, network_scope, environment, criticality)
                    VALUES (%s, %s, 'Colliding Asset 1', 'server', 'ip', '10.0.1.1', '10.0.1.1', 'internal', 'test', 'medium');
                    """,
                    (str(asset_1_id), str(tenant_1)),
                )

                collector_2_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO collectors (id, tenant_id, name, enrollment_status, operator_status)
                    VALUES (%s, %s, 'Colliding Collector 2', 'awaiting_enrollment', 'active');
                    """,
                    (str(collector_2_id), str(tenant_2)),
                )

                asset_2_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO assets (id, tenant_id, name, asset_type, target_type, target_value, normalized_target, network_scope, environment, criticality)
                    VALUES (%s, %s, 'Colliding Asset 2', 'domain', 'domain', 'app.example.com', 'app.example.com', 'internet', 'production', 'high');
                    """,
                    (str(asset_2_id), str(tenant_2)),
                )

                scan_auth_2_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO asset_scan_authorizations (id, tenant_id, asset_id, target_type, normalized_target, network_scope, status, requested_by)
                    VALUES (%s, %s, %s, 'domain', 'app.example.com', 'internet', 'pending', 'operator-2');
                    """,
                    (str(scan_auth_2_id), str(tenant_2), str(asset_2_id)),
                )

                audit_event_1_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO audit_events (id, tenant_id, actor_id, actor_role, event_name, asset_id, details)
                    VALUES (%s, %s, 'actor-1', 'admin', 'asset_created', %s, '{"source": "pre_migration"}'::jsonb);
                    """,
                    (str(audit_event_1_id), str(tenant_1), str(asset_1_id)),
                )

                # Commit pre-migration state
                conn.commit()

                # 3. Genuinely execute Migration 004 against the populated pre-migration operational tables
                mig_004_sql = (MIGRATIONS_DIR / "004_tenancy_and_auth_foundation.sql").read_text(encoding="utf-8")
                cur.execute(mig_004_sql)
                conn.commit()

                # 4. Assert both colliding tenant rows exist with deterministic full-UUID slugs and active status
                with conn.cursor(row_factory=dict_row) as check_cur:
                    check_cur.execute(f"SET search_path TO {schema_name}, public;")
                    check_cur.execute(
                        "SELECT id, name, slug, status FROM tenants WHERE id IN (%s, %s) ORDER BY id;",
                        (str(tenant_1), str(tenant_2)),
                    )
                    tenants = {str(r["id"]): r for r in check_cur.fetchall()}

                    assert str(tenant_1) in tenants, f"Tenant {tenant_1} was not backfilled"
                    assert str(tenant_2) in tenants, f"Tenant {tenant_2} was not backfilled"

                    t1_row = tenants[str(tenant_1)]
                    t2_row = tenants[str(tenant_2)]

                    # Verify deterministic full-UUID slugs
                    expected_slug_1 = f"tenant-{str(tenant_1)}"
                    expected_slug_2 = f"tenant-{str(tenant_2)}"
                    assert t1_row["slug"] == expected_slug_1 == "tenant-00000000-0000-0000-0000-000000000011"
                    assert t2_row["slug"] == expected_slug_2 == "tenant-00000000-0000-0000-0000-000000000012"
                    assert t1_row["slug"] != t2_row["slug"]

                    assert t1_row["status"] == "active"
                    assert t2_row["status"] == "active"

                # 5. Assert ON DELETE RESTRICT foreign keys prevent deletion while operational records exist
                cur.execute("SAVEPOINT sp_del_t1;")
                with pytest.raises(ForeignKeyViolation):
                    cur.execute("DELETE FROM tenants WHERE id = %s;", (str(tenant_1),))
                cur.execute("ROLLBACK TO SAVEPOINT sp_del_t1;")

                cur.execute("SAVEPOINT sp_del_t2;")
                with pytest.raises(ForeignKeyViolation):
                    cur.execute("DELETE FROM tenants WHERE id = %s;", (str(tenant_2),))
                cur.execute("ROLLBACK TO SAVEPOINT sp_del_t2;")

                # 6. Verify that after deleting referencing operational records, tenant deletion succeeds
                cur.execute("DELETE FROM audit_events WHERE tenant_id = %s;", (str(tenant_1),))
                cur.execute("DELETE FROM assets WHERE id = %s;", (str(asset_1_id),))
                cur.execute("DELETE FROM tenants WHERE id = %s;", (str(tenant_1),))
                conn.commit()

                with conn.cursor(row_factory=dict_row) as check_cur:
                    check_cur.execute(f"SET search_path TO {schema_name}, public;")
                    check_cur.execute("SELECT id FROM tenants WHERE id = %s;", (str(tenant_1),))
                    assert check_cur.fetchone() is None

            finally:
                # Teardown isolated test schema
                cur.execute("SET search_path TO public;")
                cur.execute(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE;")
                conn.commit()

