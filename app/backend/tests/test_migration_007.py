import importlib.util
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


MIGRATION = Path(__file__).resolve().parents[3] / "scripts" / "migrations" / "007_create_tenant_registry.py"
spec = importlib.util.spec_from_file_location("migration_007", MIGRATION)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_migration_creates_registry_backfills_all_tenants_and_is_idempotent(tmp_path):
    db_path = tmp_path / "tenant-registry.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE tenant_packages (tenant_id VARCHAR(50) PRIMARY KEY, "
            "package_code VARCHAR(20) NOT NULL, module_overrides JSON NOT NULL, "
            "updated_by VARCHAR(255) NOT NULL)"
        ))
        connection.execute(text(
            "INSERT INTO tenant_packages VALUES ('customer-one', 'DETECT', '{}', 'seed')"
        ))
        connection.execute(text(
            "CREATE TABLE findings (id VARCHAR(20) PRIMARY KEY, tenant_id VARCHAR(50) NOT NULL)"
        ))
        connection.execute(text(
            "INSERT INTO findings VALUES ('F-1', 'customer-two')"
        ))

    migration.apply(engine)
    migration.apply(engine)

    schema = inspect(engine)
    assert "tenants" in schema.get_table_names()
    assert "version" in {column["name"] for column in schema.get_columns("tenant_packages")}
    with engine.connect() as connection:
        rows = {
            row[0]: (row[1], row[2])
            for row in connection.execute(text(
                "SELECT id, display_name, tenant_type FROM tenants ORDER BY id"
            ))
        }
        version = connection.execute(text(
            "SELECT version FROM tenant_packages WHERE tenant_id = 'customer-one'"
        )).scalar()
    assert set(rows) == {"tempris", "bug-bounty", "customer-one", "customer-two"}
    assert rows["tempris"] == ("Tempris Platform", "platform")
    assert rows["bug-bounty"] == ("Bug Bounty Research", "research")
    assert version == 1


def test_migration_dry_inventory_reports_missing_required_package_table(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'empty.db').as_posix()}")
    state = migration.inventory(engine)
    assert state["tenant_packages_exists"] is False
