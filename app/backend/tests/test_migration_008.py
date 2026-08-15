import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text


MIGRATION = Path(__file__).resolve().parents[3] / "scripts" / "migrations" / "008_canonical_posture_and_operations.py"
spec = importlib.util.spec_from_file_location("migration_008", MIGRATION)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_migration_adds_canonical_storage_without_confirming_legacy_links(tmp_path):
    db_path = tmp_path / "canonical.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE findings (id VARCHAR(50) PRIMARY KEY, tenant_id VARCHAR(50), asset_id VARCHAR(50))"
        ))
        connection.execute(text(
            "CREATE TABLE assets (id VARCHAR(50) PRIMARY KEY, tenant_id VARCHAR(50), status VARCHAR(30))"
        ))
        connection.execute(text(
            "CREATE TABLE scan_findings (id VARCHAR(50) PRIMARY KEY, tenant_id VARCHAR(50))"
        ))
        connection.execute(text(
            "CREATE TABLE strike_authorizations (id VARCHAR(50) PRIMARY KEY, tenant_id VARCHAR(50))"
        ))
        connection.execute(text(
            "CREATE TABLE strike_simulations (id VARCHAR(50) PRIMARY KEY, authorization_id VARCHAR(50))"
        ))
        connection.execute(text(
            "CREATE TABLE grc_policy_documents (id VARCHAR(80) PRIMARY KEY, tenant_id VARCHAR(50))"
        ))
        connection.execute(text("INSERT INTO findings VALUES ('F-LEGACY', 'tenant-a', 'A-1')"))
        connection.execute(text("INSERT INTO assets VALUES ('A-1', 'tenant-a', 'active')"))
        connection.execute(text("INSERT INTO strike_authorizations VALUES ('AUTH-1', 'tenant-a')"))
        connection.execute(text("INSERT INTO strike_simulations VALUES ('SIM-1', 'AUTH-1')"))

    migration.migrate(f"sqlite:///{db_path.as_posix()}", dry_run=False)
    migration.migrate(f"sqlite:///{db_path.as_posix()}", dry_run=False)

    schema = inspect(engine)
    assert {"scan_jobs", "posture_snapshots", "incidents", "operational_events"}.issubset(
        schema.get_table_names()
    )
    assert "asset_exposures" in schema.get_table_names()
    assert "evidence_metadata" in {
        column["name"] for column in schema.get_columns("asset_exposures")
    }
    assert {
        "ix_scan_findings_template_id",
        "ix_scan_findings_cve_id",
        "ix_scan_findings_normalized_finding_id",
    }.issubset({index["name"] for index in schema.get_indexes("scan_findings")})
    assert "ix_strike_simulations_tenant_id" in {
        index["name"] for index in schema.get_indexes("strike_simulations")
    }
    assert "uq_asset_exposure_tenant_finding_asset" in {
        constraint["name"] for constraint in schema.get_unique_constraints("asset_exposures")
    }
    assert "uq_incident_external_event" in {
        constraint["name"] for constraint in schema.get_unique_constraints("incidents")
    }
    with engine.connect() as connection:
        legacy_asset = connection.execute(text(
            "SELECT asset_id FROM findings WHERE id = 'F-LEGACY'"
        )).scalar_one()
        exposure_count = connection.execute(text(
            "SELECT COUNT(*) FROM asset_exposures WHERE finding_id = 'F-LEGACY'"
        )).scalar_one()
        simulation_tenant = connection.execute(text(
            "SELECT tenant_id FROM strike_simulations WHERE id = 'SIM-1'"
        )).scalar_one()
    assert legacy_asset == "A-1"
    assert exposure_count == 0
    assert simulation_tenant == "tenant-a"


def test_migration_refuses_to_guess_orphaned_strike_tenant(tmp_path):
    db_path = tmp_path / "orphan.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE findings (id VARCHAR(50) PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE assets (id VARCHAR(50) PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE scan_findings (id VARCHAR(50) PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE strike_authorizations (id VARCHAR(50) PRIMARY KEY, tenant_id VARCHAR(50))"))
        connection.execute(text("CREATE TABLE strike_simulations (id VARCHAR(50) PRIMARY KEY, authorization_id VARCHAR(50))"))
        connection.execute(text("CREATE TABLE grc_policy_documents (id VARCHAR(80) PRIMARY KEY)"))
        connection.execute(text("INSERT INTO strike_simulations VALUES ('SIM-ORPHAN', 'AUTH-MISSING')"))
    with pytest.raises(RuntimeError, match="ownership cannot be inferred"):
        migration.migrate(f"sqlite:///{db_path.as_posix()}", dry_run=False)
    assert "asset_exposures" not in inspect(engine).get_table_names()


def test_migration_dry_run_rejects_missing_prerequisite_tables(tmp_path):
    db_path = tmp_path / "empty.db"
    create_engine(f"sqlite:///{db_path.as_posix()}").dispose()
    try:
        migration.migrate(f"sqlite:///{db_path.as_posix()}", dry_run=True)
    except RuntimeError as exc:
        assert "Required existing tables are missing" in str(exc)
    else:
        raise AssertionError("Migration accepted an empty database")
