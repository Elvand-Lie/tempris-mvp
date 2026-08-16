import importlib.util
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


MIGRATION = Path(__file__).resolve().parents[3] / "scripts" / "migrations" / "010_live_cve_tes_context.py"
spec = importlib.util.spec_from_file_location("migration_010", MIGRATION)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_migration_010_is_additive_and_idempotent(tmp_path):
    from models import Base, Finding

    path = tmp_path / "live-cve-context.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    db.add(Finding(id="F-1", tenant_id="tenant-a", title="Preserved finding", asset_id="LEGACY-ASSET"))
    db.commit()
    db.close()
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE findings DROP COLUMN cve_context")

    first = migration.migrate(f"sqlite:///{path.as_posix()}")
    second = migration.migrate(f"sqlite:///{path.as_posix()}")

    assert first["changed"] is True
    assert first["legacy_asset_links_promoted"] == 0
    assert second["changed"] is False
    db = Session()
    preserved = db.query(Finding).filter(Finding.id == "F-1").one()
    assert preserved.asset_id == "LEGACY-ASSET"
    assert preserved.cve_context in (None, {})
    db.close()
    engine.dispose()
