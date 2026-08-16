import importlib.util
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker


MIGRATION = Path(__file__).resolve().parents[3] / "scripts" / "migrations" / "009_canonical_grc_framework.py"
spec = importlib.util.spec_from_file_location("migration_009", MIGRATION)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_migration_009_seeds_one_catalog_and_preserves_legacy_sop_without_policy_guesses(tmp_path):
    from models import Base, ControlAssessment, GrcPolicyDocument, GrcState, PolicyControlLink, Tenant

    db_path = tmp_path / "grc-framework.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    db.add_all([
        Tenant(id="tenant-a", display_name="Tenant A"),
        GrcState(
            tenant_id="tenant-a", toggles={"agm": [True]},
            sop_state=[{"id": "A.2.2", "status": "completed", "pic": "Owner", "notes": "Legacy assessment"}],
        ),
        GrcPolicyDocument(id="LEGACY-POL", tenant_id="tenant-a", title="Legacy policy", content="Preserved"),
    ])
    db.commit()
    db.close()

    first = migration.migrate(f"sqlite:///{db_path.as_posix()}")
    second = migration.migrate(f"sqlite:///{db_path.as_posix()}")

    schema = inspect(engine)
    assert {"framework_definitions", "framework_controls", "control_assessments", "policy_control_links"}.issubset(schema.get_table_names())
    assert first["after"]["schema_complete"] is True
    assert second["after"]["schema_complete"] is True

    db = Session()
    assert db.query(ControlAssessment).filter(ControlAssessment.tenant_id == "tenant-a").count() == 7
    assessment = db.query(ControlAssessment).filter(ControlAssessment.tenant_id == "tenant-a", ControlAssessment.control_id == "A.2.2").one()
    assert assessment.status == "completed"
    assert assessment.pic == "Owner"
    assert assessment.notes == "Legacy assessment"
    assert db.query(PolicyControlLink).filter(PolicyControlLink.policy_id == "LEGACY-POL").count() == 0
    assert db.query(GrcPolicyDocument).filter(GrcPolicyDocument.id == "LEGACY-POL").one().content == "Preserved"
    db.close()
    engine.dispose()
