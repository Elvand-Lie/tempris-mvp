"""Tests for Migration 012 (Finding Canonical CVE Linkage).

Validates:
- Creation of canonical_cve_id column and index on findings table
- Idempotency on repeated execution
- Dry-run verification
- Non-regression of existing database tables and records
- Preservation of legacy Finding fields
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts", "migrations")))

from models import Asset, Base, CanonicalVulnerability, Finding  # noqa: E402

migration_011 = importlib.import_module("011_canonical_vulnerability_spine")
migration_012 = importlib.import_module("012_finding_canonical_cve_linkage")


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "test_migration_012.db"
    url = f"sqlite:///{path.resolve().as_posix()}"
    engine = create_engine(url)

    # 1. Create assets table
    Base.metadata.tables["assets"].create(engine)

    # 2. Create raw findings table without canonical_cve_id to simulate pre-migration state
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE findings (
                id VARCHAR(20) PRIMARY KEY,
                tenant_id VARCHAR(50) NOT NULL DEFAULT 'tempris',
                external_id VARCHAR(100),
                cve_id VARCHAR(50),
                finding_type VARCHAR(50) NOT NULL DEFAULT 'standard',
                subtype VARCHAR(50),
                sub_class VARCHAR(50),
                pipeline VARCHAR(50) NOT NULL DEFAULT 'STANDARD',
                verification VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED',
                score FLOAT,
                decision VARCHAR(50),
                sla INTEGER,
                patch_available BOOLEAN DEFAULT 1,
                cve_assigned BOOLEAN DEFAULT 1,
                exploited_in_wild BOOLEAN DEFAULT 0,
                ai_assisted BOOLEAN DEFAULT 0,
                engagement_id VARCHAR(50),
                summary TEXT,
                description TEXT,
                public_reason_codes JSON,
                updated_at DATETIME,
                cve VARCHAR(50),
                title VARCHAR(500) NOT NULL,
                vendor VARCHAR(255),
                product VARCHAR(255),
                cvss FLOAT,
                priority VARCHAR(5),
                status VARCHAR(20) DEFAULT 'unmitigated',
                cisa_kev BOOLEAN DEFAULT 0,
                ransomware BOOLEAN DEFAULT 0,
                date_added VARCHAR(50),
                short_description TEXT,
                required_action TEXT,
                raw_inputs JSON,
                cve_context JSON,
                asset_id VARCHAR(50),
                asset_data JSON,
                sss_data JSON,
                source VARCHAR(20),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """))

    # Apply migration 011 to establish canonical_vulnerabilities
    migration_011.migrate(url, dry_run=False)

    # Insert raw legacy records using raw SQL so ORM does not try to insert unmigrated column
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO assets (id, tenant_id, name, asset_type, status)
            VALUES ('A-012', 'tenant-1', 'Prod Web Server', 'server', 'active');
        """))
        conn.execute(text("""
            INSERT INTO findings (id, tenant_id, title, cve, cve_id, cvss, source, cisa_kev, ransomware)
            VALUES ('F-012', 'tenant-1', 'Pre-012 Oracle RCE', 'CVE-2012-1710', 'CVE-2012-1710', 9.5, 'kev', 1, 1);
        """))

    engine.dispose()
    return path


def test_migration_012_adds_canonical_cve_id_idempotently(db_path):
    url = f"sqlite:///{db_path.resolve().as_posix()}"

    # 1. Dry run verification
    dry_result = migration_012.migrate(url, dry_run=True)
    assert dry_result["changed"] is True
    assert dry_result["dry_run"] is True

    engine = create_engine(url)
    columns_before = {col["name"] for col in inspect(engine).get_columns("findings")}
    assert "canonical_cve_id" not in columns_before
    engine.dispose()

    # 2. Live migration execution
    run_result = migration_012.migrate(url, dry_run=False)
    assert run_result["changed"] is True
    assert run_result["column_added"] == "canonical_cve_id"

    engine = create_engine(url)
    inspector = inspect(engine)
    columns_after = {col["name"] for col in inspector.get_columns("findings")}
    assert "canonical_cve_id" in columns_after
    indexes_after = {idx["name"] for idx in inspector.get_indexes("findings")}
    assert "ix_findings_canonical_cve_id" in indexes_after

    # 3. Verify pre-existing data survives intact and ORM queries work
    Session = sessionmaker(bind=engine)
    session = Session()
    finding = session.query(Finding).filter(Finding.id == "F-012").one()
    assert finding.cve == "CVE-2012-1710"
    assert finding.cvss == 9.5
    assert finding.canonical_cve_id is None  # Not yet backfilled
    session.close()
    engine.dispose()

    # 4. Idempotent re-run
    second_run = migration_012.migrate(url, dry_run=False)
    assert second_run["changed"] is False
    assert second_run["after"]["schema_complete"] is True
