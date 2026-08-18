"""Tests for Migration 013: AssetScanAuthorization & ScanJob target provenance."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from models import Asset, AssetScanAuthorization, Base, ScanJob

migration_path = Path(__file__).resolve().parents[3] / "scripts" / "migrations" / "013_asset_scan_authorizations.py"
spec = importlib.util.spec_from_file_location("migration_013", migration_path)
mig_013 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mig_013)


@pytest.fixture()
def test_db_path(tmp_path):
    db_file = tmp_path / "test_mig_013.db"
    url = f"sqlite:///{db_file.resolve().as_posix()}"
    engine = create_engine(url)

    # Create tables up to migration 012 (ScanJob without 013 columns, Asset, etc.)
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE assets (
                id VARCHAR(50) PRIMARY KEY,
                tenant_id VARCHAR(50) NOT NULL,
                name VARCHAR(255) NOT NULL,
                asset_type VARCHAR(50) DEFAULT 'server',
                ip_address VARCHAR(50),
                hostname VARCHAR(255),
                criticality VARCHAR(20) DEFAULT 'medium',
                owner VARCHAR(255),
                environment VARCHAR(50),
                tags JSON DEFAULT '[]',
                notes TEXT,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE TABLE scan_jobs (
                id VARCHAR(50) PRIMARY KEY,
                tenant_id VARCHAR(50) NOT NULL,
                target VARCHAR(500) NOT NULL,
                normalized_target VARCHAR(255) NOT NULL,
                scan_type VARCHAR(50) NOT NULL,
                engines JSON DEFAULT '[]',
                status VARCHAR(30) NOT NULL DEFAULT 'started',
                result_count INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                authorization_context JSON DEFAULT '{}',
                started_by VARCHAR(255),
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        """))

    yield url
    engine.dispose()


def test_migration_013_dry_run_apply_and_idempotent(test_db_path):
    # 1. Dry run
    dry_res = mig_013.migrate(test_db_path, dry_run=True)
    assert dry_res["dry_run"] is True
    assert dry_res["changed"] is True

    # 2. Apply
    apply_res = mig_013.migrate(test_db_path, dry_run=False)
    assert apply_res["changed"] is True
    assert apply_res["table_created"] == "asset_scan_authorizations"
    assert "asset_id" in apply_res["columns_added"]

    # 3. Idempotent re-run
    re_res = mig_013.migrate(test_db_path, dry_run=False)
    assert re_res["changed"] is False
    assert re_res["after"]["schema_complete"] is True

    # 4. Verify table and columns exist
    engine = create_engine(test_db_path)
    inspector = inspect(engine)
    assert "asset_scan_authorizations" in inspector.get_table_names()
    cols = {c["name"] for c in inspector.get_columns("scan_jobs")}
    assert "asset_id" in cols
    assert "scan_authorization_id" in cols
    assert "authorized_canonical_target" in cols
    assert "resolved_ips" in cols
    engine.dispose()
