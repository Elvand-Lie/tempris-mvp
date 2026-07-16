import pytest
import sqlite3
import subprocess
import os
from models import Finding, Asset, AuditLog
from services.database import SessionLocal

def test_purge_test_artifacts_dry_run_and_execution():
    test_db_path = "test_purge_artifacts.db"
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except Exception:
            pass

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from services.database import Base
    
    test_engine = create_engine(f"sqlite:///{test_db_path}")
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    
    db = TestSessionLocal()
    try:
        # Seed test items in the test database
        test_finding = Finding(
            id="F-TEST-PURGE",
            cve="CVE-2026-TEST-PURGE",
            title="A Test Finding to Purge",
            vendor="TestVendor",
            product="TestProduct",
            cvss=5.0,
            priority="P1",
            status="unmitigated",
            tenant_id="tempris"
        )
        test_asset = Asset(
            id="ASSET-TEST-PURGE",
            name="Test Asset to Purge",
            asset_type="server",
            ip_address="127.0.0.99",
            hostname="test.purge.tempris.local",
            criticality="low",
            tenant_id="tempris"
        )
        test_log = AuditLog(
            action="TEST_ACTION_PURGE",
            module="TEST",
            detail="detail containing F-TEST-PURGE to purge",
            tenant_id="tempris"
        )
        db.add(test_finding)
        db.add(test_asset)
        db.add(test_log)
        db.commit()

        # 1. Run dry-run
        res_dry = subprocess.run(
            [
                "python", "scripts/maintenance/purge_test_artifacts.py",
                "--db-path", test_db_path,
                "--tenant-id", "tempris",
                "--artifact-ids", "F-TEST-PURGE,ASSET-TEST-PURGE",
                "--approval-ref", "TEST-I4"
            ],
            capture_output=True,
            text=True
        )
        assert res_dry.returncode == 0
        assert "Findings to delete: 1" in res_dry.stdout
        assert "Assets to delete: 1" in res_dry.stdout
        assert "Audit logs to delete: 1" in res_dry.stdout

        # Verify items are still in database
        assert db.query(Finding).filter(Finding.id == "F-TEST-PURGE").count() == 1
        assert db.query(Asset).filter(Asset.id == "ASSET-TEST-PURGE").count() == 1
        assert db.query(AuditLog).filter(AuditLog.action == "TEST_ACTION_PURGE").count() == 1

        # 2. Verify that environment = test rejects purge if db-path is not test_purge_artifacts.db
        res_wrong_db = subprocess.run(
            [
                "python", "scripts/maintenance/purge_test_artifacts.py",
                "--db-path", "tempris.db",
                "--tenant-id", "tempris",
                "--artifact-ids", "F-TEST-PURGE,ASSET-TEST-PURGE",
                "--approval-ref", "TEST-I4",
                "--execute"
            ],
            capture_output=True,
            text=True
        )
        assert res_wrong_db.returncode == 1
        assert "blocked in ENVIRONMENT" in res_wrong_db.stderr or "blocked in ENVIRONMENT" in res_wrong_db.stdout

        # 3. Verify that missing or unknown environment rejects execution
        env_unknown = os.environ.copy()
        env_unknown["ENVIRONMENT"] = "unknown"
        res_unknown_env = subprocess.run(
            [
                "python", "scripts/maintenance/purge_test_artifacts.py",
                "--db-path", test_db_path,
                "--tenant-id", "tempris",
                "--artifact-ids", "F-TEST-PURGE,ASSET-TEST-PURGE",
                "--approval-ref", "TEST-I4",
                "--execute"
            ],
            capture_output=True,
            text=True,
            env=env_unknown
        )
        assert res_unknown_env.returncode == 1
        assert "blocked in ENVIRONMENT" in res_unknown_env.stderr or "blocked in ENVIRONMENT" in res_unknown_env.stdout

        # 4. Run execute
        res_exec = subprocess.run(
            [
                "python", "scripts/maintenance/purge_test_artifacts.py",
                "--db-path", test_db_path,
                "--tenant-id", "tempris",
                "--artifact-ids", "F-TEST-PURGE,ASSET-TEST-PURGE",
                "--approval-ref", "TEST-I4",
                "--execute"
            ],
            capture_output=True,
            text=True
        )
        assert res_exec.returncode == 0
        assert "Purged 1 findings." in res_exec.stdout
        assert "Purged 1 assets." in res_exec.stdout
        assert "Purged 1 audit logs." in res_exec.stdout

        # Verify items are deleted from database
        db.expire_all()
        assert db.query(Finding).filter(Finding.id == "F-TEST-PURGE").count() == 0
        assert db.query(Asset).filter(Asset.id == "ASSET-TEST-PURGE").count() == 0
        assert db.query(AuditLog).filter(AuditLog.action == "TEST_ACTION_PURGE").count() == 0

    finally:
        db.close()
        test_engine.dispose()
        if os.path.exists(test_db_path):
            try:
                os.remove(test_db_path)
            except Exception:
                pass
