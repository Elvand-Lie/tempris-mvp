from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_guarded_release_covers_migration_reports_docs_and_full_rollback():
    script = (ROOT / "scripts" / "deploy-vps.ps1").read_text(encoding="utf-8")
    assert "008_canonical_posture_and_operations.py" in script
    assert "migration-008.json" in script
    assert "backups/reports" in script
    assert "tempris_backend:/tmp/`$release.reports.tar.gz" in script
    assert "tar -C /app/data" in script
    assert "tar -tzf \"`$report_backup\"" in script
    assert "docs/product" in script
    assert "pg_restore" in script and "--clean --if-exists" in script
    assert "REVISION" in script
    assert "--dry-run" in script


def test_release_runbook_describes_migration_008_and_artifact_restore():
    runbook = (ROOT / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "migration 008" in runbook.lower()
    assert "report artifacts" in runbook.lower()
    assert "REVISION" in runbook
    assert "pg_restore" in runbook
