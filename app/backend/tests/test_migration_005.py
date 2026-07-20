import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "migrations" / "005_add_tenant_uniqueness_constraints.py"


def _database(path: Path, duplicate: bool = False) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE edip_decisions (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL
            );
            CREATE TABLE control_statuses (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                framework_id TEXT NOT NULL,
                control_id TEXT NOT NULL
            );
            INSERT INTO edip_decisions VALUES (1, 'tenant-alpha', 'F-1');
            INSERT INTO control_statuses VALUES (1, 'tenant-alpha', 'mas_trm_2024', 'C-1');
            """
        )
        if duplicate:
            connection.execute(
                "INSERT INTO edip_decisions VALUES (2, 'tenant-alpha', 'F-1')"
            )
        connection.commit()
    finally:
        connection.close()


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_migration_005_dry_run_apply_and_rerun(tmp_path):
    database = tmp_path / "clean.db"
    _database(database)
    dry_run = _run("--db-path", str(database), "--dry-run")
    assert dry_run.returncode == 0
    assert '"duplicate_groups": 0' in dry_run.stdout

    first_backup = tmp_path / "first.bak"
    applied = _run("--db-path", str(database), "--backup-file", str(first_backup))
    assert applied.returncode == 0
    assert first_backup.is_file()
    connection = sqlite3.connect(database)
    try:
        indexes = {
            row[1] for row in connection.execute("PRAGMA index_list('edip_decisions')")
        }
        assert "uq_edip_decisions_tenant_finding" in indexes
    finally:
        connection.close()

    second_backup = tmp_path / "second.bak"
    rerun = _run("--db-path", str(database), "--backup-file", str(second_backup))
    assert rerun.returncode == 0
    assert second_backup.is_file()


def test_migration_005_refuses_duplicate_ownership(tmp_path):
    database = tmp_path / "duplicate.db"
    _database(database, duplicate=True)
    dry_run = _run("--db-path", str(database), "--dry-run")
    assert dry_run.returncode == 2
    assert "duplicate tenant/resource groups" in dry_run.stdout

    backup = tmp_path / "must-not-exist.bak"
    applied = _run("--db-path", str(database), "--backup-file", str(backup))
    assert applied.returncode != 0
    assert not backup.exists()
