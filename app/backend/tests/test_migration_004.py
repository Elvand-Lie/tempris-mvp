import sqlite3
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MIGRATION = REPO_ROOT / 'scripts' / 'migrations' / '004_add_grc_tes_tenant_scope.py'
DATABASE = REPO_ROOT / 'test_migration_004.db'
TABLES = (
    'grc_states',
    'grc_signoffs',
    'grc_policy_documents',
    'tes_snapshots',
)


def create_legacy_database():
    connection = sqlite3.connect(DATABASE)
    for table in TABLES:
        connection.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY)')
        connection.execute(f'INSERT INTO {table} (id) VALUES (1)')
    connection.commit()
    connection.close()


def tenant_columns() -> dict[str, list[str]]:
    connection = sqlite3.connect(DATABASE)
    result = {
        table: [row[1] for row in connection.execute(f'PRAGMA table_info({table})')]
        for table in TABLES
    }
    connection.close()
    return result


def tenant_values() -> dict[str, str]:
    connection = sqlite3.connect(DATABASE)
    result = {
        table: connection.execute(
            f'SELECT tenant_id FROM {table} WHERE id = 1'
        ).fetchone()[0]
        for table in TABLES
    }
    connection.close()
    return result


def tenant_indexes() -> dict[str, list[str]]:
    connection = sqlite3.connect(DATABASE)
    result = {
        table: [row[1] for row in connection.execute(f'PRAGMA index_list({table})')]
        for table in TABLES
    }
    connection.close()
    return result


def cleanup():
    DATABASE.unlink(missing_ok=True)
    for backup in REPO_ROOT.glob(f'{DATABASE.name}.bak-*'):
        backup.unlink(missing_ok=True)


def test_migration_004_is_explicit_dry_runnable_and_idempotent():
    cleanup()
    create_legacy_database()
    try:
        dry_run = subprocess.run(
            [
                sys.executable,
                str(MIGRATION),
                '--db-path',
                str(DATABASE),
                '--legacy-tenant-id',
                'tenant-alpha',
                '--dry-run',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert dry_run.returncode == 0, dry_run.stderr
        assert all('tenant_id' not in columns for columns in tenant_columns().values())
        assert '"row_count": 1' in dry_run.stdout

        first = subprocess.run(
            [
                sys.executable,
                str(MIGRATION),
                '--db-path',
                str(DATABASE),
                '--legacy-tenant-id',
                'tenant-alpha',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert first.returncode == 0, first.stderr
        assert all('tenant_id' in columns for columns in tenant_columns().values())
        assert set(tenant_values().values()) == {'tenant-alpha'}
        assert all(
            f'ix_{table}_tenant_id' in indexes
            for table, indexes in tenant_indexes().items()
        )
        assert all(backup.is_file() for backup in REPO_ROOT.glob(f'{DATABASE.name}.migration-004-*.bak'))

        second = subprocess.run(
            [
                sys.executable,
                str(MIGRATION),
                '--db-path',
                str(DATABASE),
                '--legacy-tenant-id',
                'tenant-alpha',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert second.returncode == 0, second.stderr
        assert set(tenant_values().values()) == {'tenant-alpha'}
    finally:
        cleanup()


def test_migration_004_rejects_ambiguous_legacy_ownership():
    cleanup()
    create_legacy_database()
    connection = sqlite3.connect(DATABASE)
    connection.execute('ALTER TABLE grc_states ADD COLUMN account_id TEXT')
    connection.execute('UPDATE grc_states SET account_id = ?', ('tenant-alpha',))
    connection.execute('INSERT INTO grc_states (id, account_id) VALUES (?, ?)', (2, 'tenant-beta'))
    connection.commit()
    connection.close()
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(MIGRATION),
                '--db-path',
                str(DATABASE),
                '--legacy-tenant-id',
                'tenant-alpha',
                '--dry-run',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert 'ownership hints conflict' in result.stderr
        assert all('tenant_id' not in columns for columns in tenant_columns().values())
    finally:
        cleanup()


def test_migration_004_refuses_implicit_legacy_ownership():
    cleanup()
    create_legacy_database()
    try:
        result = subprocess.run(
            [sys.executable, str(MIGRATION), '--db-path', str(DATABASE)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert 'legacy-tenant-id' in result.stderr
        assert all('tenant_id' not in columns for columns in tenant_columns().values())
    finally:
        cleanup()
