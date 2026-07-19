#!/usr/bin/env python3
'''Add explicit tenant ownership to legacy GRC and TES records.

This migration refuses to infer ownership. Inspect the dry-run inventory first,
create and verify a database backup, then apply with an explicit tenant ID.
Rollback is performed by restoring the backup created or verified before apply.
'''

import argparse
import json
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


TABLES = (
    'grc_states',
    'grc_signoffs',
    'grc_policy_documents',
    'tes_snapshots',
)
OWNERSHIP_HINT_COLUMNS = (
    'tenant_id',
    'tenant',
    'tenant_name',
    'organization_id',
    'organization',
    'account_id',
    'account',
    'customer_id',
    'client_id',
)
TENANT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--db-path', type=Path)
    target.add_argument('--database-url')
    parser.add_argument('--legacy-tenant-id', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument(
        '--backup-file',
        type=Path,
        help='Verified backup to use for a database URL, or destination for SQLite backup.',
    )
    parser.add_argument('--report-file', type=Path)
    return parser.parse_args()


def database_url(args: argparse.Namespace) -> str:
    if args.database_url:
        return args.database_url
    return f'sqlite:///{args.db_path.resolve().as_posix()}'


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')


def _sqlite_backup_path(source: Path, requested: Path | None) -> Path:
    if requested:
        return requested.resolve()
    return source.with_name(f'{source.name}.migration-004-{_stamp()}.bak')


def verify_sqlite_backup(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError('SQLite backup is missing or empty')
    connection = sqlite3.connect(f'file:{path.as_posix()}?mode=ro', uri=True)
    try:
        result = connection.execute('PRAGMA integrity_check').fetchone()
    finally:
        connection.close()
    if not result or result[0] != 'ok':
        raise RuntimeError('SQLite backup integrity verification failed')


def create_sqlite_backup(source: Path, requested: Path | None) -> Path:
    source = source.resolve()
    if not source.is_file():
        raise FileNotFoundError('SQLite database not found')
    backup = _sqlite_backup_path(source, requested)
    if backup.exists():
        raise RuntimeError('Refusing to overwrite an existing backup file')
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, backup)
    if backup.stat().st_size != source.stat().st_size:
        raise RuntimeError('SQLite backup size verification failed')
    verify_sqlite_backup(backup)
    return backup


def verify_postgresql_backup(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError('PostgreSQL backup is missing or empty')
    pg_restore = shutil.which('pg_restore')
    if not pg_restore:
        raise RuntimeError('pg_restore is required to verify a PostgreSQL backup')
    result = subprocess.run(
        [pg_restore, '--list', str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError('PostgreSQL backup verification failed')


def verify_supplied_backup(path: Path) -> Path:
    backup = path.resolve()
    if backup.suffix.lower() in {'.db', '.sqlite', '.sqlite3'}:
        verify_sqlite_backup(backup)
    else:
        verify_postgresql_backup(backup)
    return backup


def _table_names(engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _table_columns(engine, table: str) -> set[str]:
    return {column['name'] for column in inspect(engine).get_columns(table)}


def _row_count(connection, table: str) -> int:
    return int(connection.execute(text(f'SELECT COUNT(*) FROM {table}')).scalar_one())


def _unassigned_count(connection, table: str, has_tenant_column: bool) -> int:
    if not has_tenant_column:
        return _row_count(connection, table)
    return int(
        connection.execute(
            text(f'SELECT COUNT(*) FROM {table} WHERE tenant_id IS NULL OR TRIM(tenant_id) = \'\''),
        ).scalar_one()
    )


def _distinct_hint_count(connection, table: str, column: str) -> int:
    return int(
        connection.execute(
            text(
                f'SELECT COUNT(DISTINCT {column}) FROM {table} '
                f'WHERE {column} IS NOT NULL AND TRIM(CAST({column} AS TEXT)) <> \'\''
            ),
        ).scalar_one()
    )


def _single_hint_value(connection, table: str, column: str) -> str | None:
    value = connection.execute(
        text(
            f'SELECT CAST({column} AS TEXT) FROM {table} '
            f'WHERE {column} IS NOT NULL AND TRIM(CAST({column} AS TEXT)) <> \'\' LIMIT 1'
        ),
    ).scalar_one_or_none()
    return str(value) if value is not None else None


def inspect_legacy_rows(engine, legacy_tenant_id: str) -> tuple[list[dict], list[dict]]:
    tables = _table_names(engine)
    inventory: list[dict] = []
    conflicts: list[dict] = []
    with engine.connect() as connection:
        for table in TABLES:
            if table not in tables:
                inventory.append(
                    {
                        'table': table,
                        'exists': False,
                        'row_count': 0,
                        'unassigned_rows': 0,
                        'ownership_hint_counts': {},
                    }
                )
                continue

            columns = _table_columns(engine, table)
            has_tenant_column = 'tenant_id' in columns
            row_count = _row_count(connection, table)
            unassigned_rows = _unassigned_count(connection, table, has_tenant_column)
            hint_counts: dict[str, int] = {}
            reasons: list[str] = []
            if unassigned_rows:
                for column in OWNERSHIP_HINT_COLUMNS:
                    if column not in columns:
                        continue
                    count = _distinct_hint_count(connection, table, column)
                    hint_counts[column] = count
                    if count > 1:
                        reasons.append(f'{column} has multiple non-empty ownership values')
                    elif count == 1:
                        value = _single_hint_value(connection, table, column)
                        if value != legacy_tenant_id:
                            reasons.append(f'{column} conflicts with the explicit legacy tenant ID')
            row = {
                'table': table,
                'exists': True,
                'row_count': row_count,
                'tenant_column_exists': has_tenant_column,
                'unassigned_rows': unassigned_rows,
                'ownership_hint_counts': hint_counts,
            }
            inventory.append(row)
            if reasons:
                conflicts.append({'table': table, 'reasons': reasons})
    return inventory, conflicts


def schema_plan(engine) -> list[dict]:
    tables = _table_names(engine)
    plan: list[dict] = []
    schema = inspect(engine)
    for table in TABLES:
        if table not in tables:
            plan.append(
                {
                    'table': table,
                    'exists': False,
                    'add_tenant_column': False,
                    'create_tenant_index': False,
                }
            )
            continue
        columns = {column['name'] for column in schema.get_columns(table)}
        indexes = {index['name'] for index in schema.get_indexes(table)}
        index_name = f'ix_{table}_tenant_id'
        plan.append(
            {
                'table': table,
                'exists': True,
                'add_tenant_column': 'tenant_id' not in columns,
                'create_tenant_index': index_name not in indexes,
            }
        )
    return plan


def apply_migration(engine, tenant_id: str, plan: list[dict]) -> None:
    escaped_tenant_id = tenant_id.replace("'", "''")
    with engine.begin() as connection:
        for item in plan:
            if not item['exists']:
                continue
            table = item['table']
            if item['add_tenant_column']:
                connection.execute(
                    text(
                        f'ALTER TABLE {table} ADD COLUMN tenant_id VARCHAR(50) '
                        f'NOT NULL DEFAULT \'{escaped_tenant_id}\''
                    )
                )
            connection.execute(
                text(
                    f'UPDATE {table} SET tenant_id = :tenant_id '
                    f'WHERE tenant_id IS NULL OR TRIM(tenant_id) = \'\''
                ),
                {'tenant_id': tenant_id},
            )
            connection.execute(
                text(f'CREATE INDEX IF NOT EXISTS ix_{table}_tenant_id ON {table} (tenant_id)')
            )
            if item['add_tenant_column'] and engine.dialect.name == 'postgresql':
                connection.execute(
                    text(f'ALTER TABLE {table} ALTER COLUMN tenant_id DROP DEFAULT')
                )


def verify_migration(engine, expected_counts: dict[str, int]) -> dict:
    tables = _table_names(engine)
    schema = inspect(engine)
    checks: list[dict] = []
    with engine.connect() as connection:
        for table in TABLES:
            if table not in tables:
                checks.append(
                    {
                        'table': table,
                        'exists': False,
                        'tenant_column': False,
                        'tenant_index': False,
                        'row_count_consistent': False,
                        'unassigned_rows': None,
                    }
                )
                continue

            columns = {column['name'] for column in schema.get_columns(table)}
            indexes = {index['name'] for index in schema.get_indexes(table)}
            row_count = _row_count(connection, table)
            unassigned_rows = _unassigned_count(connection, table, 'tenant_id' in columns)
            checks.append(
                {
                    'table': table,
                    'exists': True,
                    'tenant_column': 'tenant_id' in columns,
                    'tenant_index': f'ix_{table}_tenant_id' in indexes,
                    'row_count_before': expected_counts.get(table, 0),
                    'row_count_after': row_count,
                    'row_count_consistent': row_count == expected_counts.get(table, 0),
                    'unassigned_rows': unassigned_rows,
                }
            )

    ok = all(
        item['exists']
        and item['tenant_column']
        and item['tenant_index']
        and item['row_count_consistent']
        and item['unassigned_rows'] == 0
        for item in checks
    )
    return {'ok': ok, 'tables': checks}


def write_report(report_file: Path | None, report: dict) -> None:
    if not report_file:
        return
    target = report_file.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main() -> int:
    args = parse_args()
    tenant_id = args.legacy_tenant_id.strip()
    if not TENANT_RE.fullmatch(tenant_id):
        raise SystemExit('Invalid --legacy-tenant-id')

    engine = create_engine(database_url(args), future=True)
    try:
        inventory, conflicts = inspect_legacy_rows(engine, tenant_id)
        plan = schema_plan(engine)
        before_counts = {
            item['table']: item['row_count']
            for item in inventory
            if item['exists']
        }
        report = {
            'migration': '004_add_grc_tes_tenant_scope',
            'target_kind': 'sqlite_path' if args.db_path else 'database_url',
            'legacy_tenant_id_supplied': True,
            'dry_run': args.dry_run,
            'legacy_inventory': inventory,
            'schema_plan': plan,
            'ambiguous_ownership': conflicts,
        }
        if conflicts:
            write_report(args.report_file, report)
            print(json.dumps(report, indent=2, sort_keys=True))
            raise SystemExit(
                'Refusing migration: ownership hints conflict with the explicit legacy tenant ID'
            )

        if args.dry_run:
            write_report(args.report_file, report)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0

        if args.db_path:
            backup = create_sqlite_backup(args.db_path, args.backup_file)
        else:
            if not args.backup_file:
                raise SystemExit(
                    'Refusing database URL migration without a verified --backup-file'
                )
            backup = verify_supplied_backup(args.backup_file)
        report['backup_file'] = str(backup)

        apply_migration(engine, tenant_id, plan)
        verification = verify_migration(engine, before_counts)
        report['verification'] = verification
        write_report(args.report_file, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        if not verification['ok']:
            raise SystemExit('Migration verification failed; restore the verified backup before retrying')
        return 0
    finally:
        engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
