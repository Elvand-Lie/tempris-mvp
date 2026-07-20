#!/usr/bin/env python3
"""Add tenant-scoped uniqueness for EDIP decisions and control statuses.

The migration is deliberately non-destructive: NULL tenant ownership and
duplicate tenant/resource rows must be resolved explicitly before apply.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


TARGETS = {
    "edip_decisions": {
        "columns": ("tenant_id", "finding_id"),
        "index": "uq_edip_decisions_tenant_finding",
    },
    "control_statuses": {
        "columns": ("tenant_id", "framework_id", "control_id"),
        "index": "uq_control_statuses_tenant_framework_control",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path)
    target.add_argument("--database-url")
    target.add_argument(
        "--database-url-env",
        action="store_true",
        help="Read DATABASE_URL from the environment without exposing it in process arguments.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backup-file", type=Path)
    return parser.parse_args()


def _database_url(args: argparse.Namespace) -> str:
    if args.database_url:
        return args.database_url
    if args.database_url_env:
        value = os.environ.get("DATABASE_URL", "").strip()
        if not value:
            raise RuntimeError("DATABASE_URL is not configured")
        return value
    return f"sqlite:///{args.db_path.resolve().as_posix()}"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _verify_sqlite(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError("SQLite backup is missing or empty")
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    if not result or result[0] != "ok":
        raise RuntimeError("SQLite backup integrity verification failed")


def _prepare_backup(args: argparse.Namespace) -> Path:
    if args.db_path:
        source = args.db_path.resolve()
        if not source.is_file():
            raise FileNotFoundError("SQLite database not found")
        destination = (
            args.backup_file.resolve()
            if args.backup_file
            else source.with_name(f"{source.name}.migration-005-{_stamp()}.bak")
        )
        if destination.exists():
            raise RuntimeError("Refusing to overwrite an existing backup")
        shutil.copy2(source, destination)
        _verify_sqlite(destination)
        return destination

    if not args.backup_file:
        raise RuntimeError("--backup-file is required for a database URL")
    backup = args.backup_file.resolve()
    if not backup.is_file() or backup.stat().st_size == 0:
        raise RuntimeError("Database backup is missing or empty")
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        raise RuntimeError("pg_restore is required to verify a PostgreSQL backup")
    check = subprocess.run(
        [pg_restore, "--list", str(backup)],
        capture_output=True,
        text=True,
        check=False,
    )
    if check.returncode != 0:
        raise RuntimeError("PostgreSQL backup verification failed")
    return backup


def _inventory(engine) -> tuple[list[dict], list[str]]:
    schema = inspect(engine)
    table_names = set(schema.get_table_names())
    rows = []
    blockers = []
    with engine.connect() as connection:
        for table, target in TARGETS.items():
            if table not in table_names:
                rows.append({"table": table, "exists": False})
                blockers.append(f"Required table is missing: {table}")
                continue
            existing_columns = {column["name"] for column in schema.get_columns(table)}
            missing = [column for column in target["columns"] if column not in existing_columns]
            if missing:
                blockers.append(f"{table} is missing columns: {', '.join(missing)}")
                rows.append({"table": table, "exists": True, "missing_columns": missing})
                continue
            columns = ", ".join(target["columns"])
            null_predicate = " OR ".join(
                f"{column} IS NULL OR TRIM(CAST({column} AS TEXT)) = ''"
                for column in target["columns"]
            )
            unassigned = int(connection.execute(
                text(f"SELECT COUNT(*) FROM {table} WHERE {null_predicate}")
            ).scalar_one())
            duplicate_groups = int(connection.execute(text(
                f"SELECT COUNT(*) FROM (SELECT {columns} FROM {table} "
                f"GROUP BY {columns} HAVING COUNT(*) > 1) AS duplicates"
            )).scalar_one())
            index_names = {item["name"] for item in schema.get_indexes(table)}
            constraint_names = {
                item.get("name") for item in schema.get_unique_constraints(table)
            }
            installed = target["index"] in index_names | constraint_names
            row_count = int(connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one())
            rows.append({
                "table": table,
                "exists": True,
                "row_count": row_count,
                "unassigned_rows": unassigned,
                "duplicate_groups": duplicate_groups,
                "constraint_installed": installed,
            })
            if unassigned:
                blockers.append(f"{table} has {unassigned} rows with incomplete ownership keys")
            if duplicate_groups:
                blockers.append(f"{table} has {duplicate_groups} duplicate tenant/resource groups")
    return rows, blockers


def _apply(engine) -> None:
    existing = set(inspect(engine).get_table_names())
    with engine.begin() as connection:
        for table, target in TARGETS.items():
            if table not in existing:
                continue
            columns = ", ".join(target["columns"])
            connection.execute(text(
                f"CREATE UNIQUE INDEX IF NOT EXISTS {target['index']} ON {table} ({columns})"
            ))


def main() -> int:
    args = parse_args()
    engine = create_engine(_database_url(args))
    before, blockers = _inventory(engine)
    report = {"dry_run": args.dry_run, "before": before, "blockers": blockers}
    if args.dry_run:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2 if blockers else 0
    if blockers:
        raise RuntimeError("Migration blocked: " + "; ".join(blockers))
    backup = _prepare_backup(args)
    _apply(engine)
    after, after_blockers = _inventory(engine)
    if after_blockers or any(
        row.get("exists") and not row.get("constraint_installed") for row in after
    ):
        raise RuntimeError("Post-migration constraint verification failed; restore the verified backup")
    print(json.dumps({
        "dry_run": False,
        "backup_verified": True,
        "backup_path": str(backup),
        "before": before,
        "after": after,
        "rollback": "Restore the verified database backup.",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
