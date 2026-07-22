#!/usr/bin/env python3
"""Add the v62 SSS sub_class output field to the existing findings table."""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path)
    target.add_argument("--database-url")
    target.add_argument("--database-url-env", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backup-file", type=Path)
    return parser.parse_args()


def database_url(args: argparse.Namespace) -> str:
    if args.database_url:
        return args.database_url
    if args.database_url_env:
        value = os.environ.get("DATABASE_URL", "").strip()
        if not value:
            raise RuntimeError("DATABASE_URL is not configured")
        return value
    return f"sqlite:///{args.db_path.resolve().as_posix()}"


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def verify_sqlite(path: Path) -> None:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    if not result or result[0] != "ok":
        raise RuntimeError("SQLite backup integrity verification failed")


def prepare_backup(args: argparse.Namespace) -> Path:
    if args.db_path:
        source = args.db_path.resolve()
        if not source.is_file():
            raise FileNotFoundError("SQLite database not found")
        destination = args.backup_file.resolve() if args.backup_file else source.with_name(
            f"{source.name}.migration-006-{stamp()}.bak"
        )
        if destination.exists():
            raise RuntimeError("Refusing to overwrite an existing backup")
        shutil.copy2(source, destination)
        verify_sqlite(destination)
        return destination
    if not args.backup_file:
        raise RuntimeError("--backup-file is required for a database URL")
    backup = args.backup_file.resolve()
    if not backup.is_file() or backup.stat().st_size == 0:
        raise RuntimeError("Database backup is missing or empty")
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        raise RuntimeError("pg_restore is required to verify a PostgreSQL backup")
    check = subprocess.run([pg_restore, "--list", str(backup)], capture_output=True, text=True)
    if check.returncode:
        raise RuntimeError("PostgreSQL backup verification failed")
    return backup


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    if "findings" not in tables:
        return {"table_exists": False, "column_exists": False, "index_exists": False}
    columns = {column["name"] for column in schema.get_columns("findings")}
    indexes = {index["name"] for index in schema.get_indexes("findings")}
    return {
        "table_exists": True,
        "column_exists": "sub_class" in columns,
        "index_exists": "ix_findings_sub_class" in indexes,
    }


def apply(engine) -> None:
    state = inventory(engine)
    if not state["table_exists"]:
        raise RuntimeError("Required table is missing: findings")
    with engine.begin() as connection:
        if not state["column_exists"]:
            connection.execute(text("ALTER TABLE findings ADD COLUMN sub_class VARCHAR(50)"))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_findings_sub_class ON findings (sub_class)"
        ))


def main() -> int:
    args = parse_args()
    engine = create_engine(database_url(args))
    before = inventory(engine)
    if args.dry_run:
        print(json.dumps({"dry_run": True, "before": before}, indent=2, sort_keys=True))
        return 0 if before["table_exists"] else 2
    if not before["table_exists"]:
        raise RuntimeError("Migration blocked: required table is missing: findings")
    if before["column_exists"] and before["index_exists"]:
        print(json.dumps({"changed": False, "before": before}, indent=2, sort_keys=True))
        return 0
    backup = prepare_backup(args)
    apply(engine)
    after = inventory(engine)
    if not after["column_exists"] or not after["index_exists"]:
        raise RuntimeError("Post-migration verification failed; restore the verified backup")
    print(json.dumps({
        "changed": True,
        "backup_verified": True,
        "backup_path": str(backup),
        "before": before,
        "after": after,
        "rollback": "Restore the verified database backup.",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
