#!/usr/bin/env python3
"""Create the tenant registry and add entitlement concurrency versions."""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


EXPLICIT_TENANTS = {"tempris", "bug-bounty"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path)
    target.add_argument("--database-url")
    target.add_argument("--database-url-env", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backup-file", type=Path)
    parser.add_argument("--externally-verified-backup", action="store_true")
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
            f"{source.name}.migration-007-{stamp()}.bak"
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
    if args.externally_verified_backup:
        return backup
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        raise RuntimeError("pg_restore is required to verify a PostgreSQL backup")
    check = subprocess.run([pg_restore, "--list", str(backup)], capture_output=True, text=True)
    if check.returncode:
        raise RuntimeError("PostgreSQL backup verification failed")
    return backup


def _tenant_ids(engine) -> set[str]:
    schema = inspect(engine)
    values = set(EXPLICIT_TENANTS)
    with engine.connect() as connection:
        for table in schema.get_table_names():
            columns = {column["name"] for column in schema.get_columns(table)}
            if "tenant_id" not in columns:
                continue
            quoted = schema.dialect.identifier_preparer.quote(table)
            rows = connection.execute(text(
                f"SELECT DISTINCT tenant_id FROM {quoted} "
                "WHERE tenant_id IS NOT NULL AND tenant_id <> ''"
            ))
            values.update(str(row[0]).strip() for row in rows if row[0] and str(row[0]).strip())
    return values


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    package_columns = (
        {column["name"] for column in schema.get_columns("tenant_packages")}
        if "tenant_packages" in tables else set()
    )
    tenant_columns = (
        {column["name"] for column in schema.get_columns("tenants")}
        if "tenants" in tables else set()
    )
    registry_count = 0
    if "tenants" in tables:
        with engine.connect() as connection:
            registry_count = int(connection.execute(text("SELECT COUNT(*) FROM tenants")).scalar() or 0)
    return {
        "tenant_packages_exists": "tenant_packages" in tables,
        "tenant_registry_exists": "tenants" in tables,
        "tenant_registry_columns": sorted(tenant_columns),
        "package_version_exists": "version" in package_columns,
        "registry_count": registry_count,
        "discovered_tenant_ids": sorted(_tenant_ids(engine)),
    }


def _display_name(tenant_id: str) -> str:
    if tenant_id == "tempris":
        return "Tempris Platform"
    if tenant_id == "bug-bounty":
        return "Bug Bounty Research"
    return tenant_id.replace("-", " ").replace("_", " ").title()


def _tenant_type(tenant_id: str) -> str:
    if tenant_id == "tempris":
        return "platform"
    if tenant_id == "bug-bounty":
        return "research"
    return "customer"


def apply(engine) -> None:
    before = inventory(engine)
    if not before["tenant_packages_exists"]:
        raise RuntimeError("Required table is missing: tenant_packages")
    tenant_ids = set(before["discovered_tenant_ids"])
    with engine.begin() as connection:
        if not before["tenant_registry_exists"]:
            connection.execute(text(
                "CREATE TABLE tenants ("
                "id VARCHAR(50) PRIMARY KEY, "
                "display_name VARCHAR(255) NOT NULL, "
                "tenant_type VARCHAR(30) NOT NULL DEFAULT 'customer', "
                "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            ))
            connection.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_tenants_tenant_type ON tenants (tenant_type)"
            ))
        if not before["package_version_exists"]:
            connection.execute(text(
                "ALTER TABLE tenant_packages ADD COLUMN version INTEGER NOT NULL DEFAULT 1"
            ))
        existing = {
            str(row[0]) for row in connection.execute(text("SELECT id FROM tenants"))
        }
        for tenant_id in sorted(tenant_ids - existing):
            connection.execute(text(
                "INSERT INTO tenants (id, display_name, tenant_type) "
                "VALUES (:id, :display_name, :tenant_type)"
            ), {
                "id": tenant_id,
                "display_name": _display_name(tenant_id),
                "tenant_type": _tenant_type(tenant_id),
            })


def main() -> int:
    args = parse_args()
    engine = create_engine(database_url(args))
    before = inventory(engine)
    blockers = [] if before["tenant_packages_exists"] else ["required table is missing: tenant_packages"]
    if args.dry_run:
        print(json.dumps({"dry_run": True, "before": before, "blockers": blockers}, indent=2, sort_keys=True))
        return 2 if blockers else 0
    if blockers:
        raise RuntimeError("Migration blocked: " + "; ".join(blockers))
    complete = before["tenant_registry_exists"] and before["package_version_exists"] and set(
        before["discovered_tenant_ids"]
    ).issubset(set(_registered_ids(engine)))
    if complete:
        print(json.dumps({"changed": False, "before": before}, indent=2, sort_keys=True))
        return 0
    backup = prepare_backup(args)
    apply(engine)
    after = inventory(engine)
    registered = set(_registered_ids(engine))
    if not after["tenant_registry_exists"] or not after["package_version_exists"]:
        raise RuntimeError("Post-migration schema verification failed; restore the verified backup")
    if not set(after["discovered_tenant_ids"]).issubset(registered):
        raise RuntimeError("Post-migration tenant backfill verification failed; restore the verified backup")
    print(json.dumps({
        "changed": True,
        "backup_verified": True,
        "backup_path": str(backup),
        "before": before,
        "after": after,
        "rollback": "Restore the verified database backup.",
    }, indent=2, sort_keys=True))
    return 0


def _registered_ids(engine) -> list[str]:
    if "tenants" not in inspect(engine).get_table_names():
        return []
    with engine.connect() as connection:
        return [str(row[0]) for row in connection.execute(text("SELECT id FROM tenants"))]


if __name__ == "__main__":
    raise SystemExit(main())
