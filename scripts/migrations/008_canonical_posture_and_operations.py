#!/usr/bin/env python3
"""Add canonical posture, scan-run, incident, telemetry, and lifecycle storage.

The migration preserves ``findings.asset_id`` exactly as recorded. It never
creates confirmed ``AssetExposure`` rows from legacy pointers. PostgreSQL
deployments must supply an externally verified backup before any change.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


_MIGRATION_PATH = Path(__file__).resolve()
# A guarded release mounts this file at /migrations/<name>.  That path has
# fewer parents than the repository copy, so deriving parents[2] directly can
# fail before /staged is considered.
LOCAL_ROOT = _MIGRATION_PATH.parents[2] if len(_MIGRATION_PATH.parents) > 2 else Path("/")
REQUIRED_TABLES = {
    "findings",
    "assets",
    "scan_findings",
    "strike_authorizations",
    "strike_simulations",
    "grc_policy_documents",
}
NEW_TABLES = {"asset_exposures", "scan_jobs", "posture_snapshots", "incidents", "operational_events"}
REQUIRED_COLUMNS = {
    "strike_simulations": {"tenant_id"},
    "scan_findings": {
        "template_id",
        "cve_id",
        "matched_at",
        "raw_result_hash",
        "normalized_finding_id",
        "evidence_metadata",
        "first_seen_at",
        "last_seen_at",
    },
    "grc_policy_documents": {
        "archived_at",
        "archived_by",
        "supersedes_id",
        "superseded_by_id",
        "deleted_at",
    },
    "asset_exposures": {"evidence_metadata"},
}
REQUIRED_INDEXES = {
    "strike_simulations": {"ix_strike_simulations_tenant_id"},
    "scan_findings": {
        "ix_scan_findings_template_id",
        "ix_scan_findings_cve_id",
        "ix_scan_findings_normalized_finding_id",
    },
    "asset_exposures": {"ix_asset_exposures_tenant_status"},
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path)
    target.add_argument("--database-url")
    target.add_argument("--database-url-env", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backup-file", type=Path)
    parser.add_argument("--externally-verified-backup", action="store_true")
    parser.add_argument("--report-file", type=Path)
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


def prepare_backup(args: argparse.Namespace) -> Path:
    if args.db_path:
        source = args.db_path.resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        backup = args.backup_file.resolve() if args.backup_file else source.with_name(
            f"{source.name}.migration-008-{_stamp()}.bak"
        )
        if backup.exists():
            raise RuntimeError("Refusing to overwrite an existing backup")
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, backup)
        _verify_sqlite(backup)
        return backup

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


def _load_model_metadata():
    candidates = (LOCAL_ROOT / "app" / "backend", Path.cwd(), Path("/app"), Path("/staged"))
    for candidate in candidates:
        if (candidate / "models.py").is_file():
            path = str(candidate.resolve())
            if path not in sys.path:
                sys.path.insert(0, path)
            break
    else:
        raise RuntimeError("Canonical backend model source is unavailable")
    import models  # noqa: F401
    from services.database import Base

    return Base


def _strike_backfill_blockers(engine) -> list[str]:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    if not {"strike_authorizations", "strike_simulations"}.issubset(tables):
        return []
    auth_columns = {column["name"] for column in schema.get_columns("strike_authorizations")}
    sim_columns = {column["name"] for column in schema.get_columns("strike_simulations")}
    blockers = []
    if "tenant_id" not in auth_columns:
        blockers.append("strike_authorizations.tenant_id is missing")
        return blockers
    if "authorization_id" not in sim_columns:
        blockers.append("strike_simulations.authorization_id is missing")
        return blockers
    with engine.connect() as connection:
        orphaned = int(connection.execute(text(
            "SELECT COUNT(*) FROM strike_simulations s "
            "LEFT JOIN strike_authorizations a ON a.id = s.authorization_id "
            "WHERE a.id IS NULL OR a.tenant_id IS NULL OR TRIM(a.tenant_id) = ''"
        )).scalar_one())
        if orphaned:
            blockers.append(
                f"{orphaned} STRIKE simulation(s) have no tenant-owned authorization; ownership cannot be inferred"
            )
    return blockers


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    columns = {
        table: sorted(column["name"] for column in schema.get_columns(table))
        for table in tables
    }
    indexes = {
        table: sorted(index["name"] for index in schema.get_indexes(table) if index.get("name"))
        for table in tables
    }
    unique_constraints = {
        table: sorted(
            constraint["name"] for constraint in schema.get_unique_constraints(table)
            if constraint.get("name")
        )
        for table in tables
    }
    return {
        "database_engine": engine.dialect.name,
        "tables": sorted(tables),
        "columns": columns,
        "indexes": indexes,
        "unique_constraints": unique_constraints,
        "strike_backfill_blockers": _strike_backfill_blockers(engine),
    }


def _schema_complete(state: dict) -> bool:
    tables = set(state["tables"])
    if not NEW_TABLES.issubset(tables) or state["strike_backfill_blockers"]:
        return False
    for table, required in REQUIRED_COLUMNS.items():
        if not required.issubset(set(state["columns"].get(table, []))):
            return False
    for table, required in REQUIRED_INDEXES.items():
        if not required.issubset(set(state["indexes"].get(table, []))):
            return False
    return (
        "uq_asset_exposure_tenant_finding_asset"
        in state["unique_constraints"].get("asset_exposures", [])
        and "uq_incident_external_event" in state["unique_constraints"].get("incidents", [])
    )


def _add_columns(connection, schema, table: str, columns: dict[str, str]) -> None:
    existing = {column["name"] for column in schema.get_columns(table)}
    for name, declaration in columns.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}"))


def _apply(engine) -> None:
    Base = _load_model_metadata()
    Base.metadata.tables["asset_exposures"].create(engine, checkfirst=True)
    schema = inspect(engine)
    with engine.begin() as connection:
        _add_columns(connection, schema, "strike_simulations", {"tenant_id": "VARCHAR(50)"})
        _add_columns(connection, schema, "scan_findings", {
            "template_id": "VARCHAR(255)",
            "cve_id": "VARCHAR(50)",
            "matched_at": "VARCHAR(500)",
            "raw_result_hash": "VARCHAR(64)",
            "normalized_finding_id": "VARCHAR(50)",
            "evidence_metadata": "JSON",
            "first_seen_at": "TIMESTAMP",
            "last_seen_at": "TIMESTAMP",
        })
        _add_columns(connection, schema, "grc_policy_documents", {
            "archived_at": "TIMESTAMP",
            "archived_by": "VARCHAR(255)",
            "supersedes_id": "VARCHAR(80)",
            "superseded_by_id": "VARCHAR(80)",
            "deleted_at": "TIMESTAMP",
        })
        _add_columns(connection, schema, "asset_exposures", {"evidence_metadata": "JSON"})
        connection.execute(text(
            "UPDATE strike_simulations SET tenant_id = ("
            "SELECT tenant_id FROM strike_authorizations "
            "WHERE strike_authorizations.id = strike_simulations.authorization_id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_strike_simulations_tenant_id "
            "ON strike_simulations (tenant_id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_scan_findings_template_id ON scan_findings (template_id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_scan_findings_cve_id ON scan_findings (cve_id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_scan_findings_normalized_finding_id "
            "ON scan_findings (normalized_finding_id)"
        ))
        if engine.dialect.name == "postgresql":
            connection.execute(text(
                "ALTER TABLE strike_simulations ALTER COLUMN tenant_id SET NOT NULL"
            ))

    for table_name in ("scan_jobs", "posture_snapshots", "incidents", "operational_events"):
        Base.metadata.tables[table_name].create(engine, checkfirst=True)


def migrate(url: str, dry_run: bool = False) -> dict:
    engine = create_engine(url)
    try:
        before = inventory(engine)
        missing = REQUIRED_TABLES - set(before["tables"])
        blockers = list(before["strike_backfill_blockers"])
        if missing:
            blockers.append(f"Required existing tables are missing: {', '.join(sorted(missing))}")
        if blockers:
            raise RuntimeError("; ".join(blockers))
        if dry_run:
            return {"dry_run": True, "before": before, "changed": False}
        if _schema_complete(before):
            return {"changed": False, "before": before, "after": before}

        _apply(engine)
        after = inventory(engine)
        if not _schema_complete(after):
            raise RuntimeError("Post-migration schema verification failed; restore the verified backup")
        return {
            "changed": True,
            "before": before,
            "after": after,
            "legacy_asset_links_promoted": 0,
            "rollback": "Restore the verified database backup.",
        }
    finally:
        engine.dispose()


def _write_report(path: Path | None, report: dict) -> None:
    if not path:
        return
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = arguments()
    url = database_url(args)
    dry_run_result = migrate(url, dry_run=True)
    if args.dry_run:
        dry_run_result["schema_complete"] = _schema_complete(dry_run_result["before"])
        _write_report(args.report_file, dry_run_result)
        print(json.dumps(dry_run_result, indent=2, sort_keys=True))
        return 0 if dry_run_result["schema_complete"] else 2
    if _schema_complete(dry_run_result["before"]):
        result = {"changed": False, "before": dry_run_result["before"]}
        _write_report(args.report_file, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    backup = prepare_backup(args)
    result = migrate(url, dry_run=False)
    result["backup_verified"] = True
    result["backup_path"] = str(backup)
    _write_report(args.report_file, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
