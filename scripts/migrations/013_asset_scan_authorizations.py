#!/usr/bin/env python3
"""Migration 013: Add AssetScanAuthorization table and ScanJob target provenance fields.

Adds:
- Table ``asset_scan_authorizations`` for platform-approved scan authorizations.
- Additive columns to ``scan_jobs`` for immutable target execution provenance:
  - asset_id (VARCHAR(50), nullable)
  - scan_authorization_id (VARCHAR(50), nullable)
  - authorized_canonical_target (VARCHAR(500), nullable)
  - target_kind (VARCHAR(50), nullable)
  - resolved_ips (JSON, nullable)
  - dns_resolved_at (DATETIME, nullable)
  - initiating_user_id (VARCHAR(255), nullable)
  - execution_origin (VARCHAR(255), nullable)
  - failure_reason (TEXT, nullable)

INVARIANTS:
- Preserves all historical ScanJobs and ScanFindings.
- Does NOT silently approve any existing Asset (all existing assets default to unauthorized).
- Reversible, dry-runnable, and idempotent across SQLite and PostgreSQL.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


REQUIRED_TABLE = "asset_scan_authorizations"
SCAN_JOB_COLUMNS = {
    "asset_id": "VARCHAR(50)",
    "scan_authorization_id": "VARCHAR(50)",
    "authorized_canonical_target": "VARCHAR(500)",
    "target_kind": "VARCHAR(50)",
    "resolved_ips": "JSON",
    "dns_resolved_at": "DATETIME",
    "initiating_user_id": "VARCHAR(255)",
    "execution_origin": "VARCHAR(255)",
    "failure_reason": "TEXT",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path)
    target.add_argument("--database-url")
    target.add_argument("--database-url-env", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--rollback", action="store_true")
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


def _load_backend() -> None:
    candidates = [Path.cwd(), *Path(__file__).resolve().parents]
    for candidate in candidates:
        backend = candidate / "app" / "backend"
        if backend.is_dir():
            sys.path.insert(0, str(backend))
            return
        if (candidate / "models.py").is_file():
            sys.path.insert(0, str(candidate))
            return
    raise RuntimeError("Unable to locate the backend source for migration 013")


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    scan_job_cols = {col["name"] for col in schema.get_columns("scan_jobs")} if "scan_jobs" in tables else set()
    auth_table_exists = REQUIRED_TABLE in tables
    missing_cols = [col for col in SCAN_JOB_COLUMNS if col not in scan_job_cols]
    return {
        "database_engine": engine.dialect.name,
        "scan_jobs_exists": "scan_jobs" in tables,
        "asset_scan_authorizations_exists": auth_table_exists,
        "scan_jobs_columns_present": sorted(scan_job_cols.intersection(SCAN_JOB_COLUMNS.keys())),
        "scan_jobs_columns_missing": sorted(missing_cols),
        "schema_complete": auth_table_exists and not missing_cols,
    }


def migrate(url: str, dry_run: bool = False, rollback: bool = False) -> dict:
    _load_backend()
    from services.database import Base
    import models  # noqa: F401 - registers tables on Base.metadata

    engine = create_engine(url)
    try:
        before = inventory(engine)
        if not before["scan_jobs_exists"]:
            raise RuntimeError("Required scan_jobs table is missing")

        if rollback:
            if dry_run:
                return {"before": before, "action": "rollback", "dry_run": True}
            with engine.begin() as conn:
                if before["asset_scan_authorizations_exists"]:
                    conn.execute(text(f"DROP TABLE {REQUIRED_TABLE}"))
            after = inventory(engine)
            return {"before": before, "after": after, "action": "rollback_completed"}

        if dry_run:
            return {
                "before": before,
                "changed": not before["schema_complete"],
                "dry_run": True,
            }

        # 1. Create asset_scan_authorizations table if not present
        if not before["asset_scan_authorizations_exists"]:
            if REQUIRED_TABLE in Base.metadata.tables:
                Base.metadata.tables[REQUIRED_TABLE].create(engine, checkfirst=True)
            else:
                raise RuntimeError(f"Table definition for '{REQUIRED_TABLE}' not found in Base.metadata")

        # 2. Add missing columns to scan_jobs
        is_postgres = engine.dialect.name == "postgresql"
        with engine.begin() as conn:
            for col, col_type in SCAN_JOB_COLUMNS.items():
                if col in before["scan_jobs_columns_missing"]:
                    type_str = col_type
                    if col_type == "JSON" and is_postgres:
                        type_str = "JSONB"
                    elif col_type == "DATETIME" and is_postgres:
                        type_str = "TIMESTAMP WITH TIME ZONE"
                    conn.execute(text(f"ALTER TABLE scan_jobs ADD COLUMN {col} {type_str}"))

        # 3. Verify indexes
        with engine.begin() as conn:
            try:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_jobs_asset_id ON scan_jobs (asset_id)"))
            except Exception:
                pass
            try:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_jobs_auth_id ON scan_jobs (scan_authorization_id)"))
            except Exception:
                pass

        after = inventory(engine)
        if not after["schema_complete"]:
            raise RuntimeError("Post-migration schema verification failed: schema incomplete")

        return {
            "before": before,
            "after": after,
            "changed": not before["schema_complete"],
            "table_created": REQUIRED_TABLE if not before["asset_scan_authorizations_exists"] else None,
            "columns_added": before["scan_jobs_columns_missing"],
        }
    finally:
        engine.dispose()


def main() -> int:
    args = arguments()
    result = migrate(
        database_url(args),
        dry_run=args.dry_run,
        rollback=args.rollback,
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
