#!/usr/bin/env python3
"""Migration 012: Add canonical_cve_id column and foreign key linkage to findings table.

Adds nullable ``canonical_cve_id`` (VARCHAR(32), FK to canonical_vulnerabilities.cve_id, ON DELETE RESTRICT)
with an index on ``canonical_cve_id``.

INVARIANTS:
- Preserves all existing legacy fields (cve, cve_id, cvss, cisa_kev, ransomware, raw_inputs, asset_id, asset_data).
- Zero automated external data fetching.
- Schema migration only; backfill is performed explicitly via backfill command.
- Reversible and idempotent.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path)
    target.add_argument("--database-url")
    target.add_argument("--database-url-env", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
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
    raise RuntimeError("Unable to locate the backend source for migration 012")


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    findings_cols = {col["name"] for col in schema.get_columns("findings")} if "findings" in tables else set()
    indexes = {idx["name"] for idx in schema.get_indexes("findings")} if "findings" in tables else set()
    return {
        "database_engine": engine.dialect.name,
        "findings_exists": "findings" in tables,
        "canonical_vulnerabilities_exists": "canonical_vulnerabilities" in tables,
        "canonical_cve_id_exists": "canonical_cve_id" in findings_cols,
        "canonical_cve_index_exists": "ix_findings_canonical_cve_id" in indexes,
        "schema_complete": "findings" in tables and "canonical_cve_id" in findings_cols,
    }


def migrate(url: str, dry_run: bool = False) -> dict:
    _load_backend()
    from services.database import Base
    import models  # noqa: F401 - registers tables on Base.metadata

    engine = create_engine(url)
    try:
        before = inventory(engine)
        if not before["findings_exists"]:
            raise RuntimeError("Required findings table is missing")

        if dry_run:
            return {
                "before": before,
                "changed": not before["schema_complete"],
                "dry_run": True,
            }

        if not before["canonical_cve_id_exists"]:
            with engine.begin() as conn:
                is_sqlite = engine.dialect.name == "sqlite"
                if is_sqlite:
                    # SQLite supports ADD COLUMN with REFERENCES
                    conn.execute(
                        text(
                            "ALTER TABLE findings ADD COLUMN canonical_cve_id VARCHAR(32) "
                            "REFERENCES canonical_vulnerabilities(cve_id) ON DELETE RESTRICT"
                        )
                    )
                else:
                    # PostgreSQL / standard ANSI SQL
                    conn.execute(
                        text(
                            "ALTER TABLE findings ADD COLUMN canonical_cve_id VARCHAR(32) "
                            "CONSTRAINT fk_findings_canonical_cve REFERENCES canonical_vulnerabilities(cve_id) ON DELETE RESTRICT"
                        )
                    )

        # Ensure index exists
        with engine.begin() as conn:
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_findings_canonical_cve_id ON findings (canonical_cve_id)")
            )

        after = inventory(engine)
        if not after["schema_complete"]:
            raise RuntimeError("Post-migration schema verification failed: canonical_cve_id column missing")

        return {
            "before": before,
            "after": after,
            "changed": not before["schema_complete"],
            "column_added": "canonical_cve_id",
            "rollback": "Remove column canonical_cve_id from findings or restore verified database backup.",
        }
    finally:
        engine.dispose()


def main() -> int:
    args = arguments()
    result = migrate(database_url(args), dry_run=args.dry_run)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
