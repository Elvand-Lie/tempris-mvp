#!/usr/bin/env python3
"""Add additive current-CVE context storage without changing legacy score inputs."""

from __future__ import annotations

import argparse
import os
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


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    columns = {column["name"] for column in schema.get_columns("findings")} if "findings" in tables else set()
    return {
        "database_engine": engine.dialect.name,
        "findings_exists": "findings" in tables,
        "cve_context_exists": "cve_context" in columns,
        "schema_complete": "findings" in tables and "cve_context" in columns,
    }


def migrate(url: str, dry_run: bool = False) -> dict:
    engine = create_engine(url)
    try:
        before = inventory(engine)
        if not before["findings_exists"]:
            raise RuntimeError("Required findings table is missing")
        if dry_run or before["schema_complete"]:
            return {"changed": False, "before": before, "after": before}
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE findings ADD COLUMN cve_context JSON"))
        after = inventory(engine)
        if not after["schema_complete"]:
            raise RuntimeError("Post-migration schema verification failed")
        return {
            "changed": True,
            "before": before,
            "after": after,
            "legacy_asset_links_promoted": 0,
            "rollback": "Restore the verified database backup.",
        }
    finally:
        engine.dispose()


def main() -> int:
    args = arguments()
    print(migrate(database_url(args), dry_run=args.dry_run))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
