#!/usr/bin/env python3
"""Create canonical GRC framework/control storage and preserve legacy SOP state."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker


REQUIRED_TABLES = {
    "framework_definitions", "framework_controls", "control_assessments", "policy_control_links",
}


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
    root = Path(__file__).resolve().parents[2]
    backend = root / "app" / "backend"
    if not backend.is_dir():
        backend = Path.cwd()
    sys.path.insert(0, str(backend))


def inventory(engine) -> dict:
    schema = inspect(engine)
    tables = set(schema.get_table_names())
    return {
        "database_engine": engine.dialect.name,
        "tables": sorted(tables),
        "schema_complete": REQUIRED_TABLES.issubset(tables),
    }


def migrate(url: str, dry_run: bool = False) -> dict:
    _load_backend()
    from models import GrcPolicyDocument, GrcState, Tenant
    from services.database import Base
    from services.grc_framework import ensure_framework_catalog, ensure_tenant_assessments

    engine = create_engine(url)
    try:
        before = inventory(engine)
        if dry_run:
            return {"before": before, "changed": not before["schema_complete"]}
        for table in REQUIRED_TABLES:
            Base.metadata.tables[table].create(engine, checkfirst=True)
        Session = sessionmaker(bind=engine)
        db = Session()
        try:
            ensure_framework_catalog(db)
            tenant_ids = {row[0] for row in db.query(Tenant.id).all()}
            tenant_ids.update(row[0] for row in db.query(GrcState.tenant_id).distinct().all())
            tenant_ids.update(row[0] for row in db.query(GrcPolicyDocument.tenant_id).distinct().all())
            for tenant_id in sorted(value for value in tenant_ids if value):
                ensure_tenant_assessments(db, tenant_id, actor="migration-009")
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        after = inventory(engine)
        if not after["schema_complete"]:
            raise RuntimeError("Post-migration schema verification failed")
        return {"before": before, "after": after, "changed": not before["schema_complete"]}
    finally:
        engine.dispose()


def main() -> int:
    args = arguments()
    result = migrate(database_url(args), dry_run=args.dry_run)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
