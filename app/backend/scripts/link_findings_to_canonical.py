#!/usr/bin/env python3
"""CLI utility for linking CVE-bearing Findings to CanonicalVulnerability records.

Usage:
    # Dry run inspection
    python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db --dry-run

    # Live execution across all tenants
    python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db

    # Live execution for a specific tenant
    python app/backend/scripts/link_findings_to_canonical.py --db-path ./tempris.db --tenant-id tenant-1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Link CVE-bearing Findings to CanonicalVulnerability records (idempotent, safe)"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path, help="Path to SQLite database file")
    target.add_argument("--database-url", type=str, help="SQLAlchemy database URL")
    target.add_argument("--database-url-env", action="store_true", help="Read DATABASE_URL from environment")
    parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        help="Optional tenant filter to link findings for a single tenant only",
    )
    parser.add_argument(
        "--no-create-missing",
        action="store_true",
        help="Do not create missing CanonicalVulnerability records (leaves findings unlinked if canonical is absent)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate linkage without committing changes to the database",
    )
    return parser.parse_args()


def database_url(args: argparse.Namespace) -> str:
    if args.database_url:
        return args.database_url
    if args.database_url_env:
        value = os.environ.get("DATABASE_URL", "").strip()
        if not value:
            raise RuntimeError("DATABASE_URL is not configured in environment")
        return value
    return f"sqlite:///{args.db_path.resolve().as_posix()}"


def _load_backend() -> None:
    candidates = [Path.cwd(), *Path(__file__).resolve().parents]
    for candidate in candidates:
        backend = candidate / "app" / "backend"
        if backend.is_dir():
            if str(backend) not in sys.path:
                sys.path.insert(0, str(backend))
            return
        if (candidate / "models.py").is_file():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            return
    raise RuntimeError("Unable to locate backend source directory")


def main() -> int:
    args = arguments()
    _load_backend()

    from services.cve_intelligence import link_findings_to_canonical_cves

    db_url = database_url(args)
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()

    print(f"[*] Target Database : {db_url}")
    print(f"[*] Dry Run Mode    : {args.dry_run}")
    print(f"[*] Tenant Filter   : {args.tenant_id or 'ALL'}")
    print(f"[*] Create Missing  : {not args.no_create_missing}")

    try:
        result = link_findings_to_canonical_cves(
            session,
            dry_run=args.dry_run,
            create_missing_canonical=not args.no_create_missing,
            tenant_id=args.tenant_id,
        )
        print("\n=== Linkage Summary ===")
        print(json.dumps(result, indent=2))
        return 0
    except Exception as ex:
        session.rollback()
        print(f"\n[!] Linkage failed: {ex}", file=sys.stderr)
        return 2
    finally:
        session.close()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
