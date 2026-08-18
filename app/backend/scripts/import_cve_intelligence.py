#!/usr/bin/env python3
"""CLI utility for explicit offline snapshot ingestion into the canonical CVE spine (Phase 1A).

Usage:
    python import_cve_intelligence.py --source cisa-kev --file data/cisa_kev_2026_05_22.json --db-path ./tempris.db
    python import_cve_intelligence.py --source nvd-json --file data/nvd_fixture.json --database-url sqlite:///./staging.db --dry-run
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explicit offline snapshot importer for canonical vulnerability intelligence"
    )
    parser.add_argument(
        "--source",
        choices=["cisa-kev", "nvd-json"],
        required=True,
        help="Type of snapshot to import",
    )
    parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="Path to the local JSON snapshot file",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--db-path", type=Path, help="Path to SQLite database file")
    target.add_argument("--database-url", type=str, help="SQLAlchemy database URL")
    target.add_argument("--database-url-env", action="store_true", help="Read DATABASE_URL from environment")
    parser.add_argument(
        "--snapshot-id",
        type=str,
        default=None,
        help="Optional explicit snapshot identifier",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate snapshot without writing changes to the database",
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

    from services.cve_intelligence import import_cisa_kev_snapshot, import_nvd_cve_snapshot

    file_path = args.file.resolve()
    if not file_path.is_file():
        print(f"Error: Snapshot file does not exist: {file_path}", file=sys.stderr)
        return 1

    db_url = database_url(args)
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()

    print(f"[*] Target Database : {db_url}")
    print(f"[*] Snapshot File   : {file_path}")
    print(f"[*] Source Type     : {args.source}")
    print(f"[*] Dry Run Mode    : {args.dry_run}")

    try:
        if args.dry_run:
            # Execute inside a transaction that is always rolled back
            if args.source == "cisa-kev":
                result = import_cisa_kev_snapshot(file_path, session, snapshot_id=args.snapshot_id)
            else:
                result = import_nvd_cve_snapshot(file_path, session, snapshot_id=args.snapshot_id)
            session.rollback()
            result["dry_run"] = True
        else:
            if args.source == "cisa-kev":
                result = import_cisa_kev_snapshot(file_path, session, snapshot_id=args.snapshot_id)
            else:
                result = import_nvd_cve_snapshot(file_path, session, snapshot_id=args.snapshot_id)

        print("\n=== Import Summary ===")
        for key, value in sorted(result.items()):
            print(f"  {key:20s}: {value}")
        return 0
    except Exception as ex:
        session.rollback()
        print(f"\n[!] Import failed: {ex}", file=sys.stderr)
        return 2
    finally:
        session.close()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
