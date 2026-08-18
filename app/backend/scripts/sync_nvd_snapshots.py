#!/usr/bin/env python3
"""CLI utility for synchronizing vulnerability intelligence snapshots from NIST NVD API 2.0.

Usage examples:
    # 1. Fetch specific CVE IDs to an immutable snapshot file
    python app/backend/scripts/sync_nvd_snapshots.py --output-file ./tmp/nvd_targeted.json --cves CVE-2012-1710 CVE-2021-44228

    # 2. Fetch unassessed canonical CVEs from the database into a snapshot file
    python app/backend/scripts/sync_nvd_snapshots.py --output-file ./tmp/nvd_unassessed.json --db-path ./tempris.db --unassessed-only

    # 3. Ingest the snapshot into the database after inspection
    python app/backend/scripts/import_cve_intelligence.py --source nvd-json --file ./tmp/nvd_targeted.json --db-path ./tempris.db
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.nvd_sync import get_unassessed_canonical_cve_ids, sync_nvd_snapshots


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NVD API 2.0 Snapshot Synchronization Tool (Writes immutable JSON snapshots before ingestion)"
    )
    parser.add_argument(
        "--output-file",
        required=True,
        help="Target path for the immutable local NVD JSON snapshot file",
    )
    parser.add_argument(
        "--cves",
        nargs="+",
        help="One or more specific CVE IDs to fetch (e.g. CVE-2012-1710 CVE-2021-44228)",
    )
    parser.add_argument(
        "--unassessed-only",
        action="store_true",
        help="Query database for CanonicalVulnerability rows lacking CVSS assessments and fetch them",
    )
    parser.add_argument(
        "--db-path",
        help="Path to local SQLite database (required if --unassessed-only is specified)",
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL",
    )
    parser.add_argument(
        "--api-key",
        help="NVD API Key (defaults to NVD_API_KEY environment variable)",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=50,
        help="Number of results per page (default: 50, max: 2000)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        help="Maximum pages to fetch in paginated mode",
    )
    parser.add_argument(
        "--state-file",
        help="Optional state file path to track and resume pagination",
    )
    parser.add_argument(
        "--delay",
        type=float,
        help="Override delay between requests in seconds (default: 0.6s with API key, 6.0s without)",
    )

    args = parser.parse_args()

    cve_list = args.cves or None

    if args.unassessed_only:
        if not args.db_path and not args.database_url:
            print("ERROR: --unassessed-only requires --db-path or --database-url", file=sys.stderr)
            return 1
        db_url = args.database_url or f"sqlite:///{Path(args.db_path).resolve().as_posix()}"
        engine = create_engine(db_url)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        try:
            unassessed = get_unassessed_canonical_cve_ids(session)
            print(f"Found {len(unassessed)} unassessed canonical CVEs in database.")
            cve_list = unassessed
        finally:
            session.close()
            engine.dispose()

        if not cve_list:
            print("No unassessed CVEs found. Nothing to sync.")
            return 0

    print(f"Starting NVD snapshot synchronization -> {args.output_file}")
    try:
        summary = sync_nvd_snapshots(
            output_file=args.output_file,
            cve_ids=cve_list,
            api_key=args.api_key,
            results_per_page=args.results_per_page,
            max_pages=args.max_pages,
            state_file=args.state_file,
            delay_seconds=args.delay,
        )
        print("\n=== NVD Snapshot Sync Succeeded ===")
        print(json.dumps(summary, indent=2))
        return 0
    except Exception as ex:
        print(f"ERROR: NVD snapshot synchronization failed: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
