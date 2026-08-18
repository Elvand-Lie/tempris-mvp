#!/usr/bin/env python3
"""Root CLI entrypoint for linking CVE-bearing Findings to CanonicalVulnerability records."""

from __future__ import annotations

import sys
from pathlib import Path

# Add backend to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "app" / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from scripts.link_findings_to_canonical import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
