# backend/app/vuln_intelligence/cli.py
"""
CLI/service entry points for vulnerability intelligence synchronization.

Provides:
  - bootstrap: full initial sync for one or all sources
  - sync: incremental sync for one or all sources
  - health: display per-source health state
  - schedule: configure scheduling

Suitable for manual invocation, cron, fixture evaluation, and later
Sprint 04 bounded live evidence.

Usage:
  python -m app.vuln_intelligence.cli bootstrap [--source cve]
  python -m app.vuln_intelligence.cli sync [--source kev]
  python -m app.vuln_intelligence.cli health
  python -m app.vuln_intelligence.cli schedule --source cve --enable --interval 1200
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from app.db import get_db_connection, init_db, close_db
from app.vuln_intelligence.sync_engine import (
    sync_source,
    get_source_health,
    get_all_source_health,
    get_schedule_config,
    set_schedule_config,
)
from app.vuln_intelligence.sync_adapters import ALL_ADAPTERS, get_adapter


def cmd_bootstrap(source: Optional[str] = None) -> int:
    """Run full bootstrap sync for one or all sources."""
    sources = [source] if source else list(ALL_ADAPTERS.keys())
    exit_code = 0
    for src in sources:
        adapter = get_adapter(src)
        if adapter is None:
            print(f"Unknown source: {src}", file=sys.stderr)
            exit_code = 1
            continue
        print(f"Bootstrap sync: {src}...")
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)
        _print_outcome(outcome)
        if not outcome.success:
            exit_code = 1
    return exit_code


def cmd_sync(source: Optional[str] = None) -> int:
    """Run incremental sync for one or all sources."""
    sources = [source] if source else list(ALL_ADAPTERS.keys())
    exit_code = 0
    for src in sources:
        adapter = get_adapter(src)
        if adapter is None:
            print(f"Unknown source: {src}", file=sys.stderr)
            exit_code = 1
            continue
        print(f"Sync: {src}...")
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)
        _print_outcome(outcome)
        if not outcome.success:
            exit_code = 1
    return exit_code


def cmd_health(source: Optional[str] = None) -> int:
    """Display per-source health state."""
    with get_db_connection() as conn:
        if source:
            health = get_source_health(conn, source)
            if health is None:
                print(f"Unknown source: {source}", file=sys.stderr)
                return 1
            _print_health(health)
        else:
            all_health = get_all_source_health(conn)
            for h in all_health:
                _print_health(h)
                print()
    return 0


def cmd_schedule(
    source: str,
    enable: Optional[bool] = None,
    interval: Optional[int] = None,
) -> int:
    """Configure scheduling for a source."""
    with get_db_connection() as conn:
        if enable is not None or interval is not None:
            set_schedule_config(conn, source, enabled=enable, interval_seconds=interval)
            conn.commit()
            print(f"Schedule updated for {source}")
        config = get_schedule_config(conn, source)
        print(f"  enabled: {config['enabled']}")
        print(f"  interval_seconds: {config['interval_seconds']}")
        if config.get('next_sync_at'):
            print(f"  next_sync_at: {config['next_sync_at']}")
    return 0


def _print_outcome(outcome) -> None:
    """Print sync outcome summary."""
    status = "✓" if outcome.success else "✗"
    if outcome.skipped_overlap:
        status = "⊘ (overlap)"
    print(f"  [{status}] {outcome.source} ({outcome.sync_mode})")
    print(f"    processed: {outcome.records_processed}")
    print(f"    created: {outcome.records_created}")
    print(f"    unchanged: {outcome.records_unchanged}")
    print(f"    failed: {outcome.records_failed}")
    print(f"    duration: {outcome.duration_ms}ms")
    if outcome.cursor_after:
        print(f"    cursor: {outcome.cursor_before} → {outcome.cursor_after}")
    if outcome.error:
        print(f"    error: {outcome.error}")


def _print_health(health) -> None:
    """Print source health summary."""
    icon = "🟢" if health.is_healthy else "🔴"
    print(f"{icon} {health.source}")
    print(f"  healthy: {health.is_healthy}")
    print(f"  last_attempted: {health.last_attempted_at or 'never'}")
    print(f"  last_success: {health.last_successful_at or 'never'}")
    print(f"  consecutive_failures: {health.consecutive_failures}")
    print(f"  cursor: {health.cursor_value or 'none'}")
    print(f"  active_records: {health.active_record_count}")
    if health.data_age_seconds is not None:
        print(f"  data_age: {health.data_age_seconds}s")
    if health.last_error:
        print(f"  last_error: {health.last_error}")
    print(f"  schedule: {'enabled' if health.sync_enabled else 'disabled'}"
          f" (interval: {health.sync_interval_seconds or 'default'}s)")


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Tempris V2 Vulnerability Intelligence Sync CLI"
    )
    sub = parser.add_subparsers(dest="command")

    # bootstrap
    p_boot = sub.add_parser("bootstrap", help="Full bootstrap sync")
    p_boot.add_argument("--source", choices=list(ALL_ADAPTERS.keys()))

    # sync
    p_sync = sub.add_parser("sync", help="Incremental sync")
    p_sync.add_argument("--source", choices=list(ALL_ADAPTERS.keys()))

    # health
    p_health = sub.add_parser("health", help="Display source health")
    p_health.add_argument("--source", choices=list(ALL_ADAPTERS.keys()))

    # schedule
    p_sched = sub.add_parser("schedule", help="Configure scheduling")
    p_sched.add_argument("--source", required=True, choices=list(ALL_ADAPTERS.keys()))
    p_sched.add_argument("--enable", action="store_true", default=None)
    p_sched.add_argument("--disable", action="store_true", default=None)
    p_sched.add_argument("--interval", type=int)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    init_db()
    try:
        if args.command == "bootstrap":
            return cmd_bootstrap(args.source)
        elif args.command == "sync":
            return cmd_sync(args.source)
        elif args.command == "health":
            return cmd_health(args.source)
        elif args.command == "schedule":
            enable = True if args.enable else (False if args.disable else None)
            return cmd_schedule(args.source, enable=enable, interval=args.interval)
    finally:
        close_db()

    return 0


if __name__ == "__main__":
    sys.exit(main())
