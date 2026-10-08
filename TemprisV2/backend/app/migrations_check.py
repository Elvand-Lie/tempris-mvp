# backend/app/migrations_check.py
"""Startup migration gate for the V2 ASSETS service.

The service must not accept traffic against a schema it cannot prove is
current. This module is therefore FAIL-CLOSED: any failure to apply or verify
migrations raises ``MigrationCheckError`` and aborts application startup,
instead of the previous behaviour of printing a warning and continuing.

Two distinct guarantees are enforced, in order:

1. *Application* — every migration file shipped with this build is applied
   (delegated to ``migrations.runner.run_migrations``).
2. *Verification* — after applying, the ``schema_migrations`` ledger is
   re-read and must contain every shipped migration version. This catches a
   partially applied migration, a silently skipped file, and a schema that
   was provisioned outside the ledger.

A release must be able to assert the same guarantees without starting the
service, so ``pending_migrations`` is exported for the release script's
read-only preflight and for post-deploy verification.
"""

import importlib
import sys
from pathlib import Path
from typing import Iterable, List, Optional

from app.db import get_db_connection

__all__ = [
    "MigrationCheckError",
    "available_migration_versions",
    "ensure_migrations_applied",
    "pending_migrations",
]


class MigrationCheckError(RuntimeError):
    """The applied database schema could not be proven current. Fail closed."""


def _load_migrations_runner():
    """Resolve the ``migrations.runner`` module across the supported layouts.

    The backend is importable as the top-level package ``migrations`` when the
    backend directory is on ``sys.path`` (the PM2 layout, where ``PYTHONPATH``
    points at the release's ``backend``) and as ``backend.migrations`` in other
    layouts. The final fallback adds the backend directory explicitly, matching
    the historical behaviour so no supported layout regresses.
    """
    errors = []
    for module_name in ("migrations.runner", "backend.migrations.runner"):
        try:
            return importlib.import_module(module_name)
        except ImportError as exc:  # pragma: no cover - layout dependent
            errors.append(f"{module_name}: {exc}")

    backend_dir = str(Path(__file__).resolve().parent.parent)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    try:
        return importlib.import_module("migrations.runner")
    except ImportError as exc:
        raise MigrationCheckError(
            "Unable to import migrations.runner; the migration ledger cannot "
            "be applied or verified. Attempts: " + "; ".join(errors + [f"migrations.runner: {exc}"])
        ) from exc


def available_migration_versions(migrations_dir: Optional[Path] = None) -> List[str]:
    """Every migration version shipped with this build, sorted."""
    if migrations_dir is None:
        migrations_dir = Path(_load_migrations_runner().MIGRATIONS_DIR)
    return sorted(path.name for path in Path(migrations_dir).glob("*.sql"))


def _applied_migration_versions(conn) -> set:
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM schema_migrations;")
        rows = cur.fetchall()
    return {row["version"] if isinstance(row, dict) else row[0] for row in rows}


def pending_migrations(conn, migrations_dir: Optional[Path] = None) -> List[str]:
    """Shipped migration versions not recorded as applied.

    Read-only: this inspects ``schema_migrations`` and never applies anything,
    so it is safe to call from a preflight against production.
    """
    applied = _applied_migration_versions(conn)
    return [version for version in available_migration_versions(migrations_dir) if version not in applied]


def _describe(pending: Iterable[str], prefix: str) -> str:
    pending = list(pending)
    preview = ", ".join(pending[:5])
    if len(pending) > 5:
        preview += f", ... (+{len(pending) - 5} more)"
    return f"{prefix} {len(pending)} pending migration(s): {preview}"


def ensure_migrations_applied() -> None:
    """Apply and verify migrations, or abort startup.

    Raises ``MigrationCheckError`` — and therefore fails application startup —
    when the runner cannot be imported, when a migration fails, or when the
    ledger still reports pending migrations afterwards.
    """
    runner = _load_migrations_runner()

    try:
        with get_db_connection() as conn:
            runner.run_migrations(conn)
            pending = pending_migrations(conn, Path(runner.MIGRATIONS_DIR))
    except MigrationCheckError:
        raise
    except Exception as exc:
        raise MigrationCheckError(
            f"Migration application failed; refusing to start against an unverified schema: {exc!r}"
        ) from exc

    if pending:
        raise MigrationCheckError(
            _describe(
                pending,
                "Schema verification failed after applying migrations; refusing to start:",
            )
        )