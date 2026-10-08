# backend/tests_unit/test_migrations_check_fail_closed.py
"""Startup migration gate must FAIL CLOSED (database-free half).

The defect this pins: ``app.migrations_check.ensure_migrations_applied`` used to
catch every exception, ``print`` a warning, and return normally. A release could
therefore start the V2 service against a schema whose migrations had NOT been
applied or could not be applied at all — the process reports healthy while every
route that touches a missing table fails at request time. A migration that
silently does not run is indistinguishable from one that ran, so the release
step could not assert anything either.

The contract now: the gate either proves the shipped migrations are applied, or
it raises ``MigrationCheckError`` and aborts startup. Three failure modes are
pinned, because each was previously swallowed:

  1. the runner itself raises while applying;
  2. the runner cannot even be imported (``ModuleNotFoundError``);
  3. applying "succeeds" but the ledger still reports pending migrations.

``pending_migrations`` is additionally pinned as READ-ONLY — the release
preflight calls it against production, so it must never apply anything.

Purity: ``app.migrations_check`` imports ``app.db`` (hence ``psycopg``), so it is
imported LAZILY inside ``migrations_check_module`` and every added sys.modules
entry is removed afterwards. The TES kernel purity guard
(``test_unit_suite_never_imports_db_or_app_machinery``) asserts a clean
sys.modules and must hold in any run order.
"""
import contextlib
import importlib
import os
import sys
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# app.config refuses to import without these; they are never used for I/O here.
_TEST_DATABASE_URL = "postgresql://migrations_check:migrations_check@127.0.0.1:1/migrations_check"
_TEST_JWT_SECRET = "migrations-check-unit-test-secret-value-0123456789"


class _FakeCursor:
    """Minimal cursor whose only job is to answer the ledger read."""

    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._conn.executed.append(" ".join(str(sql).split()))

    def fetchall(self):
        # dict_row is the production row factory; tuple rows are also handled.
        return [(version,) for version in sorted(self._conn.applied)]


class _FakeConnection:
    def __init__(self, applied=(), apply_versions=()):
        self.applied = set(applied)
        self._apply_versions = tuple(apply_versions)
        self.executed = []

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.executed.append("COMMIT")

    def apply(self, versions):
        """Stand in for a successful migration run."""
        self.applied.update(versions)


class _FakeRunner:
    """Stand-in for ``migrations.runner`` with an injectable failure mode."""

    def __init__(self, migrations_dir, apply_versions=(), raises=None):
        self.MIGRATIONS_DIR = Path(migrations_dir)
        self._apply_versions = tuple(apply_versions)
        self._raises = raises
        self.run_migrations_calls = 0

    def run_migrations(self, conn):
        self.run_migrations_calls += 1
        if self._raises is not None:
            raise self._raises
        conn.apply(self._apply_versions)


@pytest.fixture(scope="module")
def migrations_check_module():
    """Import ``app.migrations_check`` lazily, then revert sys.modules to its
    exact pre-import state (including app.db, psycopg, psycopg_pool, ...)."""
    before = set(sys.modules)
    saved_env = {key: os.environ.get(key) for key in ("DATABASE_URL", "JWT_SECRET")}
    os.environ["DATABASE_URL"] = _TEST_DATABASE_URL
    os.environ["JWT_SECRET"] = _TEST_JWT_SECRET
    try:
        module = importlib.import_module("app.migrations_check")
    finally:
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    added = set(sys.modules) - before
    yield module
    for name in added:
        sys.modules.pop(name, None)


def _shipped_migrations(tmp_path, names=("001_a.sql", "002_b.sql")):
    """A temp ``migrations`` directory holding the named .sql files."""
    for name in names:
        (tmp_path / name).write_text("SELECT 1;\n", encoding="utf-8")
    return tmp_path


def _install(monkeypatch, module, conn, runner):
    """Point the gate at fake connection/runner collaborators."""
    @contextlib.contextmanager
    def fake_get_db_connection():
        yield conn

    monkeypatch.setattr(module, "get_db_connection", fake_get_db_connection)
    monkeypatch.setattr(module, "_load_migrations_runner", lambda: runner)


def test_all_migrations_applied_starts_normally(monkeypatch, migrations_check_module, tmp_path):
    module = migrations_check_module
    directory = _shipped_migrations(tmp_path)
    versions = [path.name for path in sorted(directory.glob("*.sql"))]
    conn = _FakeConnection()
    runner = _FakeRunner(directory, apply_versions=versions)
    _install(monkeypatch, module, conn, runner)

    # No exception: the schema is proven current, so startup proceeds.
    assert module.ensure_migrations_applied() is None
    assert runner.run_migrations_calls == 1
    assert conn.applied == set(versions)


def test_applying_then_still_pending_migrations_fails_closed(monkeypatch, migrations_check_module, tmp_path):
    """The runner reports success but the ledger is not current — the exact
    condition a partially/silently applied migration produces."""
    module = migrations_check_module
    directory = _shipped_migrations(tmp_path)
    conn = _FakeConnection()
    runner = _FakeRunner(directory, apply_versions=())  # applies nothing
    _install(monkeypatch, module, conn, runner)

    with pytest.raises(module.MigrationCheckError) as excinfo:
        module.ensure_migrations_applied()

    message = str(excinfo.value)
    assert "verification failed" in message
    # The operator must be told WHICH migrations are pending.
    assert "001_a.sql" in message and "002_b.sql" in message


def test_runner_raising_fails_closed(monkeypatch, migrations_check_module, tmp_path):
    """A migration error must abort startup, not be printed and ignored."""
    module = migrations_check_module
    directory = _shipped_migrations(tmp_path)
    conn = _FakeConnection()
    runner = _FakeRunner(directory, raises=RuntimeError("duplicate column \"foo\""))
    _install(monkeypatch, module, conn, runner)

    with pytest.raises(module.MigrationCheckError) as excinfo:
        module.ensure_migrations_applied()

    message = str(excinfo.value)
    assert "Migration application failed" in message
    # The underlying cause is preserved for diagnosis, and the gate is a
    # RuntimeError subclass so a bare `except Exception` cannot mask it.
    assert "duplicate column" in message
    assert isinstance(excinfo.value, RuntimeError)
    assert isinstance(excinfo.value.__cause__, RuntimeError)


def test_unimportable_runner_fails_closed(monkeypatch, migrations_check_module):
    """If the ledger cannot even be located, the schema cannot be verified."""
    module = migrations_check_module

    class _BrokenImportlib:
        @staticmethod
        def import_module(name):
            raise ImportError(f"no module named {name!r}")

    monkeypatch.setattr(module, "importlib", _BrokenImportlib)

    with pytest.raises(module.MigrationCheckError) as excinfo:
        module.ensure_migrations_applied()

    assert "migrations.runner" in str(excinfo.value)


def test_pending_migrations_is_read_only(monkeypatch, migrations_check_module, tmp_path):
    """The release preflight calls this against production: it must only read."""
    module = migrations_check_module
    directory = _shipped_migrations(tmp_path)
    conn = _FakeConnection(applied=("001_a.sql",))
    runner = _FakeRunner(directory, apply_versions=("001_a.sql", "002_b.sql"))
    _install(monkeypatch, module, conn, runner)

    pending = module.pending_migrations(conn, directory)

    assert pending == ["002_b.sql"]
    assert runner.run_migrations_calls == 0
    assert all("INSERT" not in statement.upper() for statement in conn.executed)
    assert all("CREATE" not in statement.upper() for statement in conn.executed)


def test_shipped_migrations_are_visible_to_the_gate(migrations_check_module):
    """The real layout resolves: the gate sees every shipped .sql migration.

    If this regresses, the startup gate and the release preflight silently stop
    covering the migration set (the original defect's blast radius).
    """
    module = migrations_check_module
    versions = module.available_migration_versions()

    assert versions == sorted(versions), "migration order must be deterministic"
    assert "004_tenancy_and_auth_foundation.sql" in versions
    assert "005_module_catalogue_and_entitlements.sql" in versions
    assert len(versions) >= 39
    # No rollback/sidecar scripts may leak into the ledger set.
    assert all(version.endswith(".sql") for version in versions)


def test_startup_hook_no_longer_swallows_errors(migrations_check_module):
    """Source-level regression guard against reintroducing fail-open."""
    module = migrations_check_module
    source = Path(module.__file__).read_text(encoding="utf-8")

    assert "Warning: automatic migrations check" not in source
    # The gate must raise; a bare `except Exception: pass`/print pattern is the
    # regression this file exists to prevent.
    assert "raise MigrationCheckError(" in source