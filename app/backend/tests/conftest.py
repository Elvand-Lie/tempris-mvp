'''Shared test collection configuration.'''

import os
import sys
import tempfile
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

TEST_ROOT = Path(tempfile.mkdtemp(prefix='tempris-pytest-'))
os.environ['DATABASE_URL'] = 'sqlite:///' + (TEST_ROOT / 'tempris.db').as_posix()
os.environ['EVIDENCE_STORAGE_ROOT'] = str(TEST_ROOT / 'evidence')
os.environ.setdefault('ENVIRONMENT', 'test')
os.environ.setdefault('AUDIT_HMAC_KEY', 'test_audit_hmac_secret_key_12345678')

# Create a clean schema before test modules import global sessions or the app.
from services.database import Base, engine
import models  # noqa: F401

Base.metadata.create_all(bind=engine)


CORE_DEFAULT_FILES = {
    "test_synthesis_semantics.py",
    "test_assets_crud_contract.py",
    "test_scout_spectrum_authoritative_hardening.py",
    "test_scout_canonical.py",
    "test_cve_intelligence.py",
    "test_cve_intelligence_resolver.py",
    "test_cve_tes_live_context.py",
    "test_tenant_administration.py",
    "test_spa_bootstrap.py",
    "test_vdp_site_hardening.py",
    "test_nginx_auth_rate_limit.py",
    "test_reports.py",
    "test_blflaw.py",
    "test_ciso_grc_tenant.py",
    "test_speak_harden.py",
    "test_grc_sss_canonicalization.py",
    "test_intake_canonical_linkage.py",
    "test_generic_findings.py",
}


def pytest_addoption(parser):
    parser.addoption(
        "--run-e2e", action="store_true", default=False, help="run browser e2e tests"
    )
    parser.addoption(
        "--run-all", action="store_true", default=False, help="run all non-e2e test suites"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: mark test as browser end-to-end test")
    config.addinivalue_line("markers", "slow: mark test as slow running test")


def pytest_collection_modifyitems(config, items):
    run_all = bool(config.getoption("--run-all", False))
    run_e2e = bool(config.getoption("--run-e2e", False))
    marker_expr = config.getoption("-m") or ""
    has_m_e2e = "e2e" in marker_expr

    explicit_file_targets = {
        Path(arg.split("::")[0]).name
        for arg in config.args
        if arg.endswith(".py") or ".py::" in arg
    }

    selected = []
    deselected = []

    for item in items:
        item_file = getattr(item, "path", None)
        item_filename = item_file.name if item_file else Path(str(item.fspath)).name

        is_e2e = "e2e" in item.keywords or item_filename == "test_scout_browser_e2e.py"
        is_explicit = (
            item_filename in explicit_file_targets
            or any(item_filename in str(arg) for arg in config.args)
        )
        is_core = item_filename in CORE_DEFAULT_FILES

        if is_e2e:
            should_run = run_e2e or has_m_e2e or is_explicit
        else:
            should_run = is_core or run_all or is_explicit

        if should_run:
            selected.append(item)
        else:
            deselected.append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected
