"""Server-plane SCOUT Nuclei templates wiring.

The server vantage must fail closed before spawning when
SCOUT_NUCLEI_TEMPLATES_DIR is unset, missing, or template-less, and the
built argv must pin the resolved directory with -t.
"""
from __future__ import annotations

import pytest

from app import config
from app.scout import (
    ScoutTemplatesUnavailable,
    nuclei_argv,
    resolve_scout_nuclei_templates_dir,
)


def test_unset_config_refuses(monkeypatch):
    monkeypatch.setattr(config, "SCOUT_NUCLEI_TEMPLATES_DIR", None)
    with pytest.raises(ScoutTemplatesUnavailable, match="SCOUT_NUCLEI_TEMPLATES_DIR"):
        resolve_scout_nuclei_templates_dir()


def test_missing_directory_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr(
        config, "SCOUT_NUCLEI_TEMPLATES_DIR", str(tmp_path / "does-not-exist")
    )
    with pytest.raises(ScoutTemplatesUnavailable, match="is not"):
        resolve_scout_nuclei_templates_dir()


def test_directory_without_yaml_refuses(monkeypatch, tmp_path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "empty" / "readme.txt").write_text("not a template")
    monkeypatch.setattr(config, "SCOUT_NUCLEI_TEMPLATES_DIR", str(tmp_path / "empty"))
    with pytest.raises(ScoutTemplatesUnavailable, match="no .yaml"):
        resolve_scout_nuclei_templates_dir()


def test_directory_with_nested_yaml_resolves(monkeypatch, tmp_path):
    nested = tmp_path / "http" / "cves"
    nested.mkdir(parents=True)
    (nested / "cve-test.yaml").write_text("id: cve-test\ninfo:\n  name: t\n")
    monkeypatch.setattr(config, "SCOUT_NUCLEI_TEMPLATES_DIR", str(tmp_path))
    assert resolve_scout_nuclei_templates_dir() == str(tmp_path)


def test_nuclei_argv_pins_templates_dir():
    argv = nuclei_argv("/usr/bin/nuclei", "scanme.nmap.org", "/pinned/templates")
    i = argv.index("-t")
    assert argv[i + 1] == "/pinned/templates"
    # target and pinned dir are both present exactly once
    assert argv.count("-t") == 1
    assert argv[argv.index("-target") + 1] == "scanme.nmap.org"
    # normal profile skips informational templates only
    assert argv[argv.index("-severity") + 1] == "low,medium,high,critical"
