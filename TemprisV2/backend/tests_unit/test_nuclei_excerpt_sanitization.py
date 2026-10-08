# backend/tests_unit/test_nuclei_excerpt_sanitization.py
"""The sanitized diagnostic excerpt must keep match URLs readable (analysts
must be able to see where a detection occurred) while still redacting
filesystem paths and secrets."""
from app.scout import _sanitize_nuclei_stdout


def test_match_urls_stay_readable():
    line = '{"template-id":"weak-csp-detect","host":"192.168.18.1","matched-at":"http://192.168.18.1/login.css?c804c4d65178d00553184798","info":{"severity":"info"}}'
    out = _sanitize_nuclei_stdout(line)
    assert "http://192.168.18.1/login.css?c804c4d65178d00553184798" in out
    assert "[REDACTED" not in out


def test_url_with_system_path_segment_stays_readable():
    line = '{"matched-at":"https://host.example.test/var/www/index.html"}'
    out = _sanitize_nuclei_stdout(line)
    assert "https://host.example.test/var/www/index.html" in out


def test_windows_and_unix_paths_are_redacted():
    line = '"template-path":"C:\\\\tools\\\\nuclei-templates\\\\ssl\\\\weak-csp.yaml" home:/home/collector/x.yaml'
    out = _sanitize_nuclei_stdout(line)
    assert "C:\\tools" not in out
    assert "/home/collector" not in out
    assert "[REDACTED_PATH]" in out


def test_secrets_are_redacted_but_host_survives():
    line = (
        '{"matched-at":"http://192.168.18.1/","request":"GET / HTTP/1.1"}\n'
        'Authorization: Bearer abc.def.ghi\n'
    )
    out = _sanitize_nuclei_stdout(line)
    assert "http://192.168.18.1/" in out
    assert "abc.def.ghi" not in out
    assert "Authorization: [REDACTED]" in out
