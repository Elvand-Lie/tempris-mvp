# backend/tests_unit/test_nuclei_parse_repair.py
"""Regression tests for Nuclei JSONL ingestion: real-world lines whose string
values carry JSON-breaking content must be recovered and counted, never
silently discarded — a 0-parsed result must not masquerade as a clean scan."""
import json

from app.scout import parse_nuclei_jsonl_with_stats


def _event(template_id="weak-csp-detect", **extra):
    event = {
        "template-id": template_id,
        "matcher-name": "true",
        "type": "http",
        "host": "192.168.18.1",
        "matched-at": "http://192.168.18.1/",
        "info": {"name": "Weak CSP", "severity": "info"},
    }
    event.update(extra)
    return event


def test_valid_lines_parse_without_repair():
    payload = "\n".join(json.dumps(_event()) for _ in range(3)).encode()
    observations, stats = parse_nuclei_jsonl_with_stats(payload)
    assert stats["total_lines"] == 3
    assert stats["parsed_lines"] == 3
    assert stats["repaired_lines"] == 0
    assert stats["skipped_lines"] == 0
    assert len(observations) == 3


def test_invalid_unicode_escape_is_repaired_not_skipped():
    # A matched URL carrying an invalid \uXXXX escape (documented real-world case)
    line = json.dumps(_event()).replace("192.168.18.1/", "host/\\uZZ99path")
    observations, stats = parse_nuclei_jsonl_with_stats(line.encode())
    assert stats["total_lines"] == 1
    assert stats["parsed_lines"] == 1
    assert stats["repaired_lines"] == 1
    assert stats["skipped_lines"] == 0
    assert observations[0][0] == "template_match"
    assert observations[0][1]["event"]["template-id"] == "weak-csp-detect"


def test_raw_control_character_in_string_is_repaired():
    # Raw tab and BEL bytes inside a string value (not \r\n — those split the
    # JSONL line itself before parsing and are a transport-level failure).
    raw = '{"template-id":"xss-deprecated-header","response":"HTTP/1.1 200 OK\tBody\x07tail","info":{"severity":"info"}}'
    observations, stats = parse_nuclei_jsonl_with_stats(raw.encode())
    assert stats["parsed_lines"] == 1
    assert stats["repaired_lines"] == 1
    assert observations[0][1]["event"]["template-id"] == "xss-deprecated-header"


def test_generic_non_cve_match_persists_as_template_observation():
    payload = json.dumps(_event("http-missing-security-headers")).encode()
    observations, _ = parse_nuclei_jsonl_with_stats(payload)
    assert observations and observations[0][1]["event"]["template-id"] == "http-missing-security-headers"


def test_unrepairable_garbage_is_counted_skipped():
    observations, stats = parse_nuclei_jsonl_with_stats(b"{not json at all\n[1,2\n\"bare string\"")
    assert stats["total_lines"] == 3
    assert stats["parsed_lines"] == 0
    assert stats["repaired_lines"] == 0
    assert stats["skipped_lines"] == 3
    assert observations == []


def test_mixed_payload_counts_are_truthful():
    good = json.dumps(_event())
    broken_escape = json.dumps(_event("addeventlistener-detect")).replace("192.168.18.1/", "h/\\uQQ11")
    garbage = "{oops"
    observations, stats = parse_nuclei_jsonl_with_stats("\n".join([good, broken_escape, garbage]).encode())
    assert stats == {
        "total_lines": 3,
        "parsed_lines": 2,
        "repaired_lines": 1,
        "skipped_lines": 1,
    }
    assert len(observations) == 2


def test_bom_prefixed_line_parses():
    payload = ("﻿" + json.dumps(_event())).encode("utf-8")
    observations, stats = parse_nuclei_jsonl_with_stats(payload)
    assert stats["parsed_lines"] == 1
    assert observations
