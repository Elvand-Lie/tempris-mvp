# backend/app/speak/render.py
"""
Sealing + deterministic artifact rendering for SPEAK reports (Ch.11).

Every artifact is rendered FROM the sealed payload — never from live state —
so historical rendering is byte-stable and a regenerated upstream value can
never reach an already-generated report (that is what sealing is for).

The v1 templates are the built-in registry below (versioned constants): one
template per renderable report type. Template management UI is an OPEN PRD
decision; until it exists there is exactly one honest template per type.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from decimal import Decimal
from typing import Any

# Template identity carried on every report row (frozen decisions: reports
# are template-identified and versioned).
BUILTIN_TEMPLATES: dict[str, dict[str, Any]] = {
    "executive_summary": {
        "template_id": "builtin.executive_summary",
        "template_version": 1,
        "sections": [
            "severe_exposures",
            "workflow_posture",
            "coverage_quality",
            "remediation_posture",
            "accepted_risk_register",
            "regulatory_pressure",
        ],
    },
    "exposure_register": {
        "template_id": "builtin.exposure_register",
        "template_version": 1,
        "sections": ["exposures"],
    },
}

MAX_ARTIFACT_BYTES = 4 * 1024 * 1024  # mirrors the migration's size bound


# ---------------------------------------------------------------------------
# Canonicalization + sealing
# ---------------------------------------------------------------------------


def canonical_json(payload: Any) -> str:
    """Byte-stable canonical JSON: sorted keys, compact separators, the
    Decimal wire tags rendered verbatim (payloads are JSON-wire form by the
    time they reach the renderer)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def decimal_text(value: Any) -> str:
    """A Decimal wire tag or raw value → plain text for tabular rendering."""
    if value is None:
        return ""
    if isinstance(value, dict) and "__decimal__" in value:
        return str(value["__decimal__"])
    if isinstance(value, Decimal):
        return str(value)
    return str(value)


# ---------------------------------------------------------------------------
# Spreadsheet-formula injection guard (the V1 engine's rule, kept)
# ---------------------------------------------------------------------------

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value: Any) -> str:
    """Neutralize spreadsheet-formula injection: a cell whose text could be
    interpreted as a formula by a spreadsheet application is prefixed with a
    single quote. The V1 reporting engine shipped this guard; it stays."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


# ---------------------------------------------------------------------------
# Renderers — deterministic functions (sealed payload) → bytes
# ---------------------------------------------------------------------------


def _rows_for_report(report_type: str, payload: dict) -> tuple[list[str], list[list[Any]]]:
    """Flatten a sealed payload into (header, rows) for tabular output."""
    if report_type == "exposure_register":
        header = [
            "exposure_id", "finding_id", "asset_id", "canonical_cve_id",
            "finding_title", "finding_severity", "asset_name",
            "tes_state", "tes_value", "formula_version", "as_of",
        ]
        rows = [
            [
                e.get("exposure_id"),
                e.get("finding_id"),
                e.get("asset_id"),
                e.get("canonical_cve_id"),
                e.get("finding_title"),
                e.get("finding_severity"),
                e.get("asset_name"),
                e.get("tes", {}).get("state"),
                decimal_text(e.get("tes", {}).get("value")),
                e.get("tes", {}).get("formula_version"),
                payload.get("as_of"),
            ]
            for e in payload.get("exposures", [])
        ]
        return header, rows

    if report_type == "executive_summary":
        header = ["metric", "value"]
        severe = payload.get("severe_exposures", {})
        workflow = payload.get("workflow_posture", {})
        coverage = payload.get("coverage_quality", {})
        rows = [
            ["as_of", payload.get("as_of")],
            ["authority", payload.get("authority")],
            ["total_current_exposures", severe.get("total_current_exposures")],
            ["final_count", severe.get("final_count")],
            ["provisional_count", severe.get("provisional_count")],
            ["unscoreable_count", severe.get("unscoreable_count")],
            ["max_final_tes", decimal_text(severe.get("max_final_tes"))],
            ["max_provisional_tes", decimal_text(severe.get("max_provisional_tes"))],
            ["severe_count", severe.get("severe_count")],
            ["workflow_action_required", workflow.get("analysis_state_action_required")],
            ["workflow_open_edip_handoffs", workflow.get("open_edip_handoffs")],
            ["feeds_healthy", coverage.get("feeds_healthy")],
            ["feeds_stale", coverage.get("feeds_stale")],
            ["feeds_unknown", coverage.get("feeds_unknown")],
        ]
        return header, rows

    raise ValueError(f"unrenderable report type {report_type!r}")


def render_json(report_type: str, payload: dict) -> bytes:
    """The canonical JSON artifact: exactly the sealed payload bytes the
    content_hash binds."""
    return canonical_json(payload).encode("utf-8")


def render_csv(report_type: str, payload: dict) -> bytes:
    header, rows = _rows_for_report(report_type, payload)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow([csv_safe_cell(h) for h in header])
    for row in rows:
        writer.writerow([csv_safe_cell(cell) for cell in row])
    return buffer.getvalue().encode("utf-8")


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _decision_tile_summary(name: str, section: dict) -> str:
    """The one-line render of a wired decision-domain tile (the counts come
    from the sealed payload — this adds no numbers of its own)."""
    if name == "remediation_posture":
        return (
            f"{section.get('total_current_decisions')} current decisions; "
            f"{section.get('overdue_open')} overdue; "
            f"{section.get('review_expired')} past review"
        )
    if name == "accepted_risk_register":
        return (
            f"{section.get('register_count')} accepted/deferred dispositions"
        )
    return (
        f"{section.get('total_obligations')} obligations; "
        f"{section.get('overdue')} overdue; "
        f"{section.get('breached_recorded')} breached"
    )


def render_html(report_type: str, payload: dict, title: str) -> bytes:
    """Minimal, self-contained HTML rendered from the sealed payload. Every
    value is escaped; unavailable sections render 'unavailable', never a
    fabricated zero."""
    header, rows = _rows_for_report(report_type, payload)
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>{_esc(title)}</title>",
        "</head><body>",
        f"<h1>{_esc(title)}</h1>",
        f"<p>Report type: {_esc(report_type)}; as_of: {_esc(payload.get('as_of'))}; "
        f"authority: {_esc(payload.get('authority'))} (derived read-only projection; "
        "never a source of record)</p>",
        "<table border='1' cellpadding='4' cellspacing='0'>",
        "<thead><tr>",
        "".join(f"<th>{_esc(h)}</th>" for h in header),
        "</tr></thead><tbody>",
    ]
    for row in rows:
        parts.append("<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in row) + "</tr>")
    parts.append("</tbody></table>")

    if report_type == "executive_summary":
        parts.append("<h2>Severe exposures (drill-down identities)</h2>")
        parts.append("<table border='1' cellpadding='4' cellspacing='0'>")
        parts.append(
            "<thead><tr><th>exposure_id</th><th>finding_id</th>"
            "<th>asset_id</th><th>state</th><th>value</th><th>reason</th></tr></thead>"
        )
        parts.append("<tbody>")
        for item in payload.get("severe_exposures", {}).get("severe_exposures", []):
            parts.append(
                "<tr>"
                f"<td>{_esc(item.get('exposure_id'))}</td>"
                f"<td>{_esc(item.get('finding_id'))}</td>"
                f"<td>{_esc(item.get('asset_id'))}</td>"
                f"<td>{_esc(item.get('tes_state'))}</td>"
                f"<td>{_esc(decimal_text(item.get('value')))}</td>"
                f"<td>{_esc(item.get('reason'))}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    for name in ("remediation_posture", "accepted_risk_register",
                 "regulatory_pressure"):
        section = payload.get(name)
        if not isinstance(section, dict):
            continue
        if section.get("status") == "unavailable":
            parts.append(
                f"<p><strong>{_esc(name)}</strong>: unavailable "
                f"({_esc(section.get('reason'))}) — no value is rendered, "
                "because none is known.</p>"
            )
        elif section.get("status") == "ok":
            parts.append(
                f"<p><strong>{_esc(name)}</strong>: "
                f"{_esc(_decision_tile_summary(name, section))}</p>"
            )

    parts.append("</body></html>")
    return "".join(parts).encode("utf-8")


def render_artifacts(
    report_type: str, payload: dict, title: str
) -> dict[str, bytes]:
    """All three v1 artifacts rendered from one sealed payload. The caller
    verifies each stays inside the bounded size before publishing."""
    return {
        "json": render_json(report_type, payload),
        "csv": render_csv(report_type, payload),
        "html": render_html(report_type, payload, title),
    }
