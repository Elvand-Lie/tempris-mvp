# backend/app/vuln_intelligence/adapters/epss_adapter.py
"""
FIRST EPSS adapter — parses the actual FIRST bulk CSV format into the repository.

The real FIRST EPSS bulk CSV has:
  - Line 1: metadata comment starting with '#' containing model_version and score_date
    e.g. #model_version:v2024.03.01,score_date:2024-04-15T00:00:00+0000
  - Line 2: CSV header: cve,epss,percentile
  - Lines 3+: data rows

Stores dated EPSS history with score, percentile, model_version, score_date.
"""
from __future__ import annotations

import csv
import io
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Optional, Union

import psycopg

from app.vuln_intelligence.models import (
    EpssScore,
    SourceRecord,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    upsert_source_record,
    upsert_epss_score,
)


class EpssAdapterResult:
    __slots__ = ("total", "stored", "skipped", "errors")

    def __init__(self):
        self.total = 0
        self.stored = 0
        self.skipped = 0
        self.errors: list[str] = []


def _parse_metadata_line(line: str) -> tuple[Optional[str], Optional[date]]:
    """
    Parse the FIRST EPSS metadata comment line.

    Format: #model_version:v2024.03.01,score_date:2024-04-15T00:00:00+0000
    Returns (model_version, score_date) or (None, None) on failure.
    """
    line = line.lstrip("#").strip()
    model_version = None
    score_date = None

    for part in line.split(","):
        part = part.strip()
        if part.startswith("model_version:"):
            model_version = part.split(":", 1)[1].strip()
        elif part.startswith("score_date:"):
            date_str = part.split(":", 1)[1].strip()
            # Parse ISO date, extracting just the date portion
            try:
                # Handle various formats: 2024-04-15T00:00:00+0000
                dt = datetime.fromisoformat(
                    re.sub(r'(\d{2})(\d{2})$', r'\1:\2', date_str)
                    if re.search(r'[+-]\d{4}$', date_str)
                    else date_str
                )
                score_date = dt.date()
            except (ValueError, TypeError):
                # Fallback: try just the date portion
                try:
                    score_date = date.fromisoformat(date_str[:10])
                except (ValueError, TypeError):
                    pass

    return model_version, score_date


def process_epss_csv(
    conn: psycopg.Connection,
    csv_text: str,
    *,
    snapshot_id: Optional[str] = None,
) -> EpssAdapterResult:
    """
    Parse FIRST EPSS bulk CSV and store all scores.

    Accepts the raw CSV text including the metadata comment header line.
    Returns EpssAdapterResult with counts.
    """
    result = EpssAdapterResult()

    lines = csv_text.strip().split("\n")
    if not lines:
        result.errors.append("Empty CSV")
        return result

    # Parse metadata from first comment line
    model_version = None
    score_date = None
    data_start = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            model_version, score_date = _parse_metadata_line(stripped)
            data_start = i + 1
        else:
            break

    if score_date is None:
        result.errors.append("Missing score_date in metadata header")
        return result

    # Create a single source record for the entire EPSS bulk file
    bulk_payload = {"model_version": model_version, "score_date": str(score_date), "format": "FIRST_EPSS_CSV"}
    src_rec, is_new = upsert_source_record(conn, SourceRecord(
        source="epss",
        source_id=f"epss-{score_date.isoformat()}",
        content_hash=content_hash(csv_text),
        raw_payload=bulk_payload,
        snapshot_id=snapshot_id,
    ))

    if not is_new:
        # Identical EPSS file already processed
        return result

    # Parse CSV data (skip metadata lines)
    data_text = "\n".join(lines[data_start:])
    reader = csv.DictReader(io.StringIO(data_text))

    for row in reader:
        result.total += 1
        cve_id = row.get("cve", "").strip()
        if not validate_cve_id(cve_id):
            result.errors.append(f"Invalid CVE ID: {cve_id!r}")
            result.skipped += 1
            continue

        try:
            epss_score = Decimal(row.get("epss", "0").strip())
            percentile = Decimal(row.get("percentile", "0").strip())
        except Exception as e:
            result.errors.append(f"{cve_id}: bad numeric: {e}")
            result.skipped += 1
            continue

        upsert_epss_score(conn, EpssScore(
            cve_id=cve_id,
            score=epss_score,
            percentile=percentile,
            model_version=model_version,
            score_date=score_date,
            source_record_id=src_rec.id,
        ))
        result.stored += 1

    return result


def process_epss_record(
    conn: psycopg.Connection,
    record: Union[dict, str],
    *,
    snapshot_id: Optional[str] = None,
) -> tuple[bool, bool, Optional[str]]:
    """
    Process a single EPSS record (dict or line) or full CSV string.
    Returns (success, is_new, error_message).
    """
    if isinstance(record, str):
        res = process_epss_csv(conn, record, snapshot_id=snapshot_id)
        if res.errors:
            return res.stored > 0, res.stored > 0, "; ".join(res.errors[:5])
        return True, res.stored > 0, None

    if isinstance(record, dict):
        raw_line = record.get("raw_line")
        model_version = record.get("model_version")
        score_date_raw = record.get("score_date")

        if score_date_raw:
            try:
                score_date = date.fromisoformat(str(score_date_raw)[:10])
            except (ValueError, TypeError):
                score_date = date.today()
        else:
            score_date = date.today()

        if raw_line:
            parts = [p.strip() for p in raw_line.split(",")]
            if len(parts) >= 3:
                cve_id, score_str, perc_str = parts[0], parts[1], parts[2]
            else:
                return False, False, f"Invalid EPSS line format: {raw_line!r}"
        else:
            cve_id = record.get("cve_id") or record.get("cve", "")
            score_str = str(record.get("score", "0"))
            perc_str = str(record.get("percentile", "0"))

        if not validate_cve_id(cve_id):
            return False, False, f"Invalid CVE ID: {cve_id!r}"

        try:
            score = Decimal(score_str)
            percentile = Decimal(perc_str)
        except Exception as e:
            return False, False, f"Invalid score or percentile for {cve_id}: {e}"

        src_rec, is_new = upsert_source_record(conn, SourceRecord(
            source="epss",
            source_id=f"epss-{cve_id}-{score_date.isoformat()}",
            content_hash=content_hash({
                "cve_id": cve_id,
                "score": str(score),
                "percentile": str(percentile),
                "score_date": str(score_date),
            }),
            raw_payload={
                "cve": cve_id,
                "epss": str(score),
                "percentile": str(percentile),
                "score_date": str(score_date),
                "model_version": model_version,
            },
            snapshot_id=snapshot_id,
        ))

        upsert_epss_score(conn, EpssScore(
            cve_id=cve_id,
            score=score,
            percentile=percentile,
            model_version=model_version,
            score_date=score_date,
            source_record_id=src_rec.id,
        ))

        return True, is_new, None

    return False, False, f"Unsupported EPSS record type: {type(record)}"

