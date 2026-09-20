# backend/app/ciso/service.py
"""
Service layer for the SPOTLIGHT executive view (PRD-000 v1.11 Ch.10).

Design rules implemented here (each is binding Ch.10 text):

1. Severe-exposure visibility is COUNT + MAX based. Every tile aggregates
   current exposures with maxima and counts — never a mean. The V1
   ``aggregate_tes`` arithmetic mean is the named anti-pattern and is retired.
2. No tenant-wide risk index. Nothing in the payload composes tenant state
   into one authoritative-looking number.
3. Trends read this module's own append-only snapshots; deltas are computed
   BETWEEN snapshots, never fabricated.
4. Every number links to the authoritative objects that produced it:
   severe-exposure rows and the snapshot's ``source_refs`` carry upstream
   identities (exposure id + row version, feed snapshot ids) — drill-down is
   identity, not copy.
5. "Unavailable ≠ zero": an upstream domain that is not present renders its
   tile with ``status: "unavailable"`` and a reason — never a zero, which
   would read as "no severe exposures" / "no overdue obligations". A missing
   domain is LOUD, not silent (the Ch.12 degrade-loudly rule, shared).

Transaction contract (the PATCH-13 read shape reused): the caller establishes
ONE REPEATABLE READ boundary BEFORE the first query and captures one
``as_of``; every read below shares that snapshot, so a summary is one
coherent source view. Snapshot capture writes only ``posture_snapshots`` and
one audited event — never upstream state.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.exceptions import ExposureConflictError
from app.exposure.tes_read_model import _jsonify, get_exposure_tes
from app.ciso.errors import SnapshotNotFoundError

# Deterministic severe threshold: a FINAL or PROVISIONAL exposure at or above
# this TES is "severe" (the executive attention set). The definition travels
# with every payload (metric_definitions).
SEVERE_TES_THRESHOLD = Decimal("8.0")

# Defensive bound on the per-tenant current-exposure scan. A tenant above the
# cap gets a truncated flag on the tile — the summary never silently covers a
# subset (truncation must be visible, same honesty rule as a missing domain).
MAX_EXPOSURES_SCANNED = 2000

# Drill-down identity bound for the severe set (newest-severe first).
MAX_SEVERE_IDENTITIES = 25

SNAPSHOT_LIST_LIMIT = 100

# The upstream domains whose tiles need Chapters 8/9 (not part of the
# integrated Ch.1-7 baseline this build runs on). They render UNAVAILABLE —
# the PRD's fail-closed rendering rule — until their domains land; a zero
# would read as "no accepted risks" / "no overdue obligations".
DOMAIN_UNAVAILABLE = {
    "edip": "chapter8_edip_domain_not_present",
    "standard": "chapter9_standard_domain_not_present",
}


def _canonical_payload_json(payload: dict) -> str:
    """The canonical JSON string a snapshot's payload_hash is computed over:
    the JSON-wire form (Decimal-tagged) with sorted keys — byte-stable for
    identical payloads, so the hash binds exactly what was sealed."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _hash_payload(payload: dict) -> str:
    return hashlib.sha256(
        _canonical_payload_json(payload).encode("utf-8")
    ).hexdigest()


def _unavailable(reason: str) -> dict:
    return {"status": "unavailable", "reason": reason}


def _tile_ok(**metrics) -> dict:
    return {"status": "ok", **metrics}


# ---------------------------------------------------------------------------
# Inputs: current exposures (read-through recompute, Ch.3 authority)
# ---------------------------------------------------------------------------


def _current_exposure_rows(
    cur: psycopg.Cursor, tenant_id: uuid.UUID
) -> list[dict]:
    """Every CURRENT confirmed episode on an ACTIVE asset (the Ch.3/Ch.7
    currentness rule), oldest-last. The cap is defensive and visible."""
    cur.execute(
        """
        SELECT e.id AS exposure_id, e.finding_id, e.asset_id,
               e.confirmed_at, e.xmin::text AS exposure_version,
               f.canonical_cve_id
        FROM asset_exposures e
        JOIN assets a
          ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
        JOIN findings f
          ON f.tenant_id = e.tenant_id AND f.id = e.finding_id
        WHERE e.tenant_id = %s AND e.status = 'confirmed'
        ORDER BY e.confirmed_at ASC, e.id ASC
        LIMIT %s;
        """,
        (str(tenant_id), MAX_EXPOSURES_SCANNED + 1),
    )
    return cur.fetchall()


def _severe_exposures_tile(
    conn: psycopg.Connection, tenant_id: uuid.UUID, as_of: datetime
) -> tuple[dict, list[dict]]:
    """The severe-exposure tile: counts and maxima by score state over the
    tenant's current exposures (read-through recompute — no stored score is
    consulted because none exists). Returns (tile, source_refs)."""
    with conn.cursor(row_factory=dict_row) as cur:
        rows = _current_exposure_rows(cur, tenant_id)

    truncated = len(rows) > MAX_EXPOSURES_SCANNED
    rows = rows[:MAX_EXPOSURES_SCANNED]

    max_final: Optional[Decimal] = None
    max_provisional: Optional[Decimal] = None
    final_count = provisional_count = unscoreable_count = 0
    severe: list[dict] = []
    source_refs: list[dict] = []

    for row in rows:
        exposure_id = row["exposure_id"]
        tes = get_exposure_tes(conn, tenant_id, exposure_id, as_of=as_of)
        state = tes["state"]
        value = tes["value"]
        source_refs.append({
            "exposure_id": str(exposure_id),
            "exposure_version": row["exposure_version"],
            "finding_id": str(row["finding_id"]),
            "asset_id": str(row["asset_id"]),
            "tes_state": state,
        })
        if state == "FINAL":
            final_count += 1
            if value is not None and (max_final is None or value > max_final):
                max_final = value
        elif state == "PROVISIONAL":
            provisional_count += 1
            if value is not None and (
                max_provisional is None or value > max_provisional
            ):
                max_provisional = value
        else:
            unscoreable_count += 1
            # UNSCOREABLE is counted and visible, never hidden (Ch.3/Ch.7).
            severe.append({
                "exposure_id": str(exposure_id),
                "finding_id": str(row["finding_id"]),
                "asset_id": str(row["asset_id"]),
                "tes_state": state,
                "value": None,
                "reason": "unscoreable",
            })
            continue
        if value is not None and value >= SEVERE_TES_THRESHOLD:
            severe.append({
                "exposure_id": str(exposure_id),
                "finding_id": str(row["finding_id"]),
                "asset_id": str(row["asset_id"]),
                "tes_state": state,
                "value": {"__decimal__": str(value)},
                "reason": None,
            })

    # newest-severe first, numerically (UNSIGNED_DECIMALS may exceed 9.99, so
    # the sort key is the Decimal, never its string form)
    severe.sort(
        key=lambda r: (
            Decimal(r["value"]["__decimal__"]) if r["value"] else Decimal("-1"),
            r["exposure_id"],
        ),
        reverse=True,
    )

    tile = _tile_ok(
        total_current_exposures=len(rows),
        scan_truncated=truncated,
        final_count=final_count,
        provisional_count=provisional_count,
        unscoreable_count=unscoreable_count,
        # The two maxima are the tile's severity facts — final and
        # provisional NEVER combine and are NEVER averaged (Ch.3 no-blending,
        # display-binding).
        max_final_tes=({"__decimal__": str(max_final)} if max_final is not None else None),
        max_provisional_tes=(
            {"__decimal__": str(max_provisional)}
            if max_provisional is not None
            else None
        ),
        severe_threshold={"__decimal__": str(SEVERE_TES_THRESHOLD)},
        severe_count=len(severe),
        severe_exposures=severe[:MAX_SEVERE_IDENTITIES],
    )
    return tile, source_refs


# ---------------------------------------------------------------------------
# Inputs: workflow state (Ch.7), feed health (Ch.1)
# ---------------------------------------------------------------------------


def _workflow_posture_tile(cur: psycopg.Cursor, tenant_id: uuid.UUID) -> dict:
    """The Ch.7 workbench posture, read-through: analysis_state counts
    (default 'new' before any action), unassigned, and open EDIP handoffs.
    Ch.7 state is workflow truth; this tile never mutates it."""
    cur.execute(
        """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE COALESCE(w.analysis_state, 'new') = 'new') AS new_count,
            COUNT(*) FILTER (WHERE COALESCE(w.analysis_state, 'new') = 'assigned') AS assigned_count,
            COUNT(*) FILTER (WHERE COALESCE(w.analysis_state, 'new') = 'in_analysis') AS in_analysis_count,
            COUNT(*) FILTER (WHERE COALESCE(w.analysis_state, 'new') = 'action_required') AS action_required_count,
            COUNT(*) FILTER (WHERE w.assigned_to IS NULL) AS unassigned_count
        FROM asset_exposures e
        JOIN assets a
          ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
        LEFT JOIN spectrum_exposure_workflow w
          ON w.tenant_id = e.tenant_id AND w.exposure_id = e.id
        WHERE e.tenant_id = %s AND e.status = 'confirmed';
        """,
        (str(tenant_id),),
    )
    counts = cur.fetchone()

    cur.execute(
        """
        SELECT COUNT(*) AS open_handoffs
        FROM spectrum_edip_handoffs h
        WHERE h.tenant_id = %s AND h.state = 'NEEDS_DECISION';
        """,
        (str(tenant_id),),
    )
    open_handoffs = cur.fetchone()["open_handoffs"]

    return _tile_ok(
        current_exposures=counts["total"],
        analysis_state_new=counts["new_count"],
        analysis_state_assigned=counts["assigned_count"],
        analysis_state_in_analysis=counts["in_analysis_count"],
        analysis_state_action_required=counts["action_required_count"],
        unassigned=counts["unassigned_count"],
        open_edip_handoffs=open_handoffs,
    )


def _coverage_quality_tile(cur: psycopg.Cursor) -> dict:
    """Feed health straight from the Ch.1 sync_state — the authoritative feed
    facts, carried through with their own freshness semantics. A feed that
    never synced or is unhealthy renders as exactly that ('stale'/'unknown'),
    never as healthy and never as a zero."""
    cur.execute(
        """
        SELECT source, is_healthy, last_successful_at, consecutive_failures,
               last_good_snapshot_id, sync_interval_seconds
        FROM sync_state
        ORDER BY source ASC;
        """
    )
    feeds = []
    healthy = stale = unknown = 0
    for row in cur.fetchall():
        if not row["is_healthy"]:
            feed_status = "stale"
            stale += 1
        elif row["last_successful_at"] is None:
            feed_status = "unknown"
            unknown += 1
        else:
            feed_status = "healthy"
            healthy += 1
        feeds.append({
            "source": row["source"],
            "status": feed_status,
            "is_healthy": bool(row["is_healthy"]),
            "last_successful_at": row["last_successful_at"],
            "consecutive_failures": row["consecutive_failures"],
            "last_good_snapshot_id": (
                str(row["last_good_snapshot_id"])
                if row["last_good_snapshot_id"]
                else None
            ),
        })
    return _tile_ok(feeds=feeds, feeds_healthy=healthy, feeds_stale=stale,
                    feeds_unknown=unknown)


# ---------------------------------------------------------------------------
# The executive summary (one coherent source view)
# ---------------------------------------------------------------------------


def build_executive_summary(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime
) -> tuple[dict, dict]:
    """Build the executive payload inside the caller's REPEATABLE READ
    boundary. Returns (payload, source_refs). The payload carries its own
    ``as_of`` and every metric's deterministic definition — provenance is
    part of the answer, not an afterthought."""
    metric_definitions = {
        "max_final_tes": (
            "MAX recomputed TES over current confirmed exposures whose state "
            "is FINAL; null when none. Max, never a mean."
        ),
        "max_provisional_tes": (
            "MAX recomputed TES over current confirmed exposures whose state "
            "is PROVISIONAL; rendered separately from FINAL, never combined."
        ),
        "severe_count": (
            f"Count of current exposures with a FINAL/PROVISIONAL TES >= "
            f"{SEVERE_TES_THRESHOLD}, plus UNSCOREABLE exposures listed "
            f"separately with a reason."
        ),
        "unscoreable_count": (
            "Count of current exposures the Ch.3 kernel fails closed "
            "UNSCOREABLE for — visible, never hidden."
        ),
        "workflow_counts": (
            "Counts of current exposures per Ch.7 analysis_state "
            "('new' before any workbench action)."
        ),
        "feed_status": (
            "Ch.1 sync_state facts per source: stale = unhealthy feed, "
            "unknown = never synced, healthy = healthy with at least one "
            "successful sync."
        ),
    }

    severe_tile, exposure_refs = _severe_exposures_tile(conn, tenant_id, as_of)

    with conn.cursor(row_factory=dict_row) as cur:
        workflow_tile = _workflow_posture_tile(cur, tenant_id)
        coverage_tile = _coverage_quality_tile(cur)

    feed_refs = [
        {"source": f["source"], "last_good_snapshot_id": f["last_good_snapshot_id"]}
        for f in coverage_tile["feeds"]
    ]

    payload = {
        # derived, read-only, labeled — never a source of record (Ch.10)
        "authority": "derived_read_only_projection",
        "as_of": as_of,
        "tenant_id": str(tenant_id),
        "metric_definitions": metric_definitions,
        "severe_exposures": severe_tile,
        "workflow_posture": workflow_tile,
        "coverage_quality": coverage_tile,
        # Upstream decision domains (Ch.8 EDIP / Ch.9 STANDARD) are not part
        # of the integrated baseline this build runs on: their tiles render
        # UNAVAILABLE — loudly — never zero.
        "remediation_posture": _unavailable(DOMAIN_UNAVAILABLE["edip"]),
        "accepted_risk_register": _unavailable(DOMAIN_UNAVAILABLE["edip"]),
        "regulatory_pressure": _unavailable(DOMAIN_UNAVAILABLE["standard"]),
    }
    source_refs = {
        "exposures": exposure_refs,
        "feed_health": feed_refs,
    }
    return payload, source_refs


# ---------------------------------------------------------------------------
# Snapshots — the module's only owned state (append-only)
# ---------------------------------------------------------------------------


def _snapshot_row_to_dict(row: dict) -> dict:
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "captured_at": row["captured_at"],
        "captured_by": row["captured_by"],
        "actor_role": row["actor_role"],
        "payload_hash": row["payload_hash"],
        "payload": row["payload"],
        "source_refs": row["source_refs"],
    }


def capture_snapshot(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Capture one posture snapshot: build the summary inside the caller's
    REPEATABLE READ boundary, seal it with a payload hash + upstream source
    refs, append it. History is never overwritten (the DB trigger forbids
    UPDATE/DELETE). One audited append-on-commit event. Capture never
    mutates upstream state."""
    as_of = datetime.now(timezone.utc)
    payload, source_refs = build_executive_summary(conn, tenant_id, as_of=as_of)
    wire_payload = _jsonify(payload)
    payload_hash = _hash_payload(wire_payload)

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO posture_snapshots (
                tenant_id, captured_at, captured_by, actor_role,
                payload_hash, payload, source_refs
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *;
            """,
            (
                str(tenant_id), as_of, actor_id, actor_role,
                payload_hash, json.dumps(wire_payload),
                json.dumps(_jsonify(source_refs)),
            ),
        )
        row = cur.fetchone()

    record_audit_event(
        conn,
        tenant_id,
        actor_id=actor_id,
        actor_role=actor_role,
        event_name="spotlight.snapshot_captured",
        details={
            "snapshot_id": str(row["id"]),
            "payload_hash": payload_hash,
            "as_of": as_of.isoformat(),
        },
    )
    return _snapshot_row_to_dict(row)


def list_snapshots(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Bounded, newest-first listing (append-only history is read, never
    rewritten)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT COUNT(*) AS total FROM posture_snapshots
            WHERE tenant_id = %s;
            """,
            (str(tenant_id),),
        )
        total = cur.fetchone()["total"]
        cur.execute(
            """
            SELECT * FROM posture_snapshots
            WHERE tenant_id = %s
            ORDER BY captured_at DESC, id DESC
            LIMIT %s OFFSET %s;
            """,
            (str(tenant_id), max(1, min(limit, SNAPSHOT_LIST_LIMIT)),
             max(0, offset)),
        )
        rows = cur.fetchall()
    return {
        "total": total,
        "items": [_snapshot_row_to_dict(r) for r in rows],
    }


def get_snapshot(
    conn: psycopg.Connection, tenant_id: uuid.UUID, snapshot_id: uuid.UUID
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT * FROM posture_snapshots
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(snapshot_id)),
        )
        row = cur.fetchone()
    if row is None:
        raise SnapshotNotFoundError(f"Snapshot {snapshot_id} not found")
    return _snapshot_row_to_dict(row)


def _numeric_delta(previous: Any, current: Any) -> Optional[dict]:
    """Delta between two snapshot values for one metric (int or
    Decimal-tagged). Values of different kinds (or missing halves) produce no
    delta — a trend is computed, never invented."""
    prev = (
        Decimal(previous["__decimal__"])
        if isinstance(previous, dict) and "__decimal__" in previous
        else previous
    )
    cur_ = (
        Decimal(current["__decimal__"])
        if isinstance(current, dict) and "__decimal__" in current
        else current
    )
    if not isinstance(prev, (int, Decimal)) or isinstance(prev, bool):
        return None
    if not isinstance(cur_, (int, Decimal)) or isinstance(cur_, bool):
        return None
    return {"previous": previous, "current": current, "delta": cur_ - prev}


def snapshot_trend(
    conn: psycopg.Connection, tenant_id: uuid.UUID
) -> dict:
    """Trend deltas computed BETWEEN the two most recent snapshots of this
    tenant (rule 3: trends read append-only snapshots). With fewer than two
    snapshots the trend renders 'insufficient_history' — never a zero
    baseline."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, captured_at, payload FROM posture_snapshots
            WHERE tenant_id = %s
            ORDER BY captured_at DESC, id DESC
            LIMIT 2;
            """,
            (str(tenant_id),),
        )
        rows = cur.fetchall()

    if len(rows) < 2:
        return {
            "status": "insufficient_history",
            "snapshots_available": len(rows),
            "reason": "trend_deltas_require_two_snapshots",
        }

    newer, older = rows[0], rows[1]
    trended = (
        "severe_exposures.final_count",
        "severe_exposures.provisional_count",
        "severe_exposures.unscoreable_count",
        "severe_exposures.severe_count",
        "severe_exposures.max_final_tes",
        "severe_exposures.max_provisional_tes",
        "workflow_posture.analysis_state_assigned",
        "workflow_posture.analysis_state_action_required",
        "workflow_posture.open_edip_handoffs",
    )
    deltas: dict[str, Optional[dict]] = {}
    for path in trended:
        prev_value: Any = older["payload"]
        cur_value: Any = newer["payload"]
        for part in path.split("."):
            prev_value = prev_value.get(part) if isinstance(prev_value, dict) else None
            cur_value = cur_value.get(part) if isinstance(cur_value, dict) else None
            if prev_value is None and cur_value is None:
                break
        deltas[path] = _numeric_delta(prev_value, cur_value)

    return {
        "status": "ok",
        "newer_snapshot_id": str(newer["id"]),
        "older_snapshot_id": str(older["id"]),
        "newer_captured_at": newer["captured_at"],
        "older_captured_at": older["captured_at"],
        "deltas": deltas,
    }
