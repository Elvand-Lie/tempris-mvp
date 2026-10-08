# backend/app/synthesis/service.py
"""
Deterministic correlation services for SYNTHESIS (PRD-000 v1.11 Ch.12).

v1 = READ-TIME JOINS ONLY (frozen): every endpoint is a join over
authoritative objects computed inside the caller's REPEATABLE READ
boundary, and nothing is stored. Binding rules:

* Correlate, never manufacture: every row keeps its source-object
  identities; scores are read-through recomputes (Ch.3 authority) —
  SYNTHESIS has no score of its own.
* Degrade LOUDLY (the ai_context.py:351 lesson turned into a rule): an
  answer built on a missing input domain NAMES the missing domain in an
  explicit availability block and returns no fabricated rows.
* Feed staleness renders (Ch.1 facts carried through): rows whose TES
  source view bound a stale/unknown feed are marked.
* Determinism: the same source state yields the same answer; the volatile
  read instant is carried as ``as_of`` and nothing else varies.
* No writes, no AI, no prose: the module's only outputs are these
  structured answers.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.exposure.tes_read_model import _jsonify, get_exposure_tes

# Deterministic "serious" threshold for the unremediated-serious question —
# the same severe threshold Ch.10's executive tiles publish, so the two
# answers can never disagree about what counts as serious.
SERIOUS_TES_THRESHOLD = Decimal("8.0")

QUERY_LIMIT = 500

# Every input domain this module correlates is shipped authoritative state
# (Ch.1 feeds, Ch.3 exposures, Ch.7 workflow, Ch.8 EDIP, Ch.9 STANDARD): all
# render AVAILABLE. The availability block stays the degrade-loudly
# contract's carrier — a future missing/failed input domain must be NAMED in
# it (the ai_context.py:351 lesson), never silently dropped.
AVAILABILITY_DOMAINS = (
    "exposures_tes", "spectrum_workflow", "feed_health",
    "edip_decisions", "standard_obligations",
)

# The reference ids an incident's input revision may declare (free-form JSON
# object): the EDIP ⋈ STANDARD join keys. A key whose value is not a string
# is not a reference.
REFERENCE_KEYS = ("exposure_id", "finding_id", "asset_id")


def _availability() -> dict:
    """The per-domain availability block every answer carries."""
    return {name: {"status": "available"} for name in AVAILABILITY_DOMAINS}


def _envelope(
    question: str,
    definition: str,
    rows: list[dict],
    availability: dict,
    *,
    as_of: datetime,
    truncated: bool = False,
    source_counts: Optional[dict[str, int]] = None,
) -> dict:
    """The answer envelope: the question, its DETERMINISTIC definition, the
    joined rows (each carrying source identities), the availability block,
    and the read instant. ``source_counts`` is an additive diagnostic: the
    BASE populations the correlation filters over, so an empty answer can be
    distinguished from an unevaluable one. It never affects the rows."""
    missing = sorted(
        name for name, state in availability.items()
        if state["status"] == "unavailable"
    )
    return {
        "question": question,
        "definition": definition,
        "as_of": as_of,
        "authority": "read_time_join_over_authoritative_state",
        "availability": availability,
        "missing_domains": missing,
        "degraded": bool(missing),
        "row_count": len(rows),
        "truncated": truncated,
        "source_counts": {k: int(v) for k, v in (source_counts or {}).items()},
        "rows": rows,
    }


def _feed_freshness_of(tes: dict) -> str:
    """The worst input freshness the recomputed payload itself declares
    (§3.3.5: the decomposition names every unresolved potentially-higher
    source). Names carry the reason class: 'epss(stale)', 'kev(unknown)',
    'exact_exposure_evidence(stale)'. Stale beats unknown; unresolved
    sources at all make the row NOT fresh."""
    freshness = "fresh"
    for row in tes.get("decomposition", []):
        if row.get("axis") != "exploit_reality":
            continue
        for name, _why in row.get("unresolved_higher", []) or []:
            if "(stale)" in name:
                return "stale"
            if "(unknown)" in name:
                freshness = "unknown"
    return freshness


# ---------------------------------------------------------------------------
# Question 1 — unremediated serious exposures
# ---------------------------------------------------------------------------


def unremediated_serious(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    threshold: Decimal = SERIOUS_TES_THRESHOLD, limit: int = QUERY_LIMIT,
) -> dict:
    """Current confirmed exposures on active assets whose recomputed TES is
    FINAL or PROVISIONAL at/above the serious threshold — joined with their
    Ch.7 workflow state (is anyone on it? has it been actioned?). Score
    states render separately; UNSCOREABLE rows are not serious by
    definition and appear in the coverage question instead."""
    definition = (
        "Current confirmed exposures on active assets with a recomputed TES "
        f"(FINAL or PROVISIONAL, rendered separately) >= {threshold}, joined "
        "with their SPECTRUM analysis_state and open EDIP handoff. Serious "
        "is a threshold on individual exposures — never an average."
    )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id AS exposure_id, e.finding_id, e.asset_id,
                   e.confirmed_at, f.canonical_cve_id,
                   f.title AS finding_title, f.severity AS finding_severity,
                   a.name AS asset_name, a.criticality AS asset_criticality,
                   COALESCE(w.analysis_state, 'new') AS analysis_state,
                   w.assigned_to,
                   EXISTS (
                       SELECT 1 FROM spectrum_edip_handoffs h
                       WHERE h.tenant_id = e.tenant_id
                         AND h.exposure_id = e.id
                         AND h.state = 'NEEDS_DECISION'
                   ) AS open_edip_handoff
            FROM asset_exposures e
            JOIN findings f ON f.tenant_id = e.tenant_id AND f.id = e.finding_id
            JOIN assets a
              ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
             AND a.status = 'active'
            LEFT JOIN spectrum_exposure_workflow w
              ON w.tenant_id = e.tenant_id AND w.exposure_id = e.id
            WHERE e.tenant_id = %s AND e.status = 'confirmed'
            ORDER BY e.confirmed_at ASC, e.id ASC;
            """,
            (str(tenant_id),),
        )
        candidates = cur.fetchall()

    rows: list[dict] = []
    truncated = False
    for candidate in candidates:
        tes = get_exposure_tes(conn, tenant_id, candidate["exposure_id"], as_of=as_of)
        state = tes["state"]
        value = tes["value"]
        if state not in ("FINAL", "PROVISIONAL") or value is None:
            continue
        if value < threshold:
            continue
        if len(rows) >= max(1, min(limit, QUERY_LIMIT)):
            truncated = True
            break
        rows.append({
            "exposure_id": str(candidate["exposure_id"]),
            "finding_id": str(candidate["finding_id"]),
            "asset_id": str(candidate["asset_id"]),
            "canonical_cve_id": candidate["canonical_cve_id"],
            "finding_title": candidate["finding_title"],
            "finding_severity": candidate["finding_severity"],
            "asset_name": candidate["asset_name"],
            "asset_criticality": candidate["asset_criticality"],
            "confirmed_at": candidate["confirmed_at"],
            "tes_state": state,
            "tes_value": {"__decimal__": str(value)},
            "formula_version": tes["formula_version"],
            "feed_freshness": _feed_freshness_of(tes),
            "workflow": {
                "analysis_state": candidate["analysis_state"],
                "assigned_to": candidate["assigned_to"],
                "open_edip_handoff": bool(candidate["open_edip_handoff"]),
            },
        })
    rows.sort(
        key=lambda r: (Decimal(r["tes_value"]["__decimal__"]), r["exposure_id"]),
        reverse=True,
    )
    return _envelope(
        "unremediated_serious_exposures",
        definition, rows, _availability(), as_of=as_of, truncated=truncated,
        source_counts={
            "confirmed_exposures_active_assets": len(candidates),
        },
    )


# ---------------------------------------------------------------------------
# Question 2 — accepted risks vs obligations (Ch.8 ⋈ Ch.9)
# ---------------------------------------------------------------------------


def accepted_risks_vs_obligations(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    limit: int = QUERY_LIMIT,
) -> dict:
    """The PRD's headline correlation (Ch.12): 'which accepted risks map to
    regulatory obligations' = EDIP accepted-risk decisions ⋈ STANDARD
    obligations, by reference ids. Read-time join over the shipped tables:
    every CURRENT accepted/deferred EDIP decision meets every STANDARD
    obligation whose incident's current input revision declares a matching
    reference id (exposure_id / finding_id / asset_id). One row per mapped
    (decision, obligation) pair; an incident that declares no references
    maps to nothing — an empty join with both domains present is a TRUE
    empty answer, not a degradation. Nothing is written, nothing stored."""
    definition = (
        "EDIP accepted/deferred risk decisions (current revision) joined to "
        "STANDARD obligations whose incident's current input revision "
        "references the same exposure_id, finding_id, or asset_id. Read-time "
        "join over authoritative state by reference ids — SYNTHESIS stores "
        "none of it, writes nothing, and derives deadline/review state "
        "against as_of only."
    )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT d.id AS decision_id, d.decision_group_id, d.revision,
                   d.decision_type, d.state, d.owner, d.rationale,
                   d.due_at, d.review_due_at, d.snapshot_as_of, d.created_at,
                   e.id AS exposure_id, e.finding_id, e.asset_id
            FROM edip_decisions d
            JOIN asset_exposures e
              ON e.tenant_id = d.tenant_id AND e.id = d.exposure_id
            WHERE d.tenant_id = %s AND d.replaced_at IS NULL
              AND d.state IN ('accepted_risk', 'deferred')
            ORDER BY d.created_at ASC, d.id ASC;
            """,
            (str(tenant_id),),
        )
        decisions = cur.fetchall()

        cur.execute(
            """
            SELECT o.id AS obligation_id, o.kind, o.title, o.state,
                   o.due_at, o.trigger_at, o.breached_at, o.incident_id,
                   i.source AS incident_source, i.state AS incident_state,
                   i.event_time,
                   ir.inputs
            FROM standard_obligations o
            JOIN standard_incidents i
              ON i.tenant_id = o.tenant_id AND i.id = o.incident_id
            LEFT JOIN standard_incident_revisions ir
              ON ir.tenant_id = i.tenant_id AND ir.incident_id = i.id
             AND ir.revision_no = i.current_revision
            WHERE o.tenant_id = %s
            ORDER BY o.created_at ASC, o.id ASC;
            """,
            (str(tenant_id),),
        )
        obligations = cur.fetchall()

    referenced: list[tuple[dict, dict]] = []
    for obligation in obligations:
        inputs = obligation.pop("inputs") or {}
        refs = {
            key: inputs[key] for key in REFERENCE_KEYS
            if isinstance(inputs.get(key), str)
        }
        referenced.append((obligation, refs))

    cap = max(1, min(limit, QUERY_LIMIT))
    rows: list[dict] = []
    truncated = False
    for decision in decisions:
        identity = {
            "exposure_id": str(decision["exposure_id"]),
            "finding_id": str(decision["finding_id"]),
            "asset_id": str(decision["asset_id"]),
        }
        for obligation, refs in referenced:
            if len(rows) >= cap:
                truncated = True
                break
            matched_by = sorted(
                key for key in REFERENCE_KEYS
                if refs.get(key) == identity[key]
            )
            if not matched_by:
                continue
            rows.append({
                "decision_id": str(decision["decision_id"]),
                "decision_group_id": str(decision["decision_group_id"]),
                "revision": decision["revision"],
                "decision_type": decision["decision_type"],
                "decision_state": decision["state"],
                "owner": decision["owner"],
                "rationale": decision["rationale"],
                "due_at": decision["due_at"],
                "review_due_at": decision["review_due_at"],
                "review_expired": bool(
                    decision["review_due_at"] is not None
                    and decision["review_due_at"] <= as_of
                ),
                "snapshot_as_of": decision["snapshot_as_of"],
                "decision_created_at": decision["created_at"],
                "exposure_id": identity["exposure_id"],
                "finding_id": identity["finding_id"],
                "asset_id": identity["asset_id"],
                "matched_by": matched_by,
                "obligation": {
                    "obligation_id": str(obligation["obligation_id"]),
                    "kind": obligation["kind"],
                    "title": obligation["title"],
                    "state": obligation["state"],
                    "due_at": obligation["due_at"],
                    "overdue": bool(
                        obligation["due_at"] is not None
                        and obligation["due_at"] < as_of
                        and obligation["state"] in ("open", "in_progress")
                    ),
                    "trigger_at": obligation["trigger_at"],
                    "breached_at": obligation["breached_at"],
                    "incident_id": (
                        str(obligation["incident_id"])
                        if obligation["incident_id"] else None
                    ),
                    "incident_source": obligation["incident_source"],
                    "incident_state": obligation["incident_state"],
                },
            })
        if truncated:
            break

    return _envelope(
        "accepted_risks_vs_obligations",
        definition, rows, _availability(), as_of=as_of, truncated=truncated,
        source_counts={
            "accepted_risk_decisions": len(decisions),
            "standard_obligations": len(obligations),
        },
    )


# ---------------------------------------------------------------------------
# Question 3 — remediation recurrence (PATCH-14)
# ---------------------------------------------------------------------------


def remediation_recurrence(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    limit: int = QUERY_LIMIT,
) -> dict:
    """'Findings that return': current confirmed episodes of a
    (tenant, finding, asset) tuple that has a RESOLVED predecessor episode.
    PATCH-14 exclusions are structural here:
      * false_positive predecessors are NOT recurrences (a false positive
        that re-appears is a fresh quality problem, not a failed fix);
      * superseded episodes are NOT recurrences (supersession is identity
        bookkeeping, not remediation);
      * only a `resolved` predecessor makes the new episode a recurrence —
        the episode must have actually been fixed and returned.
    Decision review-expiry reverts (Ch.8) cannot occur in this baseline's
    vocabulary; the excluded set is exactly the resolved-only rule."""
    definition = (
        "Current confirmed episodes of a (tenant, finding, asset) tuple "
        "with a prior RESOLVED episode of the same tuple. Excluded per "
        "PATCH-14: predecessors that were false_positive or superseded are "
        "never recurrence evidence; only resolved predecessors count."
    )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT cur.id AS exposure_id, cur.finding_id, cur.asset_id,
                   cur.confirmed_at AS current_confirmed_at,
                   f.canonical_cve_id, f.title AS finding_title,
                   a.name AS asset_name,
                   prev.id AS predecessor_exposure_id,
                   prev.confirmed_at AS predecessor_confirmed_at,
                   prev.resolved_at AS predecessor_resolved_at,
                   prev.resolution_reason AS predecessor_resolution_reason
            FROM asset_exposures cur
            JOIN findings f ON f.tenant_id = cur.tenant_id AND f.id = cur.finding_id
            JOIN assets a
              ON a.tenant_id = cur.tenant_id AND a.id = cur.asset_id
             AND a.status = 'active'
            JOIN asset_exposures prev
              ON prev.tenant_id = cur.tenant_id
             AND prev.finding_id = cur.finding_id
             AND prev.asset_id = cur.asset_id
             AND prev.id <> cur.id
             AND prev.status = 'resolved'
             AND prev.resolved_at <= cur.confirmed_at
            WHERE cur.tenant_id = %s AND cur.status = 'confirmed'
            ORDER BY cur.confirmed_at ASC, cur.id ASC;
            """,
            (str(tenant_id),),
        )
        pairs = cur.fetchall()

        cur.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM asset_exposures e
               JOIN assets a
                 ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
                AND a.status = 'active'
               WHERE e.tenant_id = %s AND e.status = 'confirmed')
                AS confirmed_episodes_active_assets,
              (SELECT COUNT(*) FROM asset_exposures p
               WHERE p.tenant_id = %s AND p.status = 'resolved')
                AS resolved_episodes;
            """,
            (str(tenant_id), str(tenant_id)),
        )
        base_counts = cur.fetchone()

    rows: list[dict] = []
    truncated = False
    seen_current: set[str] = set()
    for pair in pairs:
        current_id = str(pair["exposure_id"])
        if current_id in seen_current:
            # the newest resolved predecessor already represents this return
            continue
        if len(rows) >= max(1, min(limit, QUERY_LIMIT)):
            truncated = True
            break
        tes = get_exposure_tes(conn, tenant_id, pair["exposure_id"], as_of=as_of)
        seen_current.add(current_id)
        rows.append({
            "exposure_id": current_id,
            "predecessor_exposure_id": str(pair["predecessor_exposure_id"]),
            "tuple": {
                "tenant_id": str(tenant_id),
                "finding_id": str(pair["finding_id"]),
                "asset_id": str(pair["asset_id"]),
            },
            "canonical_cve_id": pair["canonical_cve_id"],
            "finding_title": pair["finding_title"],
            "asset_name": pair["asset_name"],
            "current_confirmed_at": pair["current_confirmed_at"],
            "predecessor_resolved_at": pair["predecessor_resolved_at"],
            "predecessor_resolution_reason": pair["predecessor_resolution_reason"],
            "current_tes_state": tes["state"],
            "current_tes_value": (
                {"__decimal__": str(tes["value"])}
                if tes["value"] is not None else None
            ),
        })
    return _envelope(
        "remediation_recurrence",
        definition, rows, _availability(), as_of=as_of, truncated=truncated,
        source_counts={
            "confirmed_episodes_active_assets": base_counts[
                "confirmed_episodes_active_assets"
            ],
            "resolved_episodes": base_counts["resolved_episodes"],
        },
    )


# ---------------------------------------------------------------------------
# Question 4 — evidence strength vs coverage gaps
# ---------------------------------------------------------------------------


def coverage_gaps(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    limit: int = QUERY_LIMIT,
) -> dict:
    """Where evidence is missing relative to what scoring needed: every
    current exposure with its TES state, the exact input axes the kernel
    found missing, whether exploitation/reachability evidence exists, and
    the bound feed identities. UNSCOREABLE renders with its reason — the
    gap is the answer's subject, never a hidden row."""
    definition = (
        "Every current confirmed exposure on an active asset, joined with "
        "its recomputed TES state, missing scoring axes (from the §3.3.5 "
        "payload), exploitation/reachability evidence presence, and the "
        "bound feed snapshot identities. UNSCOREABLE rows render with "
        "their reason."
    )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id AS exposure_id, e.finding_id, e.asset_id,
                   f.canonical_cve_id,
                   EXISTS (
                       SELECT 1 FROM exposure_exploitation_evidence x
                       WHERE x.tenant_id = e.tenant_id
                         AND x.exposure_id = e.id
                         AND x.revocation_of_id IS NULL
                         AND x.evidence_kind IS NOT NULL
                         AND NOT EXISTS (
                             SELECT 1 FROM exposure_exploitation_evidence rx
                             WHERE rx.revocation_of_id = x.id
                         )
                   ) AS has_exploitation_evidence,
                   EXISTS (
                       SELECT 1 FROM exposure_reachability_evidence r
                       WHERE r.tenant_id = e.tenant_id
                         AND r.exposure_id = e.id
                         AND r.revocation_of_id IS NULL
                         AND r.vantage IS NOT NULL
                         AND NOT EXISTS (
                             SELECT 1 FROM exposure_reachability_evidence rr
                             WHERE rr.revocation_of_id = r.id
                         )
                   ) AS has_reachability_evidence
            FROM asset_exposures e
            JOIN assets a
              ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
             AND a.status = 'active'
            JOIN findings f ON f.tenant_id = e.tenant_id AND f.id = e.finding_id
            WHERE e.tenant_id = %s AND e.status = 'confirmed'
            ORDER BY e.confirmed_at ASC, e.id ASC;
            """,
            (str(tenant_id),),
        )
        candidates = cur.fetchall()

    rows: list[dict] = []
    truncated = False
    for candidate in candidates:
        if len(rows) >= max(1, min(limit, QUERY_LIMIT)):
            truncated = True
            break
        exposure_id = candidate["exposure_id"]
        tes = get_exposure_tes(conn, tenant_id, exposure_id, as_of=as_of)
        source_view = tes.get("source_view", {})
        rows.append({
            "exposure_id": str(exposure_id),
            "finding_id": str(candidate["finding_id"]),
            "asset_id": str(candidate["asset_id"]),
            "canonical_cve_id": candidate["canonical_cve_id"],
            "tes_state": tes["state"],
            "tes_value": (
                {"__decimal__": str(tes["value"])}
                if tes["value"] is not None else None
            ),
            "unscoreable_reason": source_view.get("cvss_unscoreable_reason_code")
            if tes["state"] == "UNSCOREABLE" else None,
            "missing_axes": list(tes.get("missing_inputs", [])),
            "has_exploitation_evidence": bool(
                candidate["has_exploitation_evidence"]
            ),
            "has_reachability_evidence": bool(
                candidate["has_reachability_evidence"]
            ),
            "bound_feed_snapshots": {
                "epss_snapshot_id": source_view.get("epss_snapshot_id"),
                "kev_snapshot_id": source_view.get("kev_snapshot_id"),
            },
        })
    return _envelope(
        "evidence_strength_vs_coverage_gaps",
        definition, rows, _availability(), as_of=as_of, truncated=truncated,
        source_counts={"confirmed_exposures": len(candidates)},
    )


# ---------------------------------------------------------------------------
# Question 5 — recurring weakness classes across assets
# ---------------------------------------------------------------------------


def weakness_recurrence(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    min_assets: int = 2, limit: int = QUERY_LIMIT,
) -> dict:
    """The same weakness (finding) currently confirmed on several assets:
    a recurring weakness CLASS, with the severity facts of its worst
    current episode (max by state — never a mean) and the identity list
    for drill-down."""
    definition = (
        "Findings with current confirmed episodes on >= {min_assets} "
        "distinct active assets, each with its worst current-episode TES "
        "per state (max FINAL / max PROVISIONAL — never combined, never "
        "averaged) and the exposure identities."
    ).format(min_assets=min_assets)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT f.id AS finding_id, f.canonical_cve_id, f.title,
                   f.severity,
                   COUNT(DISTINCT e.asset_id) AS asset_count,
                   COUNT(e.id) AS episode_count
            FROM asset_exposures e
            JOIN assets a
              ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
             AND a.status = 'active'
            JOIN findings f ON f.tenant_id = e.tenant_id AND f.id = e.finding_id
            WHERE e.tenant_id = %s AND e.status = 'confirmed'
            GROUP BY f.id, f.canonical_cve_id, f.title, f.severity
            HAVING COUNT(DISTINCT e.asset_id) >= %s
            ORDER BY COUNT(DISTINCT e.asset_id) DESC, f.id ASC;
            """,
            (str(tenant_id), max(2, min_assets)),
        )
        classes = cur.fetchall()

        cur.execute(
            """
            SELECT COUNT(*) AS confirmed_episodes_active_assets
            FROM asset_exposures e
            JOIN assets a
              ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
             AND a.status = 'active'
            WHERE e.tenant_id = %s AND e.status = 'confirmed';
            """,
            (str(tenant_id),),
        )
        base_count = cur.fetchone()

    rows: list[dict] = []
    truncated = False
    for weakness in classes:
        if len(rows) >= max(1, min(limit, QUERY_LIMIT)):
            truncated = True
            break
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT e.id AS exposure_id, e.asset_id, a.name AS asset_name,
                       e.confirmed_at
                FROM asset_exposures e
                JOIN assets a
                  ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
                 AND a.status = 'active'
                WHERE e.tenant_id = %s AND e.finding_id = %s
                  AND e.status = 'confirmed'
                ORDER BY e.confirmed_at ASC, e.id ASC;
                """,
                (str(tenant_id), str(weakness["finding_id"])),
            )
            episodes = cur.fetchall()

        max_final: Optional[Decimal] = None
        max_provisional: Optional[Decimal] = None
        final_count = provisional_count = unscoreable_count = 0
        episode_rows: list[dict] = []
        for episode in episodes:
            tes = get_exposure_tes(
                conn, tenant_id, episode["exposure_id"], as_of=as_of
            )
            state = tes["state"]
            value = tes["value"]
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
            episode_rows.append({
                "exposure_id": str(episode["exposure_id"]),
                "asset_id": str(episode["asset_id"]),
                "asset_name": episode["asset_name"],
                "confirmed_at": episode["confirmed_at"],
                "tes_state": state,
            })

        rows.append({
            "finding_id": str(weakness["finding_id"]),
            "canonical_cve_id": weakness["canonical_cve_id"],
            "finding_title": weakness["title"],
            "finding_severity": weakness["severity"],
            "asset_count": weakness["asset_count"],
            "episode_count": weakness["episode_count"],
            "max_final_tes": (
                {"__decimal__": str(max_final)}
                if max_final is not None else None
            ),
            "max_provisional_tes": (
                {"__decimal__": str(max_provisional)}
                if max_provisional is not None else None
            ),
            "final_count": final_count,
            "provisional_count": provisional_count,
            "unscoreable_count": unscoreable_count,
            "episodes": episode_rows,
        })
    return _envelope(
        "weakness_class_recurrence",
        definition, rows, _availability(), as_of=as_of, truncated=truncated,
        source_counts={
            "confirmed_episodes_active_assets": base_count[
                "confirmed_episodes_active_assets"
            ],
        },
    )
