# backend/app/intake/service.py
"""
Service layer for Intake & Triage (PRD-000 v1.11 Ch.6).

Lifecycle: submitted → under_review → confirmed | rejected | duplicate |
needs_info. Confirmation is the ONLY handoff into Ch.3/Ch.7: it resolves the
finding (shared CVE allocator / v1 non-CVE signature), matches the exposure
tuple against the FULL exposure history (PATCH-06), and creates the
finding + evidence-backed exposure through the ONE shared Ch.3 confirmation
command (``exposure.service.confirm_exposure``) — intake adds no second
confirmation writer and no new dual-control gate.

Duplicate outcomes depend on the matched EXPOSURE's lifecycle state, never
the finding's (D-16): current ⇒ duplicate (hard refusal + stored reference);
resolved ⇒ recurrence (new episode, never a refusal); false_positive ⇒ fresh
analyst re-review required; superseded ⇒ the anchor must be re-resolved first.

Source-event replay identity (PATCH-07): (tenant, registration, event id,
payload digest). Identical replay returns the original outcome; a conflicting
payload under the same event id is rejected — never silently revised.

Purity note: everything here is storage + orchestration; the taxonomy spine
validator is shared with Ch.3 (``app.exposure.sss.validate_taxonomy_spine``)
— one validator, Python and SQL agree.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.models import ExposureConfirm, FindingCreate, ReviewCreate
from app.exposure.sss import validate_taxonomy_spine
from app.exposure.service import (
    OUTCOME_CREATED,
    OUTCOME_REPLAY,
    _advisory_xact_lock,
    allocate_finding_for_cve,
    confirm_exposure,
    create_finding,
)
from app.intake.errors import (
    IntakeAnchorRequiredError,
    IntakeAnchorSupersededError,
    IntakeAnchorlessClassError,
    IntakeAmbiguousIdentityError,
    IntakeConnectorRegistrationError,
    IntakeDuplicateExposureError,
    IntakeEventConflictError,
    IntakeNotFoundError,
    IntakePriorFalsePositiveError,
    IntakeStateError,
)
from app.intake.models import (
    ConnectorRegistration,
    IntakeConfirmIn,
    IntakeCreate,
    IntakeRecord,
)

_INTAKE_COLUMNS = (
    "id, tenant_id, source, state, payload, payload_digest, "
    "source_registration_id, source_event_id, title, description, severity, "
    "canonical_cve_id, taxonomy_class, taxonomy_subclass, taxonomy_subtype, "
    "asset_id, anchor_state, finding_id, exposure_id, duplicate_of_exposure_id, "
    "requested_by, reviewed_by, reviewed_at, deficiency, rejection_reason, "
    "duplicate_reason, created_at, updated_at"
)


@dataclass(frozen=True)
class IntakeCreateResult:
    record: IntakeRecord
    outcome: str  # OUTCOME_CREATED | OUTCOME_REPLAY


@dataclass(frozen=True)
class IntakeConfirmResult:
    """Confirmation outcome. 'duplicate' and the two 'blocked_*' outcomes are
    COMMITTED refusals — the record/event/audit rows commit, and the route
    renders the 409 from the outcome; no exception crosses the transaction."""

    outcome: str  # confirmed | duplicate | blocked_false_positive | blocked_superseded
    record: IntakeRecord
    duplicate_of_exposure_id: Optional[uuid.UUID] = None
    blocked_reason: Optional[str] = None


def _canonical_payload_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _record_event(
    cur,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    *,
    event: str,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    cur.execute(
        """
        INSERT INTO intake_record_events (
            tenant_id, record_id, event, actor, actor_role, note, detail
        ) VALUES (%s, %s, %s, %s, %s, %s, %s);
        """,
        (
            str(tenant_id), str(record_id), event, actor_id, actor_role,
            note, json.dumps(detail) if detail is not None else None,
        ),
    )


def _load_record(cur, tenant_id: uuid.UUID, record_id: uuid.UUID) -> dict:
    cur.execute(
        f"""
        SELECT {_INTAKE_COLUMNS}
        FROM intake_records
        WHERE tenant_id = %s AND id = %s;
        """,
        (str(tenant_id), str(record_id)),
    )
    row = cur.fetchone()
    if row is None:
        # unknown and cross-tenant ids are the same not-found (no disclosure)
        raise IntakeNotFoundError(f"Intake record {record_id} not found")
    return row


# ---------------------------------------------------------------------------
# Creation (with PATCH-07 replay identity)
# ---------------------------------------------------------------------------


def create_intake_record(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data: IntakeCreate,
    *,
    actor_id: str,
    actor_role: str,
) -> IntakeCreateResult:
    """Create an intake record — never a finding. Connector submissions must
    name a registered adapter destination (routing record only; credentials
    are Ch.5-owned). A repeating (registration, event id) with the same
    payload digest returns the ORIGINAL record (outcome 'replay'); a
    conflicting digest is a named 409, never a silent revision."""
    if data.taxonomy is not None:
        validate_taxonomy_spine(
            data.taxonomy.taxonomy_class,
            data.taxonomy.taxonomy_subclass,
            data.taxonomy.taxonomy_subtype,
        )

    digest = _canonical_payload_digest(data.payload)
    registration_id = data.source_registration_id
    if data.source == "CONNECTOR":
        registration = _resolve_connector_registration(
            conn, tenant_id, data.source_registration_id
        )
        registration_id = str(registration.id)

    with conn.cursor(row_factory=dict_row) as cur:
        # PATCH-07 arbitration runs under the identity lock so concurrent
        # replays of one event serialize instead of racing the unique index.
        if data.source_event_id is not None:
            _advisory_xact_lock(
                cur,
                f"intake-event:{tenant_id}:{registration_id}:{data.source_event_id}",
            )
            cur.execute(
                f"""
                SELECT {_INTAKE_COLUMNS}
                FROM intake_records
                WHERE tenant_id = %s
                  AND source_registration_id = %s
                  AND source_event_id = %s;
                """,
                (str(tenant_id), registration_id, data.source_event_id),
            )
            existing = cur.fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    record_audit_event(
                        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                        actor_role=actor_role, event_name="intake.event_conflict",
                        asset_id=None,
                        details={
                            "intake_record_id": str(existing["id"]),
                            "source_registration_id": registration_id,
                            "source_event_id": data.source_event_id,
                        },
                    )
                    raise IntakeEventConflictError(
                        f"source event {data.source_event_id!r} was already "
                        "consumed with a different payload — replay returns "
                        "the original outcome; a conflicting payload is a "
                        "rejected, audited event"
                    )
                return IntakeCreateResult(
                    IntakeRecord.model_validate(existing), OUTCOME_REPLAY
                )

        taxonomy = data.taxonomy
        cur.execute(
            f"""
            INSERT INTO intake_records (
                tenant_id, source, state, payload, payload_digest,
                source_registration_id, source_event_id,
                title, description, severity, canonical_cve_id,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                asset_id, requested_by
            ) VALUES (
                %s, %s, 'submitted', %s::jsonb, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING {_INTAKE_COLUMNS};
            """,
            (
                str(tenant_id), data.source, json.dumps(data.payload), digest,
                registration_id, data.source_event_id,
                data.title, data.description, data.severity, data.canonical_cve_id,
                taxonomy.taxonomy_class if taxonomy else None,
                taxonomy.taxonomy_subclass if taxonomy else None,
                taxonomy.taxonomy_subtype if taxonomy else None,
                str(data.asset_id) if data.asset_id else None,
                actor_id,
            ),
        )
        row = cur.fetchone()
        record = IntakeRecord.model_validate(row)

        _record_event(
            cur, tenant_id, record.id, event="created",
            actor_id=actor_id, actor_role=actor_role,
            detail={"source": record.source, "payload_digest": digest},
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="intake.created", asset_id=None,
            details={
                "intake_record_id": str(record.id),
                "source": record.source,
                "title": record.title,
                "severity": record.severity,
                "canonical_cve_id": record.canonical_cve_id,
                "source_event_id": record.source_event_id,
            },
        )
        return IntakeCreateResult(record, OUTCOME_CREATED)


def _resolve_connector_registration(
    conn: psycopg.Connection, tenant_id: uuid.UUID, registration_ref: Optional[str]
) -> ConnectorRegistration:
    if not registration_ref:
        raise IntakeConnectorRegistrationError(
            "source CONNECTOR requires source_registration_id — the registered "
            "adapter destination the payload arrived through"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, name, adapter, status, destination_routing,
                   payload_semantics, created_by, created_at, updated_at
            FROM intake_connector_registrations
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), registration_ref),
        )
        row = cur.fetchone()
    if row is None or row["status"] != "active":
        # unknown, cross-tenant, and disabled registrations are the same
        # named refusal — an unregistered payload never becomes tenant data
        raise IntakeConnectorRegistrationError(
            f"connector registration {registration_ref!r} is not an active "
            "registration for this tenant"
        )
    return ConnectorRegistration.model_validate(row)


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def get_intake_record(
    conn: psycopg.Connection, tenant_id: uuid.UUID, record_id: uuid.UUID
) -> IntakeRecord:
    with conn.cursor(row_factory=dict_row) as cur:
        return IntakeRecord.model_validate(_load_record(cur, tenant_id, record_id))


def list_intake_records(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    state: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[IntakeRecord]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            SELECT {_INTAKE_COLUMNS}
            FROM intake_records
            WHERE tenant_id = %s
              AND (%s::text IS NULL OR state = %s::text)
              AND (%s::text IS NULL OR source = %s::text)
            ORDER BY created_at DESC, id DESC
            LIMIT %s OFFSET %s;
            """,
            (
                str(tenant_id), state, state, source, source,
                max(1, min(limit, 500)), max(0, offset),
            ),
        )
        return [IntakeRecord.model_validate(r) for r in cur.fetchall()]


def list_intake_record_events(
    conn: psycopg.Connection, tenant_id: uuid.UUID, record_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        _load_record(cur, tenant_id, record_id)  # 404 gate (no disclosure)
        cur.execute(
            """
            SELECT id, tenant_id, record_id, event, actor, actor_role, note, detail, created_at
            FROM intake_record_events
            WHERE tenant_id = %s AND record_id = %s
            ORDER BY created_at ASC, id ASC;
            """,
            (str(tenant_id), str(record_id)),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Review transitions (classify / start-review / request-info / reject)
# ---------------------------------------------------------------------------


class _SqlNow:
    """Sentinel for a bare ``now()`` assignment (never a bound parameter)."""

    def __repr__(self) -> str:  # pragma: no cover
        return "SQL_NOW"


SQL_NOW = _SqlNow()


def _transition(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    *,
    from_states: tuple[str, ...],
    to_state: Optional[str],
    event: str,
    audit_event: str,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
    updates: Optional[dict[str, Any]] = None,
    require_classification: bool = False,
) -> IntakeRecord:
    """One serialized review transition under the record's advisory lock.
    ``to_state=None`` keeps the current state (a annotate-only action)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"intake:{tenant_id}:{record_id}")
        cur.execute(
            f"""
            SELECT {_INTAKE_COLUMNS}
            FROM intake_records
            WHERE tenant_id = %s AND id = %s
            FOR UPDATE;
            """,
            (str(tenant_id), str(record_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise IntakeNotFoundError(f"Intake record {record_id} not found")
        if row["state"] not in from_states:
            raise IntakeStateError(
                f"intake record {record_id} is in state '{row['state']}'; "
                f"'{event}' requires one of {list(from_states)}"
            )
        if require_classification and row["taxonomy_class"] is None:
            raise IntakeStateError(
                f"intake record {record_id} is unclassified — classify it on "
                "the closed spine before requesting confirmation"
            )

        assignments = ["updated_at = now()"]
        params: list[Any] = []
        if to_state is not None and to_state != row["state"]:
            assignments.append("state = %s")
            params.append(to_state)
        for column, value in (updates or {}).items():
            if isinstance(value, _SqlNow):
                assignments.append(f"{column} = now()")
            else:
                assignments.append(f"{column} = %s")
                params.append(value)
        params.extend([str(tenant_id), str(record_id)])
        cur.execute(
            f"""
            UPDATE intake_records
            SET {', '.join(assignments)}
            WHERE tenant_id = %s AND id = %s
            RETURNING {_INTAKE_COLUMNS};
            """,
            params,
        )
        record = IntakeRecord.model_validate(cur.fetchone())

        _record_event(
            cur, tenant_id, record.id, event=event,
            actor_id=actor_id, actor_role=actor_role, note=note,
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name=audit_event, asset_id=None,
            details={
                "intake_record_id": str(record.id),
                "prior_state": row["state"],
                "state": record.state,
                "note": note,
            },
        )
        return record


def classify_intake_record(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    taxonomy_class: str,
    taxonomy_subclass: Optional[str],
    taxonomy_subtype: Optional[str],
    *,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
) -> IntakeRecord:
    """Stamp the closed-spine classification (§3.6.5). Invalid values are
    rejected 422 by the shared validator — V1's arbitrary-string defect is
    structurally impossible here."""
    validate_taxonomy_spine(taxonomy_class, taxonomy_subclass, taxonomy_subtype)
    return _transition(
        conn, tenant_id, record_id,
        from_states=("submitted", "under_review", "needs_info"),
        to_state=None,
        event="classified",
        audit_event="intake.classified",
        actor_id=actor_id, actor_role=actor_role, note=note,
        updates={
            "taxonomy_class": taxonomy_class,
            "taxonomy_subclass": taxonomy_subclass,
            "taxonomy_subtype": taxonomy_subtype,
        },
    )


def start_intake_review(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
) -> IntakeRecord:
    return _transition(
        conn, tenant_id, record_id,
        from_states=("submitted", "needs_info"),
        to_state="under_review",
        event="review_started",
        audit_event="intake.review_started",
        actor_id=actor_id, actor_role=actor_role, note=note,
    )


def request_intake_info(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    deficiency: str,
    *,
    actor_id: str,
    actor_role: str,
) -> IntakeRecord:
    """Hold with a NAMED deficiency (needs_info) — never a silent block."""
    return _transition(
        conn, tenant_id, record_id,
        from_states=("submitted", "under_review"),
        to_state="needs_info",
        event="info_requested",
        audit_event="intake.info_requested",
        actor_id=actor_id, actor_role=actor_role,
        updates={"deficiency": deficiency},
    )


def reject_intake_record(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    reason: str,
    *,
    actor_id: str,
    actor_role: str,
) -> IntakeRecord:
    return _transition(
        conn, tenant_id, record_id,
        from_states=("submitted", "under_review", "needs_info"),
        to_state="rejected",
        event="rejected",
        audit_event="intake.rejected",
        actor_id=actor_id, actor_role=actor_role,
        updates={
            "rejection_reason": reason,
            "reviewed_by": actor_id,
            "reviewed_at": SQL_NOW,
        },
    )


# ---------------------------------------------------------------------------
# Confirmation — the single handoff into Ch.3/Ch.7
# ---------------------------------------------------------------------------


def confirm_intake_record(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    record_id: uuid.UUID,
    cmd: IntakeConfirmIn,
    *,
    actor_id: str,
    actor_role: str,
) -> IntakeConfirmResult:
    """
    Analyst+ confirmation (Ch.6 final pass: no NEW dual-control gate — the
    Ch.3 gates apply where Ch.3 says).

    Order inside the caller's transaction:
      1. advisory lock + FOR UPDATE on the intake record (state machine);
      2. classification + anchor preconditions (fail-closed, named);
      3. finding resolution — the shared CVE allocator, or the conservative
         v1 non-CVE signature (open decision #2 defers the fact-signature
         scheme); ambiguous identity ⇒ review, never auto-resolve;
      4. exposure-tuple match over the FULL history (PATCH-06): current wins
         (duplicate), then the latest terminal episode decides;
      5. the shared Ch.3 confirmation command (asset/finding locks, boundary
         precondition, evidence, review, audit, roll-up) — outcome 'created'.

    The two acknowledgment flags are named, audited analyst steps:
      * ``revalidate_prior_judgment`` — the prior false_positive judgment was
        re-examined by THIS analyst;
      * ``anchor_re_resolved`` — the current anchor was re-resolved after a
        supersession touched the tuple.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"intake:{tenant_id}:{record_id}")
        cur.execute(
            f"""
            SELECT {_INTAKE_COLUMNS}
            FROM intake_records
            WHERE tenant_id = %s AND id = %s
            FOR UPDATE;
            """,
            (str(tenant_id), str(record_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise IntakeNotFoundError(f"Intake record {record_id} not found")

        if row["state"] != "under_review":
            raise IntakeStateError(
                f"intake record {record_id} is in state '{row['state']}'; "
                "confirmation requires 'under_review'"
            )
        taxonomy_class = row["taxonomy_class"]
        if taxonomy_class is None:
            raise IntakeStateError(
                f"intake record {record_id} is unclassified — classification "
                "on the closed spine is required before confirmation"
            )

        # Anchorless classes (v1: NHI) can be held but NEVER confirmed —
        # named refusal, never a silent block (§3.6.6 #8).
        if taxonomy_class == "NHI":
            raise IntakeAnchorlessClassError(
                "class NHI has no exposure-anchor semantics yet (§3.6.6 #8) — "
                "the record can be held (needs_info) but not confirmed"
            )

        anchor_id = cmd.asset_id or row["asset_id"]
        if anchor_id is None:
            raise IntakeAnchorRequiredError(
                "confirmation requires an anchor: an active asset the "
                "evidence applies to (resolved at review time)"
            )

    finding_id = _resolve_finding_for_record(
        conn, tenant_id, row, actor_id=actor_id, actor_role=actor_role
    )

    # ---- exposure-tuple match over the FULL history (PATCH-06) -------------
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, status, resolved_at
            FROM asset_exposures
            WHERE tenant_id = %s AND finding_id = %s AND asset_id = %s
            ORDER BY confirmed_at DESC, resolved_at DESC NULLS LAST, id DESC;
            """,
            (str(tenant_id), str(finding_id), str(anchor_id)),
        )
        history = cur.fetchall()

        current = next((h for h in history if h["status"] == "confirmed"), None)
        if current is not None:
            return _commit_duplicate_outcome(
                conn, tenant_id, row, current["id"],
                reason="exact match against the tuple's current confirmed exposure",
                actor_id=actor_id, actor_role=actor_role,
            )

        terminal = [h for h in history if h["status"] != "confirmed"]
        latest = terminal[0] if terminal else None  # ordered resolved_at DESC
        if latest is not None and latest["status"] == "false_positive":
            if not cmd.revalidate_prior_judgment:
                return _commit_blocked_outcome(
                    conn, tenant_id, row,
                    outcome="blocked_false_positive",
                    reason=(
                        "the tuple's latest terminal episode is false_positive — "
                        "the prior not-applicable judgment must be re-examined "
                        "by an analyst (revalidate_prior_judgment=true)"
                    ),
                    actor_id=actor_id, actor_role=actor_role,
                )
        if latest is not None and latest["status"] == "superseded":
            if not cmd.anchor_re_resolved:
                return _commit_blocked_outcome(
                    conn, tenant_id, row,
                    outcome="blocked_superseded",
                    reason=(
                        "the tuple's history touches a superseded exposure — the "
                        "current anchor must be re-resolved first "
                        "(anchor_re_resolved=true)"
                    ),
                    actor_id=actor_id, actor_role=actor_role,
                )

    # ---- the one shared Ch.3 confirmation command --------------------------
    # (recurrence after 'resolved', fresh confirmation otherwise; the boundary
    # precondition for IDENTITY_POSTURE is enforced inside the command)
    review_reason = cmd.note or (
        "intake confirmation"
        + (" (prior false_positive judgment re-examined)"
           if cmd.revalidate_prior_judgment else "")
    )
    result = confirm_exposure(
        conn,
        tenant_id,
        ExposureConfirm(
            finding_id=finding_id,
            asset_id=anchor_id,
            evidence=cmd.evidence,
        ),
        actor_id=actor_id,
        actor_role=actor_role,
        review=ReviewCreate(
            finding_id=finding_id,
            asset_id=anchor_id,
            applicability="APPLICABLE",
            reason=review_reason,
        ),
    )

    if result.outcome == OUTCOME_REPLAY:
        # A concurrent writer committed the tuple's current episode between
        # our history read and the insert — converge on it as the duplicate.
        return _commit_duplicate_outcome(
            conn, tenant_id, row, result.exposure.id,
            reason="a concurrent confirmation committed the tuple's current "
                   "exposure; this record converges on it as the duplicate",
            actor_id=actor_id, actor_role=actor_role,
        )

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE intake_records
            SET state = 'confirmed',
                finding_id = %s,
                exposure_id = %s,
                asset_id = %s,
                anchor_state = 'resolved',
                reviewed_by = %s,
                reviewed_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING {_INTAKE_COLUMNS};
            """,
            (
                str(finding_id), str(result.exposure.id), str(anchor_id),
                actor_id, str(tenant_id), str(record_id),
            ),
        )
        record = IntakeRecord.model_validate(cur.fetchone())
        _record_event(
            cur, tenant_id, record.id, event="confirmed",
            actor_id=actor_id, actor_role=actor_role,
            detail={
                "finding_id": str(record.finding_id),
                "exposure_id": str(record.exposure_id),
                "anchor_re_resolved": cmd.anchor_re_resolved,
                "revalidate_prior_judgment": cmd.revalidate_prior_judgment,
            },
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="intake.confirmed",
            asset_id=record.asset_id,
            details={
                "intake_record_id": str(record.id),
                "finding_id": str(record.finding_id),
                "exposure_id": str(record.exposure_id),
                "asset_id": str(record.asset_id),
                "taxonomy_class": record.taxonomy_class,
            },
        )
        return IntakeConfirmResult(
            outcome="confirmed", record=record,
            duplicate_of_exposure_id=None, blocked_reason=None,
        )


def _commit_duplicate_outcome(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    row: dict,
    duplicate_of_exposure_id: uuid.UUID,
    *,
    reason: str,
    actor_id: str,
    actor_role: str,
) -> IntakeConfirmResult:
    """Terminal-duplicate: the record persists with the reference — no
    duplicate finding is created merely to have something to link."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE intake_records
            SET state = 'duplicate',
                duplicate_of_exposure_id = %s,
                duplicate_reason = %s,
                reviewed_by = %s,
                reviewed_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING {_INTAKE_COLUMNS};
            """,
            (
                str(duplicate_of_exposure_id), reason, actor_id,
                str(tenant_id), str(row["id"]),
            ),
        )
        record = IntakeRecord.model_validate(cur.fetchone())
        _record_event(
            cur, tenant_id, record.id, event="duplicate_recorded",
            actor_id=actor_id, actor_role=actor_role,
            detail={
                "duplicate_of_exposure_id": str(duplicate_of_exposure_id),
                "reason": reason,
            },
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="intake.duplicate_recorded",
            asset_id=None,
            details={
                "intake_record_id": str(record.id),
                "duplicate_of_exposure_id": str(duplicate_of_exposure_id),
            },
        )
        return IntakeConfirmResult(
            outcome="duplicate", record=record,
            duplicate_of_exposure_id=duplicate_of_exposure_id, blocked_reason=reason,
        )


def _commit_blocked_outcome(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    row: dict,
    *,
    outcome: str,
    reason: str,
    actor_id: str,
    actor_role: str,
) -> IntakeConfirmResult:
    """A committed refusal that leaves the record in review: the attempt and
    its named reason land on the record's trail; the record stays
    'under_review' and the route renders the 409."""
    with conn.cursor(row_factory=dict_row) as cur:
        _record_event(
            cur, tenant_id, row["id"], event="confirm_blocked",
            actor_id=actor_id, actor_role=actor_role, detail={"reason": reason},
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="intake.confirm_blocked",
            asset_id=None,
            details={
                "intake_record_id": str(row["id"]),
                "blocked": outcome,
                "reason": reason,
            },
        )
        return IntakeConfirmResult(
            outcome=outcome, record=IntakeRecord.model_validate(row),
            duplicate_of_exposure_id=None, blocked_reason=reason,
        )


def _resolve_finding_for_record(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    row: dict,
    *,
    actor_id: str,
    actor_role: str,
) -> uuid.UUID:
    """Finding identity (PATCH-06, v1): a CVE intake reuses the tenant's one
    finding per canonical CVE (the shared serialized allocator); a non-CVE
    intake matches the conservative v1 signature (title + closed taxonomy
    triple) and creates the finding + classification when nothing matches.
    Multiple signature matches are AMBIGUOUS — review, never auto-resolve."""
    finding_id: Optional[uuid.UUID]
    if row["canonical_cve_id"] is not None:
        return allocate_finding_for_cve(
            conn,
            tenant_id,
            row["canonical_cve_id"],
            default_title=row["title"],
            default_severity=row["severity"],
            default_description=row["description"],
            actor_id=actor_id,
            actor_role=actor_role,
        )

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT DISTINCT f.id
            FROM findings f
            WHERE f.tenant_id = %s
              AND f.canonical_cve_id IS NULL
              AND f.title = %s
              AND EXISTS (
                    SELECT 1 FROM non_cve_classifications c
                    WHERE c.tenant_id = f.tenant_id
                      AND c.finding_id = f.id
                      AND c.taxonomy_class = %s
                      AND c.taxonomy_subclass IS NOT DISTINCT FROM %s
                      AND c.taxonomy_subtype IS NOT DISTINCT FROM %s
              )
            ORDER BY f.id;
            """,
            (
                str(tenant_id), row["title"], row["taxonomy_class"],
                row["taxonomy_subclass"], row["taxonomy_subtype"],
            ),
        )
        matches = [r["id"] for r in cur.fetchall()]
        if len(matches) > 1:
            raise IntakeAmbiguousIdentityError(
                f"{len(matches)} findings match the intake identity "
                f"(title + {row['taxonomy_class']} spine) — ambiguous identity "
                "is a review decision, never an auto-resolve (PATCH-06)"
            )
        if matches:
            return matches[0]

        finding = create_finding(
            conn,
            tenant_id,
            FindingCreate(
                title=row["title"],
                severity=row["severity"],
                description=row["description"],
                canonical_cve_id=None,
            ),
        )
        # The classification spine travels with the finding (path 'manual' —
        # the analyst-classified vocabulary of migration 022; NO derivation is
        # published: intake classifies, it never scores).
        cur.execute(
            "SELECT xmin::text AS revision FROM findings "
            "WHERE tenant_id = %s AND id = %s;",
            (str(tenant_id), str(finding.id)),
        )
        revision = cur.fetchone()["revision"]
        cur.execute(
            """
            INSERT INTO non_cve_classifications (
                tenant_id, finding_id, finding_revision_xmin,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, version_id_ref, inputs, evidence, validation_state,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, %s, %s, 'manual', NULL, %s::jsonb, %s::jsonb,
                'single_source', %s, %s
            )
            RETURNING id;
            """,
            (
                str(tenant_id), str(finding.id), revision,
                row["taxonomy_class"], row["taxonomy_subclass"],
                row["taxonomy_subtype"],
                json.dumps({
                    "source": "intake",
                    "intake_record_id": str(row["id"]),
                }),
                json.dumps({"intake_record_id": str(row["id"])}),
                actor_id, actor_role,
            ),
        )
        finding_id = finding.id

    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role, event_name="intake.finding_created",
        asset_id=None,
        details={
            "finding_id": str(finding_id),
            "intake_record_id": str(row["id"]),
            "taxonomy_class": row["taxonomy_class"],
        },
    )
    return finding_id


# ---------------------------------------------------------------------------
# Connector registrations (destination routing + payload semantics ONLY)
# ---------------------------------------------------------------------------


def register_connector(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    name: str,
    adapter: str,
    destination_routing: dict,
    payload_semantics: Optional[str],
    actor_id: str,
    actor_role: str,
) -> ConnectorRegistration:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO intake_connector_registrations (
                tenant_id, name, adapter, destination_routing,
                payload_semantics, created_by
            ) VALUES (%s, %s, %s, %s::jsonb, %s, %s)
            ON CONFLICT (tenant_id, name) DO UPDATE
                SET adapter = EXCLUDED.adapter,
                    destination_routing = EXCLUDED.destination_routing,
                    payload_semantics = EXCLUDED.payload_semantics,
                    status = 'active',
                    updated_at = now()
            RETURNING id, tenant_id, name, adapter, status, destination_routing,
                      payload_semantics, created_by, created_at, updated_at;
            """,
            (
                str(tenant_id), name, adapter,
                json.dumps(destination_routing), payload_semantics, actor_id,
            ),
        )
        registration = ConnectorRegistration.model_validate(cur.fetchone())

    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role, event_name="intake.connector_registered",
        asset_id=None,
        details={
            "registration_id": str(registration.id),
            "name": registration.name,
            "adapter": registration.adapter,
        },
    )
    return registration


def list_connectors(
    conn: psycopg.Connection, tenant_id: uuid.UUID
) -> list[ConnectorRegistration]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, name, adapter, status, destination_routing,
                   payload_semantics, created_by, created_at, updated_at
            FROM intake_connector_registrations
            WHERE tenant_id = %s
            ORDER BY created_at DESC, id DESC;
            """,
            (str(tenant_id),),
        )
        return [ConnectorRegistration.model_validate(r) for r in cur.fetchall()]
