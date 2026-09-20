# backend/app/strike/operations.py
"""Operation execution truth, artifacts, and discovery routing
(PRD-000 v1.11 Ch.4 principles 7/8/10, owned-state table, Flow C).

Dispatch is fail-closed at every gate BEFORE anything runs: the engagement
must be active and inside its window, the workspace live, the target
approved and fresh, the ability on the approved allowlist (principle 7:
curated, versioned, pinned — nothing runs that is not on it). Each refusal
is named; nothing is improvised.

Execution truth: the engine seam (like the provider seam — the engine
decision is frozen-open, Ch.4 open decision #6) is two-phase: the dispatch
record is durable first, then the engine call classifies into running /
failed(ERROR) / cancel paths. Engine/transport failure is outcome ERROR —
never PREVENTED, never NOT_EXECUTED (target truth remains unknown). A
collected result passes the classifier, which refuses EXPLOITABLE/PREVENTED
(the POC A rule; outcomes.py).

Cancellation must CONFIRM the stop: confirmed → 'cancelled';
unconfirmed → 'cancel_unconfirmed' (alarm, operator reconciliation) — never
a clean 'cancelled' (principle 8 / the CALDERA cleanup precedent).

Artifacts are bounded, hashed (SHA-256, computed server-side), immutable on
write, retention-tiered. Artifact download is hash-verified at read and
audited (Appendix C Q12).

Discoveries NEVER create findings: ``report_discovery`` routes a Ch.6 intake
record (source ``STRIKE_DISCOVERY``) carrying the operation/artifact
references — Flow C; Ch.6/Ch.3 decide what is real and how bad.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import uuid

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.service import _advisory_xact_lock
from app.strike import outcomes as strike_outcomes
from app.strike.errors import (
    AbilityNotAllowlistedError,
    EngineUnavailableError,
    OperationNotFoundError,
    OperationStateError,
    OutputBoundError,
    TargetExpiredError,
    TargetStateError,
    WorkspaceStateError,
)
from app.strike.service import (
    assert_engagement_operable,
    load_engagement,
    load_target,
    target_is_expired,
    utcnow,
)

#: Bounded engine output / artifact caps (the POC A 64 KiB output bound).
MAX_OUTPUT_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024

LIVE_WORKSPACE_STATES = ("ready", "in_use")


# ---------------------------------------------------------------------------
# Engine seam (frozen-open engine decision — POC A/B adapters are the future
# implementations; the shipped default has no engine integrated)
# ---------------------------------------------------------------------------


class CancelUnconfirmed(Exception):
    """The engine could not confirm the stop."""


def engine_dispatch(operation: dict) -> str:
    """Seam: dispatch the operation to its engine; returns the native
    engine operation reference. The shipped implementation fails closed."""
    raise EngineUnavailableError(
        f"no execution engine is integrated for engine {operation['engine']!r} "
        "(PRD Ch.4 open decision #6) — the operation records outcome ERROR; "
        "target truth remains unknown"
    )


def engine_cancel(operation: dict) -> None:
    """Seam: request termination. Raises CancelUnconfirmed when the stop
    cannot be confirmed (the CALDERA PATCH state=cleanup precedent)."""
    raise EngineUnavailableError(
        "no execution engine is integrated — the stop cannot be confirmed"
    )


# ---------------------------------------------------------------------------
# Row access
# ---------------------------------------------------------------------------


def load_operation(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, operation_id: uuid.UUID,
    *, for_update: bool = False,
) -> dict:
    cur.execute(
        "SELECT * FROM strike_operations WHERE tenant_id = %s AND id = %s"
        + (" FOR UPDATE;" if for_update else ";"),
        (str(tenant_id), str(operation_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise OperationNotFoundError(f"Operation {operation_id} not found")
    return row


# ---------------------------------------------------------------------------
# Dispatch — phase 1: durable record; phase 2: engine call
# ---------------------------------------------------------------------------


def dispatch_operation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Phase 1 — validate every gate, then durably record the dispatched
    operation (stable persisted identity, PATCH-04). The caller commits
    before ``dispatch_to_engine`` runs."""
    now = utcnow()
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        engagement = load_engagement(cur, tenant_id, engagement_id)
        assert_engagement_operable(engagement, allow_states=("active",), now=now)

        workspace = _load_workspace_for_operation(cur, tenant_id, data.workspace_id)
        if workspace["engagement_id"] != engagement["id"]:
            raise WorkspaceStateError(
                f"workspace {data.workspace_id} belongs to a different engagement"
            )
        if workspace["state"] not in LIVE_WORKSPACE_STATES:
            raise WorkspaceStateError(
                f"workspace {data.workspace_id} is {workspace['state']!r}; "
                "operations dispatch against a live workspace only"
            )

        target = load_target(cur, tenant_id, data.target_id)
        if target["engagement_id"] != engagement["id"]:
            raise TargetStateError(
                f"target {data.target_id} belongs to a different engagement"
            )
        if target["state"] != "approved":
            raise TargetStateError(
                f"target {data.target_id} is {target['state']!r} — operations "
                "run against approved targets only"
            )
        # derived expiry is enforcement-immediate (failure modes)
        if target_is_expired(target, now=now):
            raise TargetExpiredError(
                f"target {data.target_id} authorization expired at "
                f"{target['expires_at'].isoformat()}"
            )

        ability = _load_ability(cur, data.ability_id)

        cur.execute(
            """
            INSERT INTO strike_operations (
                tenant_id, engagement_id, workspace_id, target_id, ability_id,
                state, engine, requested_by, native_output
            ) VALUES (%s, %s, %s, %s, %s, 'dispatched', %s, %s, %s::jsonb)
            RETURNING *;
            """,
            (
                str(tenant_id), str(engagement_id), str(data.workspace_id),
                str(data.target_id), str(data.ability_id),
                ability["engine"], actor_id, json.dumps(data.params),
            ),
        )
        operation = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.operation_dispatched",
            details={
                "operation_id": str(operation["id"]),
                "engagement_id": str(engagement_id),
                "workspace_id": str(data.workspace_id),
                "target_id": str(data.target_id),
                "ability_id": str(data.ability_id),
                "ability_slug": ability["slug"],
                "engine": ability["engine"],
            },
        )
        return dict(operation)


def _load_workspace_for_operation(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, workspace_id: uuid.UUID
) -> dict:
    from app.strike.workspaces import load_workspace

    return load_workspace(cur, tenant_id, workspace_id)


def _load_ability(cur, ability_id) -> dict:
    cur.execute(
        """
        SELECT id, slug, engine, version, active
        FROM strike_abilities WHERE id = %s;
        """,
        (str(ability_id),),
    )
    ability = cur.fetchone()
    if ability is None or not ability["active"]:
        raise AbilityNotAllowlistedError(
            f"ability {ability_id} is not on the approved allowlist — nothing "
            "runs that is not on it (principle 7)"
        )
    return ability


def dispatch_to_engine(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    operation_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Phase 2 — carry the durable dispatch record to the engine. Accepted ⇒
    'running' (+ native reference); refusal/absent engine ⇒ 'failed' with
    outcome ERROR (engine/transport failure never translates into PREVENTED
    or NOT_EXECUTED)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-operation:{tenant_id}:{operation_id}")
        operation = load_operation(cur, tenant_id, operation_id, for_update=True)
        if operation["state"] != "dispatched":
            raise OperationStateError(
                f"operation {operation_id} is {operation['state']!r}; only a "
                "dispatched operation is sent to the engine"
            )
        view = dict(operation)
        view["id"] = str(view["id"])

    try:
        engine_ref = engine_dispatch(view)
    except Exception as exc:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                UPDATE strike_operations
                SET state = 'failed', outcome = 'ERROR', completed_at = now(),
                    native_output = %s::jsonb, updated_at = now()
                WHERE tenant_id = %s AND id = %s
                RETURNING *;
                """,
                (
                    json.dumps({"error": str(exc), "phase": "dispatch"}),
                    str(tenant_id), str(operation_id),
                ),
            )
            failed = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.operation_failed",
            details={
                "operation_id": str(operation_id),
                "outcome": "ERROR",
                "phase": "dispatch",
                "error": str(exc),
                "note": "engine/transport failure — target truth remains "
                        "unknown, never PREVENTED or NOT_EXECUTED",
            },
        )
        return dict(failed)

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE strike_operations
            SET state = 'running', running_at = now(),
                engine_operation_ref = %s, updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (engine_ref, str(tenant_id), str(operation_id)),
        )
        running = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.operation_running",
            details={
                "operation_id": str(operation_id),
                "engine_operation_ref": engine_ref,
            },
        )
        return dict(running)


# ---------------------------------------------------------------------------
# Completion / cancellation
# ---------------------------------------------------------------------------


def complete_operation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    operation_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Record a collected result (running → completed). The reported outcome
    passes the classifier — EXPLOITABLE/PREVENTED refused (the POC A rule).
    Native output is bounded (64 KiB, the POC A bound)."""
    outcome = strike_outcomes.classify_reported_outcome(data.outcome)
    if data.native_output is not None:
        raw = json.dumps(data.native_output, default=str)
        if len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise OutputBoundError(
                f"native_output exceeds the {MAX_OUTPUT_BYTES}-byte bound — "
                "store an artifact instead"
            )
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-operation:{tenant_id}:{operation_id}")
        operation = load_operation(cur, tenant_id, operation_id, for_update=True)
        if operation["state"] != "running":
            raise OperationStateError(
                f"operation {operation_id} is {operation['state']!r}; results "
                "complete a running operation"
            )
        cur.execute(
            """
            UPDATE strike_operations
            SET state = 'completed', outcome = %s, output_summary = %s,
                native_output = COALESCE(%s::jsonb, native_output),
                completed_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (
                outcome, data.summary,
                json.dumps(data.native_output) if data.native_output is not None else None,
                str(tenant_id), str(operation_id),
            ),
        )
        completed = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.operation_completed",
            details={
                "operation_id": str(operation_id),
                "outcome": outcome,
                "summary": data.summary,
            },
        )
        return dict(completed)


def cancel_operation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    operation_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """running/dispatched → cancelling → engine stop → 'cancelled' ONLY on
    CONFIRMED termination; an unconfirmed stop lands 'cancel_unconfirmed'
    (alarm, operator reconciliation) — never a clean 'cancelled'."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-operation:{tenant_id}:{operation_id}")
        operation = load_operation(cur, tenant_id, operation_id, for_update=True)
        if operation["state"] not in ("dispatched", "running"):
            raise OperationStateError(
                f"operation {operation_id} is {operation['state']!r}; only a "
                "dispatched/running operation can be cancelled"
            )
        cur.execute(
            """
            UPDATE strike_operations
            SET state = 'cancelling', cancel_requested_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(operation_id)),
        )
        view = dict(cur.fetchone())
        view["id"] = str(view["id"])

    try:
        engine_cancel(view)
        confirmed, cancel_error = True, None
    except Exception as exc:
        confirmed, cancel_error = False, str(exc)

    with conn.cursor(row_factory=dict_row) as cur:
        if confirmed:
            # outcome stays NULL on cancelled: whether anything executed
            # before the confirmed stop is not established here — uncertainty
            # preserves truth (the outcome enum is for collected results)
            cur.execute(
                """
                UPDATE strike_operations
                SET state = 'cancelled',
                    cancel_confirmed_at = now(), completed_at = now(),
                    updated_at = now()
                WHERE tenant_id = %s AND id = %s
                RETURNING *;
                """,
                (str(tenant_id), str(operation_id)),
            )
            cancelled = cur.fetchone()
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role=actor_role, event_name="strike.operation_cancelled",
                details={
                    "operation_id": str(operation_id),
                    "note": "termination CONFIRMED — the only path to "
                            "cancelled",
                },
            )
            return dict(cancelled)

        cur.execute(
            """
            UPDATE strike_operations
            SET state = 'cancel_unconfirmed', completed_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(operation_id)),
        )
        unconfirmed = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.operation_cancel_unconfirmed",
            details={
                "operation_id": str(operation_id),
                "error": cancel_error,
                "note": "stop could not be confirmed — alarm; operator "
                        "reconciliation; never a clean cancelled",
            },
        )
        return dict(unconfirmed)


def list_operations(
    conn: psycopg.Connection, tenant_id: uuid.UUID, engagement_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        load_engagement(cur, tenant_id, engagement_id)
        cur.execute(
            """
            SELECT o.*, a.slug AS ability_slug, t.target_value
            FROM strike_operations o
            JOIN strike_abilities a ON a.id = o.ability_id
            JOIN strike_targets t ON t.id = o.target_id
            WHERE o.tenant_id = %s AND o.engagement_id = %s
            ORDER BY o.dispatched_at DESC, o.id;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Artifacts — bounded, hashed, immutable
# ---------------------------------------------------------------------------


def store_artifact(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    operation_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Collect an artifact: SHA-256 computed SERVER-SIDE over the bytes,
    bounded size, immutable row (migration 028 trigger). The workspace's
    claims are never trusted — hashing here is integrity, not authenticity
    (principle 9: artifacts are untrusted inputs to promotion)."""
    try:
        content = base64.b64decode(data.content_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OutputBoundError(f"content_b64 is not valid base64: {exc}") from exc
    if len(content) > MAX_ARTIFACT_BYTES:
        raise OutputBoundError(
            f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte bound — retention "
            "and storage backend are open decision #5; keep artifacts bounded"
        )
    sha256 = hashlib.sha256(content).hexdigest()
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-operation:{tenant_id}:{operation_id}")
        operation = load_operation(cur, tenant_id, operation_id)
        cur.execute(
            """
            INSERT INTO strike_artifacts (
                tenant_id, engagement_id, operation_id, name, media_type,
                size_bytes, sha256, content, retention_tier, collected_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, tenant_id, engagement_id, operation_id, name,
                      media_type, size_bytes, sha256, retention_tier,
                      collected_by, created_at;
            """,
            (
                str(tenant_id), str(operation["engagement_id"]), str(operation_id),
                data.name, data.media_type, len(content), sha256, content,
                data.retention_tier, actor_id,
            ),
        )
        artifact = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.artifact_stored",
            details={
                "artifact_id": str(artifact["id"]),
                "operation_id": str(operation_id),
                "name": data.name,
                "size_bytes": len(content),
                "sha256": sha256,
                "retention_tier": data.retention_tier,
            },
        )
        return dict(artifact)


def read_artifact(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    artifact_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Hash-verified artifact read — audited as an evidence download
    (Appendix C Q12). A hash mismatch fails closed (corrupt/immutability
    breach), never silently serves."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT * FROM strike_artifacts WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(artifact_id)),
        )
        artifact = cur.fetchone()
        if artifact is None:
            from app.strike.errors import StrikeNotFoundError

            raise StrikeNotFoundError(f"Artifact {artifact_id} not found")
        actual = hashlib.sha256(artifact["content"]).hexdigest()
        if actual != artifact["sha256"]:
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role=actor_role, event_name="strike.artifact_hash_mismatch",
                details={"artifact_id": str(artifact_id)},
            )
            raise OutputBoundError(
                f"artifact {artifact_id} failed hash verification — refusing "
                "to serve (fail-closed)"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.artifact_downloaded",
            details={
                "artifact_id": str(artifact_id),
                "operation_id": str(artifact["operation_id"]),
                "sha256": artifact["sha256"],
            },
        )
        return dict(artifact)


# ---------------------------------------------------------------------------
# Discovery (Flow C) — route to Ch.6 intake, never a finding
# ---------------------------------------------------------------------------


def report_discovery(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Flow C: a discovery becomes a Ch.6 INTAKE RECORD carrying the
    engagement/operation/artifact references — STRIKE never creates findings
    and never bypasses the confirmation/scoring authority."""
    from app.intake.models import IntakeCreate
    from app.intake.service import create_intake_record

    with conn.cursor(row_factory=dict_row) as cur:
        operation = load_operation(cur, tenant_id, data.operation_id)
        cur.execute(
            """
            SELECT id, sha256, name FROM strike_artifacts
            WHERE tenant_id = %s AND operation_id = %s;
            """,
            (str(tenant_id), str(data.operation_id)),
        )
        artifacts = [
            {"artifact_id": str(r["id"]), "name": r["name"], "sha256": r["sha256"]}
            for r in cur.fetchall()
        ]

    payload = {
        "strike_engagement_id": str(operation["engagement_id"]),
        "strike_operation_id": str(operation["id"]),
        "strike_workspace_id": str(operation["workspace_id"]),
        "strike_target_id": str(operation["target_id"]),
        "operation_outcome": operation["outcome"],
        "artifact_references": artifacts,
    }
    registration = f"strike:{operation['engagement_id']}"
    event_id = data.source_event_id or f"op:{operation['id']}:discovery"
    intake_data = IntakeCreate(
        source="STRIKE_DISCOVERY",
        title=data.title,
        severity=data.severity,
        payload=payload,
        description=data.description,
        canonical_cve_id=data.canonical_cve_id,
        asset_id=data.asset_id,
        source_registration_id=registration,
        source_event_id=event_id,
    )
    result = create_intake_record(
        conn, tenant_id, intake_data, actor_id=actor_id, actor_role=actor_role
    )
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role, event_name="strike.discovery_submitted",
        details={
            "operation_id": str(operation["id"]),
            "intake_record_id": str(result.record.id),
            "intake_outcome": result.outcome,
            "artifact_count": len(artifacts),
        },
    )
    return {
        "intake_record_id": str(result.record.id),
        "intake_state": result.record.state,
        "outcome": result.outcome,
        "operation_id": str(operation["id"]),
    }
