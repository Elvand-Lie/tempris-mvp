# backend/app/strike/workspaces.py
"""The disposable per-engagement workspace lifecycle (PRD-000 v1.11 Ch.4
principles 2/4, PATCH-02/03/04).

Cardinality lock: ONE live workspace per engagement at a time (a partial
unique index in migration 028 enforces it in storage) — sequential
generations after failure/destruction are allowed and remain historical.

Recovery-safe provisioning (PATCH-04), in the exact order the contract
names:
  1. ``reserve_workspace`` — the generation is atomically RESERVED (row
     written, state 'provisioning', egress policy compiled from approved
     fresh targets) and DURABLY COMMITTED by the caller's transaction —
     BEFORE any external provider call exists;
  2. ``provision_reservation`` — a SECOND transaction carries the stable
     persisted reservation identity to the provider and classifies the
     outcome honestly:
       - provider acceptance → 'ready' (+ native reference recorded);
       - provider refusal / no provider configured → 'provision_failed'
         (an ALARM state — operator action required, never silent; truthful
         because nothing was dispatched externally);
       - UNKNOWN outcome (accepted, response lost) → the workspace STAYS
         'provisioning' with the uncertainty recorded — reconcile before any
         retry, because execution may have occurred and a blind retry could
         create a second VM; the cardinality lock holds while it stands, so
         retry is impossible until an operator reconciles.
       ERROR is never proof of non-execution;
  3. ``reconcile_workspace`` — operator reconciliation confirms fencing of
     the predecessor generation and retires the row, releasing the lock so
     replacement can be reserved.

Destruction is the same two-phase shape: ``begin_workspace_destroy`` durably
marks 'destroying', then ``finish_workspace_destroy`` calls the provider and
lands 'destroyed' on CONFIRMED termination or 'destroy_failed' (alarm,
operator reconciliation) — never silently destroyed (PATCH-02).

Enforcement lives OUTSIDE the workspace (principle 4): the control plane
compiles approved destinations into ``egress_policy`` at reservation and
``bump_egress_generation`` raises ``egress_generation`` on every target
authorization change — stale policy generations can never reactivate
(PATCH-02/03). With no provider configured (frozen-open decision #1),
provisioning fails closed with the named alarm; nothing is fabricated.

The provider seam is deliberately tiny: two module functions, monkeypatched
by tests, to be implemented against the real hypervisor/cloud provider once
the open provider decision lands.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.service import _advisory_xact_lock
from app.strike.errors import (
    WorkspaceCardinalityError,
    WorkspaceNotFoundError,
    WorkspaceProviderUnavailableError,
    WorkspaceStateError,
)
from app.strike.service import assert_engagement_operable, load_engagement, utcnow

# ---------------------------------------------------------------------------
# Provider seam (the ONLY integration point to the outside world)
# ---------------------------------------------------------------------------

#: Configured provider name, or None = none configured (the shipped default:
#: the provider decision is frozen-open, PRD Ch.4 open decision #1).
PROVIDER_NAME: Optional[str] = None


class ProvisionUnknownOutcome(Exception):
    """The provider accepted the request but the outcome is unknown (the
    response was lost). Execution may have occurred — reconcile before any
    retry."""


def provider_provision(reservation: dict) -> str:
    """Seam: create the workspace VM for the reservation. Returns the native
    provider reference. The shipped implementation fails closed: no provider
    is configured, so nothing external is dispatched and the caller records
    a truthful provision_failed alarm."""
    raise WorkspaceProviderUnavailableError(
        "no workspace provider is configured (PRD Ch.4 open decision #1) — "
        "the reservation stays truthful; nothing was dispatched externally"
    )


def provider_terminate(workspace: dict) -> bool:
    """Seam: destroy the workspace VM. Returns True only when termination is
    CONFIRMED; False (or a raise) means unresolved — the caller marks
    destroy_failed and reconciliation follows."""
    raise WorkspaceProviderUnavailableError(
        "no workspace provider is configured — termination cannot be "
        "attempted or confirmed"
    )


LIVE_WORKSPACE_STATES = (
    "provisioning", "ready", "in_use", "collecting",
    "destroying", "destroy_failed", "provision_failed",
)


# ---------------------------------------------------------------------------
# Row access
# ---------------------------------------------------------------------------


def load_workspace(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, workspace_id: uuid.UUID,
    *, for_update: bool = False,
) -> dict:
    cur.execute(
        "SELECT * FROM strike_workspaces WHERE tenant_id = %s AND id = %s"
        + (" FOR UPDATE;" if for_update else ";"),
        (str(tenant_id), str(workspace_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise WorkspaceNotFoundError(f"Workspace {workspace_id} not found")
    return row


def bump_egress_generation(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, engagement_id: uuid.UUID
) -> None:
    """Enforcement-immediate target-change propagation (PATCH-02/03): every
    live workspace of the engagement gets its egress generation bumped so
    stale compiled policies can never reactivate. A cheap no-op when no live
    workspace exists."""
    cur.execute(
        """
        UPDATE strike_workspaces
        SET egress_generation = egress_generation + 1, updated_at = now()
        WHERE tenant_id = %s AND engagement_id = %s
          AND state IN ('provisioning', 'ready', 'in_use', 'collecting',
                        'destroying', 'destroy_failed', 'provision_failed');
        """,
        (str(tenant_id), str(engagement_id)),
    )


def _compile_egress_policy(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, engagement_id: uuid.UUID
) -> list[dict]:
    """The approved, fresh, non-revoked destinations pinned at reservation
    (PATCH-03: enforcement binds to concrete pinned destinations)."""
    now = utcnow()
    cur.execute(
        """
        SELECT target_type, target_value, normalized_target,
               authorization_version
        FROM strike_targets
        WHERE tenant_id = %s AND engagement_id = %s AND state = 'approved'
          AND expires_at > %s;
        """,
        (str(tenant_id), str(engagement_id), now),
    )
    return [
        {
            "target_type": r["target_type"],
            "target_value": r["target_value"],
            "normalized_target": r["normalized_target"],
            "authorization_version": r["authorization_version"],
        }
        for r in cur.fetchall()
    ]


def _reservation_view(workspace: dict) -> dict:
    """The stable persisted identity provider calls carry (PATCH-04)."""
    return {
        "workspace_id": str(workspace["id"]),
        "tenant_id": str(workspace["tenant_id"]),
        "engagement_id": str(workspace["engagement_id"]),
        "generation": workspace["generation"],
        "egress_policy": workspace["egress_policy"],
    }


# ---------------------------------------------------------------------------
# Provisioning — reserve (tx 1), then provision (tx 2)
# ---------------------------------------------------------------------------


def reserve_workspace(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Phase 1 — atomically reserve the next workspace generation and
    compile the pinned egress policy. NO external call happens here; the
    caller commits this transaction before ``provision_reservation`` runs.
    The cardinality lock (partial unique index) refuses a second live
    workspace — the named conflict surfaces as a 409."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        engagement = load_engagement(cur, tenant_id, engagement_id, for_update=True)
        assert_engagement_operable(engagement, allow_states=("authorized", "active"))

        cur.execute(
            """
            SELECT COALESCE(MAX(generation), 0) + 1 AS next_gen
            FROM strike_workspaces
            WHERE tenant_id = %s AND engagement_id = %s;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        generation = cur.fetchone()["next_gen"]

        egress = _compile_egress_policy(cur, tenant_id, engagement_id)
        try:
            cur.execute(
                """
                INSERT INTO strike_workspaces (
                    tenant_id, engagement_id, generation, state, egress_policy,
                    reserved_by
                ) VALUES (%s, %s, %s, 'provisioning', %s::jsonb, %s)
                RETURNING *;
                """,
                (
                    str(tenant_id), str(engagement_id), generation,
                    json.dumps(egress), actor_id,
                ),
            )
        except psycopg.errors.UniqueViolation:
            # the cardinality lock (partial unique index over the live
            # states): the standing generation must be reconciled/fenced
            # before any replacement — a named 409, never a second VM
            raise WorkspaceCardinalityError(
                f"engagement {engagement_id} already has a live workspace "
                "generation — reconcile/fence it before reserving a "
                "replacement (PATCH-04: blind retry never creates a second VM)"
            )
        reservation = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_reserved",
            details={
                "workspace_id": str(reservation["id"]),
                "generation": generation,
                "engagement_id": str(engagement_id),
                "egress_generation": reservation["egress_generation"],
                "egress_targets": len(egress),
            },
        )
        return dict(reservation)


def provision_reservation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Phase 2 — carry the durable reservation to the provider and classify
    the outcome (ready / provisioning-unknown / provision_failed). Runs in
    its own committed transaction; a workspace whose outcome is already
    unknown refuses re-attempt (reconcile before retry — PATCH-04).

    The FOR UPDATE row lock taken below is TRANSACTION-scoped, so it
    deliberately spans the provider call: two concurrent provision attempts
    of one reservation serialize, and the loser re-checks state — a second
    VM is impossible (PATCH-04)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-workspace:{tenant_id}:{workspace_id}")
        workspace = load_workspace(cur, tenant_id, workspace_id, for_update=True)
        if workspace["state"] != "provisioning":
            raise WorkspaceStateError(
                f"workspace {workspace_id} is {workspace['state']!r}; only a "
                "provisioning reservation is provisionable"
            )
        if workspace["last_error"] is not None:
            raise WorkspaceStateError(
                f"workspace {workspace_id} has an unresolved prior "
                "provisioning attempt (outcome unknown) — reconcile before "
                "any retry; a blind retry could create a second VM"
            )

    try:
        provider_ref = provider_provision(_reservation_view(workspace))
    except ProvisionUnknownOutcome as exc:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                UPDATE strike_workspaces
                SET last_error = %s, updated_at = now()
                WHERE tenant_id = %s AND id = %s
                RETURNING *;
                """,
                (f"provisioning outcome UNKNOWN: {exc}", str(tenant_id), str(workspace_id)),
            )
            unknown = cur.fetchone()
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role=actor_role, event_name="strike.workspace_provision_unknown",
                details={
                    "workspace_id": str(workspace_id),
                    "generation": unknown["generation"],
                    "note": "outcome unknown — reconcile before any retry; "
                            "execution may have occurred",
                },
            )
            return dict(unknown)
    except Exception as exc:  # refusal / unconfigured provider: truthful alarm
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                UPDATE strike_workspaces
                SET state = 'provision_failed', last_error = %s, updated_at = now()
                WHERE tenant_id = %s AND id = %s
                RETURNING *;
                """,
                (f"provisioning failed before acceptance: {exc}", str(tenant_id), str(workspace_id)),
            )
            failed = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_provision_failed",
            details={
                "workspace_id": str(workspace_id),
                "generation": failed["generation"],
                "error": str(exc),
            },
        )
        return dict(failed)

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE strike_workspaces
            SET state = 'ready', provider = %s,
                provider_workspace_ref = %s, provisioned_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (PROVIDER_NAME or "configured", provider_ref, str(tenant_id), str(workspace_id)),
        )
        ready = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_provisioned",
            details={
                "workspace_id": str(workspace_id),
                "generation": ready["generation"],
                "provider_ref": ready["provider_workspace_ref"],
            },
        )
        return dict(ready)


# ---------------------------------------------------------------------------
# Workspace usage transitions
# ---------------------------------------------------------------------------


def mark_workspace_in_use(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        row = load_workspace(cur, tenant_id, workspace_id, for_update=True)
        if row["state"] not in ("ready", "in_use"):
            raise WorkspaceStateError(
                f"workspace {workspace_id} is {row['state']!r}; only a ready "
                "workspace enters in_use"
            )
        cur.execute(
            """
            UPDATE strike_workspaces SET state = 'in_use', updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(workspace_id)),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_in_use",
            details={"workspace_id": str(workspace_id)},
        )
        return dict(cur.fetchone())


def mark_collecting(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """in_use → collecting: artifact collection starts (eventual per Q15 —
    collection itself is asynchronous workspace work)."""
    with conn.cursor(row_factory=dict_row) as cur:
        row = load_workspace(cur, tenant_id, workspace_id, for_update=True)
        if row["state"] != "in_use":
            raise WorkspaceStateError(
                f"workspace {workspace_id} is {row['state']!r}; only in_use "
                "enters collecting"
            )
        cur.execute(
            """
            UPDATE strike_workspaces SET state = 'collecting', updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(workspace_id)),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_collecting",
            details={"workspace_id": str(workspace_id)},
        )
        return dict(cur.fetchone())


# ---------------------------------------------------------------------------
# Destruction — begin (tx 1), then finish (tx 2)
# ---------------------------------------------------------------------------


def begin_workspace_destroy(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Phase 1 — durably mark 'destroying' (explicit, audited). The caller
    commits before the provider is asked to terminate."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-workspace:{tenant_id}:{workspace_id}")
        row = load_workspace(cur, tenant_id, workspace_id, for_update=True)
        if row["state"] not in ("ready", "in_use", "collecting"):
            raise WorkspaceStateError(
                f"workspace {workspace_id} is {row['state']!r}; destruction "
                "runs from ready/in_use/collecting"
            )
        cur.execute(
            """
            UPDATE strike_workspaces
            SET state = 'destroying', destroying_started_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(workspace_id)),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_destroy_started",
            details={"workspace_id": str(workspace_id)},
        )
        return dict(cur.fetchone())


def finish_workspace_destroy(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Phase 2 — ask the provider to terminate. Confirmed ⇒ 'destroyed';
    anything else ⇒ 'destroy_failed' alarm — never silently marked destroyed
    (PATCH-02: an uncertain stop is contained and reported, never absorbed)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-workspace:{tenant_id}:{workspace_id}")
        row = load_workspace(cur, tenant_id, workspace_id, for_update=True)
        if row["state"] != "destroying":
            raise WorkspaceStateError(
                f"workspace {workspace_id} is {row['state']!r}; finish runs "
                "from destroying"
            )
        view = _reservation_view(row)

    try:
        confirmed = provider_terminate(view)
        last_error = None if confirmed else (
            "termination not confirmed by the provider — unresolved until "
            "operator reconciliation"
        )
    except Exception as exc:
        confirmed = False
        last_error = f"termination not confirmed: {exc}"

    with conn.cursor(row_factory=dict_row) as cur:
        if confirmed:
            cur.execute(
                """
                UPDATE strike_workspaces
                SET state = 'destroyed', destroyed_at = now(), updated_at = now()
                WHERE tenant_id = %s AND id = %s
                RETURNING *;
                """,
                (str(tenant_id), str(workspace_id)),
            )
            destroyed = cur.fetchone()
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role=actor_role, event_name="strike.workspace_destroyed",
                details={"workspace_id": str(workspace_id), "confirmed": True},
            )
            return dict(destroyed)

        cur.execute(
            """
            UPDATE strike_workspaces
            SET state = 'destroy_failed', last_error = %s, updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (last_error, str(tenant_id), str(workspace_id)),
        )
        alarmed = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_destroy_failed",
            details={
                "workspace_id": str(workspace_id),
                "error": last_error,
                "note": "operator reconciliation required — never silently "
                        "marked destroyed",
            },
        )
        return dict(alarmed)


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def reconcile_workspace(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    confirmed_fenced: bool,
    note: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Operator reconciliation of an alarmed or unknown-outcome workspace
    (PATCH-02/04). ``confirmed_fenced=True`` attests the generation is fenced
    (no VM exists / the VM is confirmed gone) and retires the row to
    'destroyed' — releasing the cardinality lock so a replacement generation
    may be reserved. False records the check but keeps the alarm standing."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-workspace:{tenant_id}:{workspace_id}")
        row = load_workspace(cur, tenant_id, workspace_id, for_update=True)
        prior_state = row["state"]

        if prior_state == "provisioning":
            # reconciliation of an unknown provisioning outcome: the operator
            # attests what the provider actually did
            if not confirmed_fenced:
                raise WorkspaceStateError(
                    f"workspace {workspace_id} provisioning outcome is "
                    "unknown and is NOT attested fenced — the reservation "
                    "stays provisioning (execution may have occurred)"
                )
            cur.execute(
                """
                UPDATE strike_workspaces
                SET state = 'destroyed', destroyed_at = now(),
                    reconciled_by = %s, reconciled_at = now(),
                    reconcile_note = %s, updated_at = now()
                WHERE tenant_id = %s AND id = %s
                RETURNING *;
                """,
                (actor_id, note, str(tenant_id), str(workspace_id)),
            )
            reconciled = cur.fetchone()

        elif prior_state in ("destroy_failed", "provision_failed"):
            if confirmed_fenced:
                cur.execute(
                    """
                    UPDATE strike_workspaces
                    SET state = 'destroyed',
                        destroyed_at = COALESCE(destroyed_at, now()),
                        reconciled_by = %s, reconciled_at = now(),
                        reconcile_note = %s, updated_at = now()
                    WHERE tenant_id = %s AND id = %s
                    RETURNING *;
                    """,
                    (actor_id, note, str(tenant_id), str(workspace_id)),
                )
            else:
                cur.execute(
                    """
                    UPDATE strike_workspaces
                    SET reconciled_by = %s, reconciled_at = now(),
                        reconcile_note = %s, updated_at = now()
                    WHERE tenant_id = %s AND id = %s
                    RETURNING *;
                    """,
                    (actor_id, note, str(tenant_id), str(workspace_id)),
                )
            reconciled = cur.fetchone()

        else:
            raise WorkspaceStateError(
                f"workspace {workspace_id} is {prior_state!r}; reconciliation "
                "addresses provisioning-unknown or alarmed workspaces"
            )

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.workspace_reconciled",
            details={
                "workspace_id": str(workspace_id),
                "prior_state": prior_state,
                "confirmed_fenced": confirmed_fenced,
                "note": note,
                "alarm_standing": reconciled["state"] != "destroyed",
            },
        )
        return dict(reconciled)


def list_workspaces(
    conn: psycopg.Connection, tenant_id: uuid.UUID, engagement_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        load_engagement(cur, tenant_id, engagement_id)
        cur.execute(
            """
            SELECT * FROM strike_workspaces
            WHERE tenant_id = %s AND engagement_id = %s
            ORDER BY generation DESC;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        return cur.fetchall()


__all__ = [
    "PROVIDER_NAME",
    "ProvisionUnknownOutcome",
    "begin_workspace_destroy",
    "bump_egress_generation",
    "finish_workspace_destroy",
    "list_workspaces",
    "load_workspace",
    "mark_collecting",
    "mark_workspace_in_use",
    "provider_provision",
    "provider_terminate",
    "provision_reservation",
    "reconcile_workspace",
    "reserve_workspace",
]
