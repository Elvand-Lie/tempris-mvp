# backend/app/exposure/identity_boundary.py
"""
P0-07 — IDENTITY BOUNDARY LIFECYCLE (PRD-000 v1.11 §3.6.6 #7/#8; §3.3.1
supersession authority; §3.3.2 criticality mapping; Appendix C Q15/Q20).

The Chapter 3-owned ``tenant_identity_boundary`` binding is the
IDENTITY_POSTURE anchor contract (§3.6.6 #8: IDENTITY_POSTURE ships first —
NHI, supply-chain, and agentic anchor semantics are NOT defined here).

Contract (§3.6.6 #7):
  * ``tenant_id → asset_id``, AT MOST ONE current binding per tenant (0..1 —
    the partial unique index enforces at-most-one, never existence);
  * the bound asset must be same-tenant, active, ``target_type='domain'``
    (Chapter 2's asset contract is untouched; the ``asset_type`` free-text
    marker may read ``identity_boundary`` but is never required or written);
  * the binding stores its OWN criticality (design A): same vocabulary as
    ``assets.criticality``, same §3.3.2 mapping (10/8/5/2), with who/when
    provenance. Web/CVE exposures on the same domain keep reading
    ``assets.criticality`` — neither reading leaks into the other;
  * replace and clear both SUPERSEDE every current IDENTITY_POSTURE exposure
    tied to the old boundary — routed through the P0-01 exposure service
    (``supersede_exposures_for_asset``), never by writing exposure status
    here — inside ONE transaction: binding transition + supersessions +
    audits commit atomically or not at all;
  * history is immutable: replaced/cleared rows are retained, never mutated
    (DB trigger), and every transition is audited (identity_boundary_audit,
    append-only);
  * a bound asset cannot be decommissioned until the binding is replaced or
    cleared (service guard here + DB-trigger backstop in migration 020);
  * reachability never inherits from the boundary asset or prior episodes:
    replacement re-anchors through re-confirmation, which creates a fresh
    episode — nothing is moved or copied.

Idempotent replay: repeating create with the same (asset, criticality),
replace with the same (asset, criticality), or clear without a current
binding returns outcome ``replay`` with no new rows and no supersessions.

This module never writes exposure status directly and never mutates an
exposure row: the P0-01 service owns both (§3.3.1 lifecycle authority).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.audit import record_audit_event
from app.exposure.exceptions import (
    BoundAssetError,
    EntityNotFoundError,
    IdentityBoundaryNotFoundError,
    IdentityBoundaryStateError,
    InvalidAssetStatusError,
    TenantMismatchError,
)
from app.exposure.service import _advisory_xact_lock, supersede_exposures_for_asset

# The taxonomy class this binding anchors (§3.6.6 #8 — IDENTITY_POSTURE first).
BOUND_TAXONOMY_CLASS = "IDENTITY_POSTURE"

BOUNDARY_CRITICALITY_VALUES = ("critical", "high", "medium", "low")

OUTCOME_CREATED = "created"
OUTCOME_REPLAY = "replay"
OUTCOME_CLEARED = "cleared"


@dataclass(frozen=True)
class BoundaryResult:
    """Outcome of a binding command: the (new or current) binding row plus a
    stable outcome token for idempotent replay semantics."""

    boundary: dict
    outcome: str            # created | replay | cleared
    superseded: tuple       # AssetExposure rows superseded by this transition


def _validate_criticality(criticality) -> str:
    if not isinstance(criticality, str) or criticality not in BOUNDARY_CRITICALITY_VALUES:
        raise IdentityBoundaryStateError(
            f"criticality must be one of {list(BOUNDARY_CRITICALITY_VALUES)} "
            "(same vocabulary as assets.criticality, §3.3.2)"
        )
    return criticality


def _validate_boundary_asset(cur, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> dict:
    """§3.6.6 #7 preconditions for the designated asset: same-tenant, active,
    ``target_type='domain'``. Locked FOR NO KEY UPDATE so concurrent exposure
    confirmations (asset FOR SHARE) and decommissions (asset FOR UPDATE)
    serialize against the transition on the anchor row itself."""
    cur.execute(
        """
        SELECT id, tenant_id, target_type, status
        FROM assets WHERE id = %s FOR NO KEY UPDATE;
        """,
        (str(asset_id),),
    )
    row = cur.fetchone()
    if row is None:
        raise EntityNotFoundError(f"Asset {asset_id} not found")
    if str(row["tenant_id"]) != str(tenant_id):
        raise TenantMismatchError(
            f"Asset {asset_id} belongs to tenant {row['tenant_id']}, not {tenant_id}"
        )
    if row["target_type"] != "domain":
        raise IdentityBoundaryStateError(
            f"the identity boundary must target a domain asset "
            f"(asset {asset_id} target_type={row['target_type']!r})"
        )
    if row["status"] != "active":
        raise InvalidAssetStatusError(
            f"the identity boundary asset must be active "
            f"(asset {asset_id} status={row['status']!r})"
        )
    return row


def _active_binding(cur, tenant_id: uuid.UUID) -> Optional[dict]:
    cur.execute(
        """
        SELECT id, tenant_id, asset_id, state, criticality, set_by, set_at,
               created_by, created_at
        FROM tenant_identity_boundary
        WHERE tenant_id = %s AND state = 'active';
        """,
        (str(tenant_id),),
    )
    return cur.fetchone()


def get_current_identity_boundary(
    conn: psycopg.Connection, tenant_id: uuid.UUID
) -> Optional[dict]:
    """The tenant's current binding, or None (0..1 — absence is normal)."""
    with conn.cursor(row_factory=dict_row) as cur:
        return _active_binding(cur, tenant_id)


def assert_asset_not_identity_boundary(
    cur, tenant_id: uuid.UUID, asset_id: uuid.UUID
) -> None:
    """Decommission guard (§3.6.6 #7): reject when the asset IS the tenant's
    active boundary. Called inside the decommission transaction BEFORE any
    change; the migration-020 BEFORE-UPDATE trigger is the raw-SQL backstop,
    so even a caller that skips this helper fails closed."""
    cur.execute(
        """
        SELECT id FROM tenant_identity_boundary
        WHERE tenant_id = %s AND asset_id = %s AND state = 'active';
        """,
        (str(tenant_id), str(asset_id)),
    )
    row = cur.fetchone()
    if row is not None:
        raise BoundAssetError(
            f"asset {asset_id} is the active identity boundary (binding "
            f"{row['id']}) — replace or clear the binding before decommissioning"
        )


def _audit(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    boundary_id,
    action: str,
    actor_id: str,
    actor_role: str,
    details: dict,
) -> None:
    """Append-only binding audit row (migration 020 admits INSERT only)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO identity_boundary_audit (
                tenant_id, boundary_id, action, actor_id, actor_role, details
            ) VALUES (%s, %s, %s, %s, %s, %s);
            """,
            (str(tenant_id), boundary_id, action, actor_id, actor_role,
             Json(details)),
        )
    # mirror into the tenant's audit_events stream (same transaction)
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role, event_name=f"identity_boundary.{action}",
        asset_id=None, details=details,
    )


def create_identity_boundary(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    asset_id: uuid.UUID,
    criticality: str,
    actor_id: str,
    actor_role: str,
) -> BoundaryResult:
    """Designate the tenant's identity boundary (first designation, or the
    idempotent replay of an identical one). Rejects when a different active
    binding exists — that is a replacement, and must say so."""
    return _transition(
        conn, tenant_id,
        action="created", new_asset_id=asset_id, criticality=criticality,
        actor_id=actor_id, actor_role=actor_role,
    )


def replace_identity_boundary(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    asset_id: uuid.UUID,
    criticality: str,
    actor_id: str,
    actor_role: str,
) -> BoundaryResult:
    """Replace the tenant's identity boundary: supersede every current
    IDENTITY_POSTURE exposure on the old boundary, retain the old row as
    immutable history bound to the new row, and designate the new one.
    With no current binding this is a first designation (outcome 'created').
    Replacing with the identical (asset, criticality) is an idempotent replay."""
    return _transition(
        conn, tenant_id,
        action="replaced", new_asset_id=asset_id, criticality=criticality,
        actor_id=actor_id, actor_role=actor_role,
    )


def clear_identity_boundary(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> BoundaryResult:
    """Clear the tenant's identity boundary: supersede every current
    IDENTITY_POSTURE exposure on it and retain the row as cleared history.
    The class is unshippable until a new boundary is designated. Clearing
    with no current binding is an idempotent replay."""
    return _transition(
        conn, tenant_id,
        action="cleared", new_asset_id=None, criticality=None,
        actor_id=actor_id, actor_role=actor_role,
    )


def assert_boundary_exists_for_confirmation(
    conn: psycopg.Connection, tenant_id: uuid.UUID, asset_id: uuid.UUID
) -> dict:
    """§3.6.6 #7 confirmation precondition: an IDENTITY_POSTURE exposure on
    ``asset_id`` requires an ACTIVE current binding, and it must be the
    binding FOR THAT ASSET (the designated boundary is the anchor). Returns
    the binding row (its criticality is boundary-criticality provenance for
    later TES wiring — P0-08 builds that read)."""
    with conn.cursor(row_factory=dict_row) as cur:
        binding = _active_binding(cur, tenant_id)
    if binding is None:
        raise IdentityBoundaryStateError(
            "no active identity boundary is designated for this tenant — "
            "designating one is a precondition for creating or confirming "
            "IDENTITY_POSTURE exposures (§3.6.6 #7)"
        )
    if uuid.UUID(str(binding["asset_id"])) != uuid.UUID(str(asset_id)):
        raise IdentityBoundaryStateError(
            f"the active identity boundary is asset {binding['asset_id']}, not "
            f"{asset_id} — IDENTITY_POSTURE exposures anchor to the designated "
            "boundary asset"
        )
    return binding


def _transition(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    action: str,
    new_asset_id: Optional[uuid.UUID],
    criticality: Optional[str],
    actor_id: str,
    actor_role: str,
) -> BoundaryResult:
    """One serialized binding transition (§3.6.6 #7 + §3.3.1 authority).

    Order inside the caller's transaction:
      1. advisory lock per tenant serializes binding changes;
      2. read the active binding under that lock;
      3. idempotent replay short-circuits with no new rows;
      4. supersede via the P0-01 service (IDENTITY_POSTURE exposures only);
      5. insert the new row (create/replace), then close the old row with
         its successor pointer (one UPDATE — the only permitted mutation);
      6. audit rows — binding audit + tenant audit_events — all in the same
         transaction, committing atomically or not at all.
    """
    if action not in ("created", "replaced", "cleared"):
        raise IdentityBoundaryStateError(f"unknown boundary action {action!r}")
    if action in ("created", "replaced"):
        _validate_criticality(criticality)
        if new_asset_id is None:
            raise IdentityBoundaryStateError(
                f"{action} requires a designated asset"
            )

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"identity-boundary:{tenant_id}")
        current = _active_binding(cur, tenant_id)

        # ----- idempotent replay ------------------------------------------------
        if action == "created" and current is not None:
            if (uuid.UUID(str(current["asset_id"])) == new_asset_id
                    and current["criticality"] == criticality):
                return BoundaryResult(dict(current), OUTCOME_REPLAY, ())
            raise IdentityBoundaryStateError(
                f"tenant {tenant_id} already has an active identity boundary "
                f"(binding {current['id']} on asset {current['asset_id']}) — "
                "use replace or clear"
            )
        if action == "replaced" and current is not None:
            if (uuid.UUID(str(current["asset_id"])) == new_asset_id
                    and current["criticality"] == criticality):
                return BoundaryResult(dict(current), OUTCOME_REPLAY, ())
        if action == "cleared" and current is None:
            return BoundaryResult({}, OUTCOME_REPLAY, ())

        # a replace with no current binding designates the first boundary
        effective_action = (
            action if current is not None
            else ("created" if action == "replaced" else action)
        )

        # ----- validate the designated asset (create/replace) --------------------
        if action in ("created", "replaced"):
            _validate_boundary_asset(cur, tenant_id, new_asset_id)

        # ----- supersede old-boundary exposures through the P0-01 service -------
        superseded: list = []
        old = current
        if old is not None:
            # Serialize the supersession against concurrent exposure
            # confirmations on the old anchor asset: a confirmation holds the
            # asset row FOR SHARE, this FOR NO KEY UPDATE conflicts with it,
            # so either the confirmation commits first (and is superseded by
            # the statement below) or it waits and then fails the (now gone)
            # precondition. No current exposure can survive on the old
            # binding. Decommission (FOR UPDATE) serializes the same way.
            cur.execute(
                "SELECT id FROM assets WHERE id = %s FOR NO KEY UPDATE;",
                (str(old["asset_id"]),),
            )
            superseded = supersede_exposures_for_asset(
                conn, tenant_id, uuid.UUID(str(old["asset_id"])),
                actor_id=actor_id, actor_role=actor_role,
                reason=f"identity boundary {effective_action} "
                       f"(binding {old['id']} superseded)",
                taxonomy_class=BOUND_TAXONOMY_CLASS,
            )

        # ----- close the old row, then insert the new one ------------------------
        # (order matters: the partial unique index admits at most one 'active'
        # row per tenant and cannot be deferred, so the old row must leave the
        # active state before the successor is designated)
        if old is not None:
            # the ONLY permitted mutation of an active row (history thereafter)
            cur.execute(
                """
                UPDATE tenant_identity_boundary
                SET state = %s,
                    ended_by = %s,
                    ended_at = now()
                WHERE id = %s AND state = 'active';
                """,
                (
                    "replaced" if action in ("created", "replaced") else "cleared",
                    actor_id,
                    old["id"],
                ),
            )

        new_row = None
        if action in ("created", "replaced"):
            cur.execute(
                """
                INSERT INTO tenant_identity_boundary (
                    tenant_id, asset_id, state, criticality, set_by, created_by
                ) VALUES (%s, %s, 'active', %s, %s, %s)
                RETURNING id, tenant_id, asset_id, state, criticality,
                          set_by, set_at, created_by, created_at;
                """,
                (str(tenant_id), str(new_asset_id), criticality,
                 actor_id, actor_id),
            )
            new_row = cur.fetchone()

        # ----- audits (same transaction; failure rolls everything back) ----------
        details = {
            "prior_binding_id": str(old["id"]) if old is not None else None,
            "prior_asset_id": str(old["asset_id"]) if old is not None else None,
            "asset_id": (str(new_row["asset_id"])
                         if new_row is not None
                         else (str(old["asset_id"]) if old is not None else None)),
            "criticality": new_row["criticality"] if new_row is not None else None,
            "superseded_exposures": len(superseded),
        }
        _audit(
            conn, tenant_id,
            boundary_id=(new_row or old)["id"],
            action=effective_action,
            actor_id=actor_id, actor_role=actor_role,
            details=details,
        )

        return BoundaryResult(
            dict(new_row) if new_row is not None else {},
            effective_action,   # created | replaced | cleared ('replay' short-circuits above)
            tuple(superseded),
        )
