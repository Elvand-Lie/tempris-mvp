# backend/app/strike/relays.py
"""The STRIKE-specific private-network relay lifecycle (PRD-000 v1.11 Ch.4
principle 6, D-1).

NEVER the Chapter 2 Collector: the collector's remote surface is a closed
six-frame enum with unknown types dropped and "zero remote execution vector"
(§2.7) — adding tunnel frames would destroy that frozen guarantee. The relay
is a separate, tenant-bound, session-scoped, revocable component; deploying
one is itself an engagement event and is audited.

Lifecycle (migration 029 trigger-pinned): pending_pairing → paired → active
→ revoked (TERMINAL — a revoked relay is never reusable). The pairing
secret follows the collector-enrollment pattern: generated server-side,
SHA-256-stored, returned to the operator exactly once. The pairing protocol
mechanics themselves remain open decision #3 — this module pins the
lifecycle, tenancy, and revocation semantics the frozen contract requires.
"""
from __future__ import annotations

import secrets
import uuid

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.service import _advisory_xact_lock
from app.strike.errors import RelayNotFoundError, RelayStateError
from app.strike.service import assert_engagement_operable, load_engagement


def load_relay(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, relay_id: uuid.UUID
) -> dict:
    cur.execute(
        "SELECT * FROM strike_relays WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), str(relay_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise RelayNotFoundError(f"Relay {relay_id} not found")
    return row


def create_relay(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Deploy a relay for an authorized/active engagement (admin+ — deploying
    is itself an engagement event). Returns the one-time pairing secret
    EXACTLY once; only its SHA-256 is stored."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        engagement = load_engagement(cur, tenant_id, engagement_id)
        assert_engagement_operable(engagement, allow_states=("authorized", "active"))

        pairing_secret = secrets.token_urlsafe(32)
        secret_hash = _hash_secret(pairing_secret)
        cur.execute(
            """
            INSERT INTO strike_relays (
                tenant_id, engagement_id, state, pairing_secret_hash, created_by
            ) VALUES (%s, %s, 'pending_pairing', %s, %s)
            RETURNING id, tenant_id, engagement_id, state, paired_at,
                      activated_at, revoked_at, revoked_by, revoke_reason,
                      created_by, created_at;
            """,
            (str(tenant_id), str(engagement_id), secret_hash, actor_id),
        )
        relay = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.relay_created",
            details={
                "relay_id": str(relay["id"]),
                "engagement_id": str(engagement_id),
                "note": "deploying a relay is an engagement event; the "
                        "collector is never the relay (principle 6)",
            },
        )
        out = dict(relay)
        # one-time disclosure: the secret is never retrievable again
        out["pairing_secret"] = pairing_secret
        return out


def pair_relay(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    relay_id: uuid.UUID,
    pairing_secret: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Present the one-time pairing secret: pending_pairing → paired →
    active (one command; the session-scoped active relay is the paired one).
    A wrong secret fails closed without disclosing which failed."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-relay:{tenant_id}:{relay_id}")
        relay = load_relay(cur, tenant_id, relay_id)
        if relay["state"] != "pending_pairing":
            raise RelayStateError(
                f"relay {relay_id} is {relay['state']!r}; only a "
                "pending_pairing relay pairs"
            )
        if not secrets.compare_digest(
            _hash_secret(pairing_secret), relay["pairing_secret_hash"] or ""
        ):
            raise RelayStateError(f"pairing for relay {relay_id} refused")
        # both pinned edges in one transaction: pending_pairing → paired,
        # then paired → active (the trigger pins each edge separately)
        cur.execute(
            """
            UPDATE strike_relays
            SET state = 'paired', paired_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(relay_id)),
        )
        cur.execute(
            """
            UPDATE strike_relays
            SET state = 'active', activated_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING id, tenant_id, engagement_id, state, paired_at,
                      activated_at, revoked_at, revoked_by, revoke_reason,
                      created_by, created_at;
            """,
            (str(tenant_id), str(relay_id)),
        )
        active = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.relay_paired",
            details={"relay_id": str(relay_id), "state": "active"},
        )
        return dict(active)


def revoke_relay(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    relay_id: uuid.UUID,
    reason: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Revoke (admin+) — TERMINAL: a revoked relay never re-pairs."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-relay:{tenant_id}:{relay_id}")
        relay = load_relay(cur, tenant_id, relay_id)
        if relay["state"] == "revoked":
            raise RelayStateError(f"relay {relay_id} is already revoked")
        cur.execute(
            """
            UPDATE strike_relays
            SET state = 'revoked', revoked_at = now(), revoked_by = %s,
                revoke_reason = %s, updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING id, tenant_id, engagement_id, state, paired_at,
                      activated_at, revoked_at, revoked_by, revoke_reason,
                      created_by, created_at;
            """,
            (actor_id, reason, str(tenant_id), str(relay_id)),
        )
        revoked = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.relay_revoked",
            details={
                "relay_id": str(relay_id),
                "reason": reason,
                "note": "revoked is TERMINAL — the relay is never reusable",
            },
        )
        return dict(revoked)


def list_relays(
    conn: psycopg.Connection, tenant_id: uuid.UUID, engagement_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        load_engagement(cur, tenant_id, engagement_id)
        cur.execute(
            """
            SELECT id, tenant_id, engagement_id, state, paired_at,
                   activated_at, revoked_at, revoked_by, revoke_reason,
                   created_by, created_at
            FROM strike_relays
            WHERE tenant_id = %s AND engagement_id = %s
            ORDER BY created_at DESC, id;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        return cur.fetchall()


def _hash_secret(secret: str) -> str:
    import hashlib

    return hashlib.sha256(secret.encode("utf-8")).hexdigest()
