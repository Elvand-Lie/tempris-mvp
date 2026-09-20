# backend/app/audit.py
"""
Audit event writer + tamper-evident per-tenant hash chain (PRD-000 Chapter 5,
Target architecture item 4 — V1's hash chain and verify endpoint, ported).

Every write goes through :func:`record_audit_event` (the single choke point
for audit in V2). Each event is appended to its tenant's chain:

    entry_hash = 'hmac:<key_id>:' || HMAC-SHA256_hex(key, canonical_entry)

where canonical_entry is the sorted-key JSON of the entry fields plus the
previous entry's entry_hash (genesis prev_hash: ``"0"``). Appends are
serialized per tenant with a transaction-scoped advisory lock, so concurrent
writers can never fork the chain; an append becomes durable only when the
caller's transaction commits (existing append-on-commit semantics).

Schemes:
  * ``hmac:<key_id>:<hex>`` — all new writes. Key comes from AUDIT_HMAC_KEY;
    the key gate is V1's: staging/production refuse missing/short/placeholder
    keys (fail closed), development falls back to a documented dev key.
  * ``plain:<hex>`` — the migration-024 backfill of pre-chain rows only
    (deterministic SHA-256, no secret). Its SQL-side canonical string is the
    scheme contract documented in migration 024; verification mirrors it.

:func:`verify_tenant_audit_chain` recomputes the chain (read-only) and is
exposed via GET /api/audit/verify (routes/audit.py), tenant-scoped to the
caller's tenant like V1.
"""
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg

# Sanitization keys that should never appear in audit details
SENSITIVE_KEYS = {"password", "secret", "token", "authorization", "raw_response", "body", "payload", "cookie", "jwt"}

# Chain genesis: the first entry of a tenant chains from this marker.
GENESIS_PREV_HASH = "0"

# Bounded retries when losing a concurrent append race (unique index
# uq_audit_events_chain_fork); far above any realistic contention.
_MAX_CHAIN_APPEND_ATTEMPTS = 5

# Canonical UTC timestamp shape shared by writer, verifier, and the plain
# backfill in migration 024. Python strftime pattern and its exact Postgres
# to_char equivalent (6-digit microseconds, literal T/Z).
_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
_PG_TS_FMT = 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'

# ---------------------------------------------------------------------------
# Chain key management (ported from V1 routers/audit.py)
# ---------------------------------------------------------------------------

_DEV_FALLBACK_AUDIT_HMAC_KEY = b"tempris_dev_audit_hmac_key_do_not_use_in_prod_" + b"x" * 16
_DEV_KEY_MARKERS = ("test_audit_hmac", "tempris_dev_audit_hmac")


def get_audit_hmac_key() -> bytes:
    """Active HMAC key. Fails closed in staging/production: the key must be
    configured, carry >= 32 characters of secret material, and never be a
    known development placeholder."""
    environment = os.environ.get("ENVIRONMENT", "").strip().lower()
    key_env = os.environ.get("AUDIT_HMAC_KEY", "")
    if environment in ("staging", "production"):
        if not key_env:
            raise RuntimeError("FATAL: AUDIT_HMAC_KEY is missing or empty in staging/production.")
        if len(key_env) < 32:
            raise RuntimeError("FATAL: AUDIT_HMAC_KEY must have at least 32 characters of secret material.")
        if any(marker in key_env for marker in _DEV_KEY_MARKERS):
            raise RuntimeError("FATAL: Weak/development placeholder keys are refused in staging/production.")
        return key_env.encode()
    # Development/test: documented fallback when no key is configured.
    if not key_env:
        return _DEV_FALLBACK_AUDIT_HMAC_KEY
    return key_env.encode()


def get_audit_hmac_key_id() -> str:
    key_id = os.environ.get("AUDIT_HMAC_KEY_ID", "primary").strip()
    if not key_id or len(key_id) > 8 or not all(c.isalnum() or c in "._-" for c in key_id):
        raise RuntimeError("AUDIT_HMAC_KEY_ID must be 1-8 safe identifier characters")
    return key_id


def get_audit_verification_keys() -> Dict[str, bytes]:
    """Active key plus optional previous keys (rotation path): verification
    picks the key named by each row's ``hmac_key_id``. Unknown ids fail the
    affected row (never silently pass)."""
    keys: Dict[str, bytes] = {get_audit_hmac_key_id(): get_audit_hmac_key()}
    raw_previous = os.environ.get("AUDIT_HMAC_PREVIOUS_KEYS", "{}").strip() or "{}"
    try:
        previous = json.loads(raw_previous)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AUDIT_HMAC_PREVIOUS_KEYS must be a JSON object") from exc
    if not isinstance(previous, dict):
        raise RuntimeError("AUDIT_HMAC_PREVIOUS_KEYS must be a JSON object")
    for key_id, value in previous.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise RuntimeError("Audit verification key ids and values must be strings")
        if not key_id or len(key_id) > 8 or not all(c.isalnum() or c in "._-" for c in key_id):
            raise RuntimeError("Historical audit key id is invalid")
        if len(value) < 32:
            raise RuntimeError("Historical audit verification keys require 32 characters")
        if key_id in keys and keys[key_id] != value.encode():
            raise RuntimeError("Historical audit key id conflicts with the active key")
        keys[key_id] = value.encode()
    return keys


# ---------------------------------------------------------------------------
# Canonicalization + chain computation
# ---------------------------------------------------------------------------

def _canonical_entry_json(
    prev_hash: str,
    *,
    tenant_id: Any,
    actor_id: str,
    actor_role: str,
    event_name: str,
    asset_id: Optional[Any],
    details: Optional[Dict[str, Any]],
    created_at: datetime,
) -> str:
    """Canonical writer-side entry string: sorted-key compact JSON (V1's
    shape). The verifier re-derives it from the persisted row, so the details
    dict must round-trip through jsonb unchanged (it always originated as
    JSON, so it does)."""
    payload = {
        "prev_hash": prev_hash,
        "tenant_id": str(tenant_id),
        "actor_id": actor_id or "",
        "actor_role": actor_role or "",
        "event_name": event_name or "",
        "asset_id": str(asset_id) if asset_id else "",
        "details": details if details else {},
        "created_at": created_at.astimezone(timezone.utc).strftime(_TS_FMT),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _plain_scheme_canonical(
    *,
    tenant_id: Any,
    actor_id: str,
    actor_role: str,
    event_name: str,
    asset_id: Optional[Any],
    details_text: str,
    created_at_str: str,
    prev_hash: str,
) -> str:
    """Verifier-side mirror of the migration-024 plain-scheme canonical row
    string (see the scheme contract in migration 024)."""
    return "|".join([
        str(tenant_id),
        actor_id or "",
        actor_role or "",
        event_name or "",
        str(asset_id) if asset_id else "",
        details_text,
        created_at_str,
        prev_hash,
    ])


def _compute_hmac_entry_hash(prev_hash: str, canonical_entry: str) -> str:
    key_id = get_audit_hmac_key_id()
    digest = hmac.new(
        get_audit_hmac_key(), canonical_entry.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"hmac:{key_id}:{digest}"


# ---------------------------------------------------------------------------
# Sanitization + write
# ---------------------------------------------------------------------------

def sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not details:
        return {}
    sanitized = {}
    for k, v in details.items():
        if k.lower() in SENSITIVE_KEYS:
            continue
        if isinstance(v, dict):
            sanitized[k] = sanitize_details(v)
        else:
            sanitized[k] = v
    return sanitized


def record_audit_event(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    actor_id: str,
    actor_role: str,
    event_name: str,
    asset_id: Optional[uuid.UUID] = None,
    details: Optional[Dict[str, Any]] = None
) -> uuid.UUID:
    """
    Inserts a sanitized audit record chained onto the tenant's hash chain.

    Concurrency: chain linearity is enforced by the unique index
    ``uq_audit_events_chain_fork (tenant_id, prev_hash)`` — a concurrent
    append that read the same predecessor loses the race with a unique
    violation and retries (savepoint-scoped) from the new chain head. No
    advisory lock serializes audit writers, so appends add no deadlock
    surface. The append becomes durable exactly when the caller commits.
    """
    clean_details = sanitize_details(details)
    created_at = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        for _attempt in range(_MAX_CHAIN_APPEND_ATTEMPTS):
            cur.execute(
                """
                SELECT entry_hash FROM audit_events
                WHERE tenant_id = %s
                ORDER BY chain_seq DESC NULLS LAST
                LIMIT 1;
                """,
                (str(tenant_id),)
            )
            row = cur.fetchone()
            prev_hash = (
                row["entry_hash"]
                if row and row["entry_hash"]
                else GENESIS_PREV_HASH
            )
            entry_hash = _compute_hmac_entry_hash(
                prev_hash,
                _canonical_entry_json(
                    prev_hash,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    event_name=event_name,
                    asset_id=asset_id,
                    details=clean_details,
                    created_at=created_at,
                ),
            )
            try:
                cur.execute("SAVEPOINT audit_chain_append")
                cur.execute(
                    """
                    INSERT INTO audit_events (
                        id, tenant_id, actor_id, actor_role, event_name,
                        asset_id, details, created_at, prev_hash, entry_hash,
                        hmac_key_id
                    ) VALUES (
                        gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s
                    )
                    RETURNING id;
                    """,
                    (
                        str(tenant_id),
                        actor_id,
                        actor_role,
                        event_name,
                        str(asset_id) if asset_id else None,
                        json.dumps(clean_details),
                        created_at,
                        prev_hash,
                        entry_hash,
                        get_audit_hmac_key_id(),
                    )
                )
                inserted = cur.fetchone()
                return inserted["id"] if isinstance(inserted, dict) else inserted[0]
            except psycopg.errors.UniqueViolation as exc:
                if exc.diag.constraint_name != "uq_audit_events_chain_fork":
                    raise
                # Lost the append race: undo only this insert and re-chain
                # from the (advanced) head of the tenant's chain.
                cur.execute("ROLLBACK TO SAVEPOINT audit_chain_append")
                cur.execute("SHOW transaction_isolation")
                isolation_row = cur.fetchone()
                isolation = (
                    isolation_row["transaction_isolation"]
                    if isinstance(isolation_row, dict)
                    else isolation_row[0]
                )
                if isolation != "read committed":
                    # REPEATABLE READ/SERIALIZABLE cannot observe the winner's
                    # new chain head. The transaction owner must retry from a
                    # fresh snapshot instead of repeating a provably stale read.
                    raise psycopg.errors.SerializationFailure(
                        "audit chain advanced during a repeatable-read transaction"
                    ) from exc

    raise RuntimeError(
        f"audit chain append did not converge after {_MAX_CHAIN_APPEND_ATTEMPTS} attempts"
    )


# ---------------------------------------------------------------------------
# Verification (read-only) — exposed via GET /api/audit/verify
# ---------------------------------------------------------------------------

def verify_tenant_audit_chain(conn: psycopg.Connection, tenant_id: uuid.UUID) -> Dict[str, Any]:
    """Recompute one tenant's chain without modifying stored audit evidence."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, actor_id, actor_role, event_name, asset_id,
                   details AS details_dict,
                   details::text AS details_text,
                   to_char(created_at AT TIME ZONE 'UTC', %s) AS created_at_str,
                   prev_hash, entry_hash, hmac_key_id
            FROM audit_events
            WHERE tenant_id = %s
            ORDER BY chain_seq NULLS LAST, created_at, id;
            """,
            (_PG_TS_FMT, str(tenant_id))
        )
        rows = cur.fetchall()

    if not rows:
        return {
            "status": "empty",
            "records": 0,
            "intact": True,
            "mismatches": 0,
            "first_break_at_index": None,
            "latest_hash": None,
        }

    verification_keys = get_audit_verification_keys()
    running_prev = GENESIS_PREV_HASH
    broken_at = None
    mismatches = 0

    for index, row in enumerate(rows):
        entry_hash = row["entry_hash"]
        prev_hash = row["prev_hash"]

        row_valid = prev_hash == running_prev and bool(entry_hash)
        if row_valid:
            if entry_hash.startswith("hmac:"):
                parts = entry_hash.split(":", 2)
                key = verification_keys.get(parts[1]) if len(parts) == 3 else None
                if key is None:
                    row_valid = False
                else:
                    canonical = _canonical_entry_json(
                        prev_hash,
                        tenant_id=tenant_id,
                        actor_id=row["actor_id"],
                        actor_role=row["actor_role"],
                        event_name=row["event_name"],
                        asset_id=row["asset_id"],
                        details=row["details_dict"],
                        # strftime of the DB-rendered string is the identity op;
                        # parse back to datetime only to keep one code path.
                        created_at=datetime.strptime(row["created_at_str"], _TS_FMT).replace(tzinfo=timezone.utc),
                    )
                    expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
                    row_valid = parts[2] == expected
            elif entry_hash.startswith("plain:"):
                canonical = _plain_scheme_canonical(
                    tenant_id=tenant_id,
                    actor_id=row["actor_id"],
                    actor_role=row["actor_role"],
                    event_name=row["event_name"],
                    asset_id=row["asset_id"],
                    details_text=row["details_text"],
                    created_at_str=row["created_at_str"],
                    prev_hash=prev_hash,
                )
                expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                row_valid = entry_hash == f"plain:{expected}"
            else:
                row_valid = False

        if not row_valid:
            mismatches += 1
            if broken_at is None:
                broken_at = index
        if entry_hash:
            running_prev = entry_hash

    intact = mismatches == 0
    return {
        "status": "verified" if intact else "TAMPERED",
        "records": len(rows),
        "intact": intact,
        "mismatches": mismatches,
        "first_break_at_index": broken_at,
        "latest_hash": rows[-1]["entry_hash"],
    }
