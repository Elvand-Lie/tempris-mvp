# backend/app/strike/scopes.py
"""
Tenant testing-scope registry (amended PRD v1.12 Ch.4 — the /strike/scopes
owning surface).

Each entry is an EXACT hostname, IP, or CIDR — no wildcard suffixes — with a
REQUIRED future expires_at, administered exclusively by Tenant Admin /
Tenant Superadmin and audited. The parser here is STRIKE's OWN strict
parser: Chapter 2's asset/SCOUT target-validation rules (which reject CIDR)
are explicitly NOT reused, and this module deliberately does not import them
(PRD: "Ch.2's asset/SCOUT target-validation rules are unchanged and are not
reused as STRIKE's").

Expiry and revocation are DERIVED AT READ — stored state is never
back-written. There is no uniqueness constraint on entries: an expired or
revoked entry may be recreated. Run binding (resolved-destination pinning)
is a separate run-bound concept; this registry only owns the entries a run
scope references.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Tuple

from pydantic import BaseModel, ConfigDict, Field

from app.audit import record_audit_event
from app.strike.errors import StrikeDomainError, StrikeNotFoundError


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ScopeEntryInvalidError(StrikeDomainError):
    """The entry is not an exact hostname/IP/CIDR (wildcards, host bits set
    in a CIDR, malformed names, past expiry)."""

    code = "scope_entry_invalid"


class ScopeEntryNotFoundError(StrikeNotFoundError):
    """Unknown id, or an id belonging to another tenant — the identical
    not-found, no disclosure."""

    code = "scope_entry_not_found"


class ScopeEntryStateError(StrikeDomainError):
    """The entry is not in the state the command requires (e.g. already
    revoked)."""

    code = "scope_entry_state"


# ---------------------------------------------------------------------------
# STRICT parser — exact hostname / IP / CIDR only
# ---------------------------------------------------------------------------

# RFC 1123 hostname labels: alnum/hyphen, 1-63 chars, not starting or
# ending with a hyphen; 253 chars total. SINGLE-LABEL names ("intranet")
# are valid exact private hostnames (the PRD says exact hostname, not
# FQDN-only; app/target_validator.py treats them the same way). The FINAL
# label must contain at least one letter, so a bare number can never
# masquerade as a hostname next to the IP branch above.
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _validate_hostname(host: str) -> None:
    if len(host) > _MAX_ENTRY_LENGTH:
        raise ScopeEntryInvalidError("Scope entry exceeds 253 characters")
    labels = host.split(".")
    if any(not _LABEL_RE.match(label) for label in labels):
        raise ScopeEntryInvalidError(
            "Scope entry must be an exact hostname, IP, or CIDR "
            "(no wildcards, no schemes, no paths)"
        )
    if not re.search(r"[a-z]", labels[-1]):
        raise ScopeEntryInvalidError(
            "A numeric-only name is not a valid hostname scope entry"
        )

_MAX_ENTRY_LENGTH = 253


def parse_scope_entry(raw: str) -> Tuple[str, str]:
    """Validate and normalize one testing-scope entry.

    Returns (entry_kind, canonical_value). Raises ScopeEntryInvalidError on
    anything that is not an exact hostname, IP, or CIDR — including
    wildcards (the PRD names them refused) and CIDRs with host bits set
    (ip_network(strict=True)).
    """
    if raw is None:
        raise ScopeEntryInvalidError("A scope entry is required")
    value = raw.strip()
    if not value:
        raise ScopeEntryInvalidError("A scope entry is required")
    if len(value) > _MAX_ENTRY_LENGTH:
        raise ScopeEntryInvalidError("Scope entry exceeds 253 characters")
    if "*" in value:
        raise ScopeEntryInvalidError(
            "Wildcard entries are refused: a scope entry is an exact "
            "hostname, IP, or CIDR"
        )
    if "%" in value:  # zone ids / percent-encoding never name a scope host
        raise ScopeEntryInvalidError("Scope entry contains forbidden characters")

    # IP first (a bare address is exact), then strict CIDR, then hostname.
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        # strict=True refuses CIDRs with host bits set (10.0.0.1/24).
        return "cidr", str(ipaddress.ip_network(value, strict=True))
    except ValueError:
        pass

    # at most ONE terminal dot is normalization ("example.com." →
    # "example.com"); more is a malformed name ("example.com.." — its empty
    # label fails the label check)
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    _validate_hostname(host)
    return "hostname", host


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScopeEntryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry: str = Field(..., min_length=1, max_length=_MAX_ENTRY_LENGTH)
    # REQUIRED per the amended PRD: each entry carries expires_at.
    expires_at: datetime
    note: str | None = Field(None, max_length=2000)


class ScopeEntryRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=2000)


# ---------------------------------------------------------------------------
# Derived-at-read state
# ---------------------------------------------------------------------------


def scope_entry_state(row: dict, *, now: datetime | None = None) -> str:
    """'active' | 'expired' | 'revoked' — derived at read; never written."""
    if row["revoked_at"] is not None:
        return "revoked"
    now = now or datetime.now(timezone.utc)
    expires_at = row["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        return "expired"
    return "active"


def _render(row: dict) -> dict:
    out = dict(row)
    out["state"] = scope_entry_state(row)
    return out


# ---------------------------------------------------------------------------
# Service — create / list / revoke (Tenant Admin / Tenant Superadmin only)
# ---------------------------------------------------------------------------


def create_scope_entry(
    conn,
    tenant_id: uuid.UUID,
    payload: ScopeEntryCreate,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    entry_kind, value = parse_scope_entry(payload.entry)

    expires_at = payload.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise ScopeEntryInvalidError("expires_at must be in the future")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO strike_testing_scopes (
                tenant_id, entry_kind, value, note, created_by, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *;
            """,
            (
                str(tenant_id), entry_kind, value,
                payload.note, actor_id, expires_at,
            ),
        )
        row = cur.fetchone()

    record_audit_event(
        conn, tenant_id, actor_id, actor_role,
        "strike.scope.created",
        asset_id=row["id"],
        details={
            "entry_kind": entry_kind,
            "value": value,
            "expires_at": expires_at.isoformat(),
        },
    )
    return _render(row)


def list_scope_entries(conn, tenant_id: uuid.UUID) -> list[dict]:
    """The tenant's registry (newest first) — permanent administration
    history; expired/revoked rows stay visible with their derived state."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM strike_testing_scopes
            WHERE tenant_id = %s
            ORDER BY created_at DESC, id;
            """,
            (str(tenant_id),),
        )
        return [_render(r) for r in cur.fetchall()]


def revoke_scope_entry(
    conn,
    tenant_id: uuid.UUID,
    scope_entry_id: uuid.UUID,
    reason: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Enforcement-immediate revocation: the write is the contract for the
    registry surface (a run's bound scope dies at its enforcement point; the
    run-side termination is the run-bound concept's responsibility)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM strike_testing_scopes
            WHERE id = %s AND tenant_id = %s;
            """,
            (str(scope_entry_id), str(tenant_id)),
        )
        row = cur.fetchone()
        if row is None:
            # unknown and cross-tenant are the identical not-found
            raise ScopeEntryNotFoundError("Scope entry not found")
        if row["revoked_at"] is not None:
            raise ScopeEntryStateError("Scope entry is already revoked")

        cur.execute(
            """
            UPDATE strike_testing_scopes
            SET revoked_at = now(), revoked_by = %s, revoke_reason = %s
            WHERE id = %s AND tenant_id = %s AND revoked_at IS NULL
            RETURNING *;
            """,
            (actor_id, reason, str(scope_entry_id), str(tenant_id)),
        )
        updated = cur.fetchone()
        if updated is None:
            # a concurrent revoke won the write; never overwrite its
            # attribution
            raise ScopeEntryStateError("Scope entry is already revoked")

    record_audit_event(
        conn, tenant_id, actor_id, actor_role,
        "strike.scope.revoked",
        asset_id=row["id"],
        details={
            "entry_kind": row["entry_kind"],
            "value": row["value"],
            "reason": reason,
        },
    )
    return _render(updated)
