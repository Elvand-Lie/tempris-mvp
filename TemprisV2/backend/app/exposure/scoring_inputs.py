# backend/app/exposure/scoring_inputs.py
"""
Scoring input ledgers (P0-02, PRD-000 v1.11 §§3.3.2–3.3.4).

Persists the mutable contextual TES inputs as provenance-bearing records
bound to ONE exposure episode: exact-exposure reachability evidence,
per-exposure Business Impact, exploitation evidence, and the reserved
non-exploitation attestation. This module supplies inputs only — the TES
formula, CVE resolvers, snapshots, and Chapter 5 approvals are later
tickets.

Server-side policy enforced here (never client-supplied):
  * tenant / actor / producer identity;
  * evidence_kind classification (write-time rule, D-7): basis 'observed'
    ⇒ observed_exploitation, basis 'validated' ⇒ controlled_validation;
  * producer policy: reachability evidence is PRODUCER-AGNOSTIC (§3.3.2 —
    any server-authenticated producer with evidence + provenance may
    establish it; producer stays server-owned and non-empty), while
    exploitation-evidence producers ARE closed to strike|analyst_review
    (§3.3.3 — reserved future producers are rejected, Q20);
  * success-only semantics — failed/prevented/cancelled/unconfirmed/
    artifact-only attempts never create a score-bearing record;
  * occurrence-time sanity (future observations rejected);
  * exact-episode binding — records attach only to a CURRENT confirmed
    episode; terminal episodes are immutable history;
  * exact stable-source replay — a source identity replays only when the
    existing row IS the same logical record (episode, producer,
    classification/vantage, EXACT occurrence time, payload, recorded_by,
    reviewer, source provenance); a conflicting reuse raises
    EvidencePolicyError and discloses nothing. Stable producers must
    supply stable occurrence timestamps for retries of the same source
    event — the service never generates a fresh server timestamp on retry;
  * append-only correction via revocation records; TTL expiry never deletes;
  * revocation of one original converges on one append-only revocation
    row and one audit event (retry- and concurrency-idempotent) via
    INSERT … ON CONFLICT DO NOTHING — never by rolling back the connection;
  * TRANSACTION OWNERSHIP: no command here ever calls conn.commit() or
    conn.rollback(). The public API route owns the transaction boundary
    (REPEATABLE READ before the first query; commit / rollback at the
    application boundary), so prior uncommitted work on the caller's
    connection is never silently discarded or published.

Missing inputs are unknown, never zero.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal, Optional

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.audit import record_audit_event
from app.exposure.exceptions import (
    EntityNotFoundError,
    EvidencePolicyError,
    ExposureConflictError,
    ExposureNotFoundError,
    TenantMismatchError,
)

# Policy constants (PRD §3.3.3, locked): TTLs govern scoring ELIGIBILITY only;
# rows persist forever as history.
OBSERVED_EXPLOITATION_TTL = timedelta(days=365)
CONTROLLED_VALIDATION_TTL = timedelta(days=180)
ATTESTATION_TTL = timedelta(days=180)
# Occurrence times further in the future than this clock-skew tolerance are
# rejected (server-side occurrence-time enforcement).
OCCURRENCE_CLOCK_SKEW = timedelta(minutes=5)
# Documented finite Business Impact decimal precision (TES input): stored as
# NUMERIC(5,4) and preserved exactly; more precise input is rejected.
BI_DECIMAL_PLACES = 4

REACHABILITY_VALUE = {"external": Decimal("10.0"), "internal": Decimal("8.0")}

EXPLOITATION_PRODUCERS = ("strike", "analyst_review")
# Reachability is producer-agnostic (§3.3.2): no allowlist. Identity stays
# server-owned and non-empty — the only hard rule the ledger enforces.

OUTCOME_CREATED = "created"
OUTCOME_REPLAY = "replay"


# ---------------------------------------------------------------------------
# Request models (public surface — extra fields like evidence_kind, producer,
# tenant_id, or actor identity are rejected outright)
# ---------------------------------------------------------------------------


class ReachabilityEvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vantage: Literal["external", "internal"]
    evidence: dict[str, Any]
    observed_at: Optional[datetime] = None

    @field_validator("evidence")
    @classmethod
    def _non_empty(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict) or len(v) == 0:
            raise ValueError("Evidence must be a non-empty dictionary/object")
        return v


class BusinessImpactIn(BaseModel):
    """Business Impact input (§3.3.2: 0–10). Values are Decimals, never binary
    floats: a documented finite precision of four decimal places is preserved
    EXACTLY (migration 017 stores NUMERIC(5,4)); excess precision is rejected,
    never silently rounded."""

    model_config = ConfigDict(extra="forbid")

    value: Decimal = Field(ge=Decimal("0"), le=Decimal("10"))
    reason: Optional[str] = None  # optional by contract (PRD §3.3.2)

    @field_validator("value")
    @classmethod
    def _bounded_decimal_precision(cls, v: Decimal) -> Decimal:
        if -v.as_tuple().exponent > BI_DECIMAL_PLACES:
            raise ValueError(
                f"Business Impact supports at most {BI_DECIMAL_PLACES} decimal "
                "places; excess precision is rejected, never silently rounded."
            )
        return v


class ExploitationEvidenceIn(BaseModel):
    """Analyst-recorded exploitation evidence. The evidence KIND is a
    server-side write-time classification of the analyst's basis — clients
    never send evidence_kind. `result` is constrained to 'succeeded':
    failed/prevented/cancelled/unconfirmed attempts are policy-rejected."""

    model_config = ConfigDict(extra="forbid")

    basis: Literal["observed", "validated"]
    result: Literal["succeeded"]
    evidence: dict[str, Any]
    observed_at: Optional[datetime] = None

    @field_validator("evidence")
    @classmethod
    def _non_empty(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict) or len(v) == 0:
            raise ValueError("Evidence must be a non-empty dictionary/object")
        return v


class EvidenceRevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ReachabilityEvidence(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    exposure_id: uuid.UUID
    vantage: str
    evidence: dict[str, Any]
    producer: str
    observed_at: datetime
    recorded_by: str
    source_object_type: str
    source_object_id: str
    revoked: bool = False
    created_at: datetime


class BusinessImpactRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    exposure_id: uuid.UUID
    value: Decimal  # exact stored decimal — never a binary float
    reason: Optional[str] = None
    assessed_by: str
    created_at: datetime


class ExploitationEvidence(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    exposure_id: uuid.UUID
    evidence_kind: str
    producer: str
    evidence: dict[str, Any]
    observed_at: datetime
    recorded_by: str
    reviewed_by: Optional[str] = None
    source_object_type: str
    source_object_id: str
    revoked: bool = False
    created_at: datetime


class NonExploitationAttestation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    exposure_id: uuid.UUID
    attested_by: str
    attested_at: datetime
    evidence_ref: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: datetime


@dataclass(frozen=True)
class RecordResult:
    record: Any
    outcome: str  # OUTCOME_CREATED | OUTCOME_REPLAY


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_occurrence(value: Optional[datetime], field_name: str) -> datetime:
    """Server-side occurrence-time policy: absent → server clock; naive → UTC;
    further future than the skew tolerance → rejected."""
    observed = value if value is not None else _utcnow()
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    if observed - _utcnow() > OCCURRENCE_CLOCK_SKEW:
        raise EvidencePolicyError(
            f"{field_name} lies in the future beyond the {OCCURRENCE_CLOCK_SKEW} clock-skew "
            "tolerance; occurrence times are enforced server-side."
        )
    return observed


def _serialize_payload(evidence: Any) -> str:
    if not isinstance(evidence, dict) or len(evidence) == 0:
        raise EvidencePolicyError("Evidence must be a non-empty dictionary/object")
    return json.dumps(evidence)


def _server_producer(producer: Optional[str]) -> str:
    """Producer identity is SERVER-SUPPLIED and non-empty: internal callers
    declare which authenticated plane is writing; None defaults to the
    analyst-review path. Empty/whitespace producers are rejected — a record
    without a producer identity is unprovable provenance."""
    if producer is None:
        return "analyst_review"
    if not isinstance(producer, str) or len(producer.strip()) == 0:
        raise EvidencePolicyError("Producer identity must be a non-empty server-supplied string.")
    return producer.strip()


def _replay_matches(
    existing: dict[str, Any],
    *,
    exposure_id: uuid.UUID,
    classification: str,
    producer: str,
    observed_at: datetime,
    evidence_json: str,
    recorded_by: str,
    source_object_type: str,
    source_object_id: str,
    classification_field: str,
    reviewed_by: Optional[str] = None,
) -> bool:
    """EXACT stable-source replay rule (P0-02 round 2): a source-identity
    collision replays only when the existing row IS the same logical record —
    exact tenant (guaranteed by the unique key), exact exposure episode,
    EXACT normalized occurrence time (no tolerance), exact producer, exact
    classification (evidence_kind / vantage), exact immutable evidence
    payload, exact source type/id, exact recorded_by, and — for exploitation
    evidence — exact reviewed_by. ANY difference (actor, reviewer, occurrence
    time, payload, classification, producer, or episode) is a conflicting
    reuse: rejected via evidence_policy_rejected, nothing disclosed, nothing
    committed. Stable producers must therefore supply stable occurrence
    timestamps; the service never substitutes a fresh server timestamp on a
    retry of the same source event."""
    same_exposure = str(existing["exposure_id"]) == str(exposure_id)
    existing_observed = existing["observed_at"]
    if existing_observed.tzinfo is None:
        existing_observed = existing_observed.replace(tzinfo=timezone.utc)
    supplied_observed = observed_at
    if supplied_observed.tzinfo is None:
        supplied_observed = supplied_observed.replace(tzinfo=timezone.utc)
    # Reachability rows carry no reviewer field; the check applies to
    # exploitation evidence only.
    reviewer_matches = (
        existing["reviewed_by"] == reviewed_by
        if classification_field == "evidence_kind"
        else True
    )
    return all(
        (
            same_exposure,
            existing_observed == supplied_observed,
            existing[classification_field] == classification,
            existing["producer"] == producer,
            existing["evidence"] == json.loads(evidence_json),
            existing["recorded_by"] == recorded_by,
            reviewer_matches,
            existing["source_object_type"] == source_object_type,
            existing["source_object_id"] == source_object_id,
        )
    )


def _reject_conflicting_replay(source_object_type: str, source_object_id: str) -> None:
    """Stable rejection for a conflicting stable-source reuse. The conflicting
    record is never returned or disclosed; the transaction commits nothing."""
    raise EvidencePolicyError(
        "Source identity "
        f"({source_object_type}, {source_object_id}) already records different "
        "evidence: stable-source reuse must replay the exact same logical record. "
        "The conflicting record is not disclosed; nothing was committed."
    )


def _require_current_confirmed_episode(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> None:
    """
    Score-bearing records bind to a CURRENT confirmed episode. The row is
    locked FOR SHARE and its status rechecked inside the caller's transaction:
    a concurrent supersession (asset decommission) either completed first
    (this write rejects) or waits for this commit (its supersession then makes
    the episode history — the record never becomes current-score eligible).
    """
    cur.execute(
        "SELECT tenant_id, status FROM asset_exposures WHERE id = %s FOR SHARE;",
        (str(exposure_id),),
    )
    row = cur.fetchone()
    if not row:
        raise ExposureNotFoundError(f"Exposure {exposure_id} not found")
    if str(row["tenant_id"]) != str(tenant_id):
        raise TenantMismatchError(
            f"Exposure {exposure_id} belongs to tenant {row['tenant_id']}, not {tenant_id}"
        )
    if row["status"] != "confirmed":
        raise ExposureConflictError(
            f"Exposure {exposure_id} is terminal (status={row['status']}); "
            "score-bearing records bind only to a current confirmed episode. "
            "Terminal episodes are immutable history."
        )


def _lookup_exposure(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> dict:
    cur.execute(
        "SELECT tenant_id, finding_id FROM asset_exposures WHERE id = %s;",
        (str(exposure_id),),
    )
    row = cur.fetchone()
    if not row:
        raise ExposureNotFoundError(f"Exposure {exposure_id} not found")
    if str(row["tenant_id"]) != str(tenant_id):
        raise TenantMismatchError(
            f"Exposure {exposure_id} belongs to tenant {row['tenant_id']}, not {tenant_id}"
        )
    return row


def _revoked_ids(cur, table: str, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> set[str]:
    cur.execute(
        f"""
        SELECT revocation_of_id FROM {table}
        WHERE tenant_id = %s AND exposure_id = %s AND revocation_of_id IS NOT NULL;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    return {str(r["revocation_of_id"]) for r in cur.fetchall()}


# ---------------------------------------------------------------------------
# Reachability evidence (§3.3.2: external=10 / internal=8 / absent=unknown)
# ---------------------------------------------------------------------------


def record_reachability_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    data: ReachabilityEvidenceIn,
    *,
    actor_id: str,
    actor_role: str,
    producer: Optional[str] = None,
    source_object_type: Optional[str] = None,
    source_object_id: Optional[str] = None,
) -> RecordResult:
    """Record exact-exposure reachability evidence (§3.3.2). Reachability is
    PRODUCER-AGNOSTIC: any server-authenticated producer may establish it —
    there is no producer allowlist on this ledger. Producer identity stays
    server-supplied, non-empty, and never client-provided (the request model
    forbids the field; service callers declare which authenticated plane is
    writing). External vantage = 10, internal = 8; absent = unknown."""
    resolved_producer = _server_producer(producer)
    observed_at = _normalize_occurrence(data.observed_at, "observed_at")
    raw_evidence = _serialize_payload(data.evidence)
    sot = source_object_type or "analyst_submission"
    sop = source_object_id or str(uuid.uuid4())

    with conn.cursor(row_factory=dict_row) as cur:
        _require_current_confirmed_episode(cur, tenant_id, exposure_id)
        cur.execute(
            """
            INSERT INTO exposure_reachability_evidence (
                id, tenant_id, exposure_id, vantage, evidence, producer,
                observed_at, recorded_by, source_object_type, source_object_id
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s
            )
            ON CONFLICT (tenant_id, source_object_type, source_object_id) WHERE revocation_of_id IS NULL DO NOTHING
            RETURNING id, tenant_id, exposure_id, vantage, evidence, producer,
                      observed_at, recorded_by, source_object_type, source_object_id, created_at;
            """,
            (
                str(tenant_id), str(exposure_id), data.vantage, raw_evidence,
                resolved_producer, observed_at, actor_id, sot, sop,
            ),
        )
        row = cur.fetchone()
        if row is None:
            # Stable-source identity collision: replay only when the existing
            # row IS the same logical record (exact episode, producer, vantage,
            # occurrence time, payload, provenance); otherwise the identity was
            # reused for different evidence — reject and disclose nothing.
            cur.execute(
                """
                SELECT id, tenant_id, exposure_id, vantage, evidence, producer,
                       observed_at, recorded_by, source_object_type, source_object_id, created_at
                FROM exposure_reachability_evidence
                WHERE tenant_id = %s AND source_object_type = %s AND source_object_id = %s;
                """,
                (str(tenant_id), sot, sop),
            )
            existing = cur.fetchone()
            if existing is None or not _replay_matches(
                existing,
                exposure_id=exposure_id,
                classification=data.vantage,
                producer=resolved_producer,
                observed_at=observed_at,
                evidence_json=raw_evidence,
                recorded_by=actor_id,
                source_object_type=sot,
                source_object_id=sop,
                classification_field="vantage",
            ):
                _reject_conflicting_replay(sot, sop)
            return RecordResult(ReachabilityEvidence.model_validate(existing), OUTCOME_REPLAY)
        record = ReachabilityEvidence.model_validate(row)
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
            event_name="exposure.reachability_recorded",
            details={
                "exposure_id": str(exposure_id),
                "record_id": str(record.id),
                "vantage": record.vantage,
                "producer": record.producer,
                "observed_at": record.observed_at.isoformat(),
                "outcome": OUTCOME_CREATED,
            },
        )
        return RecordResult(record, OUTCOME_CREATED)


def _current_reachability(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> tuple[Optional[Decimal], Optional[ReachabilityEvidence]]:
    """Current exact-exposure reachability: the latest non-revoked record's
    vantage maps to 10 (external) / 8 (internal). No record ⇒ (None, None) —
    unknown, never zero, never inherited from host-level fields."""
    cur.execute(
        """
        SELECT id, tenant_id, exposure_id, vantage, evidence, producer,
               observed_at, recorded_by, source_object_type, source_object_id, created_at
        FROM exposure_reachability_evidence
        WHERE tenant_id = %s AND exposure_id = %s AND revocation_of_id IS NULL
        ORDER BY observed_at DESC, id DESC
        """,
        (str(tenant_id), str(exposure_id)),
    )
    rows = cur.fetchall()
    if not rows:
        return None, None
    cur.execute(
        """
        SELECT revocation_of_id FROM exposure_reachability_evidence
        WHERE tenant_id = %s AND exposure_id = %s AND revocation_of_id IS NOT NULL;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    revoked = {str(r["revocation_of_id"]) for r in cur.fetchall()}
    for row in rows:
        if str(row["id"]) not in revoked:
            record = ReachabilityEvidence.model_validate(row)
            return REACHABILITY_VALUE[record.vantage], record
    return None, None


# ---------------------------------------------------------------------------
# Business Impact (§3.3.2: per-exposure 0–10, versioned; update affects only
# this exposure; no assessment = unknown)
# ---------------------------------------------------------------------------


def set_business_impact(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    data: BusinessImpactIn,
    *,
    actor_id: str,
    actor_role: str,
) -> RecordResult:
    with conn.cursor(row_factory=dict_row) as cur:
        _require_current_confirmed_episode(cur, tenant_id, exposure_id)
        cur.execute(
            """
            INSERT INTO exposure_business_impact (
                id, tenant_id, exposure_id, value, reason, assessed_by
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s
            )
            RETURNING id, tenant_id, exposure_id, value, reason, assessed_by, created_at;
            """,
            (
                str(tenant_id), str(exposure_id),
                data.value, data.reason, actor_id,
            ),
        )
        record = BusinessImpactRecord.model_validate(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
            event_name="exposure.business_impact_recorded",
            details={
                "exposure_id": str(exposure_id),
                "record_id": str(record.id),
                "value": float(record.value),
                "reason": record.reason,
                "outcome": OUTCOME_CREATED,
            },
        )
        return RecordResult(record, OUTCOME_CREATED)


def current_reachability(
    conn: psycopg.Connection, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> tuple[Optional[Decimal], Optional[ReachabilityEvidence]]:
    """Connection-scoped wrapper; see _current_reachability."""
    with conn.cursor(row_factory=dict_row) as cur:
        return _current_reachability(cur, tenant_id, exposure_id)


def _current_business_impact(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> Optional[BusinessImpactRecord]:
    """Latest version for the exposure; no version ⇒ unknown (None)."""
    cur.execute(
        """
        SELECT id, tenant_id, exposure_id, value, reason, assessed_by, created_at
        FROM exposure_business_impact
        WHERE tenant_id = %s AND exposure_id = %s
        ORDER BY created_at DESC, id DESC
        LIMIT 1;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    row = cur.fetchone()
    return BusinessImpactRecord.model_validate(row) if row else None


def current_business_impact(
    conn: psycopg.Connection, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> Optional[BusinessImpactRecord]:
    """Connection-scoped wrapper; see _current_business_impact."""
    with conn.cursor(row_factory=dict_row) as cur:
        return _current_business_impact(cur, tenant_id, exposure_id)


# ---------------------------------------------------------------------------
# Exploitation evidence (§3.3.3: closed producers, write-time kind, TTLs)
# ---------------------------------------------------------------------------


def record_exploitation_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    data: ExploitationEvidenceIn,
    *,
    actor_id: str,
    actor_role: str,
    producer: Optional[str] = "analyst_review",
    source_object_type: Optional[str] = None,
    source_object_id: Optional[str] = None,
    reviewed_by: Optional[str] = None,
) -> RecordResult:
    """
    Success-only record command. The evidence KIND is assigned here from the
    claimed basis (write-time rule): observed compromise ⇒
    observed_exploitation, successful controlled test ⇒
    controlled_validation. `result` must be 'succeeded' — failed, prevented,
    cancelled, unconfirmed, or artifact-only attempts raise
    EvidencePolicyError and create no record (they never form a rung).

    Producer is server-owned (closed allowlist: strike | analyst_review) and
    defaults to the analyst-review path. For producer='analyst_review' the
    authenticated actor IS the review authority: reviewed_by is forced to
    actor_id and any conflicting internally supplied reviewer is rejected.
    A successful test or uploaded artifact alone never becomes
    observed_exploitation — the kind follows the declared basis, and the
    write-time classification (not the producer) decides which TTL applies.
    """
    if producer not in EXPLOITATION_PRODUCERS:
        raise EvidencePolicyError(
            f"Producer '{producer}' is outside the closed exploitation-evidence "
            f"allowlist {EXPLOITATION_PRODUCERS}. Reserved producers (SIEM/EDR "
            "telemetry, workspace artifacts, unvalidated connectors) are rejected."
        )
    if data.result != "succeeded":
        raise EvidencePolicyError(
            f"Attempt result '{data.result}' is not a success; failed/prevented/"
            "cancelled/unconfirmed attempts never create exploitation evidence."
        )
    if producer == "analyst_review":
        # Analyst-review provenance (P0-02 correction): the authenticated actor
        # is the reviewer of record. A conflicting internally supplied reviewer
        # is a provenance forgery — rejected, never silently overwritten.
        if reviewed_by is not None and reviewed_by != actor_id:
            raise EvidencePolicyError(
                "reviewed_by must be the authenticated actor for analyst_review "
                "evidence; a conflicting reviewer identity is rejected."
            )
        reviewed_by = actor_id
    kind = "observed_exploitation" if data.basis == "observed" else "controlled_validation"
    observed_at = _normalize_occurrence(data.observed_at, "observed_at")
    raw_evidence = _serialize_payload(data.evidence)
    sot = source_object_type or ("strike_event" if producer == "strike" else "analyst_submission")
    sop = source_object_id or str(uuid.uuid4())

    with conn.cursor(row_factory=dict_row) as cur:
        _require_current_confirmed_episode(cur, tenant_id, exposure_id)
        cur.execute(
            """
            INSERT INTO exposure_exploitation_evidence (
                id, tenant_id, exposure_id, evidence_kind, producer, evidence,
                observed_at, recorded_by, reviewed_by, source_object_type, source_object_id
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s
            )
            ON CONFLICT (tenant_id, source_object_type, source_object_id) WHERE revocation_of_id IS NULL DO NOTHING
            RETURNING id, tenant_id, exposure_id, evidence_kind, producer, evidence,
                      observed_at, recorded_by, reviewed_by, source_object_type, source_object_id, created_at;
            """,
            (
                str(tenant_id), str(exposure_id), kind, producer, raw_evidence,
                observed_at, actor_id, reviewed_by, sot, sop,
            ),
        )
        row = cur.fetchone()
        if row is None:
            # Stable-source identity collision: replay only the exact same
            # logical record; a conflicting reuse is rejected, disclosed to
            # nobody, and commits nothing.
            cur.execute(
                """
                SELECT id, tenant_id, exposure_id, evidence_kind, producer, evidence,
                       observed_at, recorded_by, reviewed_by, source_object_type, source_object_id, created_at
                FROM exposure_exploitation_evidence
                WHERE tenant_id = %s AND source_object_type = %s AND source_object_id = %s;
                """,
                (str(tenant_id), sot, sop),
            )
            existing = cur.fetchone()
            if existing is None or not _replay_matches(
                existing,
                exposure_id=exposure_id,
                classification=kind,
                producer=producer,
                observed_at=observed_at,
                evidence_json=raw_evidence,
                recorded_by=actor_id,
                reviewed_by=reviewed_by,
                source_object_type=sot,
                source_object_id=sop,
                classification_field="evidence_kind",
            ):
                _reject_conflicting_replay(sot, sop)
            return RecordResult(ExploitationEvidence.model_validate(existing), OUTCOME_REPLAY)
        record = ExploitationEvidence.model_validate(row)
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
            event_name="exposure.exploitation_evidence_recorded",
            details={
                "exposure_id": str(exposure_id),
                "record_id": str(record.id),
                "evidence_kind": kind,
                "producer": producer,
                "observed_at": record.observed_at.isoformat(),
                "reviewed_by": record.reviewed_by,
                "outcome": OUTCOME_CREATED,
            },
        )
        return RecordResult(record, OUTCOME_CREATED)


def exploitation_ttl(kind: str) -> timedelta:
    """Locked policy constants (§3.3.3): eligibility windows keyed by kind."""
    if kind == "observed_exploitation":
        return OBSERVED_EXPLOITATION_TTL
    if kind == "controlled_validation":
        return CONTROLLED_VALIDATION_TTL
    raise EvidencePolicyError(f"Unknown evidence kind '{kind}'")


def is_exploitation_evidence_eligible(record: ExploitationEvidence, now: Optional[datetime] = None) -> bool:
    """
    Scoring eligibility: not revoked AND observed_at within the kind's TTL.
    Expired rows persist (queryable history) but are ineligible — TTL governs
    eligibility only, never deletion.
    """
    if record.revoked:
        return False
    now = now or _utcnow()
    observed = record.observed_at
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    return now - observed <= exploitation_ttl(record.evidence_kind)


def _list_exploitation_evidence(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[ExploitationEvidence]:
    cur.execute(
        """
        SELECT id, tenant_id, exposure_id, evidence_kind, producer, evidence,
               observed_at, recorded_by, reviewed_by, source_object_type, source_object_id,
               revocation_of_id, created_at
        FROM exposure_exploitation_evidence
        WHERE tenant_id = %s AND exposure_id = %s
        ORDER BY observed_at DESC, id DESC;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    rows = cur.fetchall()
    revoked = _revoked_ids(cur, "exposure_exploitation_evidence", tenant_id, exposure_id)
    return [
        ExploitationEvidence.model_validate({**r, "revoked": str(r["id"]) in revoked})
        for r in rows
        if r["revocation_of_id"] is None
    ]


def list_exploitation_evidence(
    conn: psycopg.Connection, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[ExploitationEvidence]:
    """Connection-scoped wrapper; see _list_exploitation_evidence."""
    with conn.cursor(row_factory=dict_row) as cur:
        return _list_exploitation_evidence(cur, tenant_id, exposure_id)


# ---------------------------------------------------------------------------
# Non-exploitation attestation (§3.6.4 — reserved, approval-gated)
# ---------------------------------------------------------------------------


def record_non_exploitation_attestation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    evidence_ref: str,
    actor_id: str,
    actor_role: str,
    attested_at: Optional[datetime] = None,
) -> RecordResult:
    """
    Reserve-shape attestation for the non-CVE ER floor ("no known
    exploitation" = 1.0 for 180 days, PRD §3.6.4). Non-CVE exposures only.
    The Chapter 5 dual-control approval columns stay empty — no attestation
    created here is scoring-eligible until P0-08 applies a valid approval.
    """
    attested = _normalize_occurrence(attested_at, "attested_at")
    with conn.cursor(row_factory=dict_row) as cur:
        _require_current_confirmed_episode(cur, tenant_id, exposure_id)
        episode = _lookup_exposure(cur, tenant_id, exposure_id)
        cur.execute(
            "SELECT canonical_cve_id FROM findings WHERE tenant_id = %s AND id = %s;",
            (str(tenant_id), str(episode["finding_id"])),
        )
        finding = cur.fetchone()
        if finding and finding["canonical_cve_id"] is not None:
            raise EvidencePolicyError(
                "Non-exploitation attestations apply to non-CVE exposures only "
                "(PRD §3.6.4); the CVE path uses intel feeds, not attestations."
            )
        cur.execute(
            """
            INSERT INTO exposure_non_exploitation_attestations (
                id, tenant_id, exposure_id, attested_by, attested_at, evidence_ref
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s
            )
            RETURNING id, tenant_id, exposure_id, attested_by, attested_at, evidence_ref, approved_by, approved_at, created_at;
            """,
            (str(tenant_id), str(exposure_id), actor_id, attested, evidence_ref),
        )
        record = NonExploitationAttestation.model_validate(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
            event_name="exposure.attestation_recorded",
            details={
                "exposure_id": str(exposure_id),
                "record_id": str(record.id),
                "attested_at": record.attested_at.isoformat(),
                "note": "reserved shape: not scoring-eligible until a Chapter 5 approval is applied (P0-08)",
                "outcome": OUTCOME_CREATED,
            },
        )
        return RecordResult(record, OUTCOME_CREATED)


def is_attestation_eligible(record: NonExploitationAttestation, now: Optional[datetime] = None) -> bool:
    """
    Eligible only when (a) the 180-day window from attested_at is open AND
    (b) a Chapter 5 dual-control approval is attached. Nothing in this ticket
    can set the approval, so no attestation is eligible yet — by design.
    """
    if record.approved_by is None or record.approved_at is None:
        return False
    now = now or _utcnow()
    attested = record.attested_at
    if attested.tzinfo is None:
        attested = attested.replace(tzinfo=timezone.utc)
    return now - attested <= ATTESTATION_TTL


def _list_attestations(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[NonExploitationAttestation]:
    cur.execute(
        """
        SELECT id, tenant_id, exposure_id, attested_by, attested_at, evidence_ref,
               approved_by, approved_at, created_at
        FROM exposure_non_exploitation_attestations
        WHERE tenant_id = %s AND exposure_id = %s
        ORDER BY attested_at DESC, id DESC;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    return [NonExploitationAttestation.model_validate(r) for r in cur.fetchall()]


def list_attestations(
    conn: psycopg.Connection, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[NonExploitationAttestation]:
    """Connection-scoped wrapper; see _list_attestations."""
    with conn.cursor(row_factory=dict_row) as cur:
        return _list_attestations(cur, tenant_id, exposure_id)


# ---------------------------------------------------------------------------
# Snapshot-scoped readers (share the caller's REPEATABLE READ snapshot)
# ---------------------------------------------------------------------------


def current_reachability_in_snapshot(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> tuple[Optional[Decimal], Optional[ReachabilityEvidence]]:
    return _current_reachability(cur, tenant_id, exposure_id)


def current_business_impact_in_snapshot(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> Optional[BusinessImpactRecord]:
    return _current_business_impact(cur, tenant_id, exposure_id)


def list_exploitation_evidence_in_snapshot(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[ExploitationEvidence]:
    return _list_exploitation_evidence(cur, tenant_id, exposure_id)


def list_attestations_in_snapshot(
    cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[NonExploitationAttestation]:
    return _list_attestations(cur, tenant_id, exposure_id)


# ---------------------------------------------------------------------------
# Revocation (append-only correction; original rows are never mutated)
# ---------------------------------------------------------------------------

_EVIDENCE_TABLES = {
    "reachability": "exposure_reachability_evidence",
    "exploitation": "exposure_exploitation_evidence",
}


def revoke_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    record_id: uuid.UUID,
    kind: Literal["reachability", "exploitation"],
    reason: str,
    *,
    actor_id: str,
    actor_role: str,
) -> RecordResult:
    """Append a revocation record pointing at the original; audit both ids.

    Idempotent by ORIGINAL (P0-02 final): the revocation source identity is
    ALWAYS derived from the original record ('revocation', 'revocation:<id>')
    — there is no caller-supplied override — and the database enforces the
    deeper invariant with a partial unique index
    (tenant_id, revocation_of_id) WHERE revocation_of_id IS NOT NULL, so no
    source identity, however constructed, can produce a second revocation of
    the same original.

    Convergence uses the PostgreSQL pattern INSERT … ON CONFLICT DO NOTHING
    RETURNING, targeting the partial uniqueness invariant:
      * a returned row is this caller's revocation — emit the one audit event
        and return 'created';
      * no returned row means another writer (or an earlier retry) already
        revoked this original — select the existing revocation whose
        revocation_of_id is the original and return 'replay'.
    No exception is caught; the connection is never committed or rolled back
    here: all earlier uncommitted work in the caller's transaction survives.
    Revoking a revocation row is rejected. All records stay append-only."""
    if not isinstance(reason, str) or len(reason.strip()) == 0:
        raise EvidencePolicyError("A revocation requires a non-empty reason.")
    table = _EVIDENCE_TABLES[kind]
    sop = f"revocation:{record_id}"  # always derived from the original record
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            SELECT tenant_id, exposure_id, revocation_of_id
            FROM {table} WHERE id = %s;
            """,
            (str(record_id),),
        )
        original = cur.fetchone()
        if not original:
            raise EntityNotFoundError(f"{kind} evidence record {record_id} not found")
        if str(original["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Evidence record {record_id} belongs to tenant {original['tenant_id']}, not {tenant_id}"
            )
        if str(original["exposure_id"]) != str(exposure_id):
            raise EvidencePolicyError(
                "Evidence records cannot be rebound to a different exposure episode."
            )
        if original["revocation_of_id"] is not None:
            # The supplied row IS a revocation; revocations are never revoked.
            raise EvidencePolicyError(
                "A revocation record cannot itself be revoked; append-only "
                "correction of a revocation requires a superseding workflow."
            )

        cur.execute(
            f"""
            INSERT INTO {table} (
                tenant_id, exposure_id, revocation_of_id, revocation_reason, recorded_by,
                source_object_type, source_object_id
            ) VALUES (
                %s, %s, %s, %s, %s, 'revocation', %s
            )
            ON CONFLICT (tenant_id, revocation_of_id) WHERE revocation_of_id IS NOT NULL DO NOTHING
            RETURNING id;
            """,
            (
                str(tenant_id), str(exposure_id), str(record_id), reason,
                actor_id, sop,
            ),
        )
        inserted = cur.fetchone()
        if inserted is not None:
            # This caller created the revocation: emit the single audit event.
            revocation_id = inserted["id"]
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
                event_name="exposure.evidence_revoked",
                details={
                    "kind": kind,
                    "exposure_id": str(exposure_id),
                    "record_id": str(record_id),
                    "revocation_id": str(revocation_id),
                    "outcome": OUTCOME_CREATED,
                },
            )
            return RecordResult(
                {"id": revocation_id, "revoked_record_id": str(record_id)}, OUTCOME_CREATED
            )

        # Lost the insert race (retry or concurrent retry): converge on the
        # existing revocation of this original — one row, no second audit.
        cur.execute(
            f"""
            SELECT id FROM {table}
            WHERE tenant_id = %s AND revocation_of_id = %s
            ORDER BY created_at, id
            LIMIT 1;
            """,
            (str(tenant_id), str(record_id)),
        )
        winner = cur.fetchone()
        if winner is None:  # pragma: no cover - defensive
            raise EvidencePolicyError(
                "Revocation source-identity collision resolved to no revocation."
            )
        return RecordResult(
            {"id": winner["id"], "revoked_record_id": str(record_id)}, OUTCOME_REPLAY
        )


# ---------------------------------------------------------------------------
# Snapshot read (evidence download — audited per Appendix C Q12)
# ---------------------------------------------------------------------------


def get_scoring_inputs(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict[str, Any]:
    """
    ONE snapshot of the exposure's scoring inputs with provenance and
    eligibility, read through the caller's single PostgreSQL REPEATABLE READ
    transaction snapshot established BEFORE the first query: concurrent ledger
    writes that commit midway cannot produce a mixed-time response.

    TRANSACTION OWNERSHIP (P0-02 round 2): this command NEVER calls
    conn.commit() or conn.rollback(). The caller (the API route) establishes
    REPEATABLE READ before invoking it, owns the boundary, commits on success,
    and rolls back on failure — so prior uncommitted work on the caller's
    connection is never silently discarded or published, and an audit failure
    here surfaces to the caller whose rollback undoes the whole snapshot
    including the audit event (Q12: the read is an evidence download, audited
    inside the same snapshot transaction).
    """
    with conn.cursor(row_factory=dict_row) as cur:
        _lookup_exposure(cur, tenant_id, exposure_id)

        reachability_value, reachability_record = current_reachability_in_snapshot(cur, tenant_id, exposure_id)
        bi_record = current_business_impact_in_snapshot(cur, tenant_id, exposure_id)
        exploitation = list_exploitation_evidence_in_snapshot(cur, tenant_id, exposure_id)
        attestations = list_attestations_in_snapshot(cur, tenant_id, exposure_id)

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
            event_name="exposure.evidence_downloaded",
            details={
                "exposure_id": str(exposure_id),
                "evidence_ids": [str(r.id) for r in exploitation],
                "reachability_record_id": str(reachability_record.id) if reachability_record else None,
            },
        )
        # No commit / no rollback here: the application boundary decides.

    return {
        "exposure_id": str(exposure_id),
        "tenant_id": str(tenant_id),
        "reachability": None
        if reachability_record is None
        else {
            "value": float(reachability_value),
            "vantage": reachability_record.vantage,
            "record": reachability_record.model_dump(mode="json"),
        },
        "business_impact": None
        if bi_record is None
        else {"value": bi_record.value, "record": bi_record.model_dump(mode="json")},  # exact Decimal
        "exploitation_evidence": [
            {
                "record": r.model_dump(mode="json"),
                "eligible": is_exploitation_evidence_eligible(r),
                "ttl_days": exploitation_ttl(r.evidence_kind).days,
            }
            for r in exploitation
        ],
        "non_exploitation_attestations": [
            {
                "record": a.model_dump(mode="json"),
                "eligible": is_attestation_eligible(a),
                "ttl_days": ATTESTATION_TTL.days,
            }
            for a in attestations
        ],
    }
