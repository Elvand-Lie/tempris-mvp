# backend/app/exposure/tes_read_model.py
"""
P0-05 — CVE TES READ MODEL (PRD-000 v1.11 §3.3.1–§3.3.6; §3.5 #2/#3/#6/#7;
Appendix C Q17; Appendix D PATCH-13; ticket P0-05 cve-tes-read-model).

The authorized CURRENT-SCORE read service. Per §3.3.6 (one truth) the current
score is deterministically recomputed from current authoritative inputs at
read time; this module is the composition — it owns NO scoring logic of its
own. Every rule it applies is reused verbatim:

  * exposure truth / finding roll-up ..... P0-01 exposure service
  * exact-episode reachability, Business
    Impact, exploitation evidence,
    revocations .......................... P0-02 ledger readers (scoring_inputs)
  * CVSS authority, EPSS freshness,
    KEV ternary, feed health ............. P0-03 resolvers (repository)
  * rung selection, renormalization,
    states, decomposition ................ P0-04 kernel (tes_kernel.compute_tes)

TRANSACTION OWNERSHIP (PATCH-13; mirrors get_scoring_inputs): this service
NEVER commits or rolls back. The route establishes ONE caller-owned
REPEATABLE READ transaction BEFORE the first query, captures one `as_of`,
and owns the boundary — commit on success, rollback on any failure. Every
read below (exposure, asset, ledgers, CVSS, EPSS, KEV) shares that one
snapshot, so the payload is one coherent source view: a concurrent ledger or
feed write that commits midway cannot produce a mixed-time response, and a
supersession that commits after the snapshot simply does not exist inside it.

GETs are side-effect free: no score persistence, no snapshots, no audit rows,
no refresh, no scheduler work (§3.3.6 — snapshots are written when a decision
consumes the score, never on read; Appendix C Q12 reads stay unaudited).
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.exposure import scoring_inputs as ledger
from app.exposure.tes_kernel import (
    BusinessImpactInput,
    CriticalityInput,
    CriticalityLabel,
    EpssObservation,
    ExactExposureEvidence,
    ExactExposureEvidenceState,
    ExploitRealityInput,
    EvidenceKind,
    FeedFreshness,
    FeedHealthProvenance,
    FreshnessState,
    IntrinsicInput,
    KevObservation,
    KevRansomwareFlag,
    KevTernaryState,
    ProvenanceClass,
    QualifiedValue,
    ReachabilityInput,
    ReachabilityVantage,
    TesInputs,
    TesResult,
    compute_tes,
    FORMULA_VERSION,
)
from app.exposure.exceptions import (
    EvidencePolicyError,
    ExposureNotFoundError,
    TenantMismatchError,
)
from app.vuln_intelligence.repository import (
    resolve_cvss_authority,
    resolve_epss_freshness,
    resolve_kev_status,
    EPSS_STALE,
    KEV_STALE,
)

# ---------------------------------------------------------------------------
# Source view — the PATCH-13 binding block (every identity the payload is
# bound to, so any reader can re-derive exactly which facts produced it)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceView:
    """Identity references of the coherent snapshot the payload was computed
    from (PATCH-13: one coherent `as_of` source view per snapshot; the read
    is bound to exposure episode, coherent as_of, exposure status/version,
    CVSS assessment identity, EPSS/KEV last-good snapshot identities, and
    the exact ledger rows used)."""

    as_of: datetime
    exposure_id: str
    exposure_status: str
    exposure_confirmed_at: datetime
    finding_id: str
    asset_id: str
    asset_status: str
    cvss_assessment_id: Optional[str] = None
    cvss_source_record_id: Optional[str] = None
    epss_snapshot_id: Optional[str] = None
    epss_source_record_id: Optional[str] = None
    kev_snapshot_id: Optional[str] = None
    kev_source_record_id: Optional[str] = None
    reachability_record_id: Optional[str] = None
    business_impact_record_id: Optional[str] = None
    exploitation_evidence_ids: tuple[str, ...] = ()


# §3.5 #6: the summary is returned as a plain dict of EXACTLY these six flat
# fields — max_final_tes, max_provisional_tes, final_count,
# provisional_count, unscoreable_count, total_current_exposures — and
# nothing else (the route already identifies the finding; finding_id and
# as_of are deliberately not part of the response body).


class FindingNotFoundError(ExposureNotFoundError):
    """The finding does not exist in the requesting tenant (fail closed —
    the response is identical for a missing and a cross-tenant finding)."""


# ---------------------------------------------------------------------------
# Internal read helpers — thin tenant-scoped SELECTs over the shared snapshot
# ---------------------------------------------------------------------------


def _load_exposure_for_tes(
    conn: psycopg.Connection, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> dict:
    """One joined read: exposure episode + finding (CVE identity) + active
    asset. Current = status 'confirmed' AND asset active (PRD §3.3.1
    currentness); finding status is NEVER a filter (§3.3.1; the recorded
    dedupe precedent that filters f.status is behavior, not authority). A
    missing row, a cross-tenant id, or a non-current episode is the same
    fail-closed outcome: no TES.

    Tenant isolation is enforced directly in SQL — the AuthContext tenant is
    bound into the WHERE clause alongside the object id (not filtered in
    Python after fetching), so another tenant's row is never read.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id AS exposure_id, e.tenant_id, e.finding_id, e.asset_id,
                   e.status AS exposure_status, e.confirmed_at, e.evidence,
                   e.xmin::text AS exposure_version,
                   f.canonical_cve_id, f.status AS finding_status,
                   a.status AS asset_status, a.criticality AS asset_criticality,
                   a.updated_at AS asset_updated_at
            FROM asset_exposures e
            JOIN findings f ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
            JOIN assets a ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
            WHERE e.tenant_id = %s AND e.id = %s;
            """,
            (str(tenant_id), str(exposure_id)),
        )
        row = cur.fetchone()
    if row is None:
        # Same 404 for unknown and cross-tenant ids — no disclosure (the
        # tenant predicate above already excluded other tenants' rows).
        raise ExposureNotFoundError(f"Exposure {exposure_id} not found")
    if row["exposure_status"] != "confirmed":
        raise ExposureNotFoundError(
            f"Exposure {exposure_id} is not a current confirmed episode "
            f"(status={row['exposure_status']}); it has no current TES value"
        )
    if row["asset_status"] != "active":
        raise ExposureNotFoundError(
            f"Exposure {exposure_id} sits on an inactive asset; it has no "
            "current TES value"
        )
    return row


def _load_finding_for_summary(
    conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> dict:
    """Tenant isolation is enforced directly in SQL (AuthContext tenant bound
    into the WHERE clause with the object id); unknown and cross-tenant ids
    are the same 404."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, canonical_cve_id, status AS finding_status
            FROM findings
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(finding_id)),
        )
        row = cur.fetchone()
    if row is None:
        raise FindingNotFoundError(f"Finding {finding_id} not found")
    return row


def _list_current_exposure_ids_for_finding(
    conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> list[dict]:
    """Current-episode set for the summary grain: status 'confirmed' on
    active assets, EXCLUDING resolved / false_positive / superseded history
    (recurrence episodes of the same finding are separate current episodes
    and legitimately counted). No finding-status predicate (§3.3.1)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id AS exposure_id
            FROM asset_exposures e
            JOIN assets a ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
            WHERE e.tenant_id = %s AND e.finding_id = %s
              AND e.status = 'confirmed'
              AND a.status = 'active'
            ORDER BY e.confirmed_at DESC, e.id ASC;
            """,
            (str(tenant_id), str(finding_id)),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Resolver → kernel input mapping (P0-03 → P0-04; complete feed-health
# provenance per the mandatory-health contract)
# ---------------------------------------------------------------------------


def _feed_health(resolver_provenance) -> FeedHealthProvenance:
    """Field-for-field map of P0-03's ResolverProvenance into the pure P0-04
    type. freshness_age_seconds is normalized to float (None stays None); the
    kernel validates finite/non-negative."""
    prov = resolver_provenance
    if prov is None:
        raise ExposureNotFoundError("Feed provenance missing from resolver result")
    age = prov.freshness_age_seconds
    if age is not None:
        age = float(age)
    return FeedHealthProvenance(
        source=prov.source,
        is_healthy=prov.is_healthy,
        last_successful_at=prov.last_successful_at,
        last_snapshot_id=prov.last_snapshot_id,
        last_good_snapshot_id=prov.last_good_snapshot_id,
        freshness_age_seconds=age,
    )


def _feed_freshness(state: str, reason_code: Optional[str]) -> FeedFreshness:
    """The resolvers encode feed staleness in the reason code (the KEV
    'state' is the snapshot ternary itself): a stale gate failure is STALE;
    every other non-fresh outcome (no sync state, unhealthy, never imported,
    no last-good generation) is UNKNOWN — the feed cannot establish any
    current state. Fresh state maps to FRESH."""
    if state == "fresh":
        return FeedFreshness.FRESH
    if reason_code in (EPSS_STALE, KEV_STALE):
        return FeedFreshness.STALE
    return FeedFreshness.UNKNOWN


def _map_epss(resolution, as_of: datetime) -> Optional[EpssObservation]:
    """EPSS resolver result → kernel observation.

    ``state='fresh'`` with a score is the score-bearing observation; a fresh
    feed with NO row for this CVE maps to a valueless FRESH observation
    (checked feed, unknown score — it cannot claim the <0.002 bottom band);
    stale/unhealthy feeds map to valueless STALE/UNKNOWN observations so the
    kernel names the unresolved potentially-higher source."""
    if resolution is None:
        return None
    freshness = _feed_freshness(resolution.state, resolution.reason_code)
    is_fresh = resolution.state == "fresh"
    value = resolution.score if is_fresh else None
    observed_at: Optional[datetime] = None
    if is_fresh:
        if resolution.score_date is not None:
            observed_at = datetime.combine(
                resolution.score_date, datetime.min.time(), tzinfo=timezone.utc
            )
        else:
            # Honest fallback: the observation belongs to the last-good
            # import generation; its import instant is the feed's own fact.
            observed_at = (
                resolution.provenance.last_successful_at
                if resolution.provenance is not None
                else None
            ) or as_of
    return EpssObservation(
        value=value,
        freshness=freshness,
        percentile=(resolution.percentile if is_fresh else None),
        source="epss",
        observed_at=observed_at,
        feed_health=_feed_health(resolution.provenance),
    )


def _map_kev(resolution, as_of: datetime) -> Optional[KevObservation]:
    """KEV ternary resolver result → kernel observation (listed /
    not_listed / unknown; the kernel decides rungs and provisionalness).
    listed/not_listed imply the fresh gate passed (absence inside a fresh
    authoritative generation is definitive); a stale gate failure maps to
    STALE, any other non-fresh outcome to UNKNOWN."""
    if resolution is None:
        return None
    state = {
        "listed": KevTernaryState.LISTED,
        "not_listed": KevTernaryState.NOT_LISTED,
        "unknown": KevTernaryState.UNKNOWN,
    }.get(resolution.state)
    if state is None:
        raise TenantMismatchError(  # defensive: closed ternary upstream
            f"KEV resolver returned an out-of-vocabulary state {resolution.state!r}"
        )
    ransomware = {
        "known": KevRansomwareFlag.KNOWN,
        "not_known": KevRansomwareFlag.NOT_KNOWN,
    }.get((resolution.known_ransomware or "").strip().lower(), KevRansomwareFlag.UNKNOWN)
    prov = resolution.provenance
    # The KEV ternary carries a snapshot identity, not a per-CVE observation
    # timestamp; the observation's effective timestamp is the last-good
    # generation's import instant (the caller-supplied provenance fact). A
    # never-imported feed has none — the resolution instant (as_of) is the
    # honest effective time of an unknown-state resolution.
    kev_observed_at = (prov.last_successful_at if prov is not None else None) or as_of
    # Freshness from the TERNARY, not the word 'fresh': the resolver returns
    # listed/not_listed only inside a fresh authoritative last-good
    # generation (fresh absence is definitive not_listed), so those two map
    # to FRESH. An unknown ternary is STALE only on a stale gate failure;
    # every other unknown outcome (unhealthy / never / no snapshot) is
    # UNKNOWN — the feed cannot establish any current state.
    if state is not KevTernaryState.UNKNOWN:
        kev_freshness = FeedFreshness.FRESH
    elif resolution.reason_code == KEV_STALE:
        kev_freshness = FeedFreshness.STALE
    else:
        kev_freshness = FeedFreshness.UNKNOWN
    return KevObservation(
        state=state,
        freshness=kev_freshness,
        ransomware=ransomware,
        source="kev",
        observed_at=kev_observed_at,
        feed_health=_feed_health(resolution.provenance),
    )


def _map_cvss(resolution, as_of: datetime) -> Optional[IntrinsicInput]:
    """CVSS authority resolution → intrinsic input. UNSCOREABLE results
    (missing/ambiguous authority) map to None — the kernel fails closed
    UNSCOREABLE (§3.3.4); the reason survives in the payload source view."""
    if resolution is None or not resolution.is_scoreable:
        return None
    return IntrinsicInput(
        value=resolution.score,
        provenance_class=ProvenanceClass.MACHINE_OBSERVED,
        freshness=FreshnessState.FRESH,
        # The authoritative row's own creation instant; the read instant is
        # the effective timestamp of this read's authority resolution.
        observed_at=(resolution.created_at or as_of),
        source=f"cvss_authority:{resolution.version}:{resolution.role or 'unknown'}",
        derivation=f"cvss_{str(resolution.version).replace('.', '_')}_cna",
    )


def _map_criticality(row: dict, as_of: datetime) -> Optional[CriticalityInput]:
    label = row.get("asset_criticality")
    if not label:
        return None
    return CriticalityInput(
        label=CriticalityLabel(label),
        provenance_class=ProvenanceClass.MACHINE_OBSERVED,
        freshness=FreshnessState.FRESH,
        observed_at=(row.get("asset_updated_at") or as_of),
        source="assets-service",
    )


def _map_boundary_criticality(
    binding: Optional[dict], as_of: datetime
) -> Optional[CriticalityInput]:
    """Design-A criticality for IDENTITY_POSTURE exposures (P0-07/P0-08):
    the tenant_identity_boundary binding's OWN criticality — never
    assets.criticality. A missing binding renders the axis unknown
    (the caller falls back to None ⇒ PROVISIONAL, never assets.criticality)."""
    if binding is None or not binding.get("criticality"):
        return None
    return CriticalityInput(
        label=CriticalityLabel(binding["criticality"]),
        provenance_class=ProvenanceClass.ANALYST_ENTERED,
        freshness=FreshnessState.FRESH,
        observed_at=(binding.get("set_at") or as_of),
        source=f"identity_boundary:{binding['id']}",
    )


def _map_reachability(value: Optional[Decimal], record) -> Optional[ReachabilityInput]:
    if record is None or value is None:
        return None
    return ReachabilityInput(
        vantage=ReachabilityVantage(record.vantage),
        provenance_class=ProvenanceClass.MACHINE_OBSERVED,
        freshness=FreshnessState.FRESH,
        observed_at=record.observed_at,
        source=record.producer,
    )


def _map_exploitation_evidence(
    records: list, as_of: datetime
) -> tuple[Optional[ExactExposureEvidence], Optional[ExactExposureEvidence], list[str]]:
    """Eligibility-resolved exact-exposure evidence → kernel slots.

    Returns (fresh_slot, stale_slot, evidence_ids):
      * fresh slot — the newest non-revoked record within its kind TTL
        (TTL eligibility is the P0-02 helper's rule, never re-derived);
      * stale slot — the newest non-revoked record past its TTL, kept fully
        qualified so the stale-higher rule stays auditable (P0-04 contract);
      * ids — every non-revoked record consulted (source view binding).
    Revoked records enter nothing (P0-02 revocation semantics reused).
    """
    fresh: Optional[ExactExposureEvidence] = None
    stale: Optional[ExactExposureEvidence] = None
    ids: list[str] = []
    for r in records:  # newest-first from the ledger reader
        if r.revoked:
            continue
        ids.append(str(r.id))
        kind = EvidenceKind(r.evidence_kind)
        if ledger.is_exploitation_evidence_eligible(r, now=as_of):
            if fresh is None:
                fresh = ExactExposureEvidence(
                    ExactExposureEvidenceState.FRESH_QUALIFYING,
                    kind=kind,
                    observed_at=r.observed_at,
                    source=r.producer,
                    provenance_class=(
                        ProvenanceClass.ANALYST_ENTERED
                        if r.producer == "analyst_review"
                        else ProvenanceClass.MACHINE_OBSERVED
                    ),
                )
        elif stale is None:
            stale = ExactExposureEvidence(
                ExactExposureEvidenceState.STALE,
                kind=kind,
                observed_at=r.observed_at,
                source=r.producer,
                provenance_class=(
                    ProvenanceClass.ANALYST_ENTERED
                    if r.producer == "analyst_review"
                    else ProvenanceClass.MACHINE_OBSERVED
                ),
            )
    return fresh, stale, ids


def _build_er_input(
    epss, kev, fresh_slot, stale_slot
) -> ExploitRealityInput:
    """The CVE-path ER input factory (§3.3.3 ladder).

    P0-08a structural containment: the signature has NO attestation
    parameter, so a CVE-path caller is UNABLE to populate
    ``attested_no_exploitation`` through this factory — the CVE ladder has
    no attestation rung and its bottom rung requires fresh intel (fresh
    EPSS < 0.002 AND fresh KEV not-listed). The non-CVE path (§3.6.4) is
    the ONLY writer of the attestation slot (``_map_non_cve_er``), and
    ``_assert_cve_path_er_input`` backstops any object that reaches a CVE
    composition by another route.
    """
    return ExploitRealityInput(
        epss=epss,
        kev=kev,
        exact_exposure_fresh=fresh_slot,
        exact_exposure_stale=stale_slot,
    )


def _assert_cve_path_er_input(er_input: ExploitRealityInput) -> None:
    """Defense-in-depth for the CVE ER ladder (P0-08a): the attestation rung
    is non-CVE-only (§3.6.6 #5), so a populated ``attested_no_exploitation``
    slot arriving from a CVE-path producer is a contract violation and fails
    closed — a CVE must never reach FINAL on ER 1.0 without fresh intel.
    The non-CVE path never calls this (its slot is legitimate)."""
    if er_input.attested_no_exploitation is not None:
        raise EvidencePolicyError(
            "attested_no_exploitation is a non-CVE-only ER rung (§3.6.6 #5); "
            "the CVE ladder (§3.3.3) has no attestation rung — fail closed"
        )


def _map_non_cve_er(
    exploitation: list, attestation: Optional[dict], as_of: datetime
) -> tuple[ExploitRealityInput, Optional[str]]:
    """Non-CVE ER inputs (§3.6.4 ladder; P0-08 item 3):

      * observed/validated exploitation on THIS episode ⇒ 10.0 — the P0-02
        ledger through the SAME mapping as CVE (kind TTLs: observed 365d,
        controlled validation 180d; failed/prevented never score; producers
        are analyst-reviewed evidence in this phase — STRIKE does not exist);
      * a fresh approved attestation ⇒ ER 1.0 — attested + approved in the
        180-day window (P0-06's ``is_attestation_eligible`` rule reused
        verbatim: eligibility needs BOTH the window and the approval stamp;
        an unapproved analyst assertion is NEVER ER 1);
      * otherwise unknown ⇒ the kernel renormalizes PROVISIONAL.

    Returns (ExploitRealityInput, attestation_state) — the attestation state
    ("fresh_approved" | "stale" | "unapproved" | None) keeps the ladder
    auditable in the payload's source view.
    """
    fresh_slot, stale_slot, _ids = _map_exploitation_evidence(exploitation, as_of)
    attestation_state: Optional[str] = None
    attestation_slot = None
    if attestation is not None:
        approved = getattr(attestation, "approved_at", None) is not None
        attested = getattr(attestation, "attested_at", None)
        if attested is not None and attested.tzinfo is None:
            from datetime import timezone as _tz
            attested = attested.replace(tzinfo=_tz.utc)
        in_window = (
            attested is not None
            and (as_of - attested) <= ledger.ATTESTATION_TTL
        )
        if approved and in_window:
            attestation_state = "fresh_approved"
            # the dedicated §3.6.4 attestation slot — ER 1.0 exactly, a
            # DISTINCT rung (never rendered as observed exploitation ER 10)
            attestation_slot = ExactExposureEvidence(
                ExactExposureEvidenceState.FRESH_QUALIFYING,
                kind=EvidenceKind.OBSERVED_EXPLOITATION,
                observed_at=attested,
                source=f"attestation:{attestation.id}",
                provenance_class=ProvenanceClass.ANALYST_ENTERED,
            )
        elif approved:
            attestation_state = "stale"
            attestation_slot = ExactExposureEvidence(
                ExactExposureEvidenceState.STALE,
                kind=EvidenceKind.OBSERVED_EXPLOITATION,
                observed_at=attested or as_of,
                source=f"attestation:{attestation.id}",
                provenance_class=ProvenanceClass.ANALYST_ENTERED,
            )
        else:
            attestation_state = "unapproved"  # visible, never ER 1
    # P0-08a: the non-CVE path is the ONLY construction site that may carry
    # the attestation slot (the CVE-path factory's signature cannot).
    er_input = ExploitRealityInput(
        epss=None,
        kev=None,
        exact_exposure_fresh=fresh_slot,
        exact_exposure_stale=stale_slot,
        attested_no_exploitation=attestation_slot,
    )
    return er_input, attestation_state


# ---------------------------------------------------------------------------
# Serialization — lossless Decimal (API data keeps full precision; only
# display_value is rounded, and it comes rounded from the kernel)
# ---------------------------------------------------------------------------


def _jsonify(obj: Any) -> Any:
    """Recursively convert kernel dataclasses/enums/Decimals into
    JSON-safe values WITHOUT losing precision: every Decimal becomes its
    exact string form (the API consumer decodes losslessly)."""
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    if isinstance(obj, Decimal):
        return {"__decimal__": str(obj)}  # exact string form, no float hop
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, enum.Enum):
        return obj.value

    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _jsonify(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonify(v) for v in obj]
    if hasattr(obj, "__dataclass_fields__"):
        return {
            k: _jsonify(v)
            for k, v in obj.__dict__.items()
        }
    return str(obj)


# ---------------------------------------------------------------------------
# The read services (transaction: caller-owned REPEATABLE READ; this module
# never commits, never rolls back, never writes)
# ---------------------------------------------------------------------------


def get_exposure_tes(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    as_of: datetime,
) -> dict:
    """One exposure's atomic current-TES payload (§3.3.5).

    Caller contract: `conn` is inside a REPEATABLE READ transaction
    established BEFORE the first query and `as_of` was captured at/inside
    that boundary; all reads share that one snapshot. The payload is bound
    to the actual episode row version (``e.xmin::text`` — PostgreSQL's
    native row-version token, which changes when lifecycle status changes,
    unlike confirmed_at) via ``source_view.exposure_version``; a
    supersession commit outside the snapshot therefore never alters this
    response's version token.
    """
    exposure = _load_exposure_for_tes(conn, tenant_id, exposure_id)
    finding_id = exposure["finding_id"]
    asset_id = exposure["asset_id"]
    cve_id = exposure.get("canonical_cve_id")

    source_view = {
        "exposure_id": str(exposure_id),
        "exposure_status": exposure["exposure_status"],
        "exposure_confirmed_at": exposure["confirmed_at"],
        # PostgreSQL's native row-version token (xmin at read time): the
        # status/version reference that actually changes when the episode's
        # lifecycle row changes (e.g. supersession). No new versioning
        # subsystem — a native column cast, per the bounded correction.
        "exposure_version": exposure["exposure_version"],
        "finding_id": str(finding_id),
        "asset_id": str(asset_id),
        "asset_status": exposure["asset_status"],
    }

    # ---- Intrinsic: authoritative CVSS through P0-03 (same snapshot) -------
    cvss_resolution = None
    sss_intrinsic = None
    taxonomy_class = None
    if cve_id:
        cvss_resolution = resolve_cvss_authority(conn, cve_id)
    else:
        # Non-CVE finding (§3.6.4): the SSS occupies the intrinsic slot —
        # the current derivation (vrt/rubric), else an approved manual
        # proposal / override (P0-08); none ⇒ None ⇒ kernel fails closed
        # UNSCOREABLE (never guesses).
        from app.exposure.sss import current_sss_intrinsic
        from app.exposure.approval_consumers_noncve_read import \
            current_sss_intrinsic_with_provenance, taxonomy_class_of_finding
        sss_intrinsic = current_sss_intrinsic_with_provenance(
            conn, tenant_id, finding_id
        )
        taxonomy_class = taxonomy_class_of_finding(conn, tenant_id, finding_id)

    # ---- Contextual: P0-02 exact-episode ledgers (same snapshot) ----------
    with conn.cursor(row_factory=dict_row) as cur:
        reach_value, reach_record = ledger.current_reachability_in_snapshot(
            cur, tenant_id, exposure_id
        )
        bi_record = ledger.current_business_impact_in_snapshot(
            cur, tenant_id, exposure_id
        )
        exploitation = ledger.list_exploitation_evidence_in_snapshot(
            cur, tenant_id, exposure_id
        )
        attestation = None
        if not cve_id:
            attestation = ledger.list_attestations_in_snapshot(
                cur, tenant_id, exposure_id
            )
            attestation = attestation[0] if attestation else None  # newest
    if cve_id:
        fresh_slot, stale_slot, evidence_ids = _map_exploitation_evidence(
            exploitation, as_of
        )
        # ---- Intel: P0-03 EPSS + KEV (same connection, snapshot, as_of) ---
        epss_res = resolve_epss_freshness(conn, cve_id, as_of=as_of)
        kev_res = resolve_kev_status(conn, cve_id, as_of=as_of)
        er_input = _build_er_input(
            _map_epss(epss_res, as_of), _map_kev(kev_res, as_of),
            fresh_slot, stale_slot,
        )
        # P0-08a defense-in-depth: fail closed if attestation-shaped data
        # ever reaches a CVE-path ER composition through any route.
        _assert_cve_path_er_input(er_input)
    else:
        attestation_state = None
        er_input, attestation_state = _map_non_cve_er(
            exploitation, attestation, as_of
        )

    # ---- Compose the kernel input -----------------------------------------
    intrinsic = _map_cvss(cvss_resolution, as_of) if cve_id else sss_intrinsic

    # Criticality per design A (P0-07/P0-08): IDENTITY_POSTURE exposures
    # read the boundary binding's OWN criticality; every other exposure on
    # the same asset keeps assets.criticality. A missing binding renders the
    # axis unknown (⇒ PROVISIONAL) — never a silent fallback to the asset.
    criticality = None
    boundary_binding = None
    if taxonomy_class == "IDENTITY_POSTURE":
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, criticality, set_at FROM tenant_identity_boundary
                WHERE tenant_id = %s AND asset_id = %s AND state = 'active';
                """,
                (str(tenant_id), str(asset_id)),
            )
            boundary_binding = cur.fetchone()
        criticality = _map_boundary_criticality(boundary_binding, as_of)
    else:
        criticality = _map_criticality(exposure, as_of)
    reachability = _map_reachability(reach_value, reach_record)
    business_impact = (
        BusinessImpactInput(
            assessment=QualifiedValue(
                value=bi_record.value,
                provenance_class=ProvenanceClass.ANALYST_ENTERED,
                freshness=FreshnessState.FRESH,
                observed_at=bi_record.created_at,
                source=bi_record.assessed_by,
            )
        )
        if bi_record is not None
        else None
    )

    result: TesResult = compute_tes(
        TesInputs(intrinsic=intrinsic, exploit_reality=er_input,
                  criticality=criticality, reachability=reachability,
                  business_impact=business_impact)
    )

    # ---- Source view completion (PATCH-13 identities) ---------------------
    source_view["cvss_assessment_id"] = (
        cvss_resolution.assessment_id if cvss_resolution else None
    )
    source_view["cvss_source_record_id"] = (
        cvss_resolution.source_record_id if cvss_resolution else None
    )
    # Non-CVE provenance (P0-08 item 4: approved-vs-derived visible in the
    # decomposition/payload; the pre-override derived value stays visible)
    source_view["taxonomy_class"] = taxonomy_class
    source_view["sss"] = (
        {
            "derivation_id": sss_intrinsic.source_view.get("derivation_id"),
            "path": sss_intrinsic.source_view.get("path"),
            "value": str(sss_intrinsic.source_view.get("value")),
            "provenance": (
                "analyst override" if sss_intrinsic.source_view.get("path") == "override"
                else ("approved manual" if sss_intrinsic.source_view.get("path") == "manual"
                      else "derived")),
            "approval_id": sss_intrinsic.source_view.get("approval_id"),
            "pre_override_derivation_id": sss_intrinsic.source_view.get(
                "pre_override_derivation_id"),
            "pre_override_value": (
                str(sss_intrinsic.source_view["pre_override_value"])
                if sss_intrinsic.source_view.get("pre_override_value") is not None
                else None),
        }
        if sss_intrinsic is not None else None
    )
    source_view["attestation_state"] = (
        attestation_state if not cve_id else None
    )
    source_view["boundary_binding_id"] = (
        str(boundary_binding["id"]) if boundary_binding is not None else None
    )
    if cve_id:
        source_view["epss_snapshot_id"] = (
            epss_res.snapshot_id if epss_res else None)
        source_view["epss_source_record_id"] = (
            epss_res.source_record_id if epss_res else None)
        source_view["kev_snapshot_id"] = (
            kev_res.snapshot_id if kev_res else None)
        source_view["kev_source_record_id"] = (
            kev_res.source_record_id if kev_res else None)
    else:
        # Non-CVE: no intel feeds (the CVE/EPSS/KEV resolvers are never
        # consulted — §3.6.4 keeps the non-CVE path feed-independent)
        source_view["epss_snapshot_id"] = None
        source_view["epss_source_record_id"] = None
        source_view["kev_snapshot_id"] = None
        source_view["kev_source_record_id"] = None
    source_view["reachability_record_id"] = (
        str(reach_record.id) if reach_record is not None else None
    )
    source_view["business_impact_record_id"] = (
        str(bi_record.id) if bi_record is not None else None
    )
    if cve_id:
        source_view["exploitation_evidence_ids"] = tuple(evidence_ids)
    else:
        source_view["exploitation_evidence_ids"] = tuple(
            str(r.id) for r in exploitation if not r.revoked
        )

    unscoreable_reason = None
    if result.state.value == "UNSCOREABLE":
        if cvss_resolution is not None:
            unscoreable_reason = cvss_resolution.reason_code or cvss_resolution.reason
        elif not cve_id and sss_intrinsic is None:
            unscoreable_reason = "no_valid_sss"

    return {
        "exposure_id": str(exposure_id),
        "finding_id": str(finding_id),
        "asset_id": str(asset_id),
        "tenant_id": str(tenant_id),
        "canonical_cve_id": cve_id,
        "formula_version": result.formula_version,
        "state": result.state.value,
        "value": result.value,
        "display_value": result.display_value,
        "known_axes": result.known_axes_count,
        "known_weight": result.known_weight,
        "missing_inputs": list(result.missing_inputs),
        "decomposition": _jsonify(result.decomposition),
        "source_view": {
            **source_view,
            "as_of": as_of,
            "cvss_unscoreable_reason_code": unscoreable_reason,
        },
    }


def get_finding_tes_summary(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    as_of: datetime,
) -> dict:
    """The exact six-field finding summary (§3.5 #6) over the finding's
    CURRENT confirmed exposures on ACTIVE assets. Max, never mean; FINAL and
    PROVISIONAL maxima never combine; UNSCOREABLE is counted, never hidden.
    Supersession racing the read is coherent by construction: the episode
    set and every per-exposure read share the caller's REPEATABLE READ
    snapshot — a superseding commit is simply not in this view (the payload
    binds its episode ids and as_of)."""
    _load_finding_for_summary(conn, tenant_id, finding_id)  # 404 gate
    episodes = _list_current_exposure_ids_for_finding(conn, tenant_id, finding_id)

    max_final: Optional[Decimal] = None
    max_provisional: Optional[Decimal] = None
    final_count = provisional_count = unscoreable_count = 0

    for ep in episodes:
        payload = get_exposure_tes(
            conn, tenant_id, ep["exposure_id"], as_of=as_of
        )
        state = payload["state"]
        value = payload["value"]
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

    return {
        "max_final_tes": max_final,
        "max_provisional_tes": max_provisional,
        "final_count": final_count,
        "provisional_count": provisional_count,
        "unscoreable_count": unscoreable_count,
        "total_current_exposures": len(episodes),
    }
