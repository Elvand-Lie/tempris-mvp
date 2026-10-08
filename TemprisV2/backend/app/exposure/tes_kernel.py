# backend/app/exposure/tes_kernel.py
"""
P0-04 — TES computation kernel (PRD-000 v1.11 §3.3.2–§3.3.6, §3.5 decisions
1, 3–5, 7, 9, 12–13; ticket p0-04-tes-computation-kernel).

A small, deterministic, side-effect-free evaluator over ALREADY-AUTHORIZED,
typed, qualified inputs. It performs the locked mappings, the Exploit Reality
rung selection, score-state determination, known-weight renormalization, and
the mandatory decomposition. It returns plain dataclasses.

Purity contract (§3.3.6 — the kernel is the recomputation rule):
  * no database access, no network access, no persistence, no snapshots;
  * no authorization, no tenant knowledge, no exposure IDs;
  * no reading of P0-02 ledgers or P0-03 repositories — callers pass the
    already-resolved, already-freshness-qualified observations in;
  * no I/O of any kind; import-time and call-time side-effect free;
  * stdlib only: dataclasses, enums, decimal, datetime, typing.

Locked composition (§3.3.2, weights locked 40/30/15/10/5):

    TES = 0.40*Intrinsic + 0.30*ER + 0.15*Criticality + 0.10*Reachability
          + 0.05*BusinessImpact      (all axes on the 0-10 scale)

All arithmetic is Decimal — no float conversions, no intermediate rounding
(the renormalization runs under an elevated Decimal context precision; only
``display_value`` is quantized, two decimals ROUND_HALF_UP).

States (§3.3.4): UNSCOREABLE (no valid intrinsic — always fail-closed,
value None), PROVISIONAL (intrinsic present; any contextual axis unknown or
stale, or an unresolved potentially-higher stale ER source), FINAL (all axes
resolved and fresh, no unresolved higher source).

Unknown axes are NEVER zero and never defaulted (V1's neutral-5.0 and
zero-coercion are banned, §3.3.4/§3.6.5): they stay out of the renormalized
denominator and render an explicit reason (§3.5 #1, §3.3.5).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation, localcontext
from enum import Enum
from typing import Optional, Tuple

__all__ = [
    "FeedHealthProvenance",
    "FORMULA_VERSION",
    "WEIGHT_INTRINSIC",
    "WEIGHT_EXPLOIT_REALITY",
    "WEIGHT_CRITICALITY",
    "WEIGHT_REACHABILITY",
    "WEIGHT_BUSINESS_IMPACT",
    "ZERO",
    "TEN",
    "ProvenanceClass",
    "FreshnessState",
    "TesState",
    "AxisId",
    "CriticalityLabel",
    "ReachabilityVantage",
    "EvidenceKind",
    "ExactExposureEvidenceState",
    "KevTernaryState",
    "KevRansomwareFlag",
    "FeedFreshness",
    "QualifiedValue",
    "IntrinsicInput",
    "CriticalityInput",
    "ReachabilityInput",
    "BusinessImpactInput",
    "EpssObservation",
    "KevObservation",
    "ExactExposureEvidence",
    "ExploitRealityInput",
    "TesInputs",
    "AxisDecompositionRow",
    "ExploitRealityDecompositionRow",
    "TesResult",
    "compute_tes",
    "TesInputError",
    "CRITICALITY_MAPPING",
    "REACHABILITY_MAPPING",
]


# ---------------------------------------------------------------------------
# Locked constants (PRD-000 v1.11 §3.3.2; §3.5 locked values)
# ---------------------------------------------------------------------------

#: Formula namespace (§3.3.5; ticket: exactly "tes-v1"). One shared
#: composition for the CVE and non-CVE paths (§3.6.4).
FORMULA_VERSION = "tes-v1"

WEIGHT_INTRINSIC = Decimal("0.40")
WEIGHT_EXPLOIT_REALITY = Decimal("0.30")
WEIGHT_CRITICALITY = Decimal("0.15")
WEIGHT_REACHABILITY = Decimal("0.10")
WEIGHT_BUSINESS_IMPACT = Decimal("0.05")

ZERO = Decimal("0")
TEN = Decimal("10")

# Exact EPSS band edges (§3.3.3 / §3.5 #3) — raw probability, Decimal-exact.
_EPSS_TOP = Decimal("0.5")
_EPSS_6 = Decimal("0.1")
_EPSS_5 = Decimal("0.02")
_EPSS_3 = Decimal("0.002")

# ER rung values (§3.5 #5).
ER_EXACT_EXPOSURE = Decimal("10")
ER_KEV_RANSOMWARE = Decimal("9")
ER_KEV_LISTED = Decimal("8")
ER_EPSS_TOP_BAND = Decimal("7")
ER_EPSS_6 = Decimal("6")
ER_EPSS_5 = Decimal("5")
ER_EPSS_3 = Decimal("3")
ER_BOTTOM = Decimal("1")
# Non-CVE approved-attestation rung (§3.6.4: approved "no known
# exploitation" attestation = 1.0 for 180 days; P0-08). Numerically the
# bottom rung's value, but a DISTINCT rung: it is established by a
# dual-control-approved analyst attestation, not by fresh-checked feeds,
# and it never composes with the EPSS<0.002 bottom-rung rule.
ER_ATTESTED_NO_EXPLOITATION = Decimal("1")

# Locked axis mappings (§3.5 #12, #13).
CRITICALITY_MAPPING = {
    "critical": Decimal("10"),
    "high": Decimal("8"),
    "medium": Decimal("5"),
    "low": Decimal("2"),
}
REACHABILITY_MAPPING = {
    "external": Decimal("10"),
    "internal": Decimal("8"),
}


# ---------------------------------------------------------------------------
# Enums — closed vocabularies; malformed values fail closed (never coerced)
# ---------------------------------------------------------------------------

class ProvenanceClass(Enum):
    """§3.3.5 provenance classes."""
    MACHINE_OBSERVED = "machine_observed"
    ANALYST_ENTERED = "analyst_entered"
    INFERRED = "inferred"


class FreshnessState(Enum):
    """Freshness/currentness of a qualified input, as determined by the
    caller — the kernel never clocks inputs itself."""
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class TesState(Enum):
    """§3.3.4 score states."""
    UNSCOREABLE = "UNSCOREABLE"
    PROVISIONAL = "PROVISIONAL"
    FINAL = "FINAL"


class AxisId(Enum):
    """The five locked axes, in locked weight order."""
    INTRINSIC = "intrinsic"
    EXPLOIT_REALITY = "exploit_reality"
    CRITICALITY = "criticality"
    REACHABILITY = "reachability"
    BUSINESS_IMPACT = "business_impact"


class CriticalityLabel(Enum):
    """``assets.criticality`` vocabulary (§3.5 #12). Missing ⇒ unknown axis."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReachabilityVantage(Enum):
    """Per-exposure confirmed reachability vantage (§3.5 #13)."""
    EXTERNAL = "external"
    INTERNAL = "internal"


class EvidenceKind(Enum):
    """Locked exploitation-evidence kinds (§3.3.3). The caller resolves the
    kind's TTL eligibility — the kernel sees only the resulting state."""
    OBSERVED_EXPLOITATION = "observed_exploitation"
    CONTROLLED_VALIDATION = "controlled_validation"


class ExactExposureEvidenceState(Enum):
    """Caller-resolved eligibility of exact-exposure exploitation evidence
    (TTLs 365d/180d are caller policy; a fresh failed/prevented validation
    establishes nothing and is passed as NONE — §3.3.3, §3.5 #7)."""
    FRESH_QUALIFYING = "fresh_qualifying"   # observed exploitation or successful controlled validation, within TTL
    STALE = "stale"                          # an expired evidence record exists (stale, NOT absence)
    NONE = "none"                            # normal absence of tenant-specific evidence


class KevTernaryState(Enum):
    """KEV snapshot-ternary (§3.3.3): the caller binds the state to the
    authoritative last-good snapshot (P0-03 resolver semantics)."""
    LISTED = "listed"
    NOT_LISTED = "not_listed"
    UNKNOWN = "unknown"


class KevRansomwareFlag(Enum):
    """``kev_entries.known_ransomware`` sub-flag (§3.3.3)."""
    KNOWN = "known"
    NOT_KNOWN = "not_known"
    UNKNOWN = "unknown"


class FeedFreshness(Enum):
    """Caller-resolved intel-feed freshness — the three-clause source-health
    rule of §3.3.3 (healthy + ≤48h + authoritative last-good generation)."""
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Feed-health provenance (P0-04 §3.3.5: the decomposition carries feed health,
# not freshness alone). Smallest pure typed mirror of the facts P0-03's
# ResolverProvenance already returns — the P0-03 model itself is NOT imported:
# the kernel stays pure (no application imports) and P0-05 maps resolver
# output into this type. The kernel does NOT recompute the 48-hour rule; it
# trusts the caller's already-resolved FeedFreshness.
# ---------------------------------------------------------------------------

class _UnsetPlaceholder:
    """Sentinel for a feed-health argument that was never supplied. A present
    feed observation must always receive an explicit
    :class:`FeedHealthProvenance`; the sentinel is rejected at construction
    (final surgical correction 1)."""
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug helper only
        return "<feed_health required>"


_FEED_HEALTH_UNSET = _UnsetPlaceholder()


@dataclass(frozen=True)
class FeedHealthProvenance:
    """Pure feed-health provenance for one intel feed (EPSS or KEV).

    Field-for-field mirror of the facts carried by P0-03's
    ResolverProvenance — without importing it (purity contract §3.3.6):

      * ``source`` — feed source identifier ("epss" / "kev");
      * ``is_healthy`` — three-clause source-health flag (None = never evaluated);
      * ``last_successful_at`` — last successful import timestamp (None = never);
      * ``last_snapshot_id`` — operational last-ATTEMPT snapshot (failed
        imports advance it; never authoritative);
      * ``last_good_snapshot_id`` — the authoritative last-good generation a
        resolver binds to;
      * ``freshness_age_seconds`` — age of the last successful import at the
        evaluation instant (None only when the import never ran). A present
        value must be a finite, non-negative int/float (bool is rejected).

    No clock reads, no I/O: every field is caller-supplied fact.
    """
    source: str
    is_healthy: Optional[bool] = None
    last_successful_at: Optional[datetime] = None
    last_snapshot_id: Optional[str] = None
    last_good_snapshot_id: Optional[str] = None
    freshness_age_seconds: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source:
            raise TesInputError("feed health source identifier is required")
        if self.is_healthy is not None and not isinstance(self.is_healthy, bool):
            raise TesInputError("feed health is_healthy must be a bool or None")
        if self.last_successful_at is not None and not isinstance(self.last_successful_at, datetime):
            raise TesInputError("feed health last_successful_at must be a datetime or None")
        if self.last_snapshot_id is not None and (
            not isinstance(self.last_snapshot_id, str) or not self.last_snapshot_id
        ):
            raise TesInputError("feed health last_snapshot_id must be a non-empty string or None")
        if self.last_good_snapshot_id is not None and (
            not isinstance(self.last_good_snapshot_id, str) or not self.last_good_snapshot_id
        ):
            raise TesInputError(
                "feed health last_good_snapshot_id must be a non-empty string or None"
            )
        if self.freshness_age_seconds is not None:
            age = self.freshness_age_seconds
            # bool is an int subclass — reject it explicitly; NaN/infinity
            # and negative ages are rejected. Ordinary non-negative int/float
            # values returned by P0-03 are accepted (final surgical
            # correction 5).
            if isinstance(age, bool) or not isinstance(age, (int, float)):
                raise TesInputError(
                    "feed health freshness_age_seconds must be a non-negative "
                    "int/float or None"
                )
            if math.isnan(age) or math.isinf(age):
                raise TesInputError(
                    "feed health freshness_age_seconds must be finite"
                )
            if age < 0:
                raise TesInputError(
                    "feed health freshness_age_seconds must be non-negative"
                )


def _validated_feed_health(
    health: object,
    observation_source: Optional[str],
    what: str,
    *,
    freshness: "FeedFreshness",
) -> FeedHealthProvenance:
    """Final surgical correction (mandatory feed health): consistency
    validation over caller-supplied ALREADY-RESOLVED facts — NOT a second
    freshness engine.

      * A present feed observation MUST carry a FeedHealthProvenance; it may
        be absent only when the entire observation is absent from
        :class:`ExploitRealityInput` (enforced by that class's slots).
      * The health object's source must equal the observation's source —
        cross-wired EPSS/KEV provenance is rejected.
      * FeedFreshness.FRESH is only coherent when the health record itself
        establishes the fresh state: is_healthy is True, last_successful_at,
        last_snapshot_id, and last_good_snapshot_id are present, and
        freshness_age_seconds is present and non-negative. STALE and UNKNOWN
        may legitimately carry missing operational facts, but the object and
        the matching source remain mandatory.

    The 48-hour window is never recomputed here — the caller's resolved
    FeedFreshness is trusted; these are coherence checks only.
    """
    if not isinstance(health, FeedHealthProvenance):
        raise TesInputError(
            f"{what} requires a FeedHealthProvenance (a present feed "
            f"observation may never omit its feed health)"
        )
    if health.source != observation_source:
        raise TesInputError(
            f"{what} feed health source {health.source!r} does not match the "
            f"observation source {observation_source!r} — cross-wired "
            f"provenance is rejected"
        )
    if freshness == FeedFreshness.FRESH:
        if health.is_healthy is not True:
            raise TesInputError(
                f"{what} FeedFreshness.FRESH requires feed health "
                f"is_healthy True (got {health.is_healthy!r})"
            )
        if not isinstance(health.last_successful_at, datetime):
            raise TesInputError(
                f"{what} FeedFreshness.FRESH requires feed health "
                "last_successful_at"
            )
        if not health.last_snapshot_id:
            raise TesInputError(
                f"{what} FeedFreshness.FRESH requires feed health "
                "last_snapshot_id"
            )
        if not health.last_good_snapshot_id:
            raise TesInputError(
                f"{what} FeedFreshness.FRESH requires feed health "
                "last_good_snapshot_id"
            )
        if not isinstance(health.freshness_age_seconds, (int, float)) \
                or isinstance(health.freshness_age_seconds, bool) \
                or health.freshness_age_seconds < 0:
            raise TesInputError(
                f"{what} FeedFreshness.FRESH requires a non-negative "
                "freshness_age_seconds"
            )
    return health


# ---------------------------------------------------------------------------
# Qualified-input model — a caller can never pass a naked scalar (§3.4)
# ---------------------------------------------------------------------------

def _validated_decimal(raw: object, what: str, low: Decimal, high: Decimal) -> Decimal:
    """Coerce through Decimal (never float) and range-check; fail closed."""
    if isinstance(raw, Decimal):
        value = raw
    elif isinstance(raw, int) and not isinstance(raw, bool):
        value = Decimal(raw)
    elif isinstance(raw, str):
        try:
            value = Decimal(raw)
        except (InvalidOperation, ValueError) as exc:
            raise TesInputError(f"{what} is not a valid Decimal: {raw!r}") from exc
    else:
        raise TesInputError(
            f"{what} must be Decimal (float is forbidden), got {type(raw).__name__}"
        )
    if value < low or value > high:
        raise TesInputError(f"{what} out of range {low}-{high}: {value}")
    return value


@dataclass(frozen=True)
class QualifiedValue:
    """A trusted numeric input: value + mandatory qualification.

    ``value`` must be a Decimal within 0–10 inclusive (an int or a numeric
    string is coerced through Decimal, never through float). Malformed or
    out-of-range values raise :class:`TesInputError` — never clamped.
    """
    value: Decimal
    provenance_class: ProvenanceClass
    freshness: FreshnessState
    observed_at: datetime                 # observation/effective timestamp
    source: str                           # source identifier or source class

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "value",
            _validated_decimal(self.value, "qualified value", ZERO, TEN),
        )
        if not isinstance(self.provenance_class, ProvenanceClass):
            raise TesInputError(
                f"provenance_class must be a ProvenanceClass, got {self.provenance_class!r}"
            )
        if not isinstance(self.freshness, FreshnessState):
            raise TesInputError(
                f"freshness must be a FreshnessState, got {self.freshness!r}"
            )
        if not isinstance(self.observed_at, datetime):
            raise TesInputError("observed_at must be a datetime")
        if not isinstance(self.source, str) or not self.source:
            raise TesInputError("source identifier is required")


# ---------------------------------------------------------------------------
# Per-axis inputs — every contextual axis is Optional; absence = unknown
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntrinsicInput:
    """Intrinsic severity: an authoritative CVSS value or a valid SSS, 0-10
    (§3.3.2; §3.6.4). Absent/invalid ⇒ the whole result is UNSCOREABLE.
    ``derivation`` records path provenance (CVSS authority row / SSS rubric
    version); the shared composition stays ``tes-v1`` (§3.6.4).

    The value is NORMALIZED at construction: the Decimal returned by the
    validator is stored (a numeric string like "9.0" becomes Decimal("9.0")),
    so no input can pass construction and later fail because its stored
    numeric type is invalid (correction 6)."""
    value: Decimal
    provenance_class: ProvenanceClass
    freshness: FreshnessState
    observed_at: datetime
    source: str
    derivation: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "value",
            _validated_decimal(self.value, "intrinsic value", ZERO, TEN),
        )
        if not isinstance(self.provenance_class, ProvenanceClass):
            raise TesInputError("intrinsic provenance_class must be a ProvenanceClass")
        if not isinstance(self.freshness, FreshnessState):
            raise TesInputError("intrinsic freshness must be a FreshnessState")
        if not isinstance(self.observed_at, datetime):
            raise TesInputError("intrinsic observed_at must be a datetime")
        if not isinstance(self.source, str) or not self.source:
            raise TesInputError("intrinsic source is required")
        if not isinstance(self.derivation, str) or not self.derivation:
            raise TesInputError("intrinsic derivation is required")


@dataclass(frozen=True)
class CriticalityInput:
    """Asset criticality label (§3.5 #12). ``label=None`` models a missing
    criticality (unknown axis). A present label requires full qualification."""
    label: Optional[CriticalityLabel]
    provenance_class: ProvenanceClass = None
    freshness: FreshnessState = None
    observed_at: Optional[datetime] = None
    source: Optional[str] = None

    def __post_init__(self) -> None:
        if self.label is not None and not isinstance(self.label, CriticalityLabel):
            raise TesInputError(
                f"criticality label must be a CriticalityLabel, got {self.label!r}"
            )
        if self.label is not None:
            if not isinstance(self.provenance_class, ProvenanceClass):
                raise TesInputError("criticality provenance_class is required when a label is given")
            if not isinstance(self.freshness, FreshnessState):
                raise TesInputError("criticality freshness is required when a label is given")
            if not isinstance(self.observed_at, datetime):
                raise TesInputError("criticality observed_at is required when a label is given")
            if not isinstance(self.source, str) or not self.source:
                raise TesInputError("criticality source is required when a label is given")
        elif (
            self.provenance_class is not None or self.freshness is not None
            or self.observed_at is not None or self.source is not None
        ):
            raise TesInputError(
                "criticality qualification fields require a label; "
                "pass CriticalityInput(None) to model a missing axis"
            )


@dataclass(frozen=True)
class ReachabilityInput:
    """Per-exposure confirmed reachability evidence (§3.5 #13). Absence of
    evidence ⇒ vantage=None (unknown axis; host-level fields never scored)."""
    vantage: Optional[ReachabilityVantage]
    provenance_class: ProvenanceClass = None
    freshness: FreshnessState = None
    observed_at: Optional[datetime] = None
    source: Optional[str] = None

    def __post_init__(self) -> None:
        if self.vantage is not None and not isinstance(self.vantage, ReachabilityVantage):
            raise TesInputError(
                f"reachability vantage must be a ReachabilityVantage, got {self.vantage!r}"
            )
        if self.vantage is not None:
            if not isinstance(self.provenance_class, ProvenanceClass):
                raise TesInputError("reachability provenance_class is required when vantage is given")
            if not isinstance(self.freshness, FreshnessState):
                raise TesInputError("reachability freshness is required when vantage is given")
            if not isinstance(self.observed_at, datetime):
                raise TesInputError("reachability observed_at is required when vantage is given")
            if not isinstance(self.source, str) or not self.source:
                raise TesInputError("reachability source is required when vantage is given")
        elif (
            self.provenance_class is not None or self.freshness is not None
            or self.observed_at is not None or self.source is not None
        ):
            raise TesInputError(
                "reachability qualification fields require a vantage; "
                "pass ReachabilityInput(None) to model missing evidence"
            )


@dataclass(frozen=True)
class BusinessImpactInput:
    """Analyst-entered per-exposure Business Impact, 0-10 (§3.3.2 grain rule).
    Absent ⇒ assessment=None (unknown axis; never defaulted to 0 or 5)."""
    assessment: Optional[QualifiedValue] = None

    def __post_init__(self) -> None:
        if self.assessment is not None and not isinstance(self.assessment, QualifiedValue):
            raise TesInputError(
                f"business impact assessment must be a QualifiedValue, "
                f"got {type(self.assessment).__name__} — naked scalars are not trusted input"
            )


@dataclass(frozen=True)
class EpssObservation:
    """One EPSS observation, already resolved by the caller through the P0-03
    resolver (value + three-clause source-health freshness; percentile is
    display-only metadata and never a scoring input — §3.3.3).

    Qualification (correction: close the ER qualification hole): a
    score-bearing observation (``value`` present) MUST carry a non-empty
    ``source`` AND an ``observed_at`` observation timestamp. A valueless
    observation stays legal (models a checked feed with no row / unknown
    score).

    ``feed_health`` is MANDATORY (final surgical correction): a present
    observation always carries a source-matched :class:`FeedHealthProvenance`
    rendered in the decomposition (§3.3.5); it may be absent only when the
    entire observation is absent from :class:`ExploitRealityInput`. For
    ``FeedFreshness.FRESH`` the health record must itself establish the
    already-resolved fresh state (healthy + last-good generation present,
    non-negative age). STALE/UNKNOWN observations keep full support with a
    source-matched health object whose operational facts may be missing. The
    48-hour window is never recomputed — consistency validation only.
    """
    value: Optional[Decimal]
    freshness: FeedFreshness
    percentile: Optional[Decimal] = None
    source: Optional[str] = "epss"
    observed_at: Optional[datetime] = None  # observation/effective timestamp
    feed_health: FeedHealthProvenance = _FEED_HEALTH_UNSET  # MANDATORY — sentinel rejected

    def __post_init__(self) -> None:
        if self.value is not None:
            object.__setattr__(
                self, "value",
                _validated_decimal(self.value, "EPSS value", ZERO, Decimal("1")),
            )
        if not isinstance(self.freshness, FeedFreshness):
            raise TesInputError("EPSS freshness must be a FeedFreshness")
        if self.percentile is not None:
            object.__setattr__(
                self, "percentile",
                _validated_decimal(self.percentile, "EPSS percentile", ZERO, Decimal("1")),
            )
        if self.source is not None and not isinstance(self.source, str):
            raise TesInputError("EPSS source must be a string")
        if self.value is not None:
            if not isinstance(self.source, str) or not self.source:
                raise TesInputError(
                    "EPSS observation with a value requires a non-empty source"
                )
            if not isinstance(self.observed_at, datetime):
                raise TesInputError(
                    "EPSS observation with a value requires an observed_at timestamp"
                )
        # Mandatory feed health: source-matched, and FRESH-coherent (final
        # surgical correction; None or wrong type is rejected here).
        _validated_feed_health(
            self.feed_health, self.source, "EPSS", freshness=self.freshness,
        )


@dataclass(frozen=True)
class KevObservation:
    """KEV snapshot-ternary observation (freshness already resolved by the
    caller against the authoritative last-good snapshot).

    Qualification (correction: close the ER qualification hole): every
    state carries feed health facts, so EVERY observation requires a
    non-empty ``source`` AND an ``observed_at`` observation/effective
    timestamp (a ternary has no valueless form). Coherent state
    combinations are enforced here, fail-closed (correction: incoherent KEV
    states must never reach scoring):

      * NOT_LISTED requires the ransomware sub-flag to be UNKNOWN or
        NOT_KNOWN (KNOWN contradicts not-listed);
      * LISTED is coherent with any ransomware sub-flag.

    ``feed_health`` is MANDATORY (final surgical correction): a present
    observation always carries a source-matched :class:`FeedHealthProvenance`
    rendered in the decomposition (§3.3.5); it may be absent only when the
    entire observation is absent from :class:`ExploitRealityInput`. For
    ``FeedFreshness.FRESH`` the health record must itself establish the
    already-resolved fresh state. STALE/UNKNOWN observations keep full
    support with a source-matched health object whose operational facts may
    be missing. The 48-hour window is never recomputed — consistency
    validation only.
    """
    state: KevTernaryState
    freshness: FeedFreshness
    ransomware: KevRansomwareFlag = KevRansomwareFlag.UNKNOWN
    source: Optional[str] = "kev"
    observed_at: Optional[datetime] = None  # observation/effective timestamp
    feed_health: FeedHealthProvenance = _FEED_HEALTH_UNSET  # MANDATORY — sentinel rejected

    def __post_init__(self) -> None:
        if not isinstance(self.state, KevTernaryState):
            raise TesInputError(f"KEV state must be a KevTernaryState, got {self.state!r}")
        if not isinstance(self.freshness, FeedFreshness):
            raise TesInputError("KEV freshness must be a FeedFreshness")
        if not isinstance(self.ransomware, KevRansomwareFlag):
            raise TesInputError("KEV ransomware must be a KevRansomwareFlag")
        if not isinstance(self.source, str) or not self.source:
            raise TesInputError("KEV observation requires a non-empty source")
        if not isinstance(self.observed_at, datetime):
            raise TesInputError("KEV observation requires an observed_at timestamp")
        if self.state == KevTernaryState.NOT_LISTED \
                and self.ransomware == KevRansomwareFlag.KNOWN:
            raise TesInputError(
                "incoherent KEV observation: NOT_LISTED contradicts "
                "ransomware KNOWN"
            )
        # Mandatory feed health: source-matched, and FRESH-coherent (final
        # surgical correction; None or wrong type is rejected here).
        _validated_feed_health(
            self.feed_health, self.source, "KEV", freshness=self.freshness,
        )


@dataclass(frozen=True)
class ExactExposureEvidence:
    """Exact-exposure tenant exploitation evidence, caller-resolved against
    the locked TTLs (§3.3.3, §3.5 #7). ``state`` is the resolved eligibility.
    A fresh failed/prevented validation establishes nothing: it is NONE,
    never a rung.

    Qualification (correction: close the ER qualification hole):
      * FRESH_QUALIFYING — a score-bearing record — requires ``kind``,
        ``observed_at``, a non-empty ``source``, and ``provenance_class``;
      * STALE — retained for auditability of the stale-higher rule — also
        requires its ``kind``, ``observed_at``, non-empty ``source``, and
        ``provenance_class``;
      * NONE (normal absence / fresh failed-prevented validation) carries no
        record and requires nothing.
    """
    state: ExactExposureEvidenceState
    kind: Optional[EvidenceKind] = None
    observed_at: Optional[datetime] = None
    source: Optional[str] = None
    provenance_class: Optional[ProvenanceClass] = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, ExactExposureEvidenceState):
            raise TesInputError(
                f"exact-exposure evidence state must be an ExactExposureEvidenceState,"
                f" got {self.state!r}"
            )
        if self.kind is not None and not isinstance(self.kind, EvidenceKind):
            raise TesInputError("evidence kind must be an EvidenceKind")
        if self.provenance_class is not None and not isinstance(
            self.provenance_class, ProvenanceClass
        ):
            raise TesInputError(
                "exact-exposure evidence provenance_class must be a ProvenanceClass"
            )
        if self.state in (
            ExactExposureEvidenceState.FRESH_QUALIFYING,
            ExactExposureEvidenceState.STALE,
        ):
            if self.kind is None:
                raise TesInputError(
                    f"exact-exposure evidence in state {self.state.value} requires an "
                    "evidence kind"
                )
            if not isinstance(self.observed_at, datetime):
                raise TesInputError(
                    f"exact-exposure evidence in state {self.state.value} requires an "
                    "observed_at timestamp"
                )
            if not isinstance(self.source, str) or not self.source:
                raise TesInputError(
                    f"exact-exposure evidence in state {self.state.value} requires a "
                    "non-empty source"
                )
            if self.provenance_class is None:
                raise TesInputError(
                    f"exact-exposure evidence in state {self.state.value} requires a "
                    "provenance_class"
                )


@dataclass(frozen=True)
class ExploitRealityInput:
    """Structured ER inputs preserving every signal's state for rendering
    (§3.3.5): the exact-exposure evidence state (fresh and/or stale), the
    EPSS observation, and the KEV ternary with its ransomware sub-flag. The
    kernel selects ONE highest fresh qualifying rung — never addition or
    averaging.

    Slot coherence (correction: reject inconsistent slot/state
    combinations, fail-closed):
      * the fresh slot carries only FRESH_QUALIFYING or NONE (an expired
        record passed as fresh is an incoherent slot/state pair);
      * the stale slot carries only STALE (a qualifying or absent record in
        the stale slot is an incoherent slot/state pair).

    P0-08 non-CVE extension (§3.6.4): ``attested_no_exploitation`` carries
    the caller-resolved state of the approved "no known exploitation"
    attestation — FRESH_QUALIFYING within the approved 180-day window
    (establishes ER_ATTESTED_NO_EXPLOITATION = 1, the rung
    ``attested_no_exploitation``), STALE past it (auditable, never scores),
    or None for absence. An UNAPPROVED attestation is passed as None: an
    unapproved analyst assertion is NEVER ER 1 (§3.6.6 #5). The slot is a
    distinct input — it never shares the exact-exposure slot with the
    exploitation-evidence rungs, and it cannot exceed them: attested "no
    known exploitation" is the FLOOR rung, so any higher established rung
    simply wins the one-rung selection.
    """
    exact_exposure_fresh: Optional[ExactExposureEvidence] = None
    exact_exposure_stale: Optional[ExactExposureEvidence] = None
    epss: Optional[EpssObservation] = None
    kev: Optional[KevObservation] = None
    attested_no_exploitation: Optional[ExactExposureEvidence] = None

    def __post_init__(self) -> None:
        # Wrong component types are rejected, never silently accepted (a
        # naked scalar or a foreign object must never reach scoring).
        if self.exact_exposure_fresh is not None and not isinstance(
            self.exact_exposure_fresh, ExactExposureEvidence
        ):
            raise TesInputError(
                "exact_exposure_fresh must be an ExactExposureEvidence or None, "
                f"got {type(self.exact_exposure_fresh).__name__}"
            )
        if self.exact_exposure_stale is not None and not isinstance(
            self.exact_exposure_stale, ExactExposureEvidence
        ):
            raise TesInputError(
                "exact_exposure_stale must be an ExactExposureEvidence or None, "
                f"got {type(self.exact_exposure_stale).__name__}"
            )
        if self.epss is not None and not isinstance(self.epss, EpssObservation):
            raise TesInputError(
                f"epss must be an EpssObservation or None, got {type(self.epss).__name__}"
            )
        if self.kev is not None and not isinstance(self.kev, KevObservation):
            raise TesInputError(
                f"kev must be a KevObservation or None, got {type(self.kev).__name__}"
            )
        if self.attested_no_exploitation is not None and not isinstance(
            self.attested_no_exploitation, ExactExposureEvidence
        ):
            raise TesInputError(
                "attested_no_exploitation must be an ExactExposureEvidence or "
                f"None, got {type(self.attested_no_exploitation).__name__}"
            )
        if self.attested_no_exploitation is not None and self.attested_no_exploitation.state not in (
            ExactExposureEvidenceState.FRESH_QUALIFYING,
            ExactExposureEvidenceState.STALE,
        ):
            raise TesInputError(
                "attested_no_exploitation slot carries only FRESH_QUALIFYING "
                "or STALE (absence is modeled by passing None)"
            )
        # Inconsistent slot/state combinations are rejected: the fresh slot
        # carries only FRESH_QUALIFYING or NONE; the stale slot only STALE.
        for slot, expected in (
            (self.exact_exposure_fresh,
             (ExactExposureEvidenceState.FRESH_QUALIFYING,
              ExactExposureEvidenceState.NONE)),
            (self.exact_exposure_stale,
             (ExactExposureEvidenceState.STALE,)),
        ):
            if slot is not None and slot.state not in expected:
                raise TesInputError(
                    f"incoherent exact-exposure slot/state combination: "
                    f"{slot.state.value} evidence in the "
                    f"{'fresh' if slot is self.exact_exposure_fresh else 'stale'} slot"
                )


@dataclass(frozen=True)
class TesInputs:
    """The five qualified inputs. ``intrinsic`` is required (None ⇒
    UNSCOREABLE); every contextual axis is optional and absent means
    unknown, never a default."""
    intrinsic: Optional[IntrinsicInput]
    exploit_reality: ExploitRealityInput = field(default_factory=ExploitRealityInput)
    criticality: Optional[CriticalityInput] = None
    reachability: Optional[ReachabilityInput] = None
    business_impact: Optional[BusinessImpactInput] = None


# ---------------------------------------------------------------------------
# Output contract (§3.3.5) — one atomic result, decomposition always present
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AxisDecompositionRow:
    """One axis row: raw value, base weight, effective weight, contribution,
    state, provenance, freshness, timestamp, source, and an explicit reason
    whenever the axis is missing, stale, or provisional. Unknown/stale axes
    keep base_weight and carry effective_weight=None, contribution=None —
    never zero (§3.5 #1)."""
    axis: AxisId
    raw_value: Optional[Decimal]
    base_weight: Decimal
    effective_weight: Optional[Decimal]
    contribution: Optional[Decimal]
    state: str                       # "known" | "unknown" | "stale"
    provenance_class: Optional[ProvenanceClass]
    freshness: Optional[FreshnessState]
    observed_at: Optional[datetime]
    source: Optional[str]
    reason: Optional[str] = None


@dataclass(frozen=True)
class ExploitRealityDecompositionRow(AxisDecompositionRow):
    """The ER row additionally exposes its rung, selected source set, EPSS
    and KEV metadata, feed-health provenance, and any unresolved
    (stale/unknown) potentially-higher sources (§3.3.5: the ER value never
    renders as a bare number).

    ``unresolved_higher`` carries ``(source_name, reason)`` pairs: STALE and
    UNKNOWN sources are named distinctly and each reason is auditable."""
    selected_rung: Optional[str] = None
    selected_sources: Tuple[str, ...] = ()
    epss_freshness: Optional[FeedFreshness] = None
    epss_value: Optional[Decimal] = None
    epss_feed_health: Optional[FeedHealthProvenance] = None
    kev_state: Optional[KevTernaryState] = None
    kev_freshness: Optional[FeedFreshness] = None
    kev_ransomware: Optional[KevRansomwareFlag] = None
    kev_feed_health: Optional[FeedHealthProvenance] = None
    exact_exposure_fresh_state: Optional[ExactExposureEvidenceState] = None
    exact_exposure_stale_state: Optional[ExactExposureEvidenceState] = None
    attestation_state: Optional[ExactExposureEvidenceState] = None
    unresolved_higher: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class TesResult:
    """One atomic TES payload (§3.3.5): value + state + formula version +
    coverage + explicit missing inputs + the five decomposition rows in
    locked weight order. ``value`` is full precision; ``display_value`` is
    the two-decimal presentation rounding (ROUND_HALF_UP)."""
    value: Optional[Decimal]
    display_value: Optional[Decimal]
    state: TesState
    formula_version: str
    known_axes: Tuple[AxisId, ...]        # ordered, locked weight order
    known_weight: Decimal
    missing_inputs: Tuple[str, ...]       # explicit reasons, stable order
    decomposition: Tuple[AxisDecompositionRow, ...]

    @property
    def known_axes_count(self) -> str:
        """Coverage rendering like "4/5" (§3.3.5)."""
        return f"{len(self.known_axes)}/5"


class TesInputError(ValueError):
    """Malformed enums, unqualified values, missing provenance on known
    values, missing timestamps, or out-of-range numerics — the kernel fails
    closed, never clamps (§3.4 input qualification)."""


# ---------------------------------------------------------------------------
# Exploit Reality rung selection (§3.3.3, §3.5 #3/#5/#7)
# ---------------------------------------------------------------------------

def _epss_band(value: Decimal) -> Decimal:
    """Locked EPSS band mapping. Exact Decimal comparisons — no float, no
    epsilon. The bottom band returns ER_BOTTOM as a *candidate* only: the
    bottom rung additionally requires fresh KEV not_listed."""
    if value >= _EPSS_TOP:
        return ER_EPSS_TOP_BAND
    if value >= _EPSS_6:
        return ER_EPSS_6
    if value >= _EPSS_5:
        return ER_EPSS_5
    if value >= _EPSS_3:
        return ER_EPSS_3
    return ER_BOTTOM


def _select_exploit_reality(
    er_in: ExploitRealityInput,
) -> Tuple[Optional[Decimal], Optional[str], Tuple[str, ...], Tuple[Tuple[str, str], ...], Optional[str]]:
    """One highest fresh qualifying rung — never addition, never averaging.

    Returns ``(er_value, selected_rung, selected_sources,
    unresolved_higher, er_axis_reason)`` where ``unresolved_higher`` is a
    tuple of ``(source_name, reason)`` pairs — STALE and UNKNOWN
    potentially-higher sources are distinguished (correction: complete
    missing/state reporting).

    Qualification gates (fail-closed — a caller cannot smuggle a rung
    through an unqualified record; construction-time validation enforces
    the same rules, these are the defense-in-depth re-checks):
      * a score-bearing EPSS observation (value present) must carry a
        non-empty source and an observed_at timestamp — an unqualified one
        raises :class:`TesInputError` and never establishes a rung;
      * FRESH_QUALIFYING and STALE exact-exposure evidence must carry kind,
        observed_at, non-empty source, and provenance_class — otherwise
        TesInputError (a STALE record stays auditable);
      * NONE never establishes a rung;
      * KevTernaryState.UNKNOWN can never be treated as a fresh
        authoritative listed/not-listed result: on a FRESH feed it leaves
        the KEV axis UNRESOLVED (not stale — the feed answered, the answer
        is indeterminate); it never completes the bottom rung;
      * coherent KEV state combinations only (LISTED+KNOWN → 9,
        LISTED+NOT_KNOWN/UNKNOWN → 8 with ransomware unresolved;
        NOT_LISTED+KNOWN is rejected at construction); NOT_LISTED completes
        the bottom rung only with fresh EPSS < 0.002.

    Freshness gates (unchanged):
      * a stale or unknown-freshness source NEVER establishes a rung;
      * a fresh failed/prevented validation establishes nothing (callers
        pass it as exact_exposure NONE — it is not a rung);
      * the stale-higher rule: an established fresh rung stands when a
        potentially-higher source is stale/unknown, the axis stays known
        and TES becomes PROVISIONAL, and the unresolved source is named
        in missing_inputs. "Potentially higher" is bounded per source:
        stale EPSS can never exceed 7, stale KEV never exceeds 9, stale
        exact-exposure evidence never exceeds 10 — a source at or below
        the established rung never invalidates it (ticket examples: fresh
        KEV 8 beats stale EPSS; fresh exact-exposure 10 beats stale intel
        feeds).
    """
    value: Optional[Decimal] = None
    rung: Optional[str] = None
    sources: Tuple[str, ...] = ()
    unresolved: list = []          # (name, reason) pairs, deterministic order
    reason: Optional[str] = None

    def _note_unresolved(name: str, why: str) -> None:
        if not any(existing == name for existing, _ in unresolved):
            unresolved.append((name, why))

    # --- Top rung: exact-exposure tenant evidence (max 10) -----------------
    ee_fresh = er_in.exact_exposure_fresh
    ee_stale = er_in.exact_exposure_stale
    if ee_fresh is not None:
        if ee_fresh.state == ExactExposureEvidenceState.FRESH_QUALIFYING:
            # Defense-in-depth re-check (construction already enforces this):
            # an unqualified record must never establish ER 10.
            if (ee_fresh.kind is None or not isinstance(ee_fresh.observed_at, datetime)
                    or not ee_fresh.source or ee_fresh.provenance_class is None):
                raise TesInputError(
                    "FRESH_QUALIFYING exact-exposure evidence is unqualified "
                    "(kind, observed_at, source, provenance_class required)"
                )
            value = ER_EXACT_EXPOSURE
            rung = "exact_exposure_evidence"
            sources = (ee_fresh.source,)
        elif ee_fresh.state == ExactExposureEvidenceState.STALE:
            _note_unresolved(
                "exact_exposure_evidence(stale)",
                "exact-exposure exploitation evidence is stale (expired past its kind TTL)",
            )
    if ee_stale is not None and ee_stale.state == ExactExposureEvidenceState.STALE:
        if (ee_stale.kind is None or not isinstance(ee_stale.observed_at, datetime)
                or not ee_stale.source or ee_stale.provenance_class is None):
            raise TesInputError(
                "STALE exact-exposure evidence is unqualified "
                "(kind, observed_at, source, provenance_class required so the "
                "stale-higher row remains auditable)"
            )
        _note_unresolved(
            "exact_exposure_evidence(stale)",
            "exact-exposure exploitation evidence is stale (expired past its kind TTL)",
        )

    # --- EPSS rungs (max 7) --------------------------------------------------
    epss = er_in.epss
    epss_rung: Optional[Decimal] = None
    epss_score_bearing = (
        epss is not None and epss.value is not None
        and epss.freshness == FeedFreshness.FRESH
    )
    if epss is not None and epss.value is not None:
        # Defense-in-depth re-check (construction already enforces this): a
        # score-bearing EPSS observation is qualified or rejected.
        if not epss.source or not isinstance(epss.observed_at, datetime):
            raise TesInputError(
                "EPSS observation with a value requires a non-empty source "
                "and an observed_at timestamp"
            )
    if epss is not None:
        # Defense-in-depth re-check (construction already enforces this): a
        # present observation always carries a source-matched,
        # freshness-coherent FeedHealthProvenance (mandatory feed health).
        _validated_feed_health(
            epss.feed_health, epss.source, "EPSS", freshness=epss.freshness,
        )
    if epss_score_bearing:
        epss_rung = _epss_band(epss.value)
        if epss_rung != ER_BOTTOM and (value is None or epss_rung > value):
            value = epss_rung
            rung = f"epss_band({epss.value})"
            sources = (epss.source,)
        # Fresh EPSS in the bottom band alone establishes nothing yet.
    elif epss is not None and epss.freshness == FeedFreshness.STALE:
        _note_unresolved(
            "epss(stale)",
            "EPSS observation is stale; a higher EPSS band may exist",
        )
    elif epss is not None and epss.freshness == FeedFreshness.UNKNOWN:
        _note_unresolved(
            "epss(unknown)",
            "EPSS freshness is unknown; a higher EPSS band may exist",
        )

    # --- KEV rungs (max 9) ----------------------------------------------------
    kev = er_in.kev
    kev_ransomware_unresolved = False
    if kev is not None:
        # Defense-in-depth re-check (construction already enforces this):
        # mandatory source-matched, freshness-coherent feed health.
        _validated_feed_health(
            kev.feed_health, kev.source, "KEV", freshness=kev.freshness,
        )
    if kev is not None and kev.freshness == FeedFreshness.FRESH:
        if kev.state == KevTernaryState.LISTED:
            if kev.ransomware == KevRansomwareFlag.KNOWN:
                kev_rung, kev_rung_name = ER_KEV_RANSOMWARE, "kev_listed+ransomware"
            else:
                # NOT_KNOWN or UNKNOWN sub-flag: LISTED establishes ER 8.
                # UNKNOWN leaves the potentially-higher ER 9 unresolved ->
                # the result goes PROVISIONAL and the decomposition names it.
                kev_rung, kev_rung_name = ER_KEV_LISTED, "kev_listed"
                if kev.ransomware == KevRansomwareFlag.UNKNOWN:
                    kev_ransomware_unresolved = True
            if value is None or kev_rung > value:
                value = kev_rung
                rung = kev_rung_name
                sources = (kev.source,)
        elif kev.state == KevTernaryState.NOT_LISTED:
            # Fresh not_listed completes the bottom rung only: it requires
            # fresh EPSS < 0.002 as well (fresh-checked nothing-found, §3.3.3).
            # It never lowers what EPSS established (KEV is a curated subset).
            if value is None and epss_rung == ER_BOTTOM:
                value = ER_BOTTOM
                rung = "no_known_evidence"
                sources = (
                    (epss.source if epss is not None else "epss"),
                    kev.source,
                )
        elif kev.state == KevTernaryState.UNKNOWN:
            # A fresh feed that cannot say listed/not-listed is NOT an
            # authoritative answer: it establishes no rung, never completes
            # the bottom rung, and leaves the KEV axis unresolved.
            _note_unresolved(
                "kev(unknown)",
                "KEV state is unknown on a fresh feed; a KEV rung may exist",
            )
    elif kev is not None and kev.freshness == FeedFreshness.STALE:
        _note_unresolved(
            "kev(stale)",
            "KEV feed is stale; a KEV rung may exist or be higher",
        )
    elif kev is not None and kev.freshness == FeedFreshness.UNKNOWN:
        _note_unresolved(
            "kev(unknown)",
            "KEV feed freshness is unknown; a KEV rung may exist",
        )

    # --- Non-CVE approved-attestation rung (§3.6.4; P0-08) -------------------
    # The FLOOR rung: established only by a dual-control-approved "no known
    # exploitation" attestation inside its 180-day window. It can never beat
    # a higher rung (one-highest selection below keeps strict >) and never
    # composes with the EPSS bottom-band rule.
    att = er_in.attested_no_exploitation
    att_fresh = (
        att is not None
        and att.state == ExactExposureEvidenceState.FRESH_QUALIFYING
    )
    if att is not None:
        if att_fresh:
            if (att.kind is None or not isinstance(att.observed_at, datetime)
                    or not att.source or att.provenance_class is None):
                raise TesInputError(
                    "FRESH_QUALIFYING attested_no_exploitation is unqualified "
                    "(kind, observed_at, source, provenance_class required)"
                )
            if value is None or ER_ATTESTED_NO_EXPLOITATION > value:
                value = ER_ATTESTED_NO_EXPLOITATION
                rung = "attested_no_exploitation"
                sources = (att.source,)
        else:
            _note_unresolved(
                "attested_no_exploitation(stale)",
                "the approved attestation is past its 180-day window; an "
                "unapproved assertion never establishes a rung",
            )


    # Prune unresolved candidates that cannot exceed the established rung.
    ceilings = {
        "exact_exposure_evidence(stale)": ER_EXACT_EXPOSURE,
        "epss(stale)": ER_EPSS_TOP_BAND,
        "epss(unknown)": ER_EPSS_TOP_BAND,
        "kev(stale)": ER_KEV_RANSOMWARE,
        "kev(unknown)": ER_KEV_RANSOMWARE,
        "attested_no_exploitation(stale)": ER_ATTESTED_NO_EXPLOITATION,
    }
    unresolved_higher: Tuple[Tuple[str, str], ...] = ()
    for name, why in unresolved:
        if value is None or value < ceilings[name]:
            unresolved_higher += ((name, why),)
            if reason is None:
                reason = why

    # LISTED + ransomware UNKNOWN: the sub-flag may still be higher (ER 9),
    # so the established ER 8 stands but stays PROVISIONAL (correction 4).
    if value is not None and kev_ransomware_unresolved and rung == "kev_listed":
        unresolved_higher += ((
            "kev(ransomware_unknown)",
            "KEV listed but the known-ransomware sub-flag is unresolved; "
            "ER 9 may apply",
        ),)

    if value is None and reason is None:
        # No fresh evidence established any rung and no unresolved
        # potentially-higher source was named: ER is unknown. Absence of
        # tenant-specific evidence is normal absence — but the bottom rung
        # was not completed (it needs both feeds fresh-checked).
        reason = "no fresh evidence establishes any Exploit Reality rung"
    return value, rung, sources, unresolved_higher, reason


# ---------------------------------------------------------------------------
# Row builders (private)
# ---------------------------------------------------------------------------

def _build_criticality_row(crit: Optional[CriticalityInput]) -> AxisDecompositionRow:
    if crit is None or crit.label is None:
        return AxisDecompositionRow(
            axis=AxisId.CRITICALITY, raw_value=None, base_weight=WEIGHT_CRITICALITY,
            effective_weight=None, contribution=None, state="unknown",
            provenance_class=(crit.provenance_class if crit else None),
            freshness=(crit.freshness if crit else None),
            observed_at=(crit.observed_at if crit else None),
            source=(crit.source if crit else None),
            reason="criticality not mapped (label absent) — unknown, never zero",
        )
    raw = CRITICALITY_MAPPING[crit.label.value]
    if crit.freshness != FreshnessState.FRESH:
        return AxisDecompositionRow(
            axis=AxisId.CRITICALITY, raw_value=raw, base_weight=WEIGHT_CRITICALITY,
            effective_weight=None, contribution=None,
            state=("stale" if crit.freshness == FreshnessState.STALE else "unknown"),
            provenance_class=crit.provenance_class, freshness=crit.freshness,
            observed_at=crit.observed_at, source=crit.source,
            reason=f"criticality '{crit.label.value}' is {crit.freshness.value} — not scored",
        )
    return AxisDecompositionRow(
        axis=AxisId.CRITICALITY, raw_value=raw, base_weight=WEIGHT_CRITICALITY,
        effective_weight=None, contribution=None, state="known",
        provenance_class=crit.provenance_class, freshness=crit.freshness,
        observed_at=crit.observed_at, source=crit.source,
    )


def _build_reachability_row(reach: Optional[ReachabilityInput]) -> AxisDecompositionRow:
    if reach is None or reach.vantage is None:
        return AxisDecompositionRow(
            axis=AxisId.REACHABILITY, raw_value=None, base_weight=WEIGHT_REACHABILITY,
            effective_weight=None, contribution=None, state="unknown",
            provenance_class=(reach.provenance_class if reach else None),
            freshness=(reach.freshness if reach else None),
            observed_at=(reach.observed_at if reach else None),
            source=(reach.source if reach else None),
            reason="no per-exposure reachability evidence — unknown, never zero",
        )
    raw = REACHABILITY_MAPPING[reach.vantage.value]
    if reach.freshness != FreshnessState.FRESH:
        return AxisDecompositionRow(
            axis=AxisId.REACHABILITY, raw_value=raw, base_weight=WEIGHT_REACHABILITY,
            effective_weight=None, contribution=None,
            state=("stale" if reach.freshness == FreshnessState.STALE else "unknown"),
            provenance_class=reach.provenance_class, freshness=reach.freshness,
            observed_at=reach.observed_at, source=reach.source,
            reason=f"reachability '{reach.vantage.value}' is {reach.freshness.value} — not scored",
        )
    return AxisDecompositionRow(
        axis=AxisId.REACHABILITY, raw_value=raw, base_weight=WEIGHT_REACHABILITY,
        effective_weight=None, contribution=None, state="known",
        provenance_class=reach.provenance_class, freshness=reach.freshness,
        observed_at=reach.observed_at, source=reach.source,
    )


def _build_business_impact_row(bi: Optional[BusinessImpactInput]) -> AxisDecompositionRow:
    if bi is None or bi.assessment is None:
        return AxisDecompositionRow(
            axis=AxisId.BUSINESS_IMPACT, raw_value=None, base_weight=WEIGHT_BUSINESS_IMPACT,
            effective_weight=None, contribution=None, state="unknown",
            provenance_class=(bi.assessment.provenance_class if bi and bi.assessment else None),
            freshness=(bi.assessment.freshness if bi and bi.assessment else None),
            observed_at=(bi.assessment.observed_at if bi and bi.assessment else None),
            source=(bi.assessment.source if bi and bi.assessment else None),
            reason="business impact not assessed — unknown, never zero (no default)",
        )
    qv = bi.assessment
    if qv.freshness != FreshnessState.FRESH:
        return AxisDecompositionRow(
            axis=AxisId.BUSINESS_IMPACT, raw_value=qv.value, base_weight=WEIGHT_BUSINESS_IMPACT,
            effective_weight=None, contribution=None,
            state=("stale" if qv.freshness == FreshnessState.STALE else "unknown"),
            provenance_class=qv.provenance_class, freshness=qv.freshness,
            observed_at=qv.observed_at, source=qv.source,
            reason=f"business impact is {qv.freshness.value} — not scored",
        )
    return AxisDecompositionRow(
        axis=AxisId.BUSINESS_IMPACT, raw_value=qv.value, base_weight=WEIGHT_BUSINESS_IMPACT,
        effective_weight=None, contribution=None, state="known",
        provenance_class=qv.provenance_class, freshness=qv.freshness,
        observed_at=qv.observed_at, source=qv.source,
    )


def _build_er_row(
    er_in: ExploitRealityInput,
    er_value: Optional[Decimal],
    *,
    rung: Optional[str],
    sources: Tuple[str, ...],
    stale_higher: Tuple[str, ...],
    unknown_reason: Optional[str],
    scored: bool,
) -> ExploitRealityDecompositionRow:
    """Render the ER row. ``scored=False`` (UNSCOREABLE result): metadata is
    still rendered, but the row cannot carry a known state or a contribution
    that would imply a valid TES (§3.3.4)."""
    epss = er_in.epss
    kev = er_in.kev
    ee_fresh = er_in.exact_exposure_fresh
    ee_stale = er_in.exact_exposure_stale

    # Feed-health provenance (P0-04 §3.3.5: the decomposition carries feed
    # health) — rendered verbatim from the caller-supplied pure values; the
    # kernel never recomputes the 48-hour rule (correction 2).
    epss_health = epss.feed_health if epss else None
    kev_health = kev.feed_health if kev else None
    att = er_in.attested_no_exploitation

    # Truthful provenance (correction 3): the winning evidence record's own
    # provenance class wins. EPSS/KEV and the bottom EPSS+KEV rung are
    # machine-observed; an analyst-reviewed exact-exposure record must never
    # render as machine-observed merely because it established ER 10.
    if rung == "exact_exposure_evidence" and ee_fresh is not None:
        er_provenance = ee_fresh.provenance_class
    elif rung == "attested_no_exploitation" and att is not None:
        er_provenance = att.provenance_class
    elif rung in ("epss_band", "kev_listed", "kev_listed+ransomware",
                  "no_known_evidence") or (
        rung is not None and rung.startswith("epss_band")
    ):
        er_provenance = ProvenanceClass.MACHINE_OBSERVED
    else:
        er_provenance = None

    # Surface the selected rung's observation timestamp when the caller
    # supplied one for the winning source.
    er_observed: Optional[datetime] = None
    if rung == "exact_exposure_evidence":
        er_observed = ee_fresh.observed_at if ee_fresh else None
    elif rung == "attested_no_exploitation":
        er_observed = att.observed_at if att is not None else None
    elif rung is not None and rung.startswith("epss_band"):
        er_observed = epss.observed_at if epss else None
    elif rung in ("kev_listed", "kev_listed+ransomware"):
        er_observed = kev.observed_at if kev else None
    elif rung == "no_known_evidence":
        stamps = [t for t in (
            (epss.observed_at if epss else None),
            (kev.observed_at if kev else None),
        ) if t is not None]
        er_observed = max(stamps) if stamps else None

    if not scored:
        if er_value is not None:
            # UNSCOREABLE decomposition: an established rung is real evidence
            # — render it truthfully (raw_value/state/provenance/freshness)
            # without implying a scored TES: the UNSCOREABLE path never calls
            # _finalize_rows, so the contribution stays None.
            state = "known"
            reason = (
                "overall result is UNSCOREABLE (no authoritative intrinsic); "
                "axis rendered for decomposition only"
            )
            if stale_higher:
                reason += "; " + "; ".join(name for name, _ in stale_higher)
        else:
            state = "unknown"
            reason = (
                unknown_reason
                or "ER not scored: result is UNSCOREABLE (no authoritative intrinsic)"
            )
            if stale_higher:
                reason = (reason + "; " if reason else "") + "; ".join(
                    name for name, _ in stale_higher
                )
    elif er_value is None:
        state = "unknown"
        reason = unknown_reason or "no fresh evidence establishes any Exploit Reality rung"
    else:
        # A known lower rung retained under the stale-higher rule REMAINS a
        # known scored axis (§3.3.4); the result-level state goes PROVISIONAL
        # and the reason names the unresolved higher source.
        state = "known"
        reason = (
            "unresolved potentially-higher source(s): " + "; ".join(
                name for name, _ in stale_higher
            )
            if stale_higher else None
        )

    return ExploitRealityDecompositionRow(
        axis=AxisId.EXPLOIT_REALITY,
        raw_value=er_value,
        base_weight=WEIGHT_EXPLOIT_REALITY,
        effective_weight=None, contribution=None,
        state=state,
        provenance_class=er_provenance,
        freshness=(FreshnessState.FRESH if er_value is not None
                   else FreshnessState.UNKNOWN),
        observed_at=(er_observed if er_value is not None else None),
        source=("; ".join(sources) if sources else None),
        reason=reason,
        selected_rung=rung,
        selected_sources=sources,
        epss_freshness=(epss.freshness if epss else None),
        epss_value=(epss.value if epss else None),
        epss_feed_health=epss_health,
        kev_state=(kev.state if kev else None),
        kev_freshness=(kev.freshness if kev else None),
        kev_ransomware=(kev.ransomware if kev else None),
        kev_feed_health=kev_health,
        exact_exposure_fresh_state=(ee_fresh.state if ee_fresh else None),
        exact_exposure_stale_state=(ee_stale.state if ee_stale else None),
        attestation_state=(att.state if att is not None else None),
        unresolved_higher=stale_higher,
    )


def _finalize_rows(rows: list, known_weight: Decimal) -> None:
    """Fill effective_weight/contribution for known rows under elevated
    precision; unknown/stale rows keep None (never zero).

    Repeating quotients (e.g. 0.40/0.70) are held at 50 significant digits —
    never through float, never at the default 28-digit context."""
    with localcontext() as ctx:
        ctx.prec = 50
        for row in rows:
            if row.state == "known" and row.raw_value is not None:
                effective = row.base_weight / known_weight
                object.__setattr__(row, "effective_weight", effective)
                object.__setattr__(row, "contribution", row.raw_value * effective)


# ---------------------------------------------------------------------------
# The kernel entry point
# ---------------------------------------------------------------------------

def compute_tes(inputs: TesInputs) -> TesResult:
    """Evaluate TES over qualified inputs. Pure: no I/O, no clock, no state.

    State determination (§3.3.4):
      * UNSCOREABLE — no intrinsic (or a non-fresh intrinsic): value None;
        the decomposition still renders every axis and the failure reason;
      * PROVISIONAL — intrinsic present but any contextual axis unknown or
        stale, or ER carries an unresolved potentially-higher stale source;
      * FINAL — intrinsic + all contextual axes resolved and fresh, and ER
        has no unresolved higher source: all five locked weights participate.
    """
    if not isinstance(inputs, TesInputs):
        raise TesInputError("compute_tes requires a TesInputs instance")

    rows: list = []
    missing: list[str] = []
    known_axes: list[AxisId] = []
    known_weight = ZERO
    stale_context = False

    # ---- ER selection (always computed; rendering depends on scoreability) --
    er_value, er_rung, er_sources, er_unresolved, er_reason = _select_exploit_reality(
        inputs.exploit_reality
    )

    # ---- Intrinsic ----------------------------------------------------------
    intr = inputs.intrinsic
    intrinsic_ok = (
        intr is not None
        and intr.freshness == FreshnessState.FRESH
    )
    if intr is None:
        missing.append(
            "intrinsic severity absent (no authoritative CVSS row / no valid SSS)"
            " — UNSCOREABLE"
        )
        rows.append(AxisDecompositionRow(
            axis=AxisId.INTRINSIC, raw_value=None, base_weight=WEIGHT_INTRINSIC,
            effective_weight=None, contribution=None, state="unknown",
            provenance_class=None, freshness=None, observed_at=None, source=None,
            reason="no authoritative intrinsic severity — UNSCOREABLE (fail-closed, §3.3.4)",
        ))
    elif intr.freshness != FreshnessState.FRESH:
        missing.append(
            f"intrinsic severity is {intr.freshness.value}; it cannot anchor a"
            " current score — UNSCOREABLE"
        )
        # UNKNOWN freshness must not render as "stale" (correction 5): the
        # row state distinguishes STALE from UNKNOWN distinctly.
        rows.append(AxisDecompositionRow(
            axis=AxisId.INTRINSIC, raw_value=intr.value, base_weight=WEIGHT_INTRINSIC,
            effective_weight=None, contribution=None,
            state=("stale" if intr.freshness == FreshnessState.STALE else "unknown"),
            provenance_class=intr.provenance_class, freshness=intr.freshness,
            observed_at=intr.observed_at, source=intr.source,
            reason=f"intrinsic freshness is {intr.freshness.value} — UNSCOREABLE (fail-closed)",
        ))
    else:
        known_axes.append(AxisId.INTRINSIC)
        known_weight += WEIGHT_INTRINSIC
        rows.append(AxisDecompositionRow(
            axis=AxisId.INTRINSIC, raw_value=intr.value, base_weight=WEIGHT_INTRINSIC,
            effective_weight=None, contribution=None, state="known",
            provenance_class=intr.provenance_class, freshness=intr.freshness,
            observed_at=intr.observed_at, source=intr.source,
        ))

    # ---- Exploit Reality ------------------------------------------------------
    if intrinsic_ok:
        if er_unresolved:
            stale_context = True
            # Complete missing/state reporting (§3.3.4): when a lower fresh
            # rung is retained under a stale or unknown potentially-higher
            # source, the ER axis stays known and scored, TES goes
            # PROVISIONAL, and the unresolved source AND reason are reported.
            for _name, _why in er_unresolved:
                missing.append(f"{_name}: {_why}")
        if er_value is None:
            reason_line = er_reason or "exploit reality unknown"
            # The first unresolved why already names the cause when it became
            # the axis reason — never duplicate it in missing_inputs.
            if not any(_why == reason_line for _, _why in er_unresolved):
                missing.append(reason_line)
            rows.append(_build_er_row(
                inputs.exploit_reality, None, rung=er_rung, sources=er_sources,
                stale_higher=er_unresolved, unknown_reason=er_reason, scored=True,
            ))
        else:
            known_axes.append(AxisId.EXPLOIT_REALITY)
            known_weight += WEIGHT_EXPLOIT_REALITY
            rows.append(_build_er_row(
                inputs.exploit_reality, er_value, rung=er_rung, sources=er_sources,
                stale_higher=er_unresolved, unknown_reason=er_reason, scored=True,
            ))
    else:
        # UNSCOREABLE: render the ER axis with full metadata but no scored
        # value that could imply a valid TES.
        rows.append(_build_er_row(
            inputs.exploit_reality, er_value, rung=er_rung, sources=er_sources,
            stale_higher=er_unresolved, unknown_reason=er_reason, scored=False,
        ))

    # ---- Criticality ------------------------------------------------------------
    crit = inputs.criticality
    crit_row = _build_criticality_row(crit)
    rows.append(crit_row)
    if crit is None or crit.label is None:
        missing.append("criticality label absent (asset criticality unmapped) — unknown, never zero")
    elif crit.freshness == FreshnessState.FRESH:
        known_axes.append(AxisId.CRITICALITY)
        known_weight += WEIGHT_CRITICALITY
    else:
        missing.append(
            f"criticality label '{crit.label.value}' is {crit.freshness.value} — not scored"
        )
        stale_context = True

    # ---- Reachability --------------------------------------------------------------
    reach = inputs.reachability
    reach_row = _build_reachability_row(reach)
    rows.append(reach_row)
    if reach is None or reach.vantage is None:
        missing.append("reachability evidence absent (per-exposure evidence only) — unknown, never zero")
    elif reach.freshness == FreshnessState.FRESH:
        known_axes.append(AxisId.REACHABILITY)
        known_weight += WEIGHT_REACHABILITY
    else:
        missing.append(
            f"reachability vantage '{reach.vantage.value}' is {reach.freshness.value} — not scored"
        )
        stale_context = True

    # ---- Business Impact ---------------------------------------------------------------
    bi = inputs.business_impact
    bi_row = _build_business_impact_row(bi)
    rows.append(bi_row)
    if bi is None or bi.assessment is None:
        missing.append("business impact not assessed — unknown, never zero (no default)")
    elif bi.assessment.freshness == FreshnessState.FRESH:
        known_axes.append(AxisId.BUSINESS_IMPACT)
        known_weight += WEIGHT_BUSINESS_IMPACT
    else:
        missing.append(
            f"business impact assessment is {bi.assessment.freshness.value} — not scored"
        )
        stale_context = True

    # ---- UNSCOREABLE short-circuit ---------------------------------------------------------
    if not intrinsic_ok:
        return TesResult(
            value=None,
            display_value=None,
            state=TesState.UNSCOREABLE,
            formula_version=FORMULA_VERSION,
            known_axes=(),
            known_weight=ZERO,
            missing_inputs=tuple(missing),
            decomposition=tuple(rows),
        )

    # ---- Renormalization (§3.5 #1) -------------------------------------------------------
    if known_weight == ZERO:
        raise TesInputError(
            "internal invariant violated: intrinsic present but known_weight is zero"
        )
    # Effective weights and contributions are fixed at 50 significant digits
    # (repeating quotients like 0.40/0.70 never pass through float and are
    # never truncated to the default 28-digit context). The returned value is
    # then the EXACT sum of the stored contributions: the summation runs under
    # a far larger precision so adding the (up to) five 50-digit terms can
    # never itself round. Contributions therefore sum exactly to `value`.
    _finalize_rows(rows, known_weight)

    # The returned value is the EXACT sum of the stored contributions: the
    # summation runs under a far larger precision (200 digits) than the 50
    # digits the contributions were fixed at, so adding the (up to) five
    # terms can never itself round.
    total = ZERO
    for r_row in rows:
        if r_row.state == "known" and r_row.contribution is not None:
            with localcontext() as ctx200:
                ctx200.prec = 200
                total += r_row.contribution

    # ---- State (§3.3.4) -----------------------------------------------------------------
    # FINAL only when intrinsic AND every contextual axis is known-fresh AND
    # ER has no unresolved potentially-higher source. A missing or stale axis
    # (or a retained lower ER rung under a stale-higher source) makes the
    # score PROVISIONAL — it may never read as safe, terminal, accepted-risk,
    # or deprioritized.
    if stale_context or len(known_axes) != 5 or er_unresolved:
        state = TesState.PROVISIONAL
    else:
        state = TesState.FINAL

    display = total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    return TesResult(
        value=total,
        display_value=display,
        state=state,
        formula_version=FORMULA_VERSION,
        known_axes=tuple(known_axes),
        known_weight=known_weight,
        missing_inputs=tuple(missing),
        decomposition=tuple(rows),
    )
