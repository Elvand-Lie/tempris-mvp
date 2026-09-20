# backend/tests_unit/test_tes_kernel.py
"""
P0-04 — TES computation kernel unit suite (PRD-000 v1.11 §3.3.2-§3.3.6,
§3.5 decisions 1, 3-5, 7, 9, 12-13; ticket p0-04-tes-computation-kernel).

Database-independent: this module imports ONLY the pure kernel module
(``app.exposure.tes_kernel``) — never the exposure package ``__init__``
(which transitively imports psycopg/audit/db), never the FastAPI app,
never any repository, and never the PostgreSQL-backed conftest under
backend/tests. Run from the repository root:

    python -m pytest backend/tests_unit/ -q

The suite runs with no database configured at all.
"""
import importlib.util
import sys
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

# Import the kernel module directly by file path so the suite never executes
# app/exposure/__init__.py (which transitively imports psycopg and the audit
# module). This proves the kernel itself has zero database dependency.
_KERNEL_PATH = Path(__file__).resolve().parents[1] / "app" / "exposure" / "tes_kernel.py"
_spec = importlib.util.spec_from_file_location("tes_kernel_under_test", _KERNEL_PATH)
tes_kernel = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tes_kernel
_spec.loader.exec_module(tes_kernel)

compute_tes = tes_kernel.compute_tes
TesInputError = tes_kernel.TesInputError
TesState = tes_kernel.TesState
AxisId = tes_kernel.AxisId
D = Decimal

ProvenanceClass = tes_kernel.ProvenanceClass
FreshnessState = tes_kernel.FreshnessState
CriticalityLabel = tes_kernel.CriticalityLabel
ReachabilityVantage = tes_kernel.ReachabilityVantage
ExactExposureEvidenceState = tes_kernel.ExactExposureEvidenceState
KevTernaryState = tes_kernel.KevTernaryState
KevRansomwareFlag = tes_kernel.KevRansomwareFlag
FeedFreshness = tes_kernel.FeedFreshness
FeedHealthProvenance = tes_kernel.FeedHealthProvenance
EvidenceKind = tes_kernel.EvidenceKind
QualifiedValue = tes_kernel.QualifiedValue
IntrinsicInput = tes_kernel.IntrinsicInput
CriticalityInput = tes_kernel.CriticalityInput
ReachabilityInput = tes_kernel.ReachabilityInput
BusinessImpactInput = tes_kernel.BusinessImpactInput
EpssObservation = tes_kernel.EpssObservation
KevObservation = tes_kernel.KevObservation
ExactExposureEvidence = tes_kernel.ExactExposureEvidence
ExploitRealityInput = tes_kernel.ExploitRealityInput
TesInputs = tes_kernel.TesInputs


# ---------------------------------------------------------------------------
# Helpers — every input is qualified; helpers just shorten the spelling
# ---------------------------------------------------------------------------

NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)


def epss_health(**overrides):
    """Source-matched EPSS feed health with complete fresh-generation facts
    (the only health record that coherently pairs with FeedFreshness.FRESH)."""
    facts = dict(
        source="epss", is_healthy=True, last_successful_at=NOW,
        last_snapshot_id="snap-epss", last_good_snapshot_id="good-epss",
        freshness_age_seconds=3600.0,
    )
    facts.update(overrides)
    return FeedHealthProvenance(**facts)


def kev_health(**overrides):
    """Source-matched KEV feed health with complete fresh-generation facts."""
    facts = dict(
        source="kev", is_healthy=True, last_successful_at=NOW,
        last_snapshot_id="snap-kev", last_good_snapshot_id="good-kev",
        freshness_age_seconds=3600.0,
    )
    facts.update(overrides)
    return FeedHealthProvenance(**facts)


def qv(value, freshness=FreshnessState.FRESH, provenance=ProvenanceClass.ANALYST_ENTERED,
       observed_at=NOW, source="unit-source"):
    return QualifiedValue(
        value=value, provenance_class=provenance, freshness=freshness,
        observed_at=observed_at, source=source,
    )


def bi(value, **kw):
    return BusinessImpactInput(qv(value, **kw))


def crit(label, freshness=FreshnessState.FRESH, observed_at=NOW,
         provenance=ProvenanceClass.MACHINE_OBSERVED, source="assets-service"):
    return CriticalityInput(label, provenance_class=provenance,
                            freshness=freshness, observed_at=observed_at, source=source)


def reach(vantage, freshness=FreshnessState.FRESH, observed_at=NOW,
          provenance=ProvenanceClass.MACHINE_OBSERVED, source="scout-confirmation"):
    return ReachabilityInput(vantage, provenance_class=provenance,
                             freshness=freshness, observed_at=observed_at, source=source)


def intr(value, freshness=FreshnessState.FRESH, observed_at=NOW,
         provenance=ProvenanceClass.MACHINE_OBSERVED, source="cvss-authority",
         derivation="cvss_4.0_cna"):
    return IntrinsicInput(value, provenance_class=provenance, freshness=freshness,
                          observed_at=observed_at, source=source, derivation=derivation)


def bottom_er():
    """Fresh EPSS < 0.002 + fresh KEV not_listed -> the ER=1 bottom rung."""
    return ExploitRealityInput(
        epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                           KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                           feed_health=kev_health()),
    )


def full_inputs(intrinsic="9.0", er=None, criticality="unset", reachability="unset",
                business_impact="unset"):
    """All-five-axes-known baseline: FINAL 6.75 for the defaults.

    The string "unset" means "use the known default"; None means "omit the
    axis" (absent => unknown)."""
    return TesInputs(
        intrinsic=intr(D(intrinsic)),
        exploit_reality=bottom_er() if er is None else er,
        criticality=crit(CriticalityLabel.CRITICAL) if criticality == "unset" else criticality,
        reachability=reach(ReachabilityVantage.EXTERNAL) if reachability == "unset" else reachability,
        business_impact=bi(D("7")) if business_impact == "unset" else business_impact,
    )


def row(result, axis):
    for r in result.decomposition:
        if r.axis == axis:
            return r
    raise AssertionError(f"decomposition row missing for {axis}")


def assert_contributions_sum(result):
    """Contributions must sum EXACTLY to the returned value. The summation
    runs at 200 digits (as the kernel does) so the check itself never
    truncates; the default 28-digit context would corrupt the comparison."""
    known = [x for x in result.decomposition if x.contribution is not None]
    with localcontext() as ctx:
        ctx.prec = 200
        total = Decimal(0)
        for x in known:
            total += x.contribution
    assert total == result.value


def close(actual, expected, tol=Decimal("1e-40")):
    """High-precision proximity: |actual - expected| < tol. Used to compare
    the kernel's 50-digit fixed-precision value against an expectation
    computed independently at 60 digits (repeating quotients make exact
    Decimal equality impossible; 40+ agreeing digits prove no 28-digit
    intermediate rounding occurred).

    ``expected`` may be a Decimal or a zero-arg callable; a callable is
    evaluated under a 60-digit context so the expectation itself is never
    truncated to the default 28-digit precision."""
    if callable(expected):
        with localcontext() as ctx:
            ctx.prec = 60
            expected = expected()
    with localcontext() as ctx:
        ctx.prec = 80
        diff = abs(Decimal(actual) - Decimal(expected))
    assert diff < tol, f"{actual} !~ {expected} (diff {diff})"


# ---------------------------------------------------------------------------
# 1. All five axes known => FINAL
# ---------------------------------------------------------------------------

def test_all_five_axes_known_is_final():
    r = compute_tes(full_inputs())
    assert r.state is TesState.FINAL
    assert r.known_axes_count == "5/5"
    assert r.known_weight == D("1.00")
    assert r.value == D("6.75")          # 3.6 + 0.3 + 1.5 + 1.0 + 0.35
    assert r.display_value == D("6.75")
    assert r.formula_version == "tes-v1"
    assert r.missing_inputs == ()
    assert_contributions_sum(r)
    # decomposition order is the locked weight order
    assert [x.axis for x in r.decomposition] == [
        AxisId.INTRINSIC, AxisId.EXPLOIT_REALITY, AxisId.CRITICALITY,
        AxisId.REACHABILITY, AxisId.BUSINESS_IMPACT,
    ]


# ---------------------------------------------------------------------------
# 2. Missing intrinsic => UNSCOREABLE, value None, full decomposition
# ---------------------------------------------------------------------------

def test_missing_intrinsic_is_unscoreable():
    r = compute_tes(TesInputs(
        intrinsic=None,
        exploit_reality=bottom_er(),
        criticality=crit(CriticalityLabel.CRITICAL),
        reachability=reach(ReachabilityVantage.EXTERNAL),
        business_impact=bi(D("7")),
    ))
    assert r.state is TesState.UNSCOREABLE
    assert r.value is None
    assert r.display_value is None
    assert r.known_axes == ()
    assert r.known_weight == D("0")
    assert len(r.decomposition) == 5                       # every axis still rendered
    assert all(x.contribution is None for x in r.decomposition)
    assert any("intrinsic" in (x.reason or "").lower() for x in r.decomposition)
    assert any("UNSCOREABLE" in (m or "") for m in r.missing_inputs)
    # ER metadata is still rendered even though nothing is scored
    er = row(r, AxisId.EXPLOIT_REALITY)
    assert er.selected_rung == "no_known_evidence"
    assert er.kev_state is KevTernaryState.NOT_LISTED


def test_stale_intrinsic_is_unscoreable():
    r = compute_tes(TesInputs(
        intrinsic=intr(D("9.0"), freshness=FreshnessState.STALE),
        exploit_reality=bottom_er(),
        criticality=crit(CriticalityLabel.CRITICAL),
        reachability=reach(ReachabilityVantage.EXTERNAL),
        business_impact=bi(D("7")),
    ))
    assert r.state is TesState.UNSCOREABLE
    assert r.value is None
    intr_row = row(r, AxisId.INTRINSIC)
    assert intr_row.state == "stale"
    assert intr_row.reason and "freshness" in intr_row.reason.lower()


# ---------------------------------------------------------------------------
# 3. Each optional/context axis missing individually => exact renormalization
# ---------------------------------------------------------------------------

def test_each_context_axis_missing_individually_renormalizes():
    # (er?, crit?, reach?, bi?, known_weight, expected value)
    cases = [
        (False, True,  True,  True,  D("0.70"), lambda: D("6.45") / D("0.70")),
        (True,  False, True,  True,  D("0.85"), lambda: D("5.25") / D("0.85")),   # 3.6+0.3+1.0+0.35
        (True,  True,  False, True,  D("0.90"), lambda: D("5.75") / D("0.90")),
        (True,  True,  True,  False, D("0.95"), lambda: D("6.40") / D("0.95")),
    ]
    for er_present, crit_present, reach_present, bi_present, kw, expected in cases:
        r = compute_tes(TesInputs(
            intrinsic=intr(D("9.0")),
            exploit_reality=bottom_er() if er_present else ExploitRealityInput(),
            criticality=crit(CriticalityLabel.CRITICAL) if crit_present else None,
            reachability=reach(ReachabilityVantage.EXTERNAL) if reach_present else None,
            business_impact=bi(D("7")) if bi_present else None,
        ))
        assert r.state is TesState.PROVISIONAL, (er_present, crit_present, reach_present, bi_present)
        assert r.known_weight == kw
        close(r.value, expected)
        assert len(r.missing_inputs) == 1
        # every unknown axis keeps its full base weight and no contribution
        unknown = [x for x in r.decomposition if x.contribution is None and x.axis != AxisId.INTRINSIC]
        assert len(unknown) == 1
        assert unknown[0].effective_weight is None
        assert unknown[0].base_weight in (D("0.30"), D("0.15"), D("0.10"), D("0.05"))
        assert unknown[0].reason
        assert_contributions_sum(r)


# ---------------------------------------------------------------------------
# 4. Missing-axis combinations, including intrinsic-only
# ---------------------------------------------------------------------------

def test_intrinsic_only_is_renormalized_over_intrinsic_alone():
    r = compute_tes(TesInputs(intrinsic=intr(D("9.0"))))
    assert r.state is TesState.PROVISIONAL
    assert r.known_axes == (AxisId.INTRINSIC,)
    assert r.known_weight == D("0.40")
    # 9.0 * (0.40/0.40) = 9.0 exactly
    assert r.value == D("9.0")
    assert r.display_value == D("9.00")
    assert len(r.missing_inputs) == 4
    assert_contributions_sum(r)


def test_er_and_reachability_missing_together():
    r = compute_tes(TesInputs(
        intrinsic=intr(D("9.0")),
        criticality=crit(CriticalityLabel.CRITICAL),
        business_impact=bi(D("7")),
    ))
    assert r.state is TesState.PROVISIONAL
    assert r.known_weight == D("0.40") + D("0.15") + D("0.05")
    close(r.value, lambda: (D("9.0") * D("0.40") + D("10") * D("0.15") + D("7") * D("0.05")) / D("0.60"))
    assert len(r.missing_inputs) == 2


def test_only_intrinsic_and_business_impact_known():
    r = compute_tes(TesInputs(intrinsic=intr(D("4.0")), business_impact=bi(D("10"))))
    assert r.state is TesState.PROVISIONAL
    assert r.known_weight == D("0.45")
    close(r.value, lambda: (D("4.0") * D("0.40") + D("10") * D("0.05")) / D("0.45"))


# ---------------------------------------------------------------------------
# 5. Unknown values never contribute zero
# ---------------------------------------------------------------------------

def test_unknown_axis_never_contributes_zero_and_never_defaults():
    # BI missing: if BI were coerced to 0, value would drop by 0.35-ish;
    # if defaulted to 5, the renormalization would differ. Compare against
    # the exact renormalized expectation and against a provided-BI run.
    missing = compute_tes(full_inputs(business_impact=None))
    present = compute_tes(full_inputs(business_impact=bi(D("7"))))
    assert missing.value != present.value
    bi_row_missing = row(missing, AxisId.BUSINESS_IMPACT)
    assert bi_row_missing.raw_value is None
    assert bi_row_missing.contribution is None
    assert bi_row_missing.base_weight == D("0.05")   # base weight RETAINED, not redistributed away
    assert bi_row_missing.effective_weight is None
    # a neutral-5 default would equal bi(5); assert it does not
    defaulted = compute_tes(full_inputs(business_impact=bi(D("5"))))
    assert missing.value != defaulted.value


def test_absent_business_impact_zero_is_still_distinct_from_scored_zero():
    zero_scored = compute_tes(full_inputs(business_impact=bi(D("0"))))
    absent = compute_tes(full_inputs(business_impact=None))
    assert zero_scored.state is TesState.FINAL and absent.state is TesState.PROVISIONAL
    assert zero_scored.value != absent.value
    # scored 0 legitimately contributes 0; absent never contributes
    assert row(zero_scored, AxisId.BUSINESS_IMPACT).contribution == D("0")
    assert row(absent, AxisId.BUSINESS_IMPACT).contribution is None


# ---------------------------------------------------------------------------
# 6. Criticality mapping boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label,expected", [
    (CriticalityLabel.CRITICAL, D("10")),
    (CriticalityLabel.HIGH, D("8")),
    (CriticalityLabel.MEDIUM, D("5")),
    (CriticalityLabel.LOW, D("2")),
])
def test_criticality_mapping(label, expected):
    r = compute_tes(full_inputs(criticality=crit(label)))
    assert row(r, AxisId.CRITICALITY).raw_value == expected


def test_criticality_missing_is_unknown():
    r = compute_tes(full_inputs(criticality=None))
    cr = row(r, AxisId.CRITICALITY)
    assert cr.raw_value is None and cr.contribution is None
    assert cr.state == "unknown"
    assert cr.reason and "criticality" in cr.reason.lower()


# ---------------------------------------------------------------------------
# 7. Reachability mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vantage,expected", [
    (ReachabilityVantage.EXTERNAL, D("10")),
    (ReachabilityVantage.INTERNAL, D("8")),
])
def test_reachability_mapping(vantage, expected):
    r = compute_tes(full_inputs(reachability=reach(vantage)))
    assert row(r, AxisId.REACHABILITY).raw_value == expected


def test_reachability_absent_is_unknown():
    r = compute_tes(full_inputs(reachability=None))
    rr = row(r, AxisId.REACHABILITY)
    assert rr.raw_value is None and rr.contribution is None
    assert rr.state == "unknown"
    assert rr.reason


# ---------------------------------------------------------------------------
# 8. BI values 0 and 10
# ---------------------------------------------------------------------------

def test_business_impact_zero_and_ten():
    r0 = compute_tes(full_inputs(business_impact=bi(D("0"))))
    r10 = compute_tes(full_inputs(business_impact=bi(D("10"))))
    assert row(r0, AxisId.BUSINESS_IMPACT).raw_value == D("0")
    assert row(r10, AxisId.BUSINESS_IMPACT).raw_value == D("10")
    assert r0.value == D("6.40")   # 6.75 - 7*0.05
    assert r10.value == D("6.90")  # 6.75 + 3*0.05
    assert r0.state is TesState.FINAL and r10.state is TesState.FINAL


# ---------------------------------------------------------------------------
# 9. Every ER rung
# ---------------------------------------------------------------------------

def test_er_rung_exact_exposure_fresh():
    er = ExploitRealityInput(
        exact_exposure_fresh=ExactExposureEvidence(
            ExactExposureEvidenceState.FRESH_QUALIFYING,
            kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr",
            provenance_class=ProvenanceClass.MACHINE_OBSERVED,
        )
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("10")
    assert er_row.selected_rung == "exact_exposure_evidence"
    assert r.state is TesState.FINAL   # no other sources present at all


def test_er_rung_kev_ransomware():
    er = ExploitRealityInput(
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, KevRansomwareFlag.KNOWN, observed_at=NOW,
                                            feed_health=kev_health())
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("9")
    assert er_row.selected_rung == "kev_listed+ransomware"


def test_er_rung_kev_listed():
    er = ExploitRealityInput(
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                                              feed_health=kev_health())
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("8")
    assert er_row.selected_rung == "kev_listed"


def test_er_rung_epss_bands():
    cases = [
        ("0.5", D("7")),
        ("0.49", D("6")),
        ("0.1", D("6")),
        ("0.099", D("5")),
        ("0.02", D("5")),
        ("0.019", D("3")),
        ("0.002", D("3")),
        ("0.0019", D("1") if False else None),  # bottom rung handled below
    ]
    for raw, expected in cases:
        if expected is None:
            continue
        er = ExploitRealityInput(epss=EpssObservation(D(raw), FeedFreshness.FRESH, observed_at=NOW,
                                               feed_health=epss_health()))
        r = compute_tes(full_inputs(er=er))
        er_row = row(r, AxisId.EXPLOIT_REALITY)
        assert er_row.raw_value == expected, raw
        assert er_row.selected_rung.startswith("epss_band"), raw


def test_er_rung_bottom_requires_both_signals():
    # fresh EPSS < 0.002 AND fresh KEV not_listed => ER 1
    r = compute_tes(full_inputs(er=bottom_er()))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("1")
    assert er_row.selected_rung == "no_known_evidence"
    assert set(er_row.selected_sources) == {"epss", "kev"}
    # fresh EPSS < 0.002 but KEV stale => no bottom rung
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.STALE, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r2 = compute_tes(full_inputs(er=er))
    er_row2 = row(r2, AxisId.EXPLOIT_REALITY)
    assert er_row2.raw_value is None
    assert any(n == "kev(stale)" for n, _ in er_row2.unresolved_higher)
    # fresh KEV not_listed but the feed cannot resolve the ternary => no bottom rung
    er5 = ExploitRealityInput(
        epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.UNKNOWN, FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r5 = compute_tes(full_inputs(er=er5))
    er_row5 = row(r5, AxisId.EXPLOIT_REALITY)
    assert er_row5.raw_value is None
    assert any(n == "kev(unknown)" for n, _ in er_row5.unresolved_higher)
    assert r5.state is TesState.PROVISIONAL
    # fresh KEV not_listed but EPSS missing => no bottom rung (EPSS unchecked)
    er3 = ExploitRealityInput(kev=KevObservation(
        KevTernaryState.NOT_LISTED, FeedFreshness.FRESH, observed_at=NOW,
        feed_health=kev_health()))
    r3 = compute_tes(full_inputs(er=er3))
    assert row(r3, AxisId.EXPLOIT_REALITY).raw_value is None
    # fresh KEV not_listed but stale EPSS value => no bottom rung either
    er4 = ExploitRealityInput(
        epss=EpssObservation(D("0.001"), FeedFreshness.STALE, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r4 = compute_tes(full_inputs(er=er4))
    assert row(r4, AxisId.EXPLOIT_REALITY).raw_value is None


def test_er_higher_rung_wins_no_addition_no_averaging():
    # EPSS 0.9 fresh (7) + KEV listed fresh (8) => 8, never 15, never 7.5
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.9"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                                              feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("8")
    assert er_row.selected_rung == "kev_listed"
    # exact-exposure 10 beats everything below
    er2 = ExploitRealityInput(
        exact_exposure_fresh=ExactExposureEvidence(ExactExposureEvidenceState.FRESH_QUALIFYING, kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="x", provenance_class=ProvenanceClass.MACHINE_OBSERVED),
        epss=EpssObservation(D("0.9"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, KevRansomwareFlag.KNOWN, observed_at=NOW,
                                            feed_health=kev_health()),
    )
    r2 = compute_tes(full_inputs(er=er2))
    assert row(r2, AxisId.EXPLOIT_REALITY).raw_value == D("10")


# ---------------------------------------------------------------------------
# 10. Exact EPSS boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected_rung", [
    ("0.0019", None),          # below .002: no rung without fresh KEV not_listed
    ("0.002", "3"),
    ("0.019", "3"),
    ("0.02", "5"),
    ("0.099", "5"),
    ("0.1", "6"),
    ("0.499", "6"),
    ("0.5", "7"),
    ("0.999", "7"),
])
def test_epss_exact_boundaries(value, expected_rung):
    er = ExploitRealityInput(
        epss=EpssObservation(D(value), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        # KEV present but stale: cannot complete the bottom rung, and with
        # EPSS >= 0.002 its staleness is bounded (ceiling 9) -> provisional
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.STALE, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    if expected_rung is None:
        assert er_row.raw_value is None
        assert r.state is TesState.PROVISIONAL
    else:
        assert er_row.selected_rung == f"epss_band({value})"
        assert er_row.raw_value == D(expected_rung)
    # boundary comparisons are exact Decimal comparisons (no float drift)
    assert isinstance(er_row.epss_value, Decimal)


def test_bottom_rung_exact_boundaries_with_fresh_kev_not_listed():
    # EPSS .0019 + fresh KEV not_listed => bottom rung ER 1
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.0019"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("1")
    assert er_row.selected_rung == "no_known_evidence"
    # EPSS exactly .002 is NOT below the bottom edge -> band 3
    er2 = ExploitRealityInput(
        epss=EpssObservation(D("0.002"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r2 = compute_tes(full_inputs(er=er2))
    er_row2 = row(r2, AxisId.EXPLOIT_REALITY)
    assert er_row2.raw_value == D("3")
    assert er_row2.selected_rung == "epss_band(0.002)"


# ---------------------------------------------------------------------------
# 11. Stale-higher rule (ticket examples)
# ---------------------------------------------------------------------------

def test_stale_higher_example_kev_stale_epss_fresh_070():
    # KEV stale + EPSS 0.70 fresh => ER 7, PROVISIONAL (stale KEV ceiling 9 > 7)
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.UNKNOWN, FeedFreshness.STALE, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("7")
    assert r.state is TesState.PROVISIONAL
    assert er_row.unresolved_higher == (("kev(stale)", "KEV feed is stale; a KEV rung may exist or be higher"),)
    assert "kev(stale)" in (er_row.reason or "")
    assert_contributions_sum(r)


def test_stale_epss_cannot_exceed_fresh_kev_listing():
    # KEV listed fresh (8); stale EPSS ceiling 7 <= 8 -> rung stands, FINAL
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.70"), FeedFreshness.STALE, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                                              feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("8")
    assert er_row.selected_rung == "kev_listed"
    assert er_row.unresolved_higher == ()
    assert r.state is TesState.FINAL
    # the stale EPSS is still rendered for transparency
    assert er_row.epss_freshness is FeedFreshness.STALE
    assert er_row.epss_value == D("0.70")


def test_stale_kev_cannot_exceed_fresh_exact_exposure():
    er = ExploitRealityInput(
        exact_exposure_fresh=ExactExposureEvidence(ExactExposureEvidenceState.FRESH_QUALIFYING, kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr", provenance_class=ProvenanceClass.MACHINE_OBSERVED),
        kev=KevObservation(KevTernaryState.UNKNOWN, FeedFreshness.STALE, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("10")
    assert r.state is TesState.FINAL
    assert er_row.unresolved_higher == ()


def test_expired_exact_exposure_cannot_establish_10_but_lower_rung_is_retained():
    # Expired (stale) evidence: ceiling 10 -> any established lower rung stays provisional
    er = ExploitRealityInput(
        exact_exposure_stale=ExactExposureEvidence(ExactExposureEvidenceState.STALE, kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr-old", provenance_class=ProvenanceClass.MACHINE_OBSERVED),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                                              feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("8")            # lower fresh rung retained
    assert r.state is TesState.PROVISIONAL
    assert er_row.unresolved_higher == (("exact_exposure_evidence(stale)", "exact-exposure exploitation evidence is stale (expired past its kind TTL)"),)

    er2 = ExploitRealityInput(
        exact_exposure_stale=ExactExposureEvidence(ExactExposureEvidenceState.STALE, kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr-old", provenance_class=ProvenanceClass.MACHINE_OBSERVED),
        epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
    )
    r2 = compute_tes(full_inputs(er=er2))
    er_row2 = row(r2, AxisId.EXPLOIT_REALITY)
    assert er_row2.raw_value == D("7")
    assert r2.state is TesState.PROVISIONAL
    assert er_row2.unresolved_higher == (("exact_exposure_evidence(stale)", "exact-exposure exploitation evidence is stale (expired past its kind TTL)"),)

    # expired evidence alone: no fresh rung, stale-higher named, ER unknown
    er3 = ExploitRealityInput(
        exact_exposure_stale=ExactExposureEvidence(ExactExposureEvidenceState.STALE, kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr-old", provenance_class=ProvenanceClass.MACHINE_OBSERVED),
    )
    r3 = compute_tes(full_inputs(er=er3))
    er_row3 = row(r3, AxisId.EXPLOIT_REALITY)
    assert er_row3.raw_value is None
    assert r3.state is TesState.PROVISIONAL
    assert er_row3.unresolved_higher == (("exact_exposure_evidence(stale)", "exact-exposure exploitation evidence is stale (expired past its kind TTL)"),)
    close(r3.value, lambda: (D("9.0") * D("0.40") + D("10") * D("0.15") + D("10") * D("0.10") + D("7") * D("0.05")) / D("0.70"))


def test_failed_validation_establishes_nothing():
    # A fresh failed/prevented validation is passed as NONE (caller resolves
    # eligibility): it must not establish a rung and must not mark anything stale.
    er = ExploitRealityInput(
        exact_exposure_fresh=ExactExposureEvidence(ExactExposureEvidenceState.NONE, kind=tes_kernel.EvidenceKind.CONTROLLED_VALIDATION),
        epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("1")            # bottom rung from EPSS+KEV only
    assert r.state is TesState.FINAL
    assert er_row.unresolved_higher == ()


def test_no_er_evidence_is_unknown_renormalized_provisional():
    r = compute_tes(full_inputs(er=ExploitRealityInput()))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value is None
    assert er_row.state == "unknown"
    assert er_row.reason
    assert r.state is TesState.PROVISIONAL
    assert r.known_weight == D("0.70")


def test_normal_absence_of_tenant_evidence_is_not_staleness():
    # Absence (exact_exposure_fresh=None, exact_exposure_stale=None) is normal
    # absence: no "stale exact-exposure" source may appear anywhere.
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert not any("exact_exposure" in n for n, _ in er_row.unresolved_higher)
    assert er_row.exact_exposure_fresh_state is None
    assert er_row.exact_exposure_stale_state is None


# ---------------------------------------------------------------------------
# 12. CVE vs non-CVE identical composition
# ---------------------------------------------------------------------------

def test_cve_and_non_cve_produce_identical_composition():
    er = bottom_er()
    common = dict(exploit_reality=er,
                  criticality=crit(CriticalityLabel.HIGH),
                  reachability=reach(ReachabilityVantage.INTERNAL),
                  business_impact=bi(D("6")))
    r_cve = compute_tes(TesInputs(
        intrinsic=IntrinsicInput(D("7.5"), ProvenanceClass.MACHINE_OBSERVED,
                                 FreshnessState.FRESH, NOW, "cvss:assessment-123", "cvss_4.0_cna"),
        **common))
    r_sss = compute_tes(TesInputs(
        intrinsic=IntrinsicInput(D("7.5"), ProvenanceClass.INFERRED,
                                 FreshnessState.FRESH, NOW, "scout:sss-rubric", "sss_v1"),
        **common))
    assert r_cve.value == r_sss.value
    assert r_cve.state is r_sss.state is TesState.FINAL
    assert r_cve.formula_version == r_sss.formula_version == "tes-v1"
    for a, b in zip(r_cve.decomposition, r_sss.decomposition):
        assert a.raw_value == b.raw_value
        assert a.contribution == b.contribution
    # exact: 7.5*.4 + 1*.3 + 8*.15 + 8*.10 + 6*.05 = 3.0+0.3+1.2+0.8+0.30 = 5.60
    assert r_cve.value == D("5.60")


# ---------------------------------------------------------------------------
# 13. Arithmetic invariants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("intrinsic,er,criticality,vantage,bival", [
    ("9.0", "bottom", "critical", "external", "7"),
    ("6.5", "epss7", "high", "internal", "0"),
    ("10", "kev8", "medium", None, "10"),
    ("0", "none", "low", "external", "5"),
    ("3.3", "bottom", "critical", "external", "9.5"),
])
def test_value_always_within_0_10_and_contributions_sum(intrinsic, er, criticality, vantage, bival):
    er_map = {
        "bottom": bottom_er(),
        "epss7": ExploitRealityInput(epss=EpssObservation(
            D("0.9"), FeedFreshness.FRESH, observed_at=NOW, feed_health=epss_health())),
        "kev8": ExploitRealityInput(kev=KevObservation(
            KevTernaryState.LISTED, FeedFreshness.FRESH, observed_at=NOW,
            feed_health=kev_health())),
        "none": ExploitRealityInput(),
    }
    crit_map = {"critical": CriticalityLabel.CRITICAL, "high": CriticalityLabel.HIGH,
                "medium": CriticalityLabel.MEDIUM, "low": CriticalityLabel.LOW}
    r = compute_tes(TesInputs(
        intrinsic=intr(D(intrinsic)),
        exploit_reality=er_map[er],
        criticality=crit(crit_map[criticality]) if criticality else None,
        reachability=reach(ReachabilityVantage.EXTERNAL if vantage == "external" else ReachabilityVantage.INTERNAL) if vantage else None,
        business_impact=bi(D(bival)),
    ))
    assert D(0) <= r.value <= D(10)
    assert_contributions_sum(r)


def test_no_intermediate_rounding_full_precision_value():
    r = compute_tes(full_inputs(er=ExploitRealityInput()))
    # 9*0.4/0.7 + 10*0.15/0.7 + 7*0.05/0.7 -> non-terminating expansion
    assert r.value.as_tuple().exponent < 0 and len(r.value.as_tuple().digits) > 10
    assert r.display_value == D("9.21")


def test_presentation_rounding_half_up():
    # exact 7.436281 -> 7.44 (ticket example), via 9.0/6/8/8 + BI 0.72562
    r = compute_tes(TesInputs(
        intrinsic=intr(D("9.0")),
        exploit_reality=ExploitRealityInput(epss=EpssObservation(
            D("0.35"), FeedFreshness.FRESH, observed_at=NOW, feed_health=epss_health())),
        criticality=crit(CriticalityLabel.HIGH),
        reachability=reach(ReachabilityVantage.INTERNAL),
        business_impact=bi(D("0.72562")),
    ))
    assert r.value == D("7.4362810")
    assert r.display_value == D("7.44")
    # value itself retains full precision; only display is quantized
    assert r.value != r.display_value


def test_known_weight_and_effective_weights_sum():
    r = compute_tes(full_inputs(er=ExploitRealityInput()))  # ER unknown
    assert r.known_weight == D("0.70")
    known = [x for x in r.decomposition if x.effective_weight is not None]
    assert sum((x.effective_weight for x in known), D(0)) == D("1")


# ---------------------------------------------------------------------------
# 14. Fail-closed input qualification
# ---------------------------------------------------------------------------

def test_naked_float_rejected():
    with pytest.raises(TesInputError):
        QualifiedValue(7.5, ProvenanceClass.ANALYST_ENTERED, FreshnessState.FRESH, NOW, "t")


def test_out_of_range_rejected_no_clamping():
    for bad in ("10.01", "-0.001", "99"):
        with pytest.raises(TesInputError):
            qv(D(bad))
    # BI bounds are the same 0-10
    with pytest.raises(TesInputError):
        bi(D("10.5"))


def test_string_numeric_values_are_accepted_through_decimal_not_float():
    # "7.1" -> Decimal("7.1") exactly; 7.1 float would fail the type check
    v = qv("7.1")
    assert v.value == D("7.1")


@pytest.mark.parametrize("make", [
    lambda: CriticalityInput("critical", ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, "a"),
    lambda: CriticalityInput(None, ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, "a"),
    lambda: CriticalityInput(CriticalityLabel.HIGH, None, FreshnessState.FRESH, NOW, "a"),
    lambda: CriticalityInput(CriticalityLabel.HIGH, ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, None, "a"),
    lambda: CriticalityInput(CriticalityLabel.HIGH, ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, ""),
    lambda: ReachabilityInput("external", ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, "s"),
    lambda: ReachabilityInput(None, ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, "s"),
    lambda: EpssObservation(D("0.5"), "freshly", feed_health=epss_health()),
    lambda: EpssObservation(D("1.5"), FeedFreshness.FRESH, feed_health=epss_health()),
    lambda: EpssObservation(D("-0.1"), FeedFreshness.FRESH, feed_health=epss_health()),
    lambda: KevObservation("listed", FeedFreshness.FRESH, feed_health=kev_health()),
    lambda: KevObservation(KevTernaryState.LISTED, "fresh", feed_health=kev_health()),
    lambda: BusinessImpactInput("naked"),
    lambda: BusinessImpactInput(7.5),
    lambda: IntrinsicInput(D("9.0"), ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, "s", ""),
    lambda: IntrinsicInput(D("11"), ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH, NOW, "s", "cvss"),
    lambda: compute_tes("not-tes-inputs"),
])
def test_malformed_inputs_fail_closed(make):
    with pytest.raises(TesInputError):
        make()


def test_missing_provenance_on_known_value_fails_closed():
    with pytest.raises(TesInputError):
        CriticalityInput(CriticalityLabel.HIGH, provenance_class=None,
                         freshness=FreshnessState.FRESH, observed_at=NOW, source="a")
    with pytest.raises(TesInputError):
        ReachabilityInput(ReachabilityVantage.EXTERNAL, provenance_class=ProvenanceClass.MACHINE_OBSERVED,
                          freshness=None, observed_at=NOW, source="s")


def test_missing_timestamp_fails_closed():
    with pytest.raises(TesInputError):
        qv(D("5"), observed_at=None)


def test_float_intrinsic_rejected():
    with pytest.raises(TesInputError):
        IntrinsicInput(9.5, ProvenanceClass.MACHINE_OBSERVED, FreshnessState.FRESH,
                       NOW, "s", "cvss")


def test_bool_is_not_a_valid_decimal_input():
    with pytest.raises(TesInputError):
        qv(True)


# ---------------------------------------------------------------------------
# 15. Decomposition completeness
# ---------------------------------------------------------------------------

def test_decomposition_rows_carry_provenance():
    r = compute_tes(full_inputs(
        er=ExploitRealityInput(
            epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                                 feed_health=epss_health()),
            kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                               KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                               feed_health=kev_health()),
        )))
    for x in r.decomposition:
        assert x.provenance_class is not None
        assert x.source
        if x.state == "known":
            assert x.observed_at is not None, x.axis
            assert x.freshness is FreshnessState.FRESH
        else:
            assert x.reason


def test_unscoreable_renders_all_axes_with_reasons():
    r = compute_tes(TesInputs(intrinsic=None))
    assert len(r.decomposition) == 5
    for x in r.decomposition:
        assert x.contribution is None
        assert x.effective_weight is None
        assert x.reason


# ---------------------------------------------------------------------------
# 17. P0-04 bounded correction round — direct counterexample regressions
# ---------------------------------------------------------------------------

def er_feeds(epss_value="0.70", epss_fresh=FeedFreshness.FRESH,
             kev_state=KevTernaryState.UNKNOWN, kev_fresh=FeedFreshness.FRESH,
             kev_ransom=KevRansomwareFlag.UNKNOWN):
    """Fresh EPSS + fresh KEV helper with fully-qualified observations."""
    return ExploitRealityInput(
        epss=EpssObservation(D(epss_value), epss_fresh, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(kev_state, kev_fresh, kev_ransom, observed_at=NOW,
                           feed_health=kev_health()),
    )


# --- Correction 1: missing timestamps cannot establish fresh EPSS/KEV rungs ---

def test_fresh_epss_without_timestamp_is_rejected_at_construction():
    with pytest.raises(TesInputError, match="observed_at"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=None,
                        feed_health=epss_health())


def test_fresh_epss_with_empty_source_is_rejected_at_construction():
    with pytest.raises(TesInputError, match="source"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, source="", observed_at=NOW,
                        feed_health=epss_health())


def test_fresh_kev_without_timestamp_is_rejected_at_construction():
    with pytest.raises(TesInputError, match="observed_at"):
        KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, observed_at=None,
                       feed_health=kev_health())


def test_fresh_kev_with_empty_source_is_rejected_at_construction():
    with pytest.raises(TesInputError, match="source"):
        KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, source="", observed_at=NOW,
                       feed_health=kev_health())


def test_fresh_epss_and_kev_with_both_timestamps_absent_never_final():
    """Direct counterexample: fresh EPSS + fresh KEV, both timestamps absent —
    construction fails closed, so no FINAL score can be produced at all."""
    with pytest.raises(TesInputError):
        ExploitRealityInput(
            epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=None,
                                 feed_health=epss_health()),
            kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                               observed_at=None, feed_health=kev_health()),
        )


def test_unqualified_observations_never_reach_scoring_defense_in_depth():
    """Even if a frozen dataclass is mutated past construction, the selection
    re-check refuses to let an unqualified score-bearing record establish a
    rung (no FINAL, no rung — TesInputError)."""
    epss = EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=epss_health())
    object.__setattr__(epss, "observed_at", None)
    with pytest.raises(TesInputError):
        compute_tes(full_inputs(er=ExploitRealityInput(
            epss=epss,
            kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                               observed_at=NOW, feed_health=kev_health()),
        )))
    ee = ExactExposureEvidence(
        ExactExposureEvidenceState.FRESH_QUALIFYING,
        kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr",
        provenance_class=ProvenanceClass.MACHINE_OBSERVED,
    )
    object.__setattr__(ee, "provenance_class", None)
    with pytest.raises(TesInputError):
        compute_tes(full_inputs(er=ExploitRealityInput(exact_exposure_fresh=ee)))


@pytest.mark.parametrize("evidence", [
    # FRESH_QUALIFYING missing each qualification field individually
    lambda: ExactExposureEvidence(ExactExposureEvidenceState.FRESH_QUALIFYING),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.FRESH_QUALIFYING,
        kind=EvidenceKind.OBSERVED_EXPLOITATION),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.FRESH_QUALIFYING,
        kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.FRESH_QUALIFYING,
        kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source=""),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.FRESH_QUALIFYING,
        kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr"),
    # STALE is held to the SAME standard (stale-higher row stays auditable)
    lambda: ExactExposureEvidence(ExactExposureEvidenceState.STALE),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.STALE, kind=EvidenceKind.OBSERVED_EXPLOITATION),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.STALE,
        kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW),
    lambda: ExactExposureEvidence(
        ExactExposureEvidenceState.STALE,
        kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW, source="edr"),
])
def test_incomplete_exact_evidence_rejected_fresh_and_stale(evidence):
    with pytest.raises(TesInputError):
        evidence()


def test_none_evidence_still_establishes_nothing():
    er = ExploitRealityInput(
        exact_exposure_fresh=ExactExposureEvidence(ExactExposureEvidenceState.NONE),
        epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
    )
    r = compute_tes(full_inputs(er=er))
    assert row(r, AxisId.EXPLOIT_REALITY).raw_value == D("7")  # EPSS only


def test_inconsistent_slot_state_combinations_rejected():
    fresh_slot = lambda e: ExploitRealityInput(exact_exposure_fresh=e)
    stale_slot = lambda e: ExploitRealityInput(exact_exposure_stale=e)
    with pytest.raises(TesInputError, match="slot"):
        fresh_slot(ExactExposureEvidence(
            ExactExposureEvidenceState.STALE,
            kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW,
            source="edr", provenance_class=ProvenanceClass.MACHINE_OBSERVED))
    with pytest.raises(TesInputError, match="slot"):
        stale_slot(ExactExposureEvidence(
            ExactExposureEvidenceState.FRESH_QUALIFYING,
            kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW,
            source="edr", provenance_class=ProvenanceClass.MACHINE_OBSERVED))
    with pytest.raises(TesInputError, match="slot"):
        stale_slot(ExactExposureEvidence(ExactExposureEvidenceState.NONE))


def test_wrong_component_types_in_er_slots_rejected():
    for bad in ("naked", 7.5, 42, object()):
        with pytest.raises(TesInputError):
            ExploitRealityInput(exact_exposure_fresh=bad)
        with pytest.raises(TesInputError):
            ExploitRealityInput(exact_exposure_stale=bad)
        with pytest.raises(TesInputError):
            ExploitRealityInput(epss=bad)
        with pytest.raises(TesInputError):
            ExploitRealityInput(kev=bad)


# --- Correction 3: analyst-reviewed evidence preserves its provenance class ---

def test_analyst_reviewed_exact_evidence_preserves_provenance_class():
    """Analyst-reviewed exact evidence establishing ER 10 must never render
    as MACHINE_OBSERVED merely because it established the top rung."""
    er = ExploitRealityInput(
        exact_exposure_fresh=ExactExposureEvidence(
            ExactExposureEvidenceState.FRESH_QUALIFYING,
            kind=EvidenceKind.CONTROLLED_VALIDATION, observed_at=NOW, source="pentest-team",
            provenance_class=ProvenanceClass.ANALYST_ENTERED,
        ),
        epss=EpssObservation(D("0.9"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH,
                           KevRansomwareFlag.KNOWN, observed_at=NOW,
                                            feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("10")
    assert er_row.selected_rung == "exact_exposure_evidence"
    assert er_row.provenance_class is ProvenanceClass.ANALYST_ENTERED


def test_epss_kev_and_bottom_rung_are_machine_observed():
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.9"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH,
                           KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                                              feed_health=kev_health()),
    )
    r = compute_tes(full_inputs(er=er))
    assert row(r, AxisId.EXPLOIT_REALITY).provenance_class is ProvenanceClass.MACHINE_OBSERVED
    er2 = bottom_er()  # bottom rung built from EPSS + KEV
    r2 = compute_tes(full_inputs(er=er2))
    assert row(r2, AxisId.EXPLOIT_REALITY).provenance_class is ProvenanceClass.MACHINE_OBSERVED


# --- Correction 2: feed-health provenance appears in the decomposition ---


def test_feed_health_provenance_appears_in_decomposition():
    epss_health = FeedHealthProvenance(
        "epss", is_healthy=True, last_successful_at=NOW,
        last_snapshot_id="snap-9", last_good_snapshot_id="good-7",
        freshness_age_seconds=3600.0,
    )
    kev_health = FeedHealthProvenance(
        "kev", is_healthy=False, last_successful_at=None,
        last_snapshot_id="snap-8", last_good_snapshot_id=None,
        freshness_age_seconds=None,
    )
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health),
        kev=KevObservation(KevTernaryState.UNKNOWN, FeedFreshness.STALE,
                           observed_at=NOW, feed_health=kev_health),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.epss_feed_health is epss_health
    assert er_row.kev_feed_health is kev_health
    # every ResolverProvenance fact survives the round trip
    assert er_row.epss_feed_health.source == "epss"
    assert er_row.epss_feed_health.is_healthy is True
    assert er_row.epss_feed_health.last_successful_at == NOW
    assert er_row.epss_feed_health.last_snapshot_id == "snap-9"
    assert er_row.epss_feed_health.last_good_snapshot_id == "good-7"
    assert er_row.epss_feed_health.freshness_age_seconds == 3600.0
    assert er_row.kev_feed_health.is_healthy is False


# --- Final surgical correction: MANDATORY feed health ---

def test_missing_epss_feed_health_rejected():
    """A present EPSS observation may never omit feed health (sentinel or
    None): the whole observation can only be absent from the input."""
    with pytest.raises(TesInputError, match="FeedHealthProvenance"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW)
    with pytest.raises(TesInputError, match="FeedHealthProvenance"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                        feed_health=None)
    # valueless STALE observations are equally mandatory
    with pytest.raises(TesInputError, match="FeedHealthProvenance"):
        EpssObservation(None, FeedFreshness.STALE, feed_health=None)


def test_missing_kev_feed_health_rejected():
    """A present KEV observation may never omit feed health (a ternary has
    no valueless form, so there is no unobserved KEV shape at all)."""
    with pytest.raises(TesInputError, match="FeedHealthProvenance"):
        KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH, observed_at=NOW)
    with pytest.raises(TesInputError, match="FeedHealthProvenance"):
        KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.STALE,
                       observed_at=NOW, feed_health=None)


def test_observation_without_feed_health_never_reaches_scoring():
    """Even bypassing construction (frozen-dataclass mutation), scoring must
    fail closed on an observation whose feed health is missing."""
    epss = EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                           feed_health=epss_health())
    object.__setattr__(epss, "feed_health", None)
    with pytest.raises(TesInputError):
        compute_tes(full_inputs(er=ExploitRealityInput(epss=epss)))
    kev = KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                         observed_at=NOW, feed_health=kev_health())
    object.__setattr__(kev, "feed_health", None)
    with pytest.raises(TesInputError):
        compute_tes(full_inputs(er=ExploitRealityInput(kev=kev)))


def test_unhealthy_health_paired_with_fresh_is_rejected():
    """FRESH is only coherent with is_healthy=True (None included: a never-
    evaluated record cannot establish a fresh authoritative result)."""
    for bad in (
        epss_health(is_healthy=False),
        epss_health(is_healthy=None),
    ):
        with pytest.raises(TesInputError, match="is_healthy"):
            EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                            feed_health=bad)
    with pytest.raises(TesInputError, match="is_healthy"):
        KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH,
                       observed_at=NOW, feed_health=kev_health(is_healthy=False))


def test_missing_fresh_generation_facts_paired_with_fresh_are_rejected():
    """FRESH requires last_successful_at, last_snapshot_id,
    last_good_snapshot_id, and a non-negative freshness_age_seconds."""
    bad = [
        epss_health(last_successful_at=None),
        epss_health(last_snapshot_id=None),
        epss_health(last_good_snapshot_id=None),
        epss_health(freshness_age_seconds=None),
    ]
    for health in bad:
        with pytest.raises(TesInputError, match="FRESH"):
            EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                            feed_health=health)
    with pytest.raises(TesInputError, match="FRESH"):
        KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                       observed_at=NOW,
                       feed_health=kev_health(freshness_age_seconds=None))


def test_cross_wired_health_sources_rejected():
    """EPSS observation with KEV health (and vice versa) is rejected."""
    with pytest.raises(TesInputError, match="does not match"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                        feed_health=kev_health())
    with pytest.raises(TesInputError, match="does not match"):
        KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH,
                       observed_at=NOW, feed_health=epss_health())
    # non-empty custom sources must match exactly too
    with pytest.raises(TesInputError, match="does not match"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                        source="epss-primary", feed_health=epss_health())


def test_stale_and_unknown_keep_source_matched_health_with_missing_facts():
    """STALE/UNKNOWN may legitimately carry missing operational facts, but
    the FeedHealthProvenance object and the matching source are mandatory."""
    for freshness in (FeedFreshness.STALE, FeedFreshness.UNKNOWN):
        sparse = FeedHealthProvenance("epss")  # every operational fact None
        obs = EpssObservation(D("0.70"), freshness, observed_at=NOW,
                              feed_health=sparse)
        assert obs.feed_health is sparse
        kobs = KevObservation(KevTernaryState.LISTED, freshness, observed_at=NOW,
                              feed_health=FeedHealthProvenance("kev"))
        assert kobs.feed_health.source == "kev"
    # and a STALE/unhealthy-but-real observation still scores provisionally
    er = ExploitRealityInput(
        epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.UNKNOWN, FeedFreshness.STALE,
                           observed_at=NOW,
                           feed_health=FeedHealthProvenance("kev")),
    )
    r = compute_tes(full_inputs(er=er))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("7")
    assert r.state is TesState.PROVISIONAL
    assert er_row.kev_feed_health is not None and er_row.kev_feed_health.source == "kev"


def test_correctly_qualified_bottom_rung_still_reaches_final():
    """The full mandatory-health contract leaves the happy path intact:
    fresh qualified EPSS+KEV with source-matched healthy FRESH records."""
    r = compute_tes(full_inputs(er=bottom_er()))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("1")
    assert er_row.selected_rung == "no_known_evidence"
    assert r.state is TesState.FINAL
    assert er_row.epss_feed_health.source == "epss"
    assert er_row.kev_feed_health.source == "kev"
    # ...and a top-band FINAL too
    r2 = compute_tes(full_inputs(er=ExploitRealityInput(
        epss=EpssObservation(D("0.9"), FeedFreshness.FRESH, observed_at=NOW,
                             feed_health=epss_health()),
        kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH,
                           KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                           feed_health=kev_health()),
    )))
    assert r2.state is TesState.FINAL
    assert row(r2, AxisId.EXPLOIT_REALITY).raw_value == D("8")


def test_freshness_age_seconds_rejects_bool_nan_inf_negative():
    """freshness_age_seconds accepts ordinary non-negative int/float values
    returned by P0-03 and rejects bool, NaN, infinity, and negatives."""
    with pytest.raises(TesInputError, match="non-negative"):
        FeedHealthProvenance("epss", freshness_age_seconds=True)
    with pytest.raises(TesInputError, match="finite"):
        FeedHealthProvenance("epss", freshness_age_seconds=float("nan"))
    with pytest.raises(TesInputError, match="finite"):
        FeedHealthProvenance("epss", freshness_age_seconds=float("inf"))
    with pytest.raises(TesInputError, match="non-negative"):
        FeedHealthProvenance("epss", freshness_age_seconds=-0.5)
    with pytest.raises(TesInputError, match="non-negative"):
        FeedHealthProvenance("epss", freshness_age_seconds="3600")
    with pytest.raises(TesInputError, match="non-empty"):
        FeedHealthProvenance("epss", last_snapshot_id="")
    with pytest.raises(TesInputError, match="non-empty"):
        FeedHealthProvenance("epss", last_good_snapshot_id="")
    # accepted shapes: int, float, and Decimal-free zero
    assert FeedHealthProvenance("epss", freshness_age_seconds=0).freshness_age_seconds == 0
    assert FeedHealthProvenance("kev", freshness_age_seconds=7.25).freshness_age_seconds == 7.25
    # the FRESH coherence check also refuses a bool age (bypassing the
    # construction-time rejection of a bool directly)
    bool_age = FeedHealthProvenance("epss", freshness_age_seconds=0)
    object.__setattr__(bool_age, "freshness_age_seconds", True)
    with pytest.raises(TesInputError, match="FRESH"):
        EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                        feed_health=bool_age)


def test_feed_health_provenance_rejects_wrong_types():
    with pytest.raises(TesInputError):
        FeedHealthProvenance("")
    with pytest.raises(TesInputError):
        FeedHealthProvenance("epss", is_healthy="yes")
    with pytest.raises(TesInputError):
        FeedHealthProvenance("epss", freshness_age_seconds="3600")
    # wrong type on the observation slot itself is rejected
    with pytest.raises(TesInputError):
        EpssObservation(D("0.5"), FeedFreshness.FRESH, observed_at=NOW,
                        feed_health="healthy")


# --- Correction 4: coherent KEV states only, fail closed ---

def test_contradictory_kev_not_listed_plus_known_rejected():
    with pytest.raises(TesInputError, match="incoherent"):
        KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                       KevRansomwareFlag.KNOWN, observed_at=NOW,
                                            feed_health=kev_health())


def test_listed_plus_ransomware_unknown_yields_er8_provisional():
    """LISTED + UNKNOWN sub-flag: ER 8 stands, ER 9 unresolved, PROVISIONAL."""
    r = compute_tes(full_inputs(er=er_feeds(
        epss_value="0.30",
        kev_state=KevTernaryState.LISTED,
        kev_fresh=FeedFreshness.FRESH,
        kev_ransom=KevRansomwareFlag.UNKNOWN,
    )))
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("8")
    assert er_row.selected_rung == "kev_listed"
    assert r.state is TesState.PROVISIONAL
    assert any(n == "kev(ransomware_unknown)" for n, _ in er_row.unresolved_higher)
    assert any("ransomware" in m for m in r.missing_inputs)


def test_listed_plus_known_yields_er9_and_listed_plus_not_known_yields_er8_final():
    r9 = compute_tes(full_inputs(er=er_feeds(
        epss_value="0.30", kev_state=KevTernaryState.LISTED,
        kev_ransom=KevRansomwareFlag.KNOWN)))
    assert row(r9, AxisId.EXPLOIT_REALITY).raw_value == D("9")
    assert r9.state is TesState.FINAL
    r8 = compute_tes(full_inputs(er=er_feeds(
        epss_value="0.30", kev_state=KevTernaryState.LISTED,
        kev_ransom=KevRansomwareFlag.NOT_KNOWN)))
    assert row(r8, AxisId.EXPLOIT_REALITY).raw_value == D("8")
    assert r8.state is TesState.FINAL


def test_fresh_kev_unknown_never_final_and_never_completes_bottom():
    """Direct counterexample: fresh EPSS 0.70 + fresh KEV UNKNOWN is never
    FINAL; the indeterminate ternary stays unresolved."""
    r = compute_tes(full_inputs(er=er_feeds(epss_value="0.70")))
    assert r.state is TesState.PROVISIONAL
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("7")
    assert any(n == "kev(unknown)" for n, _ in er_row.unresolved_higher)
    assert any("kev(unknown)" in m for m in r.missing_inputs)
    # ...and a fresh KEV UNKNOWN never completes the bottom rung either
    r2 = compute_tes(full_inputs(er=er_feeds(epss_value="0.001")))
    assert row(r2, AxisId.EXPLOIT_REALITY).raw_value is None
    assert r2.state is TesState.PROVISIONAL


# --- Correction 5: missing/state reporting for unresolved higher sources ---

@pytest.mark.parametrize("kev_fresh,expected_name", [
    (FeedFreshness.STALE, "kev(stale)"),
    (FeedFreshness.UNKNOWN, "kev(unknown)"),
])
def test_stale_higher_provisional_results_have_non_empty_missing_inputs(
        kev_fresh, expected_name):
    r = compute_tes(full_inputs(er=er_feeds(epss_value="0.70", kev_fresh=kev_fresh)))
    assert r.state is TesState.PROVISIONAL
    er_row = row(r, AxisId.EXPLOIT_REALITY)
    assert er_row.raw_value == D("7")        # lower fresh rung retained
    assert er_row.state == "known"           # ER axis stays known and scored
    assert er_row.unresolved_higher and er_row.unresolved_higher[0][0] == expected_name
    assert r.missing_inputs, "PROVISIONAL stale-higher must report missing inputs"
    assert any(expected_name in m for m in r.missing_inputs)


def test_unknown_and_stale_render_distinctly():
    """UNKNOWN and STALE must never collapse to the same text."""
    r_stale = compute_tes(full_inputs(er=er_feeds(epss_value="0.70",
                                                  kev_fresh=FeedFreshness.STALE)))
    r_unknown = compute_tes(full_inputs(er=er_feeds(epss_value="0.70",
                                                    kev_fresh=FeedFreshness.UNKNOWN)))
    stale_row = row(r_stale, AxisId.EXPLOIT_REALITY)
    unknown_row = row(r_unknown, AxisId.EXPLOIT_REALITY)
    assert stale_row.unresolved_higher[0][0] != unknown_row.unresolved_higher[0][0]
    assert stale_row.unresolved_higher[0][1] != unknown_row.unresolved_higher[0][1]
    assert stale_row.reason != unknown_row.reason
    # intrinsic UNKNOWN renders "unknown", STALE renders "stale" — never swapped
    r_iu = compute_tes(TesInputs(
        intrinsic=intr(D("9.0"), freshness=FreshnessState.UNKNOWN),
        exploit_reality=bottom_er(),
        criticality=crit(CriticalityLabel.CRITICAL),
        reachability=reach(ReachabilityVantage.EXTERNAL),
        business_impact=bi(D("7")),
    ))
    intr_row = row(r_iu, AxisId.INTRINSIC)
    assert intr_row.state == "unknown"
    assert r_iu.state is TesState.UNSCOREABLE
    r_is = compute_tes(TesInputs(
        intrinsic=intr(D("9.0"), freshness=FreshnessState.STALE),
        exploit_reality=bottom_er(),
        criticality=crit(CriticalityLabel.CRITICAL),
        reachability=reach(ReachabilityVantage.EXTERNAL),
        business_impact=bi(D("7")),
    ))
    assert row(r_is, AxisId.INTRINSIC).state == "stale"


# --- Correction 6: intrinsic numeric strings normalize safely ---

def test_intrinsic_numeric_string_normalizes_to_decimal():
    """IntrinsicInput("9.0", ...) previously validated but retained a string,
    later raising TypeError during multiplication. It must now normalize."""
    v = IntrinsicInput("9.0", ProvenanceClass.MACHINE_OBSERVED,
                       FreshnessState.FRESH, NOW, "cvss-authority", "cvss_4.0_cna")
    assert isinstance(v.value, Decimal)
    assert v.value == D("9.0")
    # the whole composition runs with the normalized value — no TypeError
    r = compute_tes(TesInputs(intrinsic=v, exploit_reality=bottom_er(),
                              criticality=crit(CriticalityLabel.CRITICAL),
                              reachability=reach(ReachabilityVantage.EXTERNAL),
                              business_impact=bi(D("7"))))
    assert r.value == D("6.75")
    assert_contributions_sum(r)


def test_intrinsic_invalid_numeric_string_fails_at_construction():
    with pytest.raises(TesInputError):
        IntrinsicInput("not-a-number", ProvenanceClass.MACHINE_OBSERVED,
                       FreshnessState.FRESH, NOW, "s", "cvss")


# ---------------------------------------------------------------------------
# 18. Purity of the kernel source itself (AST check)
# ---------------------------------------------------------------------------

def test_kernel_imports_are_stdlib_only():
    """AST-level purity proof: the kernel module's import statements may
    reference ONLY stdlib modules — no application, database, or third-party
    imports, and no import of P0-03 models."""
    import ast
    tree = ast.parse(_KERNEL_PATH.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level > 0:
            roots.add("<relative>")
    allowed = {"__future__", "dataclasses", "datetime", "decimal", "enum",
               "math", "typing"}
    assert roots <= allowed, f"kernel imports non-stdlib modules: {roots - allowed}"


# ---------------------------------------------------------------------------
# 16. Purity: the unit suite provably never touches database/app machinery
# ---------------------------------------------------------------------------


def test_unit_suite_never_imports_db_or_app_machinery():
    """Self-verifying purity proof: after importing and exercising the kernel,
    no database driver, no FastAPI app, no repository, and not even the
    exposure package __init__ (which would pull psycopg/audit) may be present
    in sys.modules."""
    forbidden = [
        "psycopg",
        "psycopg_pool",
        "asyncpg",
        "sqlalchemy",
        "app.main",
        "app.db",
        "app.audit",
        "app.exposure",
        "app.exposure.service",
        "app.exposure.scoring_inputs",
        "app.vuln_intelligence",
        "app.routes",
        "tests.conftest",
        "conftest",
    ]
    loaded = [name for name in forbidden if name in sys.modules]
    assert loaded == [], f"unit suite imported forbidden modules: {loaded}"


# ===========================================================================
# P0-08 kernel coverage — the attested_no_exploitation slot (§3.6.4; the
# approved "no known exploitation" attestation is the FLOOR ER rung: exactly
# 1.0, strict-highest selection, never composes, unapproved never scores).
# Mirrors the kernel cases that the DB suites exercise end-to-end.
# ===========================================================================


def _att(state, **kw):
    facts = dict(kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW,
                 source="attestation:unit", provenance_class=ProvenanceClass.ANALYST_ENTERED)
    facts.update(kw)
    return ExactExposureEvidence(state, **facts)


class TestAttestedNoExploitationSlot:
    def test_wrong_type_rejected(self):
        with pytest.raises(TesInputError, match="attested_no_exploitation must be"):
            ExploitRealityInput(attested_no_exploitation="approved")

    @pytest.mark.parametrize("state", list(ExactExposureEvidenceState))
    def test_only_fresh_qualifying_or_stale_carry_the_slot(self, state):
        """NONE is absence: it is passed as None, never as a record."""
        if state in (ExactExposureEvidenceState.FRESH_QUALIFYING,
                     ExactExposureEvidenceState.STALE):
            er = ExploitRealityInput(attested_no_exploitation=_att(state))
            assert er.attested_no_exploitation.state is state
        else:
            with pytest.raises(TesInputError,
                               match="carries only FRESH_QUALING|carries only FRESH_QUALIFYING"):
                ExploitRealityInput(attested_no_exploitation=_att(state))

    def test_fresh_approved_attestation_establishes_exactly_er_1(self):
        er = ExploitRealityInput(attested_no_exploitation=_att(
            ExactExposureEvidenceState.FRESH_QUALIFYING))
        r = compute_tes(full_inputs(er=er))
        er_row = row(r, AxisId.EXPLOIT_REALITY)
        assert er_row.raw_value == D("1")
        assert er_row.selected_rung == "attested_no_exploitation"
        assert er_row.selected_sources == ("attestation:unit",)
        assert er_row.provenance_class is ProvenanceClass.ANALYST_ENTERED
        assert er_row.attestation_state is ExactExposureEvidenceState.FRESH_QUALIFYING
        assert er_row.unresolved_higher == ()
        # The attestation rung is as authoritative as any other established
        # rung: with every axis known the kernel FINALs (the DB-level
        # PROVISIONAL in the P0-08 suites comes from unknown reachability/BI,
        # not from the rung). The EPSS<0.002 bottom-band composition rule
        # does not apply to this rung — it established ER 1 on its own.
        assert r.state is TesState.FINAL
        # unknown contextual axes renormalize PROVISIONAL exactly like any
        # other established ER rung
        r_partial = compute_tes(TesInputs(
            intrinsic=intr(D("9.0")), exploit_reality=er,
            criticality=crit(CriticalityLabel.CRITICAL),
        ))
        assert r_partial.state is TesState.PROVISIONAL

    def test_strict_highest_attestation_never_beats_higher_rungs(self):
        # KEV listed (ER 8) beats the attestation
        er = ExploitRealityInput(
            attested_no_exploitation=_att(ExactExposureEvidenceState.FRESH_QUALIFYING),
            kev=KevObservation(KevTernaryState.LISTED, FeedFreshness.FRESH,
                               KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                               feed_health=kev_health()),
        )
        r = compute_tes(full_inputs(er=er))
        er_row = row(r, AxisId.EXPLOIT_REALITY)
        assert er_row.raw_value == D("8")
        assert er_row.selected_rung == "kev_listed"

        # exact-exposure observed exploitation (ER 10) beats the attestation
        er2 = ExploitRealityInput(
            attested_no_exploitation=_att(ExactExposureEvidenceState.FRESH_QUALIFYING),
            exact_exposure_fresh=ExactExposureEvidence(
                ExactExposureEvidenceState.FRESH_QUALIFYING,
                kind=EvidenceKind.OBSERVED_EXPLOITATION, observed_at=NOW,
                source="edr", provenance_class=ProvenanceClass.MACHINE_OBSERVED),
        )
        r2 = compute_tes(full_inputs(er=er2))
        er_row2 = row(r2, AxisId.EXPLOIT_REALITY)
        assert er_row2.raw_value == D("10")
        assert er_row2.selected_rung == "exact_exposure_evidence"

        # EPSS top band (ER 7) beats the attestation
        er3 = ExploitRealityInput(
            attested_no_exploitation=_att(ExactExposureEvidenceState.FRESH_QUALIFYING),
            epss=EpssObservation(D("0.70"), FeedFreshness.FRESH, observed_at=NOW,
                                 feed_health=epss_health()),
        )
        r3 = compute_tes(full_inputs(er=er3))
        er_row3 = row(r3, AxisId.EXPLOIT_REALITY)
        assert er_row3.raw_value == D("7")
        assert er_row3.selected_rung.startswith("epss_band")

        # the bottom EPSS+KEV band also establishes ER 1: the attestation
        # (same value) never BEATS an already-established rung
        er4 = ExploitRealityInput(
            attested_no_exploitation=_att(ExactExposureEvidenceState.FRESH_QUALIFYING),
            epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                                 feed_health=epss_health()),
            kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                               observed_at=NOW, feed_health=kev_health()),
        )
        r4 = compute_tes(full_inputs(er=er4))
        er_row4 = row(r4, AxisId.EXPLOIT_REALITY)
        assert er_row4.raw_value == D("1")
        assert er_row4.selected_rung == "no_known_evidence"

    def test_stale_attestation_establishes_nothing_and_stays_provisional(self):
        er = ExploitRealityInput(attested_no_exploitation=_att(
            ExactExposureEvidenceState.STALE))
        r = compute_tes(full_inputs(er=er))
        er_row = row(r, AxisId.EXPLOIT_REALITY)
        assert er_row.raw_value is None
        assert r.state is TesState.PROVISIONAL
        assert er_row.attestation_state is ExactExposureEvidenceState.STALE
        assert er_row.unresolved_higher == ((
            "attested_no_exploitation(stale)",
            "the approved attestation is past its 180-day window; an "
            "unapproved assertion never establishes a rung",
        ),)

    @pytest.mark.parametrize("mangle", ["kind", "observed_at", "source", "provenance"])
    def test_unqualified_fresh_attestation_raises_tes_input_error(self, mangle):
        att = _att(ExactExposureEvidenceState.FRESH_QUALIFYING)
        # bypass the frozen-construction guard exactly like the
        # defense-in-depth cases above: the selection re-check must refuse
        object.__setattr__(att, mangle if mangle != "provenance" else "provenance_class",
                           None if mangle != "source" else "")
        with pytest.raises(TesInputError, match="unqualified"):
            compute_tes(full_inputs(er=ExploitRealityInput(
                attested_no_exploitation=att)))

    def test_cve_path_with_attestation_none_is_bit_identical(self):
        """Passing attested_no_exploitation=None explicitly is field-for-field
        identical to omitting it (the frozen default) — the CVE-path
        composition is bit-unchanged by the P0-08 slot."""
        er_omitted = bottom_er()
        er_explicit = ExploitRealityInput(
            epss=EpssObservation(D("0.001"), FeedFreshness.FRESH, observed_at=NOW,
                                 feed_health=epss_health()),
            kev=KevObservation(KevTernaryState.NOT_LISTED, FeedFreshness.FRESH,
                               KevRansomwareFlag.NOT_KNOWN, observed_at=NOW,
                               feed_health=kev_health()),
            attested_no_exploitation=None,
        )
        assert er_omitted == er_explicit
        baseline = compute_tes(full_inputs(er=er_omitted))
        explicit = compute_tes(full_inputs(er=er_explicit))
        assert baseline == explicit
        # and the documented bottom-rung baseline is untouched
        assert row(baseline, AxisId.EXPLOIT_REALITY).selected_rung \
            == "no_known_evidence"
        assert row(baseline, AxisId.EXPLOIT_REALITY).raw_value == D("1")
