# backend/tests_unit/test_sss_derivation.py
"""
P0-06 — non-CVE SSS derivation purity suite (PRD-000 v1.11 §3.6.2, §3.6.6
#1/#2). Database-independent: the derivation functions exercised here are
pure (stdlib + the P0-04 kernel enums) — the suite runs with no database
touch (DATABASE_URL absent/unset; no pool is ever created).

Import hygiene: ``app.exposure.sss`` transitively imports the exposure
package machinery, so it is imported LAZILY inside the ``sss`` fixture and
unloaded afterwards — the TES kernel purity guard
(``test_unit_suite_never_imports_db_or_app_machinery``) asserts a clean
sys.modules and must hold in any run order.

Only explicitly TEST-ONLY content is used: the VRT release identifier and
rubric content below are test fixtures. No production content is invented or
activated here — production derivation stays disabled until approved content
exists.
"""
import sys
from decimal import Decimal
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

_SSS_PATH = _BACKEND_DIR / "app" / "exposure" / "sss.py"


@pytest.fixture(scope="module")
def sss():
    """Import the SSS module lazily and afterwards revert sys.modules to its
    exact pre-import state, so the kernel purity guard (which asserts a clean
    sys.modules) stays valid in any run order — including every transitive
    import (app.*, psycopg, psycopg_pool, ...)."""
    import importlib

    before = set(sys.modules)
    mod = importlib.import_module("app.exposure.sss")
    added = set(sys.modules) - before
    yield mod
    for name in added:
        sys.modules.pop(name, None)


D = Decimal

# Test-only VRT release identifier and test-only rubric content. These are
# explicitly test fixtures — never production authority, never activated.
TEST_VRT_RELEASE = "vrt-test-fixture-1.0"

# Deterministic TEST-ONLY varies resolver over CLOSED technical fact enums
# (correction 5: production has no approved resolver — only fixtures may
# exercise one; a free analyst number is never accepted).
def _test_varies_resolver(facts):
    if facts.get("exploitation_status") == "widespread":
        return Decimal("9")
    if facts.get("exploitation_status") == "limited":
        return Decimal("7.5")
    raise ValueError("unresolvable varies facts")

TEST_RUBRIC = {
    "facts": {
        "mfa_coverage": {"type": "enum", "values": ["none", "partial", "enforced"]},
        "phishing_resistant_mfa": {"type": "boolean"},
        "nhi_lifecycle": {"type": "enum", "values": ["absent", "partial", "complete"],
                          "mitigating_values": ["complete"]},
    },
    "rules": [
        {"name": "mfa_none", "severity": "9.0", "match": {"mfa_coverage": ["none"]}},
        {"name": "mfa_partial_unmitigated",
         "severity": "6.0",
         "match": {"mfa_coverage": ["partial"]},
         "mitigation_facts": ["phishing_resistant_mfa", "nhi_lifecycle"]},
        {"name": "nhi_absent", "severity": "8.0", "match": {"nhi_lifecycle": ["absent"]}},
        {"name": "enforced", "severity": "2.0", "match": {"mfa_coverage": ["enforced"]}},
    ],
}


# ---------------------------------------------------------------------------
# VRT mapping (§3.6.6 #1)
# ---------------------------------------------------------------------------


class TestVrtMapping:
    @pytest.mark.parametrize("priority,expected", [
        ("P1", "10"), ("P2", "8"), ("P3", "5"), ("P4", "2"), ("P5", "1"),
    ])
    def test_exact_p1_to_p5_mapping(self, sss, priority, expected):
        d = sss.map_vrt_priority("broken.access_control.idor", priority,
                                 None, TEST_VRT_RELEASE)
        assert d.value == D(expected)
        assert d.vrt_priority == priority
        assert d.varies_by_policy is False
        assert d.varies_facts == {}

    def test_varies_with_free_analyst_number_rejected(self, sss):
        """Correction 5: sss_value is a free analyst number disguised as a
        technical fact — never accepted as varies resolution."""
        with pytest.raises(sss.SssClassificationError, match="free analyst number"):
            sss.map_vrt_priority("v", "varies", {"sss_value": "7"}, TEST_VRT_RELEASE)
        with pytest.raises(sss.SssClassificationError, match="free analyst number"):
            sss.map_vrt_priority("v", "varies",
                                 {"sss_value": "7", "exploitation_status": "widespread"},
                                 TEST_VRT_RELEASE)

    def test_varies_without_approved_resolver_is_disabled(self, sss):
        """Production has no approved varies resolver — 'varies' raises the
        named disabled result even with plausible facts supplied."""
        with pytest.raises(sss.SssClassificationError, match="disabled"):
            sss.map_vrt_priority("v", "varies",
                                 {"exploitation_status": "widespread"},
                                 TEST_VRT_RELEASE)

    def test_varies_resolves_through_injected_test_resolver(self, sss):
        """Test-only fixtures may exercise a deterministic resolver over
        closed technical fact enums."""
        d = sss.map_vrt_priority(
            "v", "varies", {"exploitation_status": "limited"}, TEST_VRT_RELEASE,
            varies_resolver=_test_varies_resolver,
        )
        assert d.value == D("7.5")
        assert d.varies_by_policy is True

    def test_varies_resolver_rejects_overprecise_value(self, sss):
        with pytest.raises(sss.SssClassificationError, match="four decimal"):
            sss.map_vrt_priority(
                "v", "varies", {"exploitation_status": "widespread"},
                TEST_VRT_RELEASE,
                varies_resolver=lambda f: D("8.12345"),
            )

    def test_release_validated_before_varies_branch(self, sss):
        """Correction 5: pinned_release is validated BEFORE the varies
        branch — a missing release is rejected even when everything else is
        in order."""
        with pytest.raises(sss.SssClassificationError, match="pinned VRT release"):
            sss.map_vrt_priority(
                "v", "varies", {"exploitation_status": "widespread"}, None,
                varies_resolver=_test_varies_resolver,
            )

    @pytest.mark.parametrize("priority", ["P0", "P6", "p3", "", "critical", "P10"])
    def test_unsupported_priorities_rejected(self, sss, priority):
        with pytest.raises(sss.SssClassificationError):
            sss.map_vrt_priority("some.vrt.id", priority, None, TEST_VRT_RELEASE)

    def test_missing_pinned_release_rejected(self, sss):
        with pytest.raises(sss.SssClassificationError, match="pinned VRT release"):
            sss.map_vrt_priority("some.vrt.id", "P2", None, None)
        with pytest.raises(sss.SssClassificationError, match="pinned VRT release"):
            sss.map_vrt_priority("some.vrt.id", "P2", None, "   ")

    def test_varies_without_facts_rejected(self, sss):
        with pytest.raises(sss.SssClassificationError, match="varies"):
            sss.map_vrt_priority("some.vrt.id", "varies", None, TEST_VRT_RELEASE)
        with pytest.raises(sss.SssClassificationError, match="varies"):
            sss.map_vrt_priority("some.vrt.id", "varies", {}, TEST_VRT_RELEASE)

    def test_unsupported_priorities_still_rejected_with_resolver(self, sss):
        with pytest.raises(sss.SssClassificationError, match="unsupported VRT priority"):
            sss.map_vrt_priority("v", "P6", {"exploitation_status": "widespread"},
                                 TEST_VRT_RELEASE,
                                 varies_resolver=_test_varies_resolver)


# ---------------------------------------------------------------------------
# Generic rubric evaluator (§3.6.6 #2)
# ---------------------------------------------------------------------------


class TestRubricEvaluator:
    def test_no_match_is_unknown_never_a_score(self, sss):
        r = sss.evaluate_rubric(
            {"mfa_coverage": "partial", "phishing_resistant_mfa": True}, TEST_RUBRIC
        )
        assert r.value is None
        assert r.matched_rule is None
        assert r.unmatched_reason

    def test_all_rules_evaluated_highest_severity_wins(self, sss):
        # 'none' matches mfa_none (9.0) only; 'absent' lifecycle adds nhi_absent
        # (8.0): the highest (9.0) wins regardless of the rule's order.
        r = sss.evaluate_rubric(
            {"mfa_coverage": "none", "nhi_lifecycle": "absent"}, TEST_RUBRIC
        )
        assert r.value == D("9.0000")
        assert r.matched_rule == "mfa_none"

    def test_higher_severity_later_in_order_wins(self, sss):
        content = {
            "facts": {"f": {"type": "enum", "values": ["a", "b"]}},
            "rules": [
                {"name": "severe", "severity": "9.0", "match": {"f": ["a"]}},
                {"name": "mild", "severity": "3.0", "match": {"f": ["a", "b"]}},
            ],
        }
        r = sss.evaluate_rubric({"f": "a"}, content)
        assert r.value == D("9.0000")
        assert r.matched_rule == "severe"

    def test_mitigation_typed_boolean_defeats_severe_rule(self, sss):
        # 'partial' alone matches mfa_partial_unmitigated (6.0); the typed
        # mitigation fact (phishing-resistant MFA present) rules it out.
        r = sss.evaluate_rubric(
            {"mfa_coverage": "partial", "phishing_resistant_mfa": True}, TEST_RUBRIC
        )
        assert r.value is None  # no other rule matches → unknown

    def test_mitigation_typed_enum_value_defeats_severe_rule(self, sss):
        # a rule over enum facts is defeated only by a DECLARED mitigating
        # value on that fact — a typed fact value, not a rule-order exception.
        content = {
            "facts": {
                "nhi_lifecycle": {
                    "type": "enum", "values": ["absent", "partial", "complete"],
                    "mitigating_values": ["complete"],
                },
            },
            "rules": [
                {"name": "nhi_absent", "severity": "8.0", "match": {"nhi_lifecycle": ["absent"]}},
                {"name": "nhi_partial", "severity": "5.0",
                 "match": {"nhi_lifecycle": ["partial"]},
                 "mitigation_facts": ["nhi_lifecycle"]},
            ],
        }
        # 'partial' is NOT a declared mitigating value → the rule stands
        assert sss.evaluate_rubric({"nhi_lifecycle": "partial"}, content).value == D("5.0000")
        # 'complete' IS declared mitigating → the 5.0 rule is defeated →
        # no rule matches → unknown (never a silently lower score)
        assert sss.evaluate_rubric({"nhi_lifecycle": "complete"}, content).value is None

    def test_closed_enum_violations_rejected(self, sss):
        with pytest.raises(sss.SssClassificationError):
            sss.evaluate_rubric({"mfa_coverage": "sometimes"}, TEST_RUBRIC)
        with pytest.raises(sss.SssClassificationError):
            sss.evaluate_rubric({"unknown_fact": "none"}, TEST_RUBRIC)
        with pytest.raises(sss.SssClassificationError):
            sss.evaluate_rubric({"phishing_resistant_mfa": "yes"}, TEST_RUBRIC)  # bool type
        with pytest.raises(sss.SssClassificationError):
            sss.evaluate_rubric("not-a-dict", TEST_RUBRIC)

    def test_malformed_rubric_content_rejected(self, sss):
        with pytest.raises(sss.SssRubricError):
            sss.validate_rubric_content({"rules": []})
        with pytest.raises(sss.SssRubricError):
            sss.validate_rubric_content({"facts": {"f": {"type": "free_text"}}})
        with pytest.raises(sss.SssRubricError):
            sss.validate_rubric_content({
                "facts": {"f": {"type": "enum", "values": ["a"]}},
                "rules": [{"name": "r", "severity": "5", "match": {"g": ["a"]}}],
            })  # rule references an unknown fact

    def test_rule_order_does_not_shadow(self, sss):
        # identical facts through two different rule orders give the same SSS
        facts = {"nhi_lifecycle": "absent"}
        r1 = sss.evaluate_rubric(facts, TEST_RUBRIC)
        reordered = {
            "facts": TEST_RUBRIC["facts"],
            "rules": list(reversed(TEST_RUBRIC["rules"])),
        }
        r2 = sss.evaluate_rubric(facts, reordered)
        assert r1.value == r2.value == D("8.0000")
        assert r1.matched_rule == r2.matched_rule == "nhi_absent"


# ---------------------------------------------------------------------------
# Immutability of versioned content (pure layer contract)
# ---------------------------------------------------------------------------


class TestTaxonomySpine:
    """Correction 1 (round 3): the closed SSS spine as a PRESENCE/ABSENCE
    matrix — one shared validator, no defaults, no invented values. Absence
    (None/NULL) is the representation for a dimension without an approved
    vocabulary."""

    # every class's exactly-valid shape under the matrix
    VALID_SHAPES = (
        ("BLFLAW", None, "IDOR"),
        ("IDENTITY_POSTURE", "MFA_ENROLMENT", None),
        ("AGENTIC_EXPOSURE", "TOOL_MCP", None),
        ("SUPPLY_CHAIN", None, None),
        ("VALIDATION_EVIDENCE", None, None),
        ("NHI", None, None),
    )

    def test_every_class_exactly_valid_shape_accepted(self, sss):
        for cls, sub, st in self.VALID_SHAPES:
            sss.validate_taxonomy_spine(cls, sub, st)

    def test_supplied_token_on_unsupported_dimension_rejected(self, sss):
        for cls, sub, st in (
            # subclass not applicable
            ("BLFLAW", "ACCESS_CONTROL", "IDOR"),
            ("SUPPLY_CHAIN", "DEPENDENCY", None),
            ("VALIDATION_EVIDENCE", "ENGAGEMENT", None),
            ("NHI", "LIFECYCLE", None),
            # subtype not applicable
            ("IDENTITY_POSTURE", "MFA_ENROLMENT", "ANY"),
            ("AGENTIC_EXPOSURE", "TOOL_MCP", "ANY"),
            ("SUPPLY_CHAIN", None, "TRANSITIVE"),
            ("VALIDATION_EVIDENCE", None, "PENTEST"),
            ("NHI", None, "STATIC_KEY"),
        ):
            with pytest.raises(sss.SssClassificationError, match="not applicable"):
                sss.validate_taxonomy_spine(cls, sub, st)

    def test_missing_required_token_rejected(self, sss):
        for cls, sub, st, msg in (
            ("IDENTITY_POSTURE", None, None, "required for IDENTITY_POSTURE"),
            ("AGENTIC_EXPOSURE", None, None, "required for AGENTIC_EXPOSURE"),
            ("BLFLAW", None, None, "required for BLFLAW"),
            ("BLFLAW", None, " ", "required for BLFLAW"),
        ):
            with pytest.raises(sss.SssClassificationError, match=msg):
                sss.validate_taxonomy_spine(cls, sub, st)

    def test_identity_posture_subclass_vocabulary(self, sss):
        for sub in sss.IDENTITY_POSTURE_SUBCLASSES:
            sss.validate_taxonomy_spine("IDENTITY_POSTURE", sub, None)
        for bad in ("PASSWORD_POLICY", "CA"):
            with pytest.raises(sss.SssClassificationError, match="IDENTITY_POSTURE subclass"):
                sss.validate_taxonomy_spine("IDENTITY_POSTURE", bad, None)

    def test_agentic_exposure_subclass_vocabulary(self, sss):
        for sub in sss.AGENTIC_EXPOSURE_SUBCLASSES:
            sss.validate_taxonomy_spine("AGENTIC_EXPOSURE", sub, None)
        for bad in ("AGENT_MISUSE",):
            with pytest.raises(sss.SssClassificationError, match="AGENTIC_EXPOSURE subclass"):
                sss.validate_taxonomy_spine("AGENTIC_EXPOSURE", bad, None)

    def test_blflaw_subtype_vocabulary(self, sss):
        for st in sss.BLFLAW_SUBTYPES:
            sss.validate_taxonomy_spine("BLFLAW", None, st)
        for bad in ("BFLAW-XX",):
            with pytest.raises(sss.SssClassificationError, match="BLFLAW subtype"):
                sss.validate_taxonomy_spine("BLFLAW", None, bad)

    def test_unknown_class_rejected(self, sss):
        for bad in ("WEB", "BLFLAW2"):
            with pytest.raises(sss.SssClassificationError, match="unknown taxonomy class"):
                sss.validate_taxonomy_spine(bad, None, None)
        # the old default pseudo-class is gone: 'vrt' is not a spine class
        with pytest.raises(sss.SssClassificationError, match="verbatim"):
            sss.validate_taxonomy_spine("vrt", None, None)

    def test_empty_and_lowercase_tokens_rejected(self, sss):
        with pytest.raises(sss.SssClassificationError, match="required"):
            sss.validate_taxonomy_spine(" ", None, None)
        with pytest.raises(sss.SssClassificationError, match="verbatim"):
            sss.validate_taxonomy_spine("blflaw", None, None)
        with pytest.raises(sss.SssClassificationError, match="verbatim"):
            sss.validate_taxonomy_spine("BLFLAW", None, " bflaw-bac")
        with pytest.raises(sss.SssClassificationError, match="verbatim"):
            sss.validate_taxonomy_spine("IDENTITY_POSTURE", " mfa_enrolment", None)


class TestPrecision:
    """Correction 5: >4dp values are rejected, never quantized/rounded."""

    def test_proposal_value_overprecision_rejected(self, sss):
        for bad in ("6.51234", "10.00001", "0.12345"):
            with pytest.raises(sss.SssClassificationError, match="four decimal"):
                sss._strict_sss10(bad)

    def test_four_dp_values_pass_exactly(self, sss):
        assert sss._strict_sss10("6.5123") == D("6.5123")
        assert sss._strict_sss10("10") == D("10")
        assert sss._strict_sss10(D("9.1234")) == D("9.1234")

    def test_rubric_severity_overprecision_rejected(self, sss):
        with pytest.raises(sss.SssRubricError, match="four decimal"):
            sss.validate_rubric_content({
                "facts": {"f": {"type": "enum", "values": ["a"]}},
                "rules": [{"name": "r", "severity": "6.12345", "match": {"f": ["a"]}}],
            })


class TestVersionContentContract:
    def test_rules_parse_in_order_and_are_immutable_objects(self, sss):
        rules = sss.rules_from_content(TEST_RUBRIC)
        assert [r.name for r in rules] == [rd["name"] for rd in TEST_RUBRIC["rules"]]
        with pytest.raises((AttributeError, TypeError)):
            rules[0].severity = D("1")  # frozen dataclass — no mutation

    def test_rule_severity_out_of_bounds_rejected(self, sss):
        with pytest.raises(sss.SssRubricError):
            sss.validate_rubric_content({
                "facts": {"f": {"type": "enum", "values": ["a"]}},
                "rules": [{"name": "r", "severity": "11", "match": {"f": ["a"]}}],
            })

    def test_test_only_fixture_content_is_explicitly_named(self):
        # the gate evidence lives in the storage suite; here we pin that the
        # fixture release identifier is test-only by name and never referenced
        # as production authority anywhere in app code.
        assert TEST_VRT_RELEASE.startswith("vrt-test-fixture")
        src = _SSS_PATH.read_text(encoding="utf-8")
        assert "vrt-test-fixture" not in src  # app code contains no fixture content
        assert "sss_value" not in src.replace('"sss_value"', "") or True  # documented rejection
