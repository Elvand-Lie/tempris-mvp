# backend/app/exposure/sss.py
"""
P0-06 — NON-CVE SEVERITY FOUNDATION (PRD-000 v1.11 §3.6.1–§3.6.6; §3.4
non-CVE/SSS rows; Appendix C Q11–Q12) — bounded correction round.

Three derivation paths, chosen by finding shape (§3.6.2):

  path 1 — exploit-shaped: Bugcrowd VRT classification + the locked Tempris
           policy mapping P1–P5 → 10/8/5/2/1 (§3.6.6 #1). "Varies" entries
           resolve ONLY from vulnerability-specific technical facts through
           an explicit resolver — never asset criticality, reachability,
           Business Impact, or tenant context, and never a free analyst
           number. VRT release is pinned per derivation and validated on
           every branch, including "varies".
  path 2 — fact/posture-shaped: one deterministic generic rubric evaluator
           over closed-enum facts; highest-severity matching rule wins
           regardless of rule order; mitigations are typed fact values, never
           rule-ordering exceptions; no match ⇒ unknown ⇒ UNSCOREABLE
           (§3.6.6 #2). rubric_version pinned per derivation; versions are
           immutable and forward-only, so historical derivations stay
           reproducible.
  path 3 — manual/unstructured: analyst-proposed SSS stored as a PENDING
           proposal (value, mandatory reason + evidence, proposer from the
           AuthContext). It never scores in this build — §3.6.6 #6
           dual-control approval is reserved (no approve/apply mechanism is
           implemented here).

CLASSIFICATION TAXONOMY (correction 1, round 3): arbitrary strings are replaced by
the inherited closed SSS spine (§3.6.5: V1 sss_contract.py classes/subclasses,
BLFLAW subtypes) as a PRESENCE/ABSENCE matrix. One shared validator — identical
in Python and SQL — enforces: class required and closed (six classes);
subclass required-from-the-closed-list for IDENTITY_POSTURE and
AGENTIC_EXPOSURE and NULL (absent) for every other class; subtype
required-from-the-closed-list for BLFLAW and NULL for every other class.
Absence — not an invented token — is the representation for a dimension
without an approved vocabulary; supplied-but-unsupported and
required-but-missing both reject with distinct named errors. The same
combinations are CHECK-enforced in migration 019.

REVISION FENCING (correction 2): callers cannot supply or omit the finding
revision token. Every publication command captures the tenant-scoped revision
BEFORE the mapping/evaluation, recomputes it, then re-reads and compares it
immediately before publication under the per-finding advisory lock — a stale
attempt raises SssConflictError and publishes nothing.

PRECISION (correction 5): values with more than four decimal places are
REJECTED, never silently quantized/rounded — manual proposals, rubric rule
severities, and (test-only) varies resolutions alike.

PREREQUISITE GATE (ticket): the frozen PRD names no pinned immutable VRT
release identifier and no approved versioned IDENTITY_POSTURE fact schema +
production rule table. Production derivation is therefore DISABLED until
approved content exists: this module refuses production derivation with a
named, structured error, and nothing activates fixture content. Storage
accepts operator-approved version rows (migration 019) but no application
code path creates them.

Output compatibility (ticket item 7): derived values are returned in P0-04's
``IntrinsicInput`` shape. TES math is NOT forked and ``compute_tes`` is NEVER
called here.

Purity: the derivation functions (VRT mapping, rubric evaluation, taxonomy
validation) are pure — stdlib only, no I/O, no database, no application
imports, no clock reads. Storage lives in the explicit service functions.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.exceptions import ExposureDomainError
from app.exposure.service import _advisory_xact_lock
from app.exposure.tes_kernel import FreshnessState, IntrinsicInput, ProvenanceClass

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SssProductionDisabledError(ExposureDomainError):
    """Production VRT/fact-rubric derivation was attempted while no approved
    (non-test-only) version exists for the pinned content. Named, fail-closed:
    callers surface it as SSS unavailable ⇒ UNSCOREABLE, never as a score."""


class SssClassificationError(ExposureDomainError, ValueError):
    """A classification or its inputs failed closed-enum/typed validation."""


class SssNotFoundError(ExposureDomainError):
    """The referenced finding/classification/derivation does not exist in the
    requesting tenant (same not-found for unknown and cross-tenant ids)."""


class SssConflictError(ExposureDomainError):
    """A concurrency attempt lost (stale revision, superseded current)."""


class SssNotExploitShapedError(ExposureDomainError):
    """The VRT derivation path was requested for a finding whose latest
    classification is not exploit-shaped (only BLFLAW findings take the
    VRT path; other classes take the rubric/manual paths)."""


class SssRubricError(ExposureDomainError, ValueError):
    """A rubric definition is malformed (never silently skipped)."""


# ---------------------------------------------------------------------------
# Closed taxonomy spine (§3.6.5 inherited vocabulary; correction 1)
# ---------------------------------------------------------------------------

TAXONOMY_CLASSES: tuple[str, ...] = (
    "BLFLAW",
    "SUPPLY_CHAIN",
    "IDENTITY_POSTURE",
    "AGENTIC_EXPOSURE",
    "VALIDATION_EVIDENCE",
    "NHI",
)

IDENTITY_POSTURE_SUBCLASSES: tuple[str, ...] = (
    "AUTH_FLOW_ABUSE",
    "MFA_ENROLMENT",
    "SESSION_TOKEN",
    "MACHINE_KEY",
    "CONDITIONAL_ACCESS",
)

AGENTIC_EXPOSURE_SUBCLASSES: tuple[str, ...] = (
    "ADVERSARY_AI",
    "AUTONOMOUS_PRINCIPAL",
    "INJECTION_PATH",
    "MEMORY_RAG",
    "TOOL_MCP",
    "TRAINING_SUPPLY",
)

BLFLAW_SUBTYPES: tuple[str, ...] = (
    "IDOR",
    "BFLAW-BAC",
    "BFLAW-HPE",
    "BFLAW-BFB",
    "BFLAW-MSC",
)


def validate_taxonomy_spine(
    taxonomy_class: str,
    taxonomy_subclass: Optional[str],
    taxonomy_subtype: Optional[str],
) -> None:
    """One shared validator over the closed SSS spine as a presence/absence
    matrix (§3.6.5 inherited semantics):

    * class — required, closed six, verbatim uppercase token;
    * subclass — required from the closed list for IDENTITY_POSTURE and
      AGENTIC_EXPOSURE; must be NULL (absent) for BLFLAW, SUPPLY_CHAIN,
      VALIDATION_EVIDENCE, and NHI;
    * subtype — required from the closed list for BLFLAW; must be NULL for
      every other class.

    Absence — not an invented token — is the representation for a dimension
    without an approved vocabulary. Supplied-but-unsupported ("not
    applicable") and required-but-missing ("required for") reject with
distinct named errors. Raises SssClassificationError on any violation."""
    if not isinstance(taxonomy_class, str) or not taxonomy_class.strip():
        raise SssClassificationError(
            "taxonomy_class is required — the spine has no defaults"
        )
    if taxonomy_class != taxonomy_class.strip() or taxonomy_class.upper() != taxonomy_class:
        raise SssClassificationError(
            f"taxonomy_class {taxonomy_class!r} must be a verbatim spine token "
            "(uppercase, unpadded)"
        )
    if taxonomy_class not in TAXONOMY_CLASSES:
        raise SssClassificationError(
            f"unknown taxonomy class {taxonomy_class!r} — closed spine: "
            f"{list(TAXONOMY_CLASSES)}"
        )

    subclass_required = taxonomy_class in ("IDENTITY_POSTURE", "AGENTIC_EXPOSURE")
    subtype_required = taxonomy_class == "BLFLAW"

    if not subclass_required:
        if taxonomy_subclass is not None:
            raise SssClassificationError(
                f"taxonomy_subclass {taxonomy_subclass!r} is not applicable to "
                f"{taxonomy_class} — the {taxonomy_class} spine has no approved "
                "subclass vocabulary; absence (NULL) is the representation"
            )
    else:
        if not isinstance(taxonomy_subclass, str) or not taxonomy_subclass.strip():
            raise SssClassificationError(
                f"taxonomy_subclass is required for {taxonomy_class} — the spine "
                "has no defaults"
            )
        if (taxonomy_subclass != taxonomy_subclass.strip()
                or taxonomy_subclass.upper() != taxonomy_subclass):
            raise SssClassificationError(
                f"taxonomy_subclass {taxonomy_subclass!r} must be a verbatim spine "
                "token (uppercase, unpadded)"
            )
        if taxonomy_class == "IDENTITY_POSTURE" and (
            taxonomy_subclass not in IDENTITY_POSTURE_SUBCLASSES
        ):
            raise SssClassificationError(
                f"invalid IDENTITY_POSTURE subclass {taxonomy_subclass!r} — "
                f"closed vocabulary: {list(IDENTITY_POSTURE_SUBCLASSES)}"
            )
        if taxonomy_class == "AGENTIC_EXPOSURE" and (
            taxonomy_subclass not in AGENTIC_EXPOSURE_SUBCLASSES
        ):
            raise SssClassificationError(
                f"invalid AGENTIC_EXPOSURE subclass {taxonomy_subclass!r} — "
                f"closed vocabulary: {list(AGENTIC_EXPOSURE_SUBCLASSES)}"
            )

    if not subtype_required:
        if taxonomy_subtype is not None:
            raise SssClassificationError(
                f"taxonomy_subtype {taxonomy_subtype!r} is not applicable to "
                f"{taxonomy_class} — the {taxonomy_class} spine has no approved "
                "subtype vocabulary; absence (NULL) is the representation"
            )
    else:
        if not isinstance(taxonomy_subtype, str) or not taxonomy_subtype.strip():
            raise SssClassificationError(
                "taxonomy_subtype is required for BLFLAW — the spine has no defaults"
            )
        if taxonomy_subtype != taxonomy_subtype.strip() or taxonomy_subtype.upper() != taxonomy_subtype:
            raise SssClassificationError(
                f"taxonomy_subtype {taxonomy_subtype!r} must be a verbatim spine "
                "token (uppercase, unpadded)"
            )
        if taxonomy_subtype not in BLFLAW_SUBTYPES:
            raise SssClassificationError(
                f"invalid BLFLAW subtype {taxonomy_subtype!r} — closed vocabulary: "
                f"{list(BLFLAW_SUBTYPES)}"
            )


# ---------------------------------------------------------------------------
# Precision (correction 5): four decimal places is the documented grain —
# excess precision is REJECTED, never silently quantized/rounded.
# ---------------------------------------------------------------------------

_QUANT = Decimal("0.0001")


def _strict_sss10(value) -> Decimal:
    """Parse a 0–10 Decimal and reject any value with more than four decimal
    places (no quantize/round: a silently rounded severity would be a number
    nobody entered)."""
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, str)):
        raise SssClassificationError("value must be a Decimal, int, or numeric string")
    try:
        d = Decimal(value) if not isinstance(value, Decimal) else value
    except (InvalidOperation, ValueError):
        raise SssClassificationError("value is not a valid number")
    if not d.is_finite():
        raise SssClassificationError("value must be finite")
    if d != d.quantize(_QUANT):
        raise SssClassificationError(
            f"value {d} carries more than four decimal places — the documented "
            "grain is four; excess precision is rejected, never rounded"
        )
    if not (Decimal("0") <= d <= Decimal("10")):
        raise SssClassificationError("value is outside 0–10")
    return d


# ---------------------------------------------------------------------------
# Pure VRT mapping (§3.6.6 #1) — machine-checkable against the locked table
# ---------------------------------------------------------------------------

PINNED_VRT_RELEASE = "bugcrowd-vrt-1.19.1"  # approved seed row: migration 046 (official Bugcrowd VRT v1.19.1, vendored below)

# Vendored official Bugcrowd VRT taxonomy, release v1.19.1 (fetched once from
# github.com/bugcrowd/vulnerability-rating-taxonomy at tag v1.19.1). This file
# is the release content in code — version-matched to PINNED_VRT_RELEASE —
# because migration 019's 'vrt_release' kind admits no stored content. Loaded
# with stdlib json only; never fetched at runtime.
_VRT_DATA_PATH = Path(__file__).resolve().parent / "data" / "vrt_bugcrowd_v1_19_1.json"

_VRT_LEAF_PRIORITY_CACHE: Optional[dict[str, str]] = None


def _vrt_leaf_priorities() -> dict[str, str]:
    """Dotted VRT leaf id → policy priority ('P1'–'P5', or 'varies') for the
    pinned vendored release. A leaf is a node without children; its JSON
    priority is an int 1–5, None, or the literal 'varies' — None and
    'varies' both mean the policy 'varies' resolution."""
    global _VRT_LEAF_PRIORITY_CACHE
    if _VRT_LEAF_PRIORITY_CACHE is None:
        with open(_VRT_DATA_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)

        def _walk(nodes, path):
            for node in nodes:
                dotted = ".".join((*path, node["id"]))
                children = node.get("children") or []
                if children:
                    yield from _walk(children, (*path, node["id"]))
                else:
                    priority = node.get("priority")
                    if priority in (None, "varies"):
                        resolved = "varies"
                    elif isinstance(priority, int) and 1 <= priority <= 5:
                        resolved = f"P{priority}"
                    else:
                        raise SssClassificationError(
                            f"vendored VRT release data is malformed at leaf "
                            f"{dotted!r}: unsupported priority {priority!r}"
                        )
                    yield dotted, resolved

        _VRT_LEAF_PRIORITY_CACHE = dict(_walk(doc["content"], ()))
    return _VRT_LEAF_PRIORITY_CACHE


def resolve_vrt_leaf_priority(vrt_id: str) -> str:
    """Server-side authority: the pinned release's taxonomy decides the
    priority for a VRT leaf id. A caller-supplied priority claim is never
    authority — unknown or malformed leaf ids fail closed here."""
    key = vrt_id.strip() if isinstance(vrt_id, str) else ""
    if not key:
        raise SssClassificationError("VRT id is required for the vrt path")
    table = _vrt_leaf_priorities()
    if key not in table:
        raise SssClassificationError(
            f"unknown VRT leaf id {vrt_id!r} for the pinned release "
            f"{PINNED_VRT_RELEASE} — the taxonomy decides the priority, "
            "never the caller"
        )
    return table[key]


VRT_PRIORITY_TO_SSS: dict[str, Decimal] = {
    "P1": Decimal("10"),
    "P2": Decimal("8"),
    "P3": Decimal("5"),
    "P4": Decimal("2"),
    "P5": Decimal("1"),
}


@dataclass(frozen=True)
class VrtDerivation:
    """Pure result of the VRT mapping. Carries everything the derivation
    history row needs except tenant/finding identity (service concern)."""

    value: Decimal
    vrt_id: str
    vrt_priority: str
    varies_facts: dict
    varies_by_policy: bool


def _require_pinned_release(pinned_release) -> str:
    """The PRD freezes the P1–P5 mapping, not a release: a derivation without
    an explicit non-empty pinned release identifier is rejected on EVERY
    branch, including 'varies' (missing versions never score)."""
    if pinned_release is None or not isinstance(pinned_release, str) \
            or not pinned_release.strip():
        raise SssClassificationError(
            "VRT derivation requires a pinned VRT release identifier "
            "(the PRD freezes the P1–P5 mapping, not a release)"
        )
    return pinned_release.strip()


def map_vrt_priority(
    vrt_id: str,
    vrt_priority: str,
    varies_facts: Optional[dict] = None,
    pinned_release: Optional[str] = None,
    *,
    varies_resolver: Optional[Callable[[dict], Decimal]] = None,
) -> VrtDerivation:
    """Locked mapping: P1–P5 → 10/8/5/2/1 (§3.6.6 #1).

    * ``pinned_release`` is validated FIRST — on every branch, including
      'varies';
    * unsupported priorities are rejected (a VRT failure is no SSS, not a low
      score);
    * ``varies`` resolves ONLY through the supplied ``varies_resolver`` over
      vulnerability-specific technical facts — never asset criticality,
      reachability, Business Impact, or tenant context, and never a free
      analyst number (``sss_value`` is explicitly rejected: that is a score
      disguised as a fact). Without an approved, versioned varies resolver,
      'varies' raises — production derivation stays disabled until one
      exists; test-only fixtures inject a deterministic closed-enum resolver.
    """
    release = _require_pinned_release(pinned_release)  # before every branch
    if not isinstance(vrt_id, str) or not vrt_id.strip():
        raise SssClassificationError("VRT id is required for the vrt path")
    priority = (vrt_priority or "").strip()
    if not isinstance(varies_facts, (dict, type(None))):
        raise SssClassificationError("varies facts must be a structured object")
    facts = dict(varies_facts or {})

    if priority == "varies":
        if not facts:
            raise SssClassificationError(
                'VRT priority "varies" requires vulnerability-specific '
                "technical facts to resolve"
            )
        if "sss_value" in facts:
            raise SssClassificationError(
                'varies fact "sss_value" is a free analyst number, not a '
                "technical fact — varies resolves only through an approved, "
                "versioned resolver over closed technical fact enums"
            )
        if varies_resolver is None:
            raise SssClassificationError(
                'no varies resolver is approved — production "varies" '
                "derivation is disabled until an approved, versioned resolver "
                "over closed technical fact enums exists"
            )
        try:
            value = varies_resolver(facts)
        except SssClassificationError:
            raise
        except Exception as exc:
            raise SssClassificationError(
                f"varies resolver failed closed-enum resolution: {exc}"
            )
        value = _strict_sss10(value)
        return VrtDerivation(
            value=value, vrt_id=vrt_id.strip(), vrt_priority="varies",
            varies_facts=facts, varies_by_policy=True,
        )

    if priority not in VRT_PRIORITY_TO_SSS:
        raise SssClassificationError(
            f"unsupported VRT priority {priority!r} — supported: "
            f"{sorted(VRT_PRIORITY_TO_SSS)} (plus the policy 'varies' resolution)"
        )
    return VrtDerivation(
        value=_strict_sss10(VRT_PRIORITY_TO_SSS[priority]),
        vrt_id=vrt_id.strip(),
        vrt_priority=priority,
        varies_facts={},
        varies_by_policy=False,
    )


# ---------------------------------------------------------------------------
# Pure generic rubric evaluator (§3.6.6 #2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RubricRule:
    """One ordered rubric rule over closed-enum facts.

    match: {fact_name: {allowed enum values...}} — a rule matches when every
    named fact is present and its (closed-enum) value is in the allowed set.
    mitigation_facts: fact names whose presence/typed value rules the rule
    OUT (mitigations are typed fact values, never rule-ordering exceptions —
    "CA gap but phishing-resistant MFA" is a fact value that fails the severe
    rule, not a downgrade step).
    """

    name: str
    severity: Decimal            # 0–10, at most four decimal places
    match: dict[str, set]        # fact → allowed closed-enum values
    mitigation_facts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise SssRubricError("rubric rule name is required")
        sev = self.severity
        if isinstance(sev, bool) or not isinstance(sev, Decimal):
            raise SssRubricError(f"rule {self.name!r}: severity must be a Decimal 0–10")
        if not (Decimal("0") <= sev <= Decimal("10")):
            raise SssRubricError(f"rule {self.name!r}: severity outside 0–10")
        if not self.match:
            raise SssRubricError(f"rule {self.name!r}: match is required")
        for fact, allowed in self.match.items():
            if not fact or not allowed:
                raise SssRubricError(
                    f"rule {self.name!r}: fact {fact!r} needs allowed enum values"
                )


def validate_rubric_content(content: dict) -> None:
    """Structural validation of stored rubric content: closed-enum facts with
    typed metadata, mitigation facts typed as boolean or enum, every rule
    well-formed. Raises SssRubricError on any defect (fail-closed authoring)."""
    if not isinstance(content, dict):
        raise SssRubricError("rubric content must be an object")
    facts = content.get("facts")
    if not isinstance(facts, dict) or not facts:
        raise SssRubricError("rubric content requires a non-empty 'facts' object")
    for fact, spec in facts.items():
        if not isinstance(spec, dict):
            raise SssRubricError(f"fact {fact!r} spec must be an object")
        ftype = spec.get("type")
        if ftype == "enum":
            if not isinstance(spec.get("values"), (list, set)) or not spec["values"]:
                raise SssRubricError(f"enum fact {fact!r} requires 'values'")
        elif ftype in ("boolean", "numeric"):
            pass
        else:
            raise SssRubricError(f"fact {fact!r}: unsupported type {ftype!r}")
    for rd in content.get("rules", []):
        rule = _rule_from_content(rd)
        for fact in rule.match:
            if fact not in facts:
                raise SssRubricError(f"rule {rule.name!r}: unknown fact {fact!r}")
            if facts[fact].get("type") != "enum":
                raise SssRubricError(
                    f"rule {rule.name!r}: fact {fact!r} must be a closed enum"
                )
        for fact in rule.mitigation_facts:
            if fact not in facts:
                raise SssRubricError(
                    f"rule {rule.name!r}: unknown mitigation fact {fact!r}"
                )
            if facts[fact].get("type") not in ("boolean", "enum"):
                raise SssRubricError(
                    f"rule {rule.name!r}: mitigation fact {fact!r} must be typed "
                    "(boolean or enum) — mitigations are typed fact values"
                )


def _rule_from_content(rd: Any) -> RubricRule:
    if not isinstance(rd, dict):
        raise SssRubricError("rubric rule must be an object")
    try:
        severity = _strict_sss10(Decimal(str(rd["severity"])))
    except SssClassificationError as exc:
        # >4dp severity is a malformed rule (SssClassificationError IS a
        # ValueError, so this clause must precede the generic one)
        raise SssRubricError(str(exc))
    except (KeyError, InvalidOperation, ValueError):
        raise SssRubricError("rubric rule requires numeric 'severity'")
    match = rd.get("match")
    if not isinstance(match, dict):
        raise SssRubricError("rubric rule requires a 'match' object")
    return RubricRule(
        name=str(rd.get("name", "")),
        severity=severity,
        match={k: set(v) for k, v in match.items()},
        mitigation_facts=tuple(rd.get("mitigation_facts", ())),
    )


def rules_from_content(content: dict) -> tuple[RubricRule, ...]:
    """Parse ordered rules from stored content (order preserved for the
    immutability audit; evaluation order-independence is guaranteed by the
    highest-severity-wins selection)."""
    rules = tuple(_rule_from_content(rd) for rd in content.get("rules", []))
    if not rules:
        raise SssRubricError("rubric content requires at least one rule")
    return rules


def _mitigation_defeats(facts: dict, specs: dict, mf: str) -> bool:
    """A typed mitigation fact defeats a rule: boolean facts defeat when
    present (True); enum facts defeat only on a DECLARED mitigating value —
    mitigations are typed fact values, never rule-ordering exceptions."""
    ftype = specs[mf].get("type")
    value = facts.get(mf)
    if ftype == "boolean":
        return value is True
    return value in set(specs[mf].get("mitigating_values", ()))


@dataclass(frozen=True)
class RubricDerivation:
    """Pure result of rubric evaluation. ``value is None`` means no rule
    matched ⇒ SSS unknown ⇒ UNSCOREABLE (fail-closed; the manual path is the
    escape hatch)."""

    value: Optional[Decimal]
    matched_rule: Optional[str]
    matched_severity: Optional[Decimal]
    unmatched_reason: Optional[str]
    considered_rules: int


def evaluate_rubric(facts: dict, content: dict) -> RubricDerivation:
    """One deterministic evaluation: closed-enum facts only, typed mitigation
    facts enforced, ALL rules evaluated, the highest-severity matching rule
    wins regardless of order. Unknown fact names / out-of-enum values are
    validation errors (the fact layer is closed), not silent non-matches."""
    if not isinstance(facts, dict):
        raise SssClassificationError("facts must be a structured object")
    specs = content.get("facts", {})
    for name, value in facts.items():
        if name not in specs:
            raise SssClassificationError(f"unknown fact {name!r} for this rubric")
        ftype = specs[name].get("type")
        if ftype == "enum":
            if not isinstance(value, str) or value not in set(specs[name]["values"]):
                raise SssClassificationError(
                    f"fact {name!r} value {value!r} is outside the closed enum"
                )
        elif ftype == "boolean":
            if not isinstance(value, bool):
                raise SssClassificationError(f"fact {name!r} must be a boolean")
        elif ftype == "numeric":
            if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
                raise SssClassificationError(f"fact {name!r} must be numeric")
        else:
            raise SssClassificationError(f"fact {name!r} has an unsupported type")

    rules = rules_from_content(content)
    best: Optional[RubricRule] = None
    for rule in rules:  # ALL rules evaluated — order can never shadow
        matched = all(
            name in facts and facts[name] in allowed
            for name, allowed in rule.match.items()
        )
        if not matched:
            continue
        # mitigations are typed fact values that rule the severe rule out
        defeated = any(
            _mitigation_defeats(facts, specs, mf)
            for mf in rule.mitigation_facts
        )
        if defeated:
            continue
        if best is None or rule.severity > best.severity:
            best = rule

    if best is None:
        return RubricDerivation(
            value=None, matched_rule=None, matched_severity=None,
            unmatched_reason="no rubric rule matched the supplied facts",
            considered_rules=len(rules),
        )
    return RubricDerivation(
        value=best.severity, matched_rule=best.name,
        matched_severity=best.severity, unmatched_reason=None,
        considered_rules=len(rules),
    )


# ---------------------------------------------------------------------------
# Production gate — derivation is DISABLED until approved content exists
# ---------------------------------------------------------------------------


def _load_version(cur, version_id: str, kind: str) -> dict:
    cur.execute(
        """
        SELECT id, version_id, kind, content, status, test_only
        FROM sss_derivation_versions
        WHERE version_id = %s AND kind = %s;
        """,
        (version_id, kind),
    )
    row = cur.fetchone()
    if row is None:
        raise SssProductionDisabledError(
            f"{kind} version {version_id!r} is not registered — production "
            "derivation is disabled until approved content exists"
        )
    if row["status"] != "approved" or row["test_only"]:
        raise SssProductionDisabledError(
            f"{kind} version {version_id!r} is not approved production content "
            f"(status={row['status']}, test_only={row['test_only']}) — "
            "production derivation stays disabled"
        )
    return row


# ---------------------------------------------------------------------------
# Storage internals — every lookup is tenant-scoped; the finding revision is
# captured and rechecked HERE (correction 2: unavoidable fencing); audit
# commits atomically with publication.
# ---------------------------------------------------------------------------


def _read_finding_revision(cur, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> str:
    """Tenant-scoped finding read: rejects unknown and cross-tenant ids with
    the same not-found error and returns the row's xmin revision token."""
    cur.execute(
        """
        SELECT id, tenant_id, canonical_cve_id, xmin::text AS revision
        FROM findings
        WHERE tenant_id = %s AND id = %s;
        """,
        (str(tenant_id), str(finding_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise SssNotFoundError(f"Finding {finding_id} not found")
    if row["canonical_cve_id"] is not None:
        raise SssClassificationError(
            "findings with a canonical_cve_id never take non-CVE severity "
            "records (no CVE linkage is invented; SSS never creates CVE/CVSS data)"
        )
    return row["revision"]


def _finding_revision(cur, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> str:
    """Legacy-shaped helper kept for internal reads (no CVE gate)."""
    cur.execute(
        """
        SELECT xmin::text AS revision
        FROM findings
        WHERE tenant_id = %s AND id = %s;
        """,
        (str(tenant_id), str(finding_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise SssNotFoundError(f"Finding {finding_id} not found")
    return row["revision"]


def _assert_revision_unchanged(
    cur, tenant_id: uuid.UUID, finding_id: uuid.UUID, expected_xmin: str
) -> str:
    """Re-read the revision under the publication lock; a moved revision means
    the attempt is stale — SssConflictError, nothing published."""
    revision = _finding_revision(cur, tenant_id, finding_id)
    if revision != expected_xmin:
        raise SssConflictError(
            f"finding revision changed during derivation "
            f"(read {expected_xmin}, now {revision}) — attempt is stale "
            "and did not become current"
        )
    return revision


def _current_derivation(cur, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Optional[dict]:
    # §3.6.6 #2: approval paths (manual/override) carry a NULL version_id_ref
    # — the derivation label comes from path + approval id, NOT from a
    # versions JOIN (LEFT JOIN so approval-path rows survive the lookup).
    cur.execute(
        """
        SELECT d.id, d.value, d.path, d.version_id_ref, d.created_at,
               v.version_id AS version_text, d.approval_id
        FROM non_cve_sss_derivations d
        LEFT JOIN sss_derivation_versions v ON v.id = d.version_id_ref
        WHERE d.tenant_id = %s AND d.finding_id = %s AND d.is_current;
        """,
        (str(tenant_id), str(finding_id)),
    )
    return cur.fetchone()


def _publish_derivation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    path: str,
    kind: str,
    version_id: str,
    taxonomy: dict,
    inputs: dict,
    value: Decimal,
    evidence: dict,
    actor_id: str,
    actor_role: str,
    validation_state: str,
    captured_revision: str,
) -> dict:
    """Shared publication (correction 2 fencing):

      1. advisory serialization per (tenant, finding);
      2. re-read the revision captured BEFORE mapping/evaluation and compare —
         a stale attempt raises SssConflictError and publishes nothing;
      3. production gate (approved content only);
      4. classification + derivation rows with composite provenance (the
         derivation binds its classification through the (id, tenant, finding)
         key — cross-object tenant/finding consistency is a DB constraint);
      5. previous current superseded (TRUE→FALSE only, DB-enforced);
      6. audit in the same transaction (failure rolls everything back).
    """
    if not isinstance(evidence, dict) or not evidence:
        raise SssClassificationError("evidence is mandatory for classification/derivation")
    if validation_state not in ("confirmed", "single_source", "disputed"):
        raise SssClassificationError(
            f"invalid validation_state {validation_state!r} — it is server-owned"
        )
    validate_taxonomy_spine(
        taxonomy["taxonomy_class"], taxonomy["taxonomy_subclass"],
        taxonomy["taxonomy_subtype"],
    )

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"sss:{tenant_id}:{finding_id}")
        _assert_revision_unchanged(cur, tenant_id, finding_id, captured_revision)
        vrow = _load_version(cur, version_id, kind)

        cur.execute(
            """
            INSERT INTO non_cve_classifications (
                tenant_id, finding_id, finding_revision_xmin,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, vrt_id, vrt_priority, version_id_ref,
                inputs, evidence, validation_state,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id;
            """,
            (
                str(tenant_id), str(finding_id), captured_revision,
                taxonomy["taxonomy_class"], taxonomy["taxonomy_subclass"],
                taxonomy["taxonomy_subtype"],
                path,
                inputs.get("vrt_id"), inputs.get("vrt_priority"),
                vrow["id"],
                json.dumps(inputs), json.dumps(evidence),
                validation_state, actor_id, actor_role,
            ),
        )
        classification_id = cur.fetchone()["id"]

        cur.execute(
            """
            UPDATE non_cve_sss_derivations
            SET is_current = FALSE
            WHERE tenant_id = %s AND finding_id = %s AND is_current;
            """,
            (str(tenant_id), str(finding_id)),
        )
        cur.execute(
            """
            INSERT INTO non_cve_sss_derivations (
                tenant_id, finding_id, finding_revision_xmin, classification_id,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, version_id_ref, inputs, value, evidence,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id, value, path, created_at;
            """,
            (
                str(tenant_id), str(finding_id), captured_revision, classification_id,
                taxonomy["taxonomy_class"], taxonomy["taxonomy_subclass"],
                taxonomy["taxonomy_subtype"],
                path, vrow["id"], json.dumps(inputs), str(value),
                json.dumps(evidence), actor_id, actor_role,
            ),
        )
        row = cur.fetchone()

        try:
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role=actor_role, event_name=f"sss.derivation_published.{path}",
                asset_id=None,
                details={
                    "finding_id": str(finding_id),
                    "classification_id": str(classification_id),
                    "derivation_id": str(row["id"]),
                    "path": path,
                    "version": version_id,
                    "value": str(row["value"]),
                    "finding_revision_xmin": captured_revision,
                },
            )
        except Exception as exc:
            # audit failure rolls back the whole publication (the caller's
            # transaction aborts) — publication never commits unaudited
            raise SssConflictError(f"audit write failed; derivation rolled back: {exc}")

        return {
            "derivation_id": str(row["id"]),
            "classification_id": str(classification_id),
            "value": row["value"],
            "path": path,
            "version": version_id,
            "finding_revision_xmin": captured_revision,
            "created_at": row["created_at"],
        }


# ---------------------------------------------------------------------------
# Path 1 + 2 publication commands — revision fencing is unavoidable: the
# caller can neither supply nor omit the revision token.
# ---------------------------------------------------------------------------


def derive_sss_vrt(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    vrt_id: str,
    vrt_priority: str,
    varies_facts: Optional[dict],
    pinned_release: str,
    taxonomy_class: str,
    # Optional = not applicable: requiredness per class is enforced ONLY by
    # the shared validator (the presence/absence matrix).
    taxonomy_subclass: Optional[str],
    taxonomy_subtype: Optional[str],
    inputs: Optional[dict] = None,
    evidence: dict,
    actor_id: str,
    actor_role: str,
    validation_state: str = "single_source",
    varies_resolver: Optional[Callable[[dict], Decimal]] = None,
) -> dict:
    """Path 1 (exploit-shaped): publish a VRT classification + SSS derivation
    under the pinned release.

    Fencing order: the tenant-scoped revision is captured FIRST; the pure
    mapping runs; the publication lock is taken and the captured revision is
    rechecked immediately before any write — a finding changed in between
    raises SssConflictError and nothing is published. The caller cannot
    supply or omit the revision token.

    Production gate: the release must exist as an approved (non-test-only)
    sss_derivation_versions row — test fixtures are rejected. 'varies'
    resolves only through the supplied approved resolver (test fixtures may
    inject a deterministic closed-enum one; production passes none until an
    approved, versioned resolver exists).
    """
    with conn.cursor(row_factory=dict_row) as cur:
        captured_revision = _read_finding_revision(cur, tenant_id, finding_id)

    mapping = map_vrt_priority(
        vrt_id, vrt_priority, varies_facts, pinned_release,
        varies_resolver=varies_resolver,
    )
    merged_inputs = {
        "vrt_id": mapping.vrt_id,
        "vrt_priority": mapping.vrt_priority,
        "varies_facts": mapping.varies_facts,
        "varies_by_policy": mapping.varies_by_policy,
        **(inputs or {}),
    }
    return _publish_derivation(
        conn, tenant_id, finding_id,
        path="vrt", kind="vrt_release", version_id=pinned_release.strip(),
        taxonomy={
            "taxonomy_class": taxonomy_class,
            "taxonomy_subclass": taxonomy_subclass,
            "taxonomy_subtype": taxonomy_subtype,
        },
        inputs=merged_inputs,
        value=mapping.value,
        evidence=evidence,
        actor_id=actor_id, actor_role=actor_role,
        validation_state=validation_state,
        captured_revision=captured_revision,
    )


def derive_sss_vrt_for_finding(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    vrt_id: str,
    vrt_priority: Optional[str] = None,
    varies_facts: Optional[dict] = None,
    evidence: dict,
    actor_id: str,
    actor_role: str,
    validation_state: str = "single_source",
    varies_resolver: Optional[Callable[[dict], Decimal]] = None,
) -> dict:
    """Production path-1 entry: derive SSS for a finding from its OWN stored
    classification (intake classifies; this scores — intake is never touched).

    The finding's LATEST classification row supplies the taxonomy; only an
    exploit-shaped BLFLAW spine (subclass absent, subtype present) takes the
    VRT path. ``vrt_id`` is the caller's exact VRT leaf id from the source
    report/platform; the priority is resolved SERVER-SIDE from the pinned
    vendored release taxonomy (``vrt_priority`` is only an optional claim —
    a claim disagreeing with the resolved priority fails closed). The
    release is pinned server-side to PINNED_VRT_RELEASE (approved seed row:
    migration 046) — the client can never choose a version."""
    resolved_priority = resolve_vrt_leaf_priority(vrt_id)
    if vrt_priority is not None and vrt_priority.strip() != resolved_priority:
        raise SssClassificationError(
            f"supplied VRT priority claim {vrt_priority!r} disagrees with "
            f"the pinned release's resolved priority {resolved_priority!r} "
            f"for leaf {vrt_id!r} — the taxonomy decides, fail-closed"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        captured_revision = _read_finding_revision(cur, tenant_id, finding_id)
        cur.execute(
            """
            SELECT taxonomy_class, taxonomy_subclass, taxonomy_subtype
            FROM non_cve_classifications
            WHERE tenant_id = %s AND finding_id = %s
            ORDER BY created_at DESC
            LIMIT 1;
            """,
            (str(tenant_id), str(finding_id)),
        )
        classification = cur.fetchone()
    if classification is None:
        raise SssNotFoundError(
            f"Finding {finding_id} has no classification — classify it "
            "(intake or an explicit classification) before deriving SSS"
        )
    taxonomy_class = classification["taxonomy_class"]
    if taxonomy_class != "BLFLAW":
        raise SssNotExploitShapedError(
            f"only exploit-shaped BLFLAW findings take the VRT derivation "
            f"path; this finding's latest classification is {taxonomy_class!r}"
        )
    if classification["taxonomy_subclass"] is not None:
        raise SssClassificationError(
            f"BLFLAW carries no subclass vocabulary — classification subclass "
            f"{classification['taxonomy_subclass']!r} is off-spine"
        )
    if classification["taxonomy_subtype"] is None:
        raise SssClassificationError(
            "BLFLAW classification is missing its subtype — the spine has "
            "no defaults"
        )
    return derive_sss_vrt(
        conn, tenant_id, finding_id,
        vrt_id=vrt_id.strip(),
        vrt_priority=resolved_priority,
        varies_facts=varies_facts,
        pinned_release=PINNED_VRT_RELEASE,
        taxonomy_class=taxonomy_class,
        taxonomy_subclass=classification["taxonomy_subclass"],
        taxonomy_subtype=classification["taxonomy_subtype"],
        inputs=None,
        evidence=evidence,
        actor_id=actor_id,
        actor_role=actor_role,
        validation_state=validation_state,
        varies_resolver=varies_resolver,
    )


def derive_sss_rubric(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    rubric_version: str,
    taxonomy_class: str,
    # Optional = not applicable: requiredness per class is enforced ONLY by
    # the shared validator (the presence/absence matrix).
    taxonomy_subclass: Optional[str],
    taxonomy_subtype: Optional[str],
    facts: dict,
    evidence: dict,
    actor_id: str,
    actor_role: str,
    validation_state: str = "single_source",
) -> dict:
    """Path 2 (fact/posture-shaped): evaluate the facts through the pinned
    rubric version and publish the derivation, with the same unavoidable
    revision fencing as path 1.

    Production gate: the rubric version must be an approved row; test-only
    content is rejected. No rule matched ⇒ SssClassificationError (unknown ⇒
    UNSCOREABLE — a derivation row is never written for an unknown value)."""
    with conn.cursor(row_factory=dict_row) as cur:
        captured_revision = _read_finding_revision(cur, tenant_id, finding_id)

    with conn.cursor(row_factory=dict_row) as cur:
        vrow = _load_version(cur, rubric_version, "rubric")
        content = vrow["content"]
        validate_rubric_content(content)
        result = evaluate_rubric(facts, content)
        if result.value is None:
            raise SssClassificationError(
                f"no rubric rule matched the supplied facts "
                f"({result.unmatched_reason}) — SSS is unknown ⇒ UNSCOREABLE"
            )
    return _publish_derivation(
        conn, tenant_id, finding_id,
        path="rubric", kind="rubric", version_id=rubric_version,
        taxonomy={
            "taxonomy_class": taxonomy_class,
            "taxonomy_subclass": taxonomy_subclass,
            "taxonomy_subtype": taxonomy_subtype,
        },
        inputs=dict(facts),
        value=result.value,
        evidence=evidence,
        actor_id=actor_id, actor_role=actor_role,
        validation_state=validation_state,
        captured_revision=captured_revision,
    )


# ---------------------------------------------------------------------------
# Manual SSS proposals (path 3) — pending forever; never score (§3.6.6 #6)
# ---------------------------------------------------------------------------


def create_sss_proposal(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    proposed_value,
    reason: str,
    evidence: dict,
    actor_id: str,
    actor_role: str,
    taxonomy: Optional[dict] = None,
) -> dict:
    """Create a pending manual SSS proposal.

    * value bounded to 0–10 at the documented four-dp grain — values with
      more than four decimal places are REJECTED, never rounded;
    * reason and evidence are mandatory (§3.6.2 provenance: who/when/reason/
      evidence);
    * proposer and tenant come from the AuthContext (route-owned) — the client
      cannot supply actor/tenant/validation/approval state (no such fields
      exist on the input);
    * the row is born 'pending' and the DB CHECK admits no other status — it
      can never score in this build;
    * the deterministic derived comparison binds to an EXACT derivation id of
      the same tenant/finding (composite FK; DB-enforced all-or-none shape);
      revision fencing matches the derivation paths (capture → compute →
      lock → recheck → publish).
    """
    value = _strict_sss10(proposed_value)
    if not isinstance(reason, str) or not reason.strip():
        raise SssClassificationError("reason is mandatory for a manual SSS proposal")
    if not isinstance(evidence, dict) or not evidence:
        raise SssClassificationError("evidence is mandatory for a manual SSS proposal")
    taxonomy = taxonomy or {}
    if set(taxonomy) - {"taxonomy_class", "taxonomy_subclass", "taxonomy_subtype"}:
        raise SssClassificationError("taxonomy carries unknown keys")
    if taxonomy:
        if "taxonomy_class" not in taxonomy:
            raise SssClassificationError(
                "taxonomy must be supplied all-or-none (a class is required when "
                "any taxonomy dimension is supplied)"
            )
        # the shared validator enforces the presence/absence matrix: a token
        # on a dimension without an approved vocabulary rejects here; the
        # absent dimensions are stored NULL (absence is the representation)
        validate_taxonomy_spine(
            taxonomy["taxonomy_class"], taxonomy.get("taxonomy_subclass"),
            taxonomy.get("taxonomy_subtype"),
        )

    with conn.cursor(row_factory=dict_row) as cur:
        # Advisory serialization per (tenant, finding) — proposals share the
        # derivation boundary so the revision gate and the derived comparison
        # are stable under concurrency.
        _advisory_xact_lock(cur, f"sss:{tenant_id}:{finding_id}")
        captured_revision = _read_finding_revision(cur, tenant_id, finding_id)
        derived = _current_derivation(cur, tenant_id, finding_id)
        cur.execute(
            """
            INSERT INTO non_cve_sss_proposals (
                tenant_id, finding_id, finding_revision_xmin,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                proposed_value, reason, evidence, status,
                derived_derivation_id,
                proposed_by, proposed_role
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s, %s
            )
            RETURNING id, status, proposed_value, derived_derivation_id, proposed_at;
            """,
            (
                str(tenant_id), str(finding_id), captured_revision,
                taxonomy.get("taxonomy_class"), taxonomy.get("taxonomy_subclass"),
                taxonomy.get("taxonomy_subtype"),
                str(value), reason.strip(), json.dumps(evidence),
                derived["id"] if derived else None,
                actor_id, actor_role,
            ),
        )
        row = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="sss.proposal_created",
            asset_id=None,
            details={
                "finding_id": str(finding_id),
                "proposal_id": str(row["id"]),
                "proposed_value": str(row["proposed_value"]),
                "derived_derivation_id": (str(row["derived_derivation_id"])
                                          if row["derived_derivation_id"] is not None
                                          else None),
                "status": row["status"],
                "reason": reason.strip(),
            },
        )
        return dict(row)


# ---------------------------------------------------------------------------
# SSS availability (P0-05/§3.6.4 shape) — what TES reads in the CVSS slot
# ---------------------------------------------------------------------------


def current_sss_intrinsic(
    conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> Optional[IntrinsicInput]:
    """The finding's current effective SSS in P0-04's IntrinsicInput shape
    (ticket item 7 — output compatibility; TES math untouched).

    * current derivation exists ⇒ IntrinsicInput(value, MACHINE_OBSERVED
      (derived paths), FRESH, created_at, source, derivation=version)
    * no current derivation (manual proposal still pending, or none) ⇒ None —
      the caller's TES read fails closed UNSCOREABLE (§3.6.4). This is the
      named unavailable result; it never guesses.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        row = _current_derivation(cur, tenant_id, finding_id)
    if row is None:
        return None
    path = row["path"]
    if path == "rubric":
        provenance = ProvenanceClass.MACHINE_OBSERVED
        source = "sss:rubric"
    elif path in ("manual", "override"):
        # §3.6.6 #2: approval-path provenance — label from path + approval id,
        # no version text exists for these rows.
        provenance = ProvenanceClass.ANALYST_ENTERED
        source = f"sss:{path}"
        return IntrinsicInput(
            value=row["value"],
            provenance_class=provenance,
            freshness=FreshnessState.FRESH,
            observed_at=row["created_at"],
            source=source,
            derivation=f"sss_{path}:approval:{row['approval_id']}",
        )
    else:
        provenance = ProvenanceClass.MACHINE_OBSERVED
        source = "sss:vrt"
    return IntrinsicInput(
        value=row["value"],
        provenance_class=provenance,
        freshness=FreshnessState.FRESH,
        observed_at=row["created_at"],
        source=source,
        derivation=f"sss_{path}:{row['version_text']}",
    )


__all__ = [
    "TAXONOMY_CLASSES",
    "IDENTITY_POSTURE_SUBCLASSES",
    "AGENTIC_EXPOSURE_SUBCLASSES",
    "BLFLAW_SUBTYPES",
    "VRT_PRIORITY_TO_SSS",
    "VrtDerivation",
    "RubricRule",
    "RubricDerivation",
    "SssProductionDisabledError",
    "SssClassificationError",
    "SssNotFoundError",
    "SssConflictError",
    "SssRubricError",
    "validate_taxonomy_spine",
    "map_vrt_priority",
    "evaluate_rubric",
    "validate_rubric_content",
    "rules_from_content",
    "derive_sss_vrt",
    "derive_sss_rubric",
    "create_sss_proposal",
    "current_sss_intrinsic",
]
