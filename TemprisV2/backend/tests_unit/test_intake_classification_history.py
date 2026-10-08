# backend/tests_unit/test_intake_classification_history.py
"""
INTAKE-CLASSIFICATION-01 — append-only classification history, database-free
half (PRD-000 v1.11 §6:1141/1149).

The contract under test without a database:

- every classification/reclassification preserves the PRIOR
  class/subclass/subtype, the NEW values and the rationale;
- the payload is a plain JSON object (it lands in
  ``intake_record_events.detail`` JSONB) and carries no actor/timestamp,
  because those are the event row's own columns;
- a blank/absent rationale fails closed BEFORE any row is touched.

The actor, the timestamp, single-transaction atomicity and prior-event
immutability need a database and are asserted in tests/test_ch6_intake.py.

Purity: the module under test (and therefore this suite) imports no database
driver, no FastAPI app and no ``app.exposure`` — mirroring the repository's
kernel purity rule. The assertions below check that at the source level so the
guarantee does not depend on test ordering.
"""
import ast
import json
import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.intake.classification_history import (  # noqa: E402
    TAXONOMY_FIELDS,
    build_transition_detail,
    normalize_rationale,
)

_MODULE_PATH = _BACKEND_DIR / "app" / "intake" / "classification_history.py"


# ---------------------------------------------------------------------------
# Purity — the DB-free guarantee is structural, not incidental
# ---------------------------------------------------------------------------


def test_history_module_imports_no_db_or_app_machinery():
    """Inspect the ACTUAL import statements (not the prose): the module must
    stay importable with no database driver, no FastAPI and no app.exposure."""
    tree = ast.parse(_MODULE_PATH.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    forbidden_prefixes = ("psycopg", "app.db", "app.exposure", "fastapi", "app.routes")
    offenders = [
        name
        for name in imported
        if any(name == prefix or name.startswith(f"{prefix}.") for prefix in forbidden_prefixes)
    ]
    assert offenders == [], f"classification_history imported forbidden modules: {offenders}"
    # and it really is importable in a clean interpreter
    assert "psycopg" not in sys.modules


# ---------------------------------------------------------------------------
# Rationale validation — blank/absent fails closed
# ---------------------------------------------------------------------------


def test_rationale_blank_or_absent_has_no_content():
    assert normalize_rationale(None) is None
    assert normalize_rationale("") is None
    assert normalize_rationale("   \t\n ") is None


def test_rationale_is_trimmed_and_preserved():
    assert normalize_rationale("matches the IDOR reproduction") == "matches the IDOR reproduction"
    assert normalize_rationale("  padded reason  ") == "padded reason"


# ---------------------------------------------------------------------------
# The before/after payload
# ---------------------------------------------------------------------------

UNCLASSIFIED = {
    "taxonomy_class": None,
    "taxonomy_subclass": None,
    "taxonomy_subtype": None,
}


def test_first_classification_records_an_unclassified_prior():
    detail = build_transition_detail(
        UNCLASSIFIED,
        taxonomy_class="IDENTITY_POSTURE",
        taxonomy_subclass="MFA_ENROLMENT",
        taxonomy_subtype=None,
        rationale="credential-policy drift, no exploitation evidence",
    )

    assert detail["prior"] == UNCLASSIFIED
    assert detail["prior_unclassified"] is True
    assert detail["new"] == {
        "taxonomy_class": "IDENTITY_POSTURE",
        "taxonomy_subclass": "MFA_ENROLMENT",
        "taxonomy_subtype": None,
    }
    assert detail["rationale"] == "credential-policy drift, no exploitation evidence"


def test_payload_carries_exactly_the_three_taxonomy_fields_plus_rationale():
    detail = build_transition_detail(
        UNCLASSIFIED,
        taxonomy_class="SUPPLY_CHAIN",
        taxonomy_subclass=None,
        taxonomy_subtype=None,
        rationale="third-party build server",
    )
    assert set(detail["prior"]) == set(TAXONOMY_FIELDS)
    assert set(detail["new"]) == set(TAXONOMY_FIELDS)
    # the actor and timestamp are the event row's columns — never duplicated here
    assert set(detail) == {"prior", "new", "prior_unclassified", "rationale"}
    for actor_key in ("actor", "actor_role", "created_at", "timestamp"):
        assert actor_key not in detail


def test_payload_is_json_serializable_for_the_jsonb_column():
    detail = build_transition_detail(
        UNCLASSIFIED,
        taxonomy_class="BLFLAW",
        taxonomy_subclass=None,
        taxonomy_subtype="IDOR",
        rationale="invoice export lacks an ownership check",
    )
    # exactly how _record_event serializes it
    assert json.loads(json.dumps(detail)) == detail


# ---------------------------------------------------------------------------
# Two successive classifications: the prior is preserved, the projection is
# current-only
# ---------------------------------------------------------------------------


def test_two_successive_classifications_preserve_the_prior_decision():
    """Walk the projection through two decisions the way the service does:
    each decision's ``prior`` is what the projection held on entry, and the
    projection afterwards is exactly that decision's ``new`` (current-only)."""
    projection = dict(UNCLASSIFIED)
    history = []

    decisions = [
        ("BLFLAW", None, "IDOR", "invoice export allows cross-tenant reads"),
        ("IDENTITY_POSTURE", "MFA_ENROLMENT", None, "re-read: this is policy drift, not a flaw"),
    ]

    for taxonomy_class, subclass, subtype, rationale in decisions:
        prior_snapshot = dict(projection)
        detail = build_transition_detail(
            projection,
            taxonomy_class=taxonomy_class,
            taxonomy_subclass=subclass,
            taxonomy_subtype=subtype,
            rationale=rationale,
        )
        history.append(detail)
        # the projection update the service performs
        projection = dict(detail["new"])

        # each decision recorded the taxonomy as it was on entry
        assert detail["prior"] == prior_snapshot

    first, second = history

    # first classification: nothing prior
    assert first["prior_unclassified"] is True
    assert first["prior"] == UNCLASSIFIED
    assert first["new"]["taxonomy_class"] == "BLFLAW"

    # reclassification: the FIRST decision's values are the second's prior —
    # including the subtype that the second decision dropped to None
    assert second["prior_unclassified"] is False
    assert second["prior"] == first["new"]
    assert second["prior"] == {
        "taxonomy_class": "BLFLAW",
        "taxonomy_subclass": None,
        "taxonomy_subtype": "IDOR",
    }
    assert second["new"] == {
        "taxonomy_class": "IDENTITY_POSTURE",
        "taxonomy_subclass": "MFA_ENROLMENT",
        "taxonomy_subtype": None,
    }

    # append-only: the first decision's payload was not revised by the second
    assert first["rationale"] == "invoice export allows cross-tenant reads"
    assert first["new"]["taxonomy_class"] == "BLFLAW"

    # the projection is current-only — it holds just the latest decision
    assert projection == second["new"]

    # and both rationales survive, each on its own decision
    assert [d["rationale"] for d in history] == [
        "invoice export allows cross-tenant reads",
        "re-read: this is policy drift, not a flaw",
    ]


def test_a_repeated_identical_classification_is_still_a_new_decision():
    """Re-classifying to the same values is a fresh append-only decision (the
    analyst may have re-confirmed it), not a silent no-op — the prior therefore
    equals the new values."""
    prior = {"taxonomy_class": "BLFLAW", "taxonomy_subclass": None, "taxonomy_subtype": "IDOR"}
    detail = build_transition_detail(
        prior,
        taxonomy_class="BLFLAW",
        taxonomy_subclass=None,
        taxonomy_subtype="IDOR",
        rationale="re-confirmed after the anchor was re-resolved",
    )
    assert detail["prior_unclassified"] is False
    assert detail["prior"] == detail["new"]