# backend/tests/test_p06_non_cve_severity_foundation.py
"""
P0-06 — Non-CVE Severity Foundation (PRD-000 v1.11 §3.6.1–§3.6.6; §3.4
non-CVE/SSS rows; Appendix C Q11–Q12) — bounded correction round.

Covers: the production gate (test-only content can never drive derivation);
the closed taxonomy spine (class/subclass/subtype combinations); unavoidable
revision fencing (deterministic barrier tests — the finding changes AFTER the
initial revision read but BEFORE publication); DB-enforced immutability
(UPDATE/DELETE/semantic-mutation/reactivation rejected by raw SQL);
composite provenance FKs (same tenant + finding, enforced in storage);
manual proposals that never score; the authenticated analyst+ proposal
endpoint with client-forgery rejection; audit-failure rollback; and
historical reproducibility after a new rubric version.

Content gate: ONLY explicitly test-only fixtures are used (fixture-marked
version rows). No production VRT release, identity fact schema, or rubric
rule table exists in the frozen PRD, so nothing is activated.

Isolation pattern: version rows are IMMUTABLE (DB trigger, forward-only), so
tests never reuse or demote them — each test seeds its own uniquely-named
rows and cleanup deletes them whole.
"""
import uuid
from decimal import Decimal

import psycopg
import pytest

from app.db import get_db_connection
from app.exposure import sss as sss_module
from app.exposure.sss import (
    SssClassificationError,
    SssConflictError,
    SssNotFoundError,
    SssProductionDisabledError,
    create_sss_proposal,
    current_sss_intrinsic,
    derive_sss_rubric,
    derive_sss_vrt,
)
from tests.conftest import TENANT_A, TENANT_B

TEST_VRT_RELEASE = "vrt-test-fixture-1.0"   # used ONLY as a *rejected* name
TEST_RUBRIC_V1 = "rubric-test-fixture-v1"   # used ONLY as a *rejected* name

TEST_RUBRIC_CONTENT = {
    "facts": {
        "mfa_coverage": {"type": "enum", "values": ["none", "partial", "enforced"]},
        "phishing_resistant_mfa": {"type": "boolean"},
    },
    "rules": [
        {"name": "mfa_none", "severity": "9.0", "match": {"mfa_coverage": ["none"]}},
        {"name": "mfa_partial", "severity": "6.0",
         "match": {"mfa_coverage": ["partial"]},
         "mitigation_facts": ["phishing_resistant_mfa"]},
    ],
}
TEST_RUBRIC_CONTENT_V2 = {
    "facts": {
        "mfa_coverage": {"type": "enum", "values": ["none", "partial", "enforced"]},
        "phishing_resistant_mfa": {"type": "boolean"},
    },
    "rules": [
        {"name": "mfa_none_v2", "severity": "9.5", "match": {"mfa_coverage": ["none"]}},
        {"name": "mfa_partial", "severity": "6.0",
         "match": {"mfa_coverage": ["partial"]},
         "mitigation_facts": ["phishing_resistant_mfa"]},
    ],
}

# Authentic spine combinations under the presence/absence matrix: BLFLAW
# carries a subtype and NO subclass; IDENTITY_POSTURE/AGENTIC_EXPOSURE carry
# a subclass and NO subtype; all other classes are class-only (absence — not
# an invented token — is the representation).
TAX_VRT = {"taxonomy_class": "BLFLAW", "taxonomy_subclass": None,
           "taxonomy_subtype": "IDOR"}
TAX_RUBRIC = {"taxonomy_class": "IDENTITY_POSTURE",
              "taxonomy_subclass": "MFA_ENROLMENT", "taxonomy_subtype": None}

_SSS_TABLES = (
    "non_cve_sss_proposals",
    "non_cve_sss_derivations",
    "non_cve_classifications",
    "sss_derivation_versions",
)


@pytest.fixture(autouse=True)
def _clean_sss_env():
    def _clean():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # SSS history rows are DB-enforced immutable (UPDATE/DELETE
                # rejected by migration 019 triggers), so test cleanup must
                # bypass row triggers: TRUNCATE the whole tables (test DB).
                cur.execute(
                    "TRUNCATE non_cve_sss_proposals, non_cve_sss_derivations, "
                    "non_cve_classifications, sss_derivation_versions;"
                )
                cur.execute(
                    "DELETE FROM findings WHERE tenant_id = ANY(%s::uuid[]);",
                    ([str(TENANT_A), str(TENANT_B)],),
                )
                cur.execute(
                    "DELETE FROM assets WHERE tenant_id = ANY(%s::uuid[]);",
                    ([str(TENANT_A), str(TENANT_B)],),
                )
            conn.commit()
    _clean()
    yield
    _clean()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _make_non_cve_finding(tenant_id=TENANT_A, title="MFA not enforced on admin roles"):
    from app.exposure.models import FindingCreate
    from app.exposure.service import create_finding

    with get_db_connection() as conn:
        finding = create_finding(conn, tenant_id, FindingCreate(
            title=title, severity="high",
        ))
        conn.commit()
    return finding.id


def _make_cve_finding(cve="CVE-2026-6001"):
    from tests.test_p03_cve_intelligence_resolvers import _canon
    from app.exposure.service import allocate_finding_for_cve

    with get_db_connection() as conn:
        _canon(conn, cve)
        fid = allocate_finding_for_cve(
            conn, TENANT_A, cve,
            default_title="CVE finding", default_severity="high",
            actor_id="system", actor_role="admin",
        )
        conn.commit()
    return fid


def _finding_revision(finding_id) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT xmin::text AS r FROM findings WHERE id = %s;",
                (str(finding_id),),
            )
            row = cur.fetchone()
    return row["r"] if isinstance(row, dict) else row[0]


def _touch_finding(finding_id, new_title="retitled finding (revision bump)"):
    """Move the finding's revision on a SEPARATE connection (a concurrent
    writer, for the barrier tests)."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE findings SET title = %s, updated_at = now() WHERE id = %s;",
                (new_title, str(finding_id)),
            )
        conn.commit()


def _seed_test_only_version(conn, version_id, kind, content=None):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sss_derivation_versions (version_id, kind, content, status, test_only)
            VALUES (%s, %s, %s, 'test_only', TRUE)
            ON CONFLICT (version_id) DO NOTHING;
            """,
            (version_id, kind,
             psycopg.types.json.Json(content) if content is not None else None),
        )
    conn.commit()


def _seed_approved_version(conn, version_id, kind, content=None):
    """The ONLY path to 'approved': a direct operator action recorded with
    explicit approval metadata. No application code path does this — the test
    plays the operator to prove the gate opens correctly."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sss_derivation_versions
                (version_id, kind, content, status, test_only, approved_by, approved_at)
            VALUES (%s, %s, %s, 'approved', FALSE, 'ops-approver', now())
            ON CONFLICT (version_id) DO NOTHING;
            """,
            (version_id, kind,
             psycopg.types.json.Json(content) if content is not None else None),
        )
    conn.commit()


def _approve_rubric(content=TEST_RUBRIC_CONTENT):
    version_id = f"rubric-test-fixture-{uuid.uuid4()}"
    with get_db_connection() as conn:
        _seed_approved_version(conn, version_id, "rubric", content)
    return version_id


def _approve_vrt_release():
    version_id = f"vrt-test-fixture-{uuid.uuid4()}"
    with get_db_connection() as conn:
        _seed_approved_version(conn, version_id, "vrt_release")
    return version_id


def _derive_vrt_kwargs(finding_id, **over):
    kw = dict(
        vrt_id="broken.access_control.idor", vrt_priority="P2",
        varies_facts=None, pinned_release="TO-BE-FILLED",
        taxonomy_class=TAX_VRT["taxonomy_class"],
        taxonomy_subclass=TAX_VRT["taxonomy_subclass"],
        taxonomy_subtype=TAX_VRT["taxonomy_subtype"],
        inputs=None, evidence={"ref": "bugcrowd-report-1"},
        actor_id="analyst-a", actor_role="analyst",
    )
    kw.update(over)
    return kw


def _derive_rubric_kwargs(finding_id, **over):
    kw = dict(
        rubric_version="TO-BE-FILLED",
        taxonomy_class=TAX_RUBRIC["taxonomy_class"],
        taxonomy_subclass=TAX_RUBRIC["taxonomy_subclass"],
        taxonomy_subtype=TAX_RUBRIC["taxonomy_subtype"],
        facts={"mfa_coverage": "none"},
        evidence={"source": "connector", "ref": "graph-auth-methods"},
        actor_id="analyst-a", actor_role="analyst",
    )
    kw.update(over)
    return kw


def current_sss_intrinsic_of(finding_id):
    with get_db_connection() as conn:
        return current_sss_intrinsic(conn, TENANT_A, finding_id)


# ===========================================================================
# Production gate — derivation disabled until approved content exists
# ===========================================================================


class TestProductionGate:
    def test_vrt_derivation_with_unregistered_release_is_disabled(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            with pytest.raises(SssProductionDisabledError, match="disabled"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release="vrt-4.0-unregistered"))

    def test_vrt_derivation_with_test_only_release_is_rejected(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            _seed_test_only_version(conn, TEST_VRT_RELEASE, "vrt_release")
            with pytest.raises(SssProductionDisabledError, match="not approved production content"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=TEST_VRT_RELEASE))

    def test_rubric_derivation_with_test_only_content_is_rejected(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            _seed_test_only_version(
                conn, TEST_RUBRIC_V1, "rubric", TEST_RUBRIC_CONTENT)
            with pytest.raises(SssProductionDisabledError, match="not approved production content"):
                derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                    finding_id, rubric_version=TEST_RUBRIC_V1))

    def test_nothing_is_persisted_by_a_gated_attempt(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            _seed_test_only_version(conn, TEST_VRT_RELEASE, "vrt_release")
            with pytest.raises(SssProductionDisabledError):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=TEST_VRT_RELEASE))
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS c FROM non_cve_classifications;")
                assert cur.fetchone()["c"] == 0
                cur.execute("SELECT count(*) AS c FROM non_cve_sss_derivations;")
                assert cur.fetchone()["c"] == 0

    def test_approved_content_opens_the_gate(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            result = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))
        assert result["value"] == Decimal("8.0000")  # P2
        assert result["path"] == "vrt"
        assert result["version"] == release

    def test_production_varies_stays_disabled_without_approved_resolver(self):
        """Production passes no varies resolver — a 'varies' derivation is
        the named disabled result even over approved release content."""
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="disabled"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release, vrt_priority="varies",
                    varies_facts={"exploitation_status": "widespread"}))
        assert current_sss_intrinsic_of(finding_id) is None

    def test_test_only_fixture_resolver_exercises_deterministic_varies(self):
        """A test-only closed-enum resolver may exercise the deterministic
        varies path end-to-end; no fixture content activates production (the
        release row here is explicitly fixture-marked)."""
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()

        def fixture_resolver(facts):
            # deterministic closed-enum resolution (test fixture only)
            return {"widespread": Decimal("9"), "limited": Decimal("7.5")}[
                facts["exploitation_status"]
            ]

        with get_db_connection() as conn:
            result = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release, vrt_priority="varies",
                varies_facts={"exploitation_status": "limited"},
                varies_resolver=fixture_resolver))
        assert result["value"] == Decimal("7.5000")

    def test_migration_forbids_promotion_of_test_only_content(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            _seed_test_only_version(conn, TEST_VRT_RELEASE, "vrt_release")
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="never be promoted"):
                    cur.execute(
                        "UPDATE sss_derivation_versions SET status = 'approved' "
                        "WHERE version_id = %s;",
                        (TEST_VRT_RELEASE,),
                    )
            conn.rollback()

    def test_production_activation_requires_explicit_operator_approval(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.CheckViolation):
                    cur.execute(
                        """
                        INSERT INTO sss_derivation_versions
                            (version_id, kind, status, test_only, approved_by, approved_at)
                        VALUES ('vrt-no-approval-meta', 'vrt_release', 'approved', FALSE, NULL, NULL);
                        """
                    )
            conn.rollback()


# ===========================================================================
# Correction 1 — the closed taxonomy spine at the storage boundary
# ===========================================================================


class TestTaxonomyAtStorage:
    def test_arbitrary_class_rejected_by_publication(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            # the removed default pseudo-class: rejected however it arrives
            with pytest.raises(SssClassificationError):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release,
                    taxonomy_class="vrt",
                ))
            # a verbatim-valid but unknown class hits the closed-vocabulary check
            with pytest.raises(SssClassificationError, match="unknown taxonomy class"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release,
                    taxonomy_class="FROBNICATE",
                ))

    def test_no_default_class_is_applied(self):
        """Correction 1: removing defaults — omitting the taxonomy is an
        error (required arguments), never a silent 'vrt'/'subclass' default."""
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        kwargs = _derive_vrt_kwargs(finding_id, pinned_release=release)
        kwargs.pop("taxonomy_class")
        with get_db_connection() as conn:
            with pytest.raises(TypeError):
                derive_sss_vrt(conn, TENANT_A, finding_id, **kwargs)

    def test_invalid_identity_posture_subclass_rejected(self):
        finding_id = _make_non_cve_finding()
        rubric = _approve_rubric()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="IDENTITY_POSTURE subclass"):
                derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                    finding_id, rubric_version=rubric,
                    taxonomy_subclass="PASSWORD_POLICY"))

    def test_invalid_blflaw_subtype_rejected(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="BLFLAW subtype"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release, taxonomy_subtype="BFLAW-XX"))

    def test_subclass_supplied_on_class_without_vocabulary_rejected(self):
        """Matrix: BLFLAW has no approved subclass vocabulary — absence, not
        an invented token, is the representation."""
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="not applicable"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release,
                    taxonomy_subclass="ACCESS_CONTROL"))

    def test_subtype_supplied_on_class_without_vocabulary_rejected(self):
        finding_id = _make_non_cve_finding()
        rubric = _approve_rubric()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="not applicable"):
                derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                    finding_id, rubric_version=rubric, taxonomy_subtype="ANY"))

    def test_every_class_exactly_valid_shape_derives(self):
        """Matrix: each class's exactly-valid shape is accepted at the
        storage boundary (class-only classes carry NO subclass/subtype)."""
        release = _approve_vrt_release()
        shapes = (
            ("BLFLAW", None, "IDOR"),
            ("IDENTITY_POSTURE", "MFA_ENROLMENT", None),
            ("AGENTIC_EXPOSURE", "TOOL_MCP", None),
            ("SUPPLY_CHAIN", None, None),
            ("VALIDATION_EVIDENCE", None, None),
            ("NHI", None, None),
        )
        for cls, sub, st in shapes:
            finding_id = _make_non_cve_finding(
                title=f"matrix shape {cls}")
            with get_db_connection() as conn:
                result = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release,
                    taxonomy_class=cls, taxonomy_subclass=sub, taxonomy_subtype=st))
            assert result["value"] == Decimal("8.0000")

    def test_db_check_rejects_unknown_class_on_raw_insert(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="unknown taxonomy class"):
                    cur.execute(
                        """
                        INSERT INTO non_cve_classifications (
                            tenant_id, finding_id, finding_revision_xmin,
                            taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                            path, inputs, evidence, created_by, created_role
                        )
                        SELECT %s, %s, xmin::text, 'FROBNICATE', 'y', 'z', 'vrt',
                                '{}'::jsonb, '{"e":1}'::jsonb, 'a', 'analyst'
                        FROM findings WHERE id = %s;
                        """,
                        (str(TENANT_A), str(finding_id), str(finding_id)),
                    )
            conn.rollback()  # release the aborted transaction between proofs
            with conn.cursor() as cur:
                # a lowercase non-spine token hits the verbatim check first
                # (same precedence as the shared Python validator)
                with pytest.raises(psycopg.errors.RaiseException, match="verbatim spine token"):
                    cur.execute(
                        """
                        INSERT INTO non_cve_classifications (
                            tenant_id, finding_id, finding_revision_xmin,
                            taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                            path, inputs, evidence, created_by, created_role
                        )
                        SELECT %s, %s, xmin::text, 'vrt', 'y', 'z', 'vrt',
                                '{}'::jsonb, '{"e":1}'::jsonb, 'a', 'analyst'
                        FROM findings WHERE id = %s;
                        """,
                        (str(TENANT_A), str(finding_id), str(finding_id)),
                    )
            conn.rollback()


# ===========================================================================
# Derivation behavior over approved content
# ===========================================================================


class TestDerivationBehavior:
    def test_rubric_derivation_publishes_value_and_binds_revision(self):
        finding_id = _make_non_cve_finding()
        rubric = _approve_rubric()
        with get_db_connection() as conn:
            result = derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                finding_id, rubric_version=rubric))
        assert result["value"] == Decimal("9.0000")
        assert result["finding_revision_xmin"] == _finding_revision(finding_id)

        intrinsic = current_sss_intrinsic_of(finding_id)
        assert intrinsic is not None
        assert intrinsic.value == Decimal("9.0000")
        assert intrinsic.derivation == f"sss_rubric:{rubric}"

    def test_no_matching_rule_is_unknown_never_scored(self):
        finding_id = _make_non_cve_finding()
        rubric = _approve_rubric()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="no rubric rule matched"):
                derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                    finding_id, rubric_version=rubric,
                    facts={"mfa_coverage": "partial", "phishing_resistant_mfa": True}))
        assert current_sss_intrinsic_of(finding_id) is None

    def test_closed_enum_violation_rejected_at_publication(self):
        finding_id = _make_non_cve_finding()
        rubric = _approve_rubric()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="closed enum"):
                derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                    finding_id, rubric_version=rubric,
                    facts={"mfa_coverage": "sometimes"}))

    def test_append_only_history_on_republish(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            first = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))
            second = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release, vrt_priority="P3"))
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT value FROM non_cve_sss_derivations WHERE id = %s;",
                    (uuid.UUID(first["derivation_id"]),),
                )
                assert cur.fetchone()["value"] == Decimal("8.0000")  # untouched
                cur.execute(
                    "SELECT count(*) AS c FROM non_cve_sss_derivations "
                    "WHERE tenant_id = %s AND finding_id = %s;",
                    (str(TENANT_A), str(finding_id)),
                )
                assert cur.fetchone()["c"] == 2


# ===========================================================================
# Correction 2 — unavoidable revision fencing (deterministic barriers)
# ===========================================================================


class TestRevisionFencing:
    def test_vrt_barrier_finding_changes_between_capture_and_publication(self, monkeypatch):
        """The finding is updated by a concurrent writer DURING the compute
        phase (after the revision capture, before publication): the
        publication is rejected and nothing persists."""
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()

        real_map = sss_module.map_vrt_priority

        def touching_map(*args, **kwargs):
            _touch_finding(finding_id)  # revision moves during compute
            return real_map(*args, **kwargs)

        monkeypatch.setattr(sss_module, "map_vrt_priority", touching_map)
        with get_db_connection() as conn:
            with pytest.raises(SssConflictError, match="revision changed"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release))
        assert current_sss_intrinsic_of(finding_id) is None
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM non_cve_classifications "
                    "WHERE finding_id = %s;", (str(finding_id),))
                assert cur.fetchone()["c"] == 0

    def test_rubric_barrier_finding_changes_between_capture_and_publication(self, monkeypatch):
        finding_id = _make_non_cve_finding()
        rubric = _approve_rubric()

        real_eval = sss_module.evaluate_rubric

        def touching_eval(*args, **kwargs):
            _touch_finding(finding_id)
            return real_eval(*args, **kwargs)

        monkeypatch.setattr(sss_module, "evaluate_rubric", touching_eval)
        with get_db_connection() as conn:
            with pytest.raises(SssConflictError, match="revision changed"):
                derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                    finding_id, rubric_version=rubric))
        assert current_sss_intrinsic_of(finding_id) is None

    def test_caller_cannot_supply_or_omit_the_revision_token(self):
        """Correction 2: the signature owns fencing — no finding_revision_xmin
        parameter exists for callers to omit or replace."""
        import inspect
        for fn in (derive_sss_vrt, derive_sss_rubric, create_sss_proposal):
            assert "finding_revision_xmin" not in inspect.signature(fn).parameters
            assert not any(p.startswith("**") for p in
                           map(str, inspect.signature(fn).parameters.values()))

    def test_stale_revision_via_direct_write_is_rejected(self):
        """Equivalent barrier via a raw pre-touch (no monkeypatch): capture a
        revision snapshot before any service call, mutate the row, then let
        the service fence against its own fresh capture by racing through the
        trigger check — the deterministic pair above covers the mid-compute
        window; this pins the error surface shape."""
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            ok = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))
        assert ok["finding_revision_xmin"] == _finding_revision(finding_id)


# ===========================================================================
# Correction 3 — DB-enforced immutability and provenance (raw SQL proofs)
# ===========================================================================


class TestDatabaseImmutability:
    def _derive_once(self, finding_id, release):
        with get_db_connection() as conn:
            return derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))

    def test_classification_update_and_delete_rejected(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        result = self._derive_once(finding_id, release)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute(
                        "UPDATE non_cve_classifications SET taxonomy_class = 'NHI' "
                        "WHERE id = %s;", (result["classification_id"],))
            conn.rollback()  # release the aborted transaction between proofs
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute(
                        "DELETE FROM non_cve_classifications WHERE id = %s;",
                        (result["classification_id"],))
            conn.rollback()

    def test_proposal_update_and_delete_rejected(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                evidence={"r": 1}, actor_id="a", actor_role="analyst")
        pid = proposal["id"]  # psycopg RETURNING id is already a UUID
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute(
                        "UPDATE non_cve_sss_proposals SET status = 'approved' "
                        "WHERE id = %s;", (pid,))
            conn.rollback()  # release the aborted transaction between proofs
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute(
                        "DELETE FROM non_cve_sss_proposals WHERE id = %s;", (pid,))
            conn.rollback()

    def test_derivation_delete_and_semantic_update_rejected(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        result = self._derive_once(finding_id, release)
        did = result["derivation_id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute("DELETE FROM non_cve_sss_derivations WHERE id = %s;",
                                (did,))
            conn.rollback()  # release the aborted transaction between proofs
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="only is_current TRUE→FALSE"):
                    cur.execute(
                        "UPDATE non_cve_sss_derivations SET value = 1 WHERE id = %s;",
                        (did,))
            conn.rollback()

    def test_derivation_is_current_true_to_false_is_the_only_allowed_update(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        result = self._derive_once(finding_id, release)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE non_cve_sss_derivations SET is_current = FALSE "
                    "WHERE id = %s;", (uuid.UUID(result["derivation_id"]),))
            conn.commit()
        assert current_sss_intrinsic_of(finding_id) is None

    def test_reactivation_false_to_true_rejected(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        result = self._derive_once(finding_id, release)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE non_cve_sss_derivations SET is_current = FALSE "
                    "WHERE id = %s;", (uuid.UUID(result["derivation_id"]),))
                with pytest.raises(psycopg.errors.RaiseException, match="reactivat"):
                    cur.execute(
                        "UPDATE non_cve_sss_derivations SET is_current = TRUE "
                        "WHERE id = %s;", (uuid.UUID(result["derivation_id"]),))
            conn.rollback()

    def test_cross_tenant_classification_attachment_rejected_by_composite_fk(self):
        finding_id = _make_non_cve_finding(TENANT_A)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # isolate the composite-FK proof from the (correctly earlier)
                # tenant-scoped CVE-trigger lookup, which would reject first
                cur.execute(
                    "ALTER TABLE non_cve_classifications DISABLE TRIGGER "
                    "trg_non_cve_classifications_reject_cve;")
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        """
                        INSERT INTO non_cve_classifications (
                            tenant_id, finding_id, finding_revision_xmin,
                            taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                            path, inputs, evidence, created_by, created_role
                        )
                        VALUES (%s, %s, '0', 'NHI', NULL, NULL, 'vrt',
                                '{}'::jsonb, '{"e":1}'::jsonb, 'a', 'analyst');
                        """,
                        (str(TENANT_B), str(finding_id)),
                    )
            conn.rollback()  # rollback also re-enables the trigger
        # the tenant-scoped CVE trigger is active again (same statement now
        # raises the not-found guard, not the FK)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="not found in tenant"):
                    cur.execute(
                        """
                        INSERT INTO non_cve_classifications (
                            tenant_id, finding_id, finding_revision_xmin,
                            taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                            path, inputs, evidence, created_by, created_role
                        )
                        VALUES (%s, %s, '0', 'NHI', NULL, NULL, 'vrt',
                                '{}'::jsonb, '{"e":1}'::jsonb, 'a', 'analyst');
                        """,
                        (str(TENANT_B), str(finding_id)),
                    )
            conn.rollback()

    def test_fabricated_proposal_derived_comparison_rejected_by_composite_fk(self):
        """A proposal cannot display a derived value bound to another tenant's
        (or another finding's) derivation — the composite FK rejects it."""
        finding_id_a = _make_non_cve_finding(TENANT_A)
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            derivation = derive_sss_vrt(conn, TENANT_A, finding_id_a, **_derive_vrt_kwargs(
                finding_id_a, pinned_release=release))
        finding_id_b = _make_non_cve_finding(TENANT_B)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        """
                        INSERT INTO non_cve_sss_proposals (
                            tenant_id, finding_id, finding_revision_xmin,
                            proposed_value, reason, evidence,
                            derived_derivation_id, proposed_by, proposed_role
                        )
                        VALUES (%s, %s, '0', 5, 'why', '{"r":1}'::jsonb, %s, 'b', 'analyst');
                        """,
                        (str(TENANT_B), str(finding_id_b), derivation["derivation_id"]),
                    )
            conn.rollback()

    def test_proposal_taxonomy_row_shape_is_all_or_none(self):
        """All-or-none shape: class-only taxonomy (a valid matrix shape) is
        accepted; taxonomy_class alone with subclass/subtype supplied on a
        class without those vocabularies is rejected by the spine CHECK."""
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # class-only shape is valid under the matrix
                cur.execute(
                    """
                    INSERT INTO non_cve_sss_proposals (
                        tenant_id, finding_id, finding_revision_xmin,
                        taxonomy_class, proposed_value, reason, evidence,
                        proposed_by, proposed_role
                    )
                    SELECT %s, %s, xmin::text, 'NHI', 5, 'why', '{"r":1}'::jsonb,
                           'a', 'analyst'
                    FROM findings WHERE id = %s;
                    """,
                    (str(TENANT_A), str(finding_id), str(finding_id)),
                )
                # subclass token on a class without the vocabulary — rejected
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="not applicable"):
                    cur.execute(
                        """
                        INSERT INTO non_cve_sss_proposals (
                            tenant_id, finding_id, finding_revision_xmin,
                            taxonomy_class, taxonomy_subclass, proposed_value,
                            reason, evidence, proposed_by, proposed_role
                        )
                        SELECT %s, %s, xmin::text, 'NHI', 'LIFECYCLE', 5, 'why2',
                               '{"r":1}'::jsonb, 'a', 'analyst'
                        FROM findings WHERE id = %s;
                        """,
                        (str(TENANT_A), str(finding_id), str(finding_id)),
                    )
            conn.rollback()

    def test_proposal_derived_binding_null_when_no_current_derivation(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                evidence={"r": 1}, actor_id="a", actor_role="analyst")
        assert proposal["derived_derivation_id"] is None
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT derived_derivation_id FROM non_cve_sss_proposals "
                    "WHERE id = %s;", (proposal["id"],))
                assert cur.fetchone()["derived_derivation_id"] is None

    def test_cve_trigger_lookup_is_tenant_scoped(self):
        """The CVE gate reads the finding through (id, tenant) — proven by a
        same-tenant CVE finding still being rejected (lookup finds the row)
        while the composite FK excludes foreign rows structurally."""
        fid = _make_cve_finding()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="forbidden on CVE findings"):
                    cur.execute(
                        """
                        INSERT INTO non_cve_classifications (
                            tenant_id, finding_id, finding_revision_xmin,
                            taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                            path, inputs, evidence, created_by, created_role
                        )
                        SELECT f.tenant_id, f.id, f.xmin::text, 'BLFLAW', NULL,
                               'IDOR', 'vrt', '{}'::jsonb, '{"e":1}'::jsonb, 'a', 'analyst'
                        FROM findings f WHERE f.id = %s AND f.tenant_id = %s;
                        """,
                        (str(fid), str(TENANT_A)),
                    )
            conn.rollback()


# ===========================================================================
# Current-derivation semantics
# ===========================================================================


class TestCurrentDerivation:
    def test_no_derivation_returns_none(self):
        finding_id = _make_non_cve_finding()
        assert current_sss_intrinsic_of(finding_id) is None

    def test_superseded_history_retained_and_current_flipped(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            first = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))
            second = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release, vrt_priority="P4"))
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, is_current, value FROM non_cve_sss_derivations "
                    "WHERE tenant_id = %s AND finding_id = %s;",
                    (str(TENANT_A), str(finding_id)),
                )
                rows = {r["id"]: r for r in cur.fetchall()}
        assert rows[uuid.UUID(first["derivation_id"])]["is_current"] is False
        assert rows[uuid.UUID(second["derivation_id"])]["is_current"] is True
        assert rows[uuid.UUID(first["derivation_id"])]["value"] == Decimal("8.0000")
        assert len(rows) == 2
        assert current_sss_intrinsic_of(finding_id).value == Decimal("2.0000")

    def test_historical_reproducibility_after_new_rubric_version(self):
        finding_id = _make_non_cve_finding()
        rubric_v1 = _approve_rubric(TEST_RUBRIC_CONTENT)
        rubric_v2 = _approve_rubric(TEST_RUBRIC_CONTENT_V2)
        with get_db_connection() as conn:
            v1 = derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                finding_id, rubric_version=rubric_v1))
            v2 = derive_sss_rubric(conn, TENANT_A, finding_id, **_derive_rubric_kwargs(
                finding_id, rubric_version=rubric_v2))
        assert v1["value"] == Decimal("9.0000")
        assert v2["value"] == Decimal("9.5000")

        from app.exposure.sss import evaluate_rubric
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT d.inputs, v.content "
                    "FROM non_cve_sss_derivations d "
                    "JOIN sss_derivation_versions v ON v.id = d.version_id_ref "
                    "WHERE d.id = %s;",
                    (uuid.UUID(v1["derivation_id"]),),
                )
                row = cur.fetchone()
        assert evaluate_rubric(row["inputs"], row["content"]).value == v1["value"]


# ===========================================================================
# Manual SSS proposals (never score; derived comparison binds exactly)
# ===========================================================================


class TestManualProposals:
    def test_proposal_is_pending_and_score_ineligible(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            result = create_sss_proposal(
                conn, TENANT_A, finding_id,
                proposed_value=Decimal("6.5"),
                reason="pentest report severity",
                evidence={"report": "PT-2026-014"},
                actor_id="analyst-a", actor_role="analyst",
            )
        assert result["status"] == "pending"
        assert result["proposed_value"] == Decimal("6.5000")
        assert current_sss_intrinsic_of(finding_id) is None

    def test_proposal_rejects_missing_reason_or_evidence_and_out_of_bounds(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="5",
                    reason="  ", evidence={"r": 1},
                    actor_id="a", actor_role="analyst")
            with pytest.raises(SssClassificationError):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="5",
                    reason="why", evidence={},
                    actor_id="a", actor_role="analyst")
            with pytest.raises(SssClassificationError):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="10.5",
                    reason="why", evidence={"r": 1},
                    actor_id="a", actor_role="analyst")

    def test_proposal_value_overprecision_rejected_not_rounded(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="four decimal"):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="6.51234",
                    reason="why", evidence={"r": 1},
                    actor_id="a", actor_role="analyst")

    def test_proposal_supplied_taxonomy_must_validate(self):
        finding_id = _make_non_cve_finding()
        with get_db_connection() as conn:
            ok = create_sss_proposal(
                conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                evidence={"r": 1}, actor_id="a", actor_role="analyst",
                taxonomy=dict(TAX_RUBRIC))
            with pytest.raises(SssClassificationError, match="unknown taxonomy class"):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                    evidence={"r": 1}, actor_id="a", actor_role="analyst",
                    taxonomy={"taxonomy_class": "FROBNICATE", "taxonomy_subclass": "S",
                              "taxonomy_subtype": "S"})
            # matrix: subclass token on a class without the vocabulary rejects
            with pytest.raises(SssClassificationError, match="not applicable"):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                    evidence={"r": 1}, actor_id="a", actor_role="analyst",
                    taxonomy={"taxonomy_class": "NHI",
                              "taxonomy_subclass": "LIFECYCLE"})
            # subclass-only (no class) remains an all-or-none violation
            with pytest.raises(SssClassificationError, match="all-or-none"):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                    evidence={"r": 1}, actor_id="a", actor_role="analyst",
                    taxonomy={"taxonomy_subclass": "MFA_ENROLMENT"})
        assert ok["status"] == "pending"

    def test_proposal_binds_exact_derivation_id_of_same_tenant_and_finding(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            derivation = derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))
            proposal = create_sss_proposal(
                conn, TENANT_A, finding_id,
                proposed_value=Decimal("9.5"),
                reason="analyst judges higher than the VRT prior",
                evidence={"note": "chained with second issue"},
                actor_id="analyst-a", actor_role="analyst",
            )
        assert proposal["derived_derivation_id"] == uuid.UUID(derivation["derivation_id"])
        assert proposal["status"] == "pending"

    def test_db_admits_no_status_other_than_pending(self):
        _make_non_cve_finding()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.CheckViolation):
                    cur.execute(
                        """
                        INSERT INTO non_cve_sss_proposals (
                            tenant_id, finding_id, finding_revision_xmin,
                            proposed_value, reason, evidence, status,
                            proposed_by, proposed_role
                        )
                        SELECT f.tenant_id, f.id, f.xmin::text, 5, 'why',
                               '{"r":1}'::jsonb, 'approved', 'a', 'analyst'
                        FROM findings f
                        WHERE f.tenant_id = %s AND f.canonical_cve_id IS NULL
                        LIMIT 1;
                        """,
                        (str(TENANT_A),),
                    )
            conn.rollback()


# ===========================================================================
# CVE-finding rejection + tenant isolation (service level)
# ===========================================================================


class TestFindingGates:
    def test_cve_findings_never_take_non_cve_severity_records(self):
        finding_id = _make_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="canonical_cve_id"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release))
            with pytest.raises(SssClassificationError, match="canonical_cve_id"):
                create_sss_proposal(
                    conn, TENANT_A, finding_id, proposed_value="5", reason="why",
                    evidence={"r": 1}, actor_id="a", actor_role="analyst")

    def test_cross_tenant_finding_is_the_same_not_found(self):
        finding_id = _make_non_cve_finding(TENANT_A)
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            with pytest.raises(SssNotFoundError):
                derive_sss_vrt(conn, TENANT_B, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release))
            with pytest.raises(SssNotFoundError):
                create_sss_proposal(
                    conn, TENANT_B, finding_id, proposed_value="5", reason="why",
                    evidence={"r": 1}, actor_id="b", actor_role="analyst")

    def test_unknown_finding_is_the_same_not_found(self):
        ghost = uuid.uuid4()
        with get_db_connection() as conn:
            with pytest.raises(SssNotFoundError):
                create_sss_proposal(
                    conn, TENANT_A, ghost, proposed_value="5", reason="why",
                    evidence={"r": 1}, actor_id="a", actor_role="analyst")


# ===========================================================================
# Concurrency: serialization, one current derivation, audit rollback
# ===========================================================================


class TestConcurrency:
    def test_concurrent_derivations_produce_exactly_one_current(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        results = []

        def worker(priority):
            with get_db_connection() as conn:
                results.append(derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release, vrt_priority=priority)))

        import threading
        t1 = threading.Thread(target=worker, args=("P2",))
        t2 = threading.Thread(target=worker, args=("P4",))
        t1.start(); t2.start(); t1.join(); t2.join()

        assert sorted(r["value"] for r in results) == [Decimal("2.0000"), Decimal("8.0000")]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM non_cve_sss_derivations "
                    "WHERE tenant_id = %s AND finding_id = %s AND is_current;",
                    (str(TENANT_A), str(finding_id)),
                )
                assert cur.fetchone()["c"] == 1
                cur.execute(
                    "SELECT count(*) AS c FROM non_cve_sss_derivations "
                    "WHERE tenant_id = %s AND finding_id = %s;",
                    (str(TENANT_A), str(finding_id)),
                )
                assert cur.fetchone()["c"] == 2

    def test_audit_failure_rolls_back_the_whole_publication(self, monkeypatch):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                finding_id, pinned_release=release))

        def boom(*args, **kwargs):
            raise RuntimeError("audit sink unavailable")

        monkeypatch.setattr(sss_module, "record_audit_event", boom)

        def failing_attempt():
            with get_db_connection() as conn:
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release, vrt_priority="P3"))

        with pytest.raises(SssConflictError, match="audit write failed"):
            failing_attempt()

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM non_cve_sss_derivations "
                    "WHERE tenant_id = %s AND finding_id = %s;",
                    (str(TENANT_A), str(finding_id)),
                )
                assert cur.fetchone()["c"] == 1
                cur.execute(
                    "SELECT count(*) AS c FROM audit_events "
                    "WHERE details->>'finding_id' = %s;",
                    (str(finding_id),),
                )
                assert cur.fetchone()["c"] == 1
        assert current_sss_intrinsic_of(finding_id).value == Decimal("8.0000")


# ===========================================================================
# Correction 4 — the authenticated manual-proposal boundary (API)
# ===========================================================================


@pytest.fixture
def client():
    from starlette.testclient import TestClient
    from app.main import app
    from app.auth import create_test_token

    def _client(role="analyst", actor="analyst-a", tenant=TENANT_A):
        token = create_test_token(tenant_id=str(tenant), actor_id=actor, role=role)
        c = TestClient(app)
        c.headers.update({"Authorization": f"Bearer {token}"})
        return c

    return _client


class TestSssProposalEndpoint:
    def _body(self, **over):
        body = {
            "proposed_value": "6.5",
            "reason": "pentest report severity",
            "evidence": {"report": "PT-2026-014"},
        }
        body.update(over)
        return body

    def test_create_returns_pending_with_lossless_decimal(self, client):
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body(),
        )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["status"] == "pending"
        assert body["proposed_value"] == {"__decimal__": "6.5000"}

    def test_optional_valid_taxonomy_accepted(self, client):
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body(taxonomy={
                "taxonomy_class": "IDENTITY_POSTURE",
                "taxonomy_subclass": "MFA_ENROLMENT",
            }),
        )
        assert res.status_code == 201
        assert res.json()["status"] == "pending"

    def test_taxonomy_matrix_shapes_at_the_boundary(self, client):
        """API matrix: each class's exactly-valid shape is 201; a token on a
        dimension without an approved vocabulary is 422."""
        valid = (
            {"taxonomy_class": "BLFLAW", "taxonomy_subtype": "BFLAW-BAC"},
            {"taxonomy_class": "AGENTIC_EXPOSURE",
             "taxonomy_subclass": "TOOL_MCP"},
            {"taxonomy_class": "SUPPLY_CHAIN"},
            {"taxonomy_class": "VALIDATION_EVIDENCE"},
            {"taxonomy_class": "NHI"},
        )
        for tax in valid:
            finding_id = _make_non_cve_finding()
            res = client().post(
                f"/api/exposure/findings/{finding_id}/sss-proposals",
                json=self._body(taxonomy=tax),
            )
            assert res.status_code == 201, (tax, res.text)
        # supplied token on an unsupported dimension — 422, distinct error
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body(taxonomy={
                "taxonomy_class": "NHI", "taxonomy_subtype": "STATIC_KEY"}),
        )
        assert res.status_code == 422
        assert "not applicable" in res.text
        # required-but-missing at the boundary — 422 with the named error
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body(taxonomy={"taxonomy_class": "IDENTITY_POSTURE"}),
        )
        assert res.status_code == 422
        assert "required for IDENTITY_POSTURE" in res.text

    def test_invalid_taxonomy_rejected_422(self, client):
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body(taxonomy={
                "taxonomy_class": "vrt",
                "taxonomy_subclass": "S",
                "taxonomy_subtype": "S",
            }),
        )
        assert res.status_code == 422

    def test_client_forgery_of_authority_fields_is_422(self, client):
        """Tenant, actor, role, revision, status, validation state, version,
        approval state, and derived comparison are server-owned — a client
        attempting to submit them is rejected by the request model."""
        finding_id = _make_non_cve_finding()
        forged = self._body(
            tenant_id=str(TENANT_B),
            proposed_by="admin-b",
            proposed_role="admin",
            finding_revision_xmin="0",
            status="approved",
            validation_state="confirmed",
            version_id_ref="x",
            derived_value="1",
            derived_derivation_id=str(uuid.uuid4()),
        )
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals", json=forged)
        assert res.status_code == 422
        # nothing was created
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM non_cve_sss_proposals "
                    "WHERE finding_id = %s;", (str(finding_id),))
                assert cur.fetchone()["c"] == 0

    def test_overprecision_value_is_422_not_rounded(self, client):
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body(proposed_value="6.51234"),
        )
        assert res.status_code == 422
        assert "four decimal" in res.text

    def test_cross_tenant_and_unknown_findings_identical_404(self, client):
        finding_id = _make_non_cve_finding(TENANT_A)
        # the token's role must match the fixture membership (admin-b is an admin)
        res_b = client(tenant=TENANT_B, actor="admin-b", role="admin").post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body())
        res_ghost = client().post(
            f"/api/exposure/findings/{uuid.uuid4()}/sss-proposals",
            json=self._body())
        assert res_b.status_code == res_ghost.status_code == 404
        assert res_b.json() == res_ghost.json()  # identical, no disclosure

    def test_cve_finding_rejects_422(self, client):
        fid = _make_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{fid}/sss-proposals", json=self._body())
        assert res.status_code == 422
        assert "canonical_cve_id" in res.text

    def test_unauthenticated_is_401(self):
        finding_id = _make_non_cve_finding()
        from starlette.testclient import TestClient
        from app.main import app
        c = TestClient(app)
        res = c.post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body())
        assert res.status_code == 401

    def test_proposal_only_finding_remains_score_ineligible(self, client):
        finding_id = _make_non_cve_finding()
        res = client().post(
            f"/api/exposure/findings/{finding_id}/sss-proposals",
            json=self._body())
        assert res.status_code == 201
        assert current_sss_intrinsic_of(finding_id) is None


# ===========================================================================
# Client forgery — service signature ownership (defense in depth)
# ===========================================================================


class TestClientForgeryServiceLevel:
    def test_proposal_signature_has_no_client_authority_fields(self):
        import inspect
        sig = inspect.signature(create_sss_proposal)
        params = set(sig.parameters) - {"conn"}
        assert params == {
            "tenant_id", "finding_id", "proposed_value", "reason", "evidence",
            "actor_id", "actor_role", "taxonomy",
        }

    def test_validation_state_is_server_owned(self):
        finding_id = _make_non_cve_finding()
        release = _approve_vrt_release()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="validation_state"):
                derive_sss_vrt(conn, TENANT_A, finding_id, **_derive_vrt_kwargs(
                    finding_id, pinned_release=release,
                    validation_state="approved_by_client"))
