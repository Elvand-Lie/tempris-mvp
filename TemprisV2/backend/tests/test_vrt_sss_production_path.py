# backend/tests/test_vrt_sss_production_path.py
"""
Production VRT-backed SSS path (P0-06 §3.6.6 #1) — the orchestration entry
``derive_sss_vrt_for_finding`` over the migration-046 seed row.

Covers: the happy path (real vendored-taxonomy leaf id → P2 → 8, is_current,
classification carries the VRT metadata, TES read resolves the intrinsic
with 'derived'/'vrt' provenance); server-side leaf resolution (unknown leaf
id and a disagreeing priority claim both fail closed, nothing written);
exploit-shape gate (non-BLFLAW refused); CVE refusal; the fail-closed
production gate (missing version row); and tenant isolation.
"""
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.db import get_db_connection
from app.exposure.models import FindingCreate
from app.exposure.sss import (
    PINNED_VRT_RELEASE,
    SssClassificationError,
    SssNotFoundError,
    SssNotExploitShapedError,
    SssProductionDisabledError,
    current_sss_intrinsic,
    derive_sss_vrt_for_finding,
)
from app.exposure.service import create_finding
from app.exposure.tes_read_model import get_exposure_tes
from tests.conftest import TENANT_A, TENANT_B

# A REAL leaf id copied from the vendored release file
# (app/exposure/data/vrt_bugcrowd_v1_19_1.json), priority P2 → SSS 8.
P2_LEAF_ID = "broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers"

EVIDENCE = {"source": "bugcrowd", "report": "BC-2026-014"}

TAX_BLFLAW = ("BLFLAW", None, "BFLAW-BAC")
TAX_IDENTITY = ("IDENTITY_POSTURE", "MFA_ENROLMENT", None)


@pytest.fixture(autouse=True)
def _clean_and_seed():
    def _clean():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # SSS history is DB-enforced immutable: TRUNCATE (test DB)
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
                # the migration-046 seed row (re-created after truncation)
                cur.execute(
                    """
                    INSERT INTO sss_derivation_versions
                        (version_id, kind, content, status, test_only,
                         approved_by, approved_at)
                    VALUES (%s, 'vrt_release', NULL, 'approved', FALSE,
                            'system:bootstrap', now())
                    ON CONFLICT (version_id) DO NOTHING;
                    """,
                    (PINNED_VRT_RELEASE,),
                )
            conn.commit()
    _clean()
    yield
    _clean()


def _make_classified_finding(taxonomy=TAX_BLFLAW, tenant=TENANT_A,
                             title="idor on admin export"):
    """A non-CVE finding with an intake-shaped classification row
    (path 'manual', NO derivation — intake classifies, it never scores)."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            finding = create_finding(conn, tenant, FindingCreate(
                title=title, severity="high"))
            cur.execute(
                "SELECT xmin::text AS revision FROM findings "
                "WHERE tenant_id = %s AND id = %s;",
                (str(tenant), str(finding.id)),
            )
            revision = cur.fetchone()["revision"]
            cur.execute(
                """
                INSERT INTO non_cve_classifications (
                    tenant_id, finding_id, finding_revision_xmin,
                    taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                    path, version_id_ref, inputs, evidence, validation_state,
                    created_by, created_role
                ) VALUES (%s, %s, %s, %s, %s, %s, 'manual', NULL, '{}'::jsonb,
                          '{"intake_record_id": "seed"}'::jsonb,
                          'single_source', 'analyst-a', 'analyst');
                """,
                (str(tenant), str(finding.id), revision, *taxonomy),
            )
        conn.commit()
    return finding.id


def _classification_row(finding_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, vrt_id, vrt_priority, version_id_ref
                FROM non_cve_classifications
                WHERE tenant_id = %s AND finding_id = %s
                ORDER BY created_at DESC LIMIT 1;
                """,
                (str(TENANT_A), str(finding_id)),
            )
            return cur.fetchone()


def _current_derivation_row(finding_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT d.id, d.value, d.is_current, v.version_id AS version_text
                FROM non_cve_sss_derivations d
                LEFT JOIN sss_derivation_versions v ON v.id = d.version_id_ref
                WHERE d.tenant_id = %s AND d.finding_id = %s;
                """,
                (str(TENANT_A), str(finding_id)),
            )
            return cur.fetchall()


def _tes_payload(exposure_id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        as_of = datetime.now(timezone.utc)
        payload = get_exposure_tes(conn, TENANT_A, exposure_id, as_of=as_of)
        conn.rollback()
    return payload


def _confirm_episode(finding_id):
    """An asset + confirmed exposure for the finding (TES read target)."""
    from app.exposure.models import ExposureConfirm
    from app.exposure.service import confirm_exposure
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, 'server', 'domain', %s, %s, 'internal',
                          'production', 'low', 'active')
                RETURNING id;
                """,
                (str(TENANT_A), f"asset-{uuid.uuid4().hex[:6]}",
                 f"{uuid.uuid4().hex[:8]}.example.com",
                 f"{uuid.uuid4().hex[:8]}.example.com"),
            )
            asset_id = cur.fetchone()["id"]
        result = confirm_exposure(
            conn, TENANT_A,
            ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                            evidence={"source": "analyst", "note": "c"}),
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return result.exposure.id


# ===========================================================================
# Happy path
# ===========================================================================


class TestHappyPath:
    def test_real_p2_leaf_derives_8_end_to_end(self):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            result = derive_sss_vrt_for_finding(
                conn, TENANT_A, finding_id,
                vrt_id=P2_LEAF_ID,
                evidence=EVIDENCE,
                actor_id="analyst-a", actor_role="analyst",
            )
        assert result["value"] == Decimal("8.0000")
        assert result["path"] == "vrt"
        assert result["version"] == PINNED_VRT_RELEASE

        rows = _current_derivation_row(finding_id)
        assert len(rows) == 1
        assert rows[0]["is_current"] is True
        assert rows[0]["value"] == Decimal("8.0000")
        assert rows[0]["version_text"] == PINNED_VRT_RELEASE

        cls = _classification_row(finding_id)
        assert cls["vrt_id"] == P2_LEAF_ID
        assert cls["vrt_priority"] == "P2"
        assert cls["version_id_ref"] is not None

        intrinsic = current_sss_intrinsic_of(finding_id)
        assert intrinsic.value == Decimal("8.0000")
        assert intrinsic.derivation == f"sss_vrt:{PINNED_VRT_RELEASE}"

    def test_tes_read_resolves_intrinsic_with_derived_vrt_provenance(self):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            derive_sss_vrt_for_finding(
                conn, TENANT_A, finding_id,
                vrt_id=P2_LEAF_ID,
                evidence=EVIDENCE,
                actor_id="analyst-a", actor_role="analyst",
            )
        exposure_id = _confirm_episode(finding_id)
        payload = _tes_payload(exposure_id)
        assert payload["source_view"]["sss"]["path"] == "vrt"
        assert payload["source_view"]["sss"]["provenance"] == "derived"
        assert payload["source_view"]["cvss_unscoreable_reason_code"] is None
        assert payload["state"] in ("PROVISIONAL", "FINAL")
        intrinsic_row = [r for r in payload["decomposition"]
                         if r["axis"] == "intrinsic"][0]
        assert intrinsic_row["state"] == "known"
        assert intrinsic_row["raw_value"] == {"__decimal__": "8.0000"}


def current_sss_intrinsic_of(finding_id):
    with get_db_connection() as conn:
        return current_sss_intrinsic(conn, TENANT_A, finding_id)


# ===========================================================================
# Server-side leaf resolution (fail-closed)
# ===========================================================================


class TestServerSideLeafResolution:
    def test_unknown_leaf_id_fails_closed_and_writes_nothing(self):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="unknown VRT leaf id"):
                derive_sss_vrt_for_finding(
                    conn, TENANT_A, finding_id,
                    vrt_id="totally.made.up.leaf",
                    evidence=EVIDENCE,
                    actor_id="analyst-a", actor_role="analyst",
                )
        assert _current_derivation_row(finding_id) == []
        assert _classification_row(finding_id)["vrt_id"] is None

    def test_disagreeing_priority_claim_fails_closed_and_writes_nothing(self):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="disagrees"):
                derive_sss_vrt_for_finding(
                    conn, TENANT_A, finding_id,
                    vrt_id=P2_LEAF_ID,
                    vrt_priority="P1",
                    evidence=EVIDENCE,
                    actor_id="analyst-a", actor_role="analyst",
                )
        assert _current_derivation_row(finding_id) == []

    def test_matching_priority_claim_is_accepted(self):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            result = derive_sss_vrt_for_finding(
                conn, TENANT_A, finding_id,
                vrt_id=P2_LEAF_ID,
                vrt_priority="P2",
                evidence=EVIDENCE,
                actor_id="analyst-a", actor_role="analyst",
            )
        assert result["value"] == Decimal("8.0000")

    def test_varies_leaf_fails_closed_without_approved_resolver(self):
        from app.exposure.sss import _vrt_leaf_priorities
        varies_leaf = next(
            k for k, v in _vrt_leaf_priorities().items() if v == "varies")
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="varies"):
                derive_sss_vrt_for_finding(
                    conn, TENANT_A, finding_id,
                    vrt_id=varies_leaf,
                    evidence=EVIDENCE,
                    actor_id="analyst-a", actor_role="analyst",
                )
        assert _current_derivation_row(finding_id) == []


# ===========================================================================
# Gates
# ===========================================================================


class TestGates:
    def test_non_blflaw_classification_refused(self):
        finding_id = _make_classified_finding(taxonomy=TAX_IDENTITY)
        with get_db_connection() as conn:
            with pytest.raises(SssNotExploitShapedError, match="BLFLAW"):
                derive_sss_vrt_for_finding(
                    conn, TENANT_A, finding_id,
                    vrt_id=P2_LEAF_ID,
                    evidence=EVIDENCE,
                    actor_id="analyst-a", actor_role="analyst",
                )
        assert _current_derivation_row(finding_id) == []

    def test_cve_backed_finding_refused(self):
        from tests.test_p03_cve_intelligence_resolvers import _canon
        from app.exposure.service import allocate_finding_for_cve
        with get_db_connection() as conn:
            _canon(conn, "CVE-2026-6002")
            fid = allocate_finding_for_cve(
                conn, TENANT_A, "CVE-2026-6002",
                default_title="CVE finding", default_severity="high",
                actor_id="system", actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(SssClassificationError, match="canonical_cve_id"):
                derive_sss_vrt_for_finding(
                    conn, TENANT_A, fid,
                    vrt_id=P2_LEAF_ID,
                    evidence=EVIDENCE,
                    actor_id="analyst-a", actor_role="analyst",
                )

    def test_missing_version_row_fails_closed(self):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM sss_derivation_versions "
                    "WHERE version_id = %s;",  # test DB only
                    (PINNED_VRT_RELEASE,),
                )
            conn.commit()
            with pytest.raises(SssProductionDisabledError):
                derive_sss_vrt_for_finding(
                    conn, TENANT_A, finding_id,
                    vrt_id=P2_LEAF_ID,
                    evidence=EVIDENCE,
                    actor_id="analyst-a", actor_role="analyst",
                )
        assert _current_derivation_row(finding_id) == []

    def test_cross_tenant_finding_is_the_same_not_found(self):
        finding_id = _make_classified_finding(tenant=TENANT_A)
        with get_db_connection() as conn:
            with pytest.raises(SssNotFoundError):
                derive_sss_vrt_for_finding(
                    conn, TENANT_B, finding_id,
                    vrt_id=P2_LEAF_ID,
                    evidence=EVIDENCE,
                    actor_id="analyst-b", actor_role="analyst",
                )


# ===========================================================================
# Route boundary (thin: authorization + error mapping)
# ===========================================================================


class TestRoute:
    def _post(self, client, headers, finding_id, body):
        return client.post(
            f"/api/exposure/findings/{finding_id}/sss/derive-vrt",
            json=body, headers=headers,
        )

    def test_happy_route_201(self, client, auth_headers_tenant_a_analyst):
        finding_id = _make_classified_finding()
        res = self._post(
            client, auth_headers_tenant_a_analyst, finding_id,
            {"vrt_id": P2_LEAF_ID, "evidence": EVIDENCE},
        )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["value"] == {"__decimal__": "8.0000"}
        assert body["path"] == "vrt"
        assert body["version"] == PINNED_VRT_RELEASE

    def test_unknown_leaf_is_422(self, client, auth_headers_tenant_a_analyst):
        finding_id = _make_classified_finding()
        res = self._post(
            client, auth_headers_tenant_a_analyst, finding_id,
            {"vrt_id": "not.a.real.leaf", "evidence": EVIDENCE},
        )
        assert res.status_code == 422
        assert "unknown VRT leaf id" in res.text

    def test_mismatched_claim_is_422(self, client, auth_headers_tenant_a_analyst):
        finding_id = _make_classified_finding()
        res = self._post(
            client, auth_headers_tenant_a_analyst, finding_id,
            {"vrt_id": P2_LEAF_ID, "vrt_priority": "P1", "evidence": EVIDENCE},
        )
        assert res.status_code == 422
        assert "disagrees" in res.text

    def test_missing_version_row_is_409_fail_closed(
            self, client, auth_headers_tenant_a_analyst):
        finding_id = _make_classified_finding()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM sss_derivation_versions WHERE version_id = %s;",
                    (PINNED_VRT_RELEASE,),
                )
            conn.commit()
        res = self._post(
            client, auth_headers_tenant_a_analyst, finding_id,
            {"vrt_id": P2_LEAF_ID, "evidence": EVIDENCE},
        )
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "sss_production_disabled"

    def test_cross_tenant_is_identical_404(self, client, auth_headers_tenant_b_admin):
        finding_id = _make_classified_finding(tenant=TENANT_A)
        res = self._post(
            client, auth_headers_tenant_b_admin, finding_id,
            {"vrt_id": P2_LEAF_ID, "evidence": EVIDENCE},
        )
        assert res.status_code == 404
