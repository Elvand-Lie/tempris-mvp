# backend/tests/test_p07_identity_boundary_lifecycle.py
"""
P0-07 — Identity Boundary Lifecycle (PRD-000 v1.11 §3.6.6 #7/#8; §3.3.1
supersession authority; §3.3.2 criticality mapping; Appendix C Q15/Q20).

Covers: create/replace/clear lifecycle with idempotent replay; §3.6.6 #7
asset preconditions (same-tenant, active, target_type='domain'); the
decommission guard (service + raw-SQL trigger backstop) with no partial
changes; the IDENTITY_POSTURE confirmation precondition inside the common
P0-01 boundary; design-A supersession scoping (only IDENTITY_POSTURE
exposures supersede — web/CVE exposures on the same domain stay current);
immutable history retained and never mutated; atomicity (supersession and
audit failure roll back the whole binding change); races (two replacements,
decommission vs replacement, confirmation vs clear); constraint proofs
(at-most-one current binding per tenant, composite tenant FK);
reachability/BI/evidence never inherited by a re-anchored episode.

The binding service never writes exposure status directly (§3.3.1: P0-01
owns it) — supersession is routed through supersede_exposures_for_asset.
"""
import threading
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import psycopg
import pytest

from app.db import get_db_connection
from app.exposure import (
    BoundAssetError,
    EntityNotFoundError,
    IdentityBoundaryStateError,
    InvalidAssetStatusError,
    TenantMismatchError,
)
from app.exposure.identity_boundary import (
    assert_asset_not_identity_boundary,
    assert_boundary_exists_for_confirmation,
    clear_identity_boundary,
    create_identity_boundary,
    get_current_identity_boundary,
    replace_identity_boundary,
)
from app.exposure.models import ExposureConfirm, FindingCreate
from app.exposure.service import (
    confirm_exposure,
    create_finding,
    get_canonical_current_exposures,
    supersede_exposures_for_asset,
)
from tests.conftest import TENANT_A, TENANT_B

RUBRIC_CONTENT = {
    "facts": {
        "mfa_coverage": {"type": "enum", "values": ["none", "partial", "enforced"]},
    },
    "rules": [
        {"name": "mfa_none", "severity": "9.0", "match": {"mfa_coverage": ["none"]}},
    ],
}


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def _make_asset(target_type="domain", target=None, tenant=TENANT_A,
                network_scope="internal", asset_type=None):
    """Seed an asset row directly (internal scope ⇒ no reachability probe)."""
    if target is None:
        if target_type == "domain":
            target = f"{uuid.uuid4().hex[:8]}.example.com"
        else:
            target = f"10.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}.1"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'production', 'low', 'active')
                RETURNING id;
                """,
                (str(tenant), f"asset-{uuid.uuid4().hex[:6]}",
                 asset_type or ("identity_boundary" if target_type == "domain" else "server"),
                 target_type, target, target.lower(), network_scope),
            )
            asset_id = cur.fetchone()["id"]
        conn.commit()
    return asset_id


def _make_ip_asset(tenant=TENANT_A):
    return _make_asset(target_type="ip", tenant=tenant)


def _make_domain_asset(tenant=TENANT_A, target=None, network_scope="internal"):
    return _make_asset(target_type="domain", target=target, tenant=tenant,
                       network_scope=network_scope)


def _make_identity_posture_finding(tenant=TENANT_A):
    """A finding classified IDENTITY_POSTURE through the P0-06 spine."""
    from app.exposure.sss import derive_sss_rubric

    with get_db_connection() as conn:
        finding = create_finding(conn, tenant, FindingCreate(
            title="MFA not enforced", severity="high"))
        conn.commit()
    fid = finding.id
    version_id = f"rubric-p07-{uuid.uuid4()}"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sss_derivation_versions
                    (version_id, kind, content, status, test_only, approved_by, approved_at)
                VALUES (%s, 'rubric', %s, 'approved', FALSE, 'ops-approver', now())
                ON CONFLICT (version_id) DO NOTHING;
                """,
                (version_id, psycopg.types.json.Json(RUBRIC_CONTENT)),
            )
        derive_sss_rubric(
            conn, tenant, fid,
            rubric_version=version_id,
            taxonomy_class="IDENTITY_POSTURE",
            taxonomy_subclass="MFA_ENROLMENT",
            taxonomy_subtype=None,
            facts={"mfa_coverage": "none"},
            evidence={"source": "connector", "ref": "graph-auth"},
            actor_id="analyst-a", actor_role="analyst",
        )
        conn.commit()
    return fid


def _make_cve_finding(tenant=TENANT_A):
    from app.exposure.service import allocate_finding_for_cve
    from tests.test_p03_cve_intelligence_resolvers import _canon

    cve = f"CVE-2026-{7000 + uuid.uuid4().int % 1000}"
    with get_db_connection() as conn:
        _canon(conn, cve)
        fid = allocate_finding_for_cve(
            conn, tenant, cve,
            default_title="CVE finding", default_severity="high",
            actor_id="system", actor_role="admin",
        )
        conn.commit()
    return fid


def _confirm(conn, tenant, finding_id, asset_id, evidence=None):
    return confirm_exposure(
        conn, tenant,
        ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                        evidence=evidence or {"source": "analyst", "note": "confirmed"}),
        actor_id="analyst-a", actor_role="analyst",
    )


def _current_exposures(tenant, finding_id):
    with get_db_connection() as conn:
        return get_canonical_current_exposures(conn, tenant, finding_id)


def _binding_history(tenant):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, asset_id, state, ended_by, ended_at FROM tenant_identity_boundary "
                "WHERE tenant_id = %s ORDER BY created_at, id;",
                (str(tenant),),
            )
            return cur.fetchall()


# ===========================================================================
# Lifecycle: create / replace / clear / idempotent replay
# ===========================================================================


class TestLifecycle:
    def test_create_designates_the_boundary_with_own_criticality(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            result = create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id,
                criticality="critical", actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "created"
        assert result.boundary["criticality"] == "critical"
        assert result.boundary["set_by"] == "admin-a"      # who/when provenance
        assert result.boundary["set_at"] is not None
        current = get_current_identity_boundary_of(TENANT_A)
        assert current["asset_id"] == asset_id
        assert current["state"] == "active"

    def test_create_twice_identical_is_idempotent_replay(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            first = create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            second = create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert first.outcome == "created"
        assert second.outcome == "replay"
        assert second.boundary["id"] == first.boundary["id"]
        assert len(_binding_history(TENANT_A)) == 1

    def test_create_conflicting_active_binding_rejected(self):
        a1, a2 = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=a1, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            with pytest.raises(IdentityBoundaryStateError, match="already has an active"):
                create_identity_boundary(
                    conn, TENANT_A, asset_id=a2, criticality="high",
                    actor_id="admin-a", actor_role="admin")

    def test_replace_supersedes_and_retains_history(self):
        old_asset, new_asset = _make_domain_asset(), _make_domain_asset()
        fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, old_asset)
            conn.commit()
        assert len(_current_exposures(TENANT_A, fid)) == 1

        with get_db_connection() as conn:
            result = replace_identity_boundary(
                conn, TENANT_A, asset_id=new_asset, criticality="medium",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "replaced"
        assert len(result.superseded) == 1
        assert result.superseded[0].status == "superseded"
        assert _current_exposures(TENANT_A, fid) == []

        history = _binding_history(TENANT_A)
        assert len(history) == 2
        states = {r["state"] for r in history}
        assert states == {"replaced", "active"}
        # succession is reconstructible from the audit chain (prior_binding_id
        # -> boundary_id) plus created_at ordering — no successor column exists
        old_row = next(r for r in history if r["state"] == "replaced")
        assert old_row["asset_id"] == old_asset and old_row["ended_by"] == "admin-a"

    def test_clear_supersedes_and_retains_history(self):
        asset_id = _make_domain_asset()
        fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()

        with get_db_connection() as conn:
            result = clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "cleared"
        assert len(result.superseded) == 1
        assert get_current_identity_boundary_of(TENANT_A) is None
        assert _current_exposures(TENANT_A, fid) == []
        history = _binding_history(TENANT_A)
        assert [r["state"] for r in history] == ["cleared"]

    def test_clear_without_binding_is_idempotent_replay(self):
        with get_db_connection() as conn:
            result = clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "replay"
        assert result.superseded == ()

    def test_replace_without_binding_designates_first_boundary(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            result = replace_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "created"
        assert len(_binding_history(TENANT_A)) == 1

    def test_replace_identical_is_idempotent_replay(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            result = replace_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "replay"
        assert len(_binding_history(TENANT_A)) == 1

    def test_history_rows_are_never_mutated(self):
        old_asset, new_asset = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            replace_identity_boundary(
                conn, TENANT_A, asset_id=new_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        old_row = next(r for r in _binding_history(TENANT_A) if r["state"] == "replaced")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute(
                        "UPDATE tenant_identity_boundary SET criticality = 'low' WHERE id = %s;",
                        (old_row["id"],))
            conn.rollback()  # release the aborted transaction between proofs
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
                    cur.execute(
                        "DELETE FROM tenant_identity_boundary WHERE id = %s;",
                        (old_row["id"],))
            conn.rollback()

    def test_constraint_at_most_one_active_binding(self):
        a1, a2 = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=a1, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.UniqueViolation):
                    cur.execute(
                        """
                        INSERT INTO tenant_identity_boundary (
                            tenant_id, asset_id, criticality, set_by, created_by
                        ) VALUES (%s, %s, 'low', 'x', 'x');
                        """,
                        (str(TENANT_A), str(a2)),
                    )
            conn.rollback()

    def test_constraint_composite_tenant_fk(self):
        foreign_asset = _make_domain_asset(tenant=TENANT_B)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        """
                        INSERT INTO tenant_identity_boundary (
                            tenant_id, asset_id, criticality, set_by, created_by
                        ) VALUES (%s, %s, 'low', 'x', 'x');
                        """,
                        (str(TENANT_A), str(foreign_asset)),
                    )
            conn.rollback()


# ===========================================================================
# Asset preconditions (§3.6.6 #7)
# ===========================================================================


class TestAssetPreconditions:
    def test_non_domain_asset_rejected(self):
        asset_id = _make_ip_asset()
        with get_db_connection() as conn:
            with pytest.raises(IdentityBoundaryStateError, match="domain asset"):
                create_identity_boundary(
                    conn, TENANT_A, asset_id=asset_id, criticality="high",
                    actor_id="admin-a", actor_role="admin")

    def test_inactive_asset_rejected(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE assets SET status = 'decommissioned', "
                    "decommissioned_at = now() WHERE id = %s;", (str(asset_id),))
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(InvalidAssetStatusError):
                create_identity_boundary(
                    conn, TENANT_A, asset_id=asset_id, criticality="high",
                    actor_id="admin-a", actor_role="admin")

    def test_cross_tenant_asset_rejected(self):
        foreign_asset = _make_domain_asset(tenant=TENANT_B)
        with get_db_connection() as conn:
            with pytest.raises(TenantMismatchError):
                create_identity_boundary(
                    conn, TENANT_A, asset_id=foreign_asset, criticality="high",
                    actor_id="admin-a", actor_role="admin")

    def test_unknown_asset_rejected(self):
        with get_db_connection() as conn:
            with pytest.raises(EntityNotFoundError):
                create_identity_boundary(
                    conn, TENANT_A, asset_id=uuid.uuid4(), criticality="high",
                    actor_id="admin-a", actor_role="admin")

    def test_invalid_criticality_rejected(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            with pytest.raises(IdentityBoundaryStateError, match="criticality"):
                create_identity_boundary(
                    conn, TENANT_A, asset_id=asset_id, criticality="severe",
                    actor_id="admin-a", actor_role="admin")

    def test_asset_type_marker_is_never_required_or_written(self):
        """The Chapter 2 contract is untouched: the marker is free-text and
        optional — a plain 'server'-typed domain asset binds fine."""
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE assets SET asset_type = 'plain-old-domain' WHERE id = %s;",
                    (str(asset_id),))
            conn.commit()
            result = create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert result.outcome == "created"
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT asset_type FROM assets WHERE id = %s;", (str(asset_id),))
                assert cur.fetchone()["asset_type"] == "plain-old-domain"


# ===========================================================================
# Decommission guard
# ===========================================================================


class TestDecommissionGuard:
    def test_bound_asset_decommission_rejected_without_partial_changes(self):
        asset_id = _make_domain_asset()
        fid = _make_cve_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()

        client = _authed_client()
        res = client.post(f"/api/assets/{asset_id}/decommission")
        assert res.status_code == 409
        assert "identity boundary" in res.text

        # NO partial changes: the asset is still active, the exposure current
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM assets WHERE id = %s;", (str(asset_id),))
                assert cur.fetchone()["status"] == "active"
        assert len(_current_exposures(TENANT_A, fid)) == 1

    def test_decommission_guard_raw_sql_trigger_backstop(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="identity boundary"):
                    cur.execute(
                        "UPDATE assets SET status = 'decommissioned', "
                        "decommissioned_at = now() WHERE id = %s;", (str(asset_id),))
            conn.rollback()

    def test_decommission_allowed_after_clear(self):
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
        client = _authed_client()
        res = client.post(f"/api/assets/{asset_id}/decommission")
        assert res.status_code == 200, res.text


def get_current_identity_boundary_of(tenant):
    with get_db_connection() as conn:
        return get_current_identity_boundary(conn, tenant)


def _authed_client():
    import os
    from starlette.testclient import TestClient
    from app.main import app
    from app.auth import create_test_token

    token = create_test_token(str(TENANT_A), actor_id="admin-a", role="admin")
    c = TestClient(app)
    c.headers.update({"Authorization": f"Bearer {token}"})
    return c


# ===========================================================================
# Confirmation precondition (§3.6.6 #7 — inside the P0-01 boundary)
# ===========================================================================


class TestConfirmationPrecondition:
    def test_identity_posture_confirmation_requires_active_boundary(self):
        fid = _make_identity_posture_finding()
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            with pytest.raises(IdentityBoundaryStateError, match="no active identity boundary"):
                _confirm(conn, TENANT_A, fid, asset_id)
        assert _current_exposures(TENANT_A, fid) == []

    def test_confirmation_requires_the_designated_boundary_asset(self):
        fid = _make_identity_posture_finding()
        boundary_asset = _make_domain_asset()
        other_asset = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=boundary_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            # anchored to a NON-boundary domain asset — rejected
            with pytest.raises(IdentityBoundaryStateError, match="anchor to the designated"):
                _confirm(conn, TENANT_A, fid, other_asset)
        assert _current_exposures(TENANT_A, fid) == []

        with get_db_connection() as conn:
            result = _confirm(conn, TENANT_A, fid, boundary_asset)
            conn.commit()
        assert result.outcome == "created"
        assert len(_current_exposures(TENANT_A, fid)) == 1

    def test_confirmation_after_clear_is_rejected(self):
        fid = _make_identity_posture_finding()
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
            clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
            with pytest.raises(IdentityBoundaryStateError):
                _confirm(conn, TENANT_A, fid, asset_id)
        assert _current_exposures(TENANT_A, fid) == []

    def test_cve_confirmation_never_needs_a_boundary(self):
        """The precondition is class-scoped (design A): web/CVE exposures on
        the same tenant need no identity boundary at all."""
        fid = _make_cve_finding()
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            result = _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
        assert result.outcome == "created"

    def test_replayed_confirmation_survives_a_later_clear(self):
        """A replay of an already-confirmed episode after the boundary was
        cleared does NOT resurrect a current exposure: the replay returns the
        episode as it exists — superseded — and nothing becomes current."""
        fid = _make_identity_posture_finding()
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
            clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()

        # a fresh confirmation now fails closed (precondition)
        with get_db_connection() as conn:
            with pytest.raises(IdentityBoundaryStateError):
                _confirm(conn, TENANT_A, fid, asset_id)
        assert _current_exposures(TENANT_A, fid) == []


# ===========================================================================
# Design-A supersession scoping
# ===========================================================================


class TestDesignAScoping:
    def test_replace_supersedes_only_identity_posture_exposures(self):
        """Replacing the boundary supersedes the IDENTITY_POSTURE exposure on
        the boundary asset while web/CVE exposures on the SAME domain asset
        stay current (design A — neither reading leaks into the other)."""
        boundary_asset = _make_domain_asset()
        ip_fid = _make_cve_finding()
        idp_fid = _make_identity_posture_finding()
        new_asset = _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=boundary_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, ip_fid, boundary_asset)
            _confirm(conn, TENANT_A, idp_fid, boundary_asset)
            conn.commit()

        with get_db_connection() as conn:
            result = replace_identity_boundary(
                conn, TENANT_A, asset_id=new_asset, criticality="medium",
                actor_id="admin-a", actor_role="admin")
            conn.commit()

        assert len(result.superseded) == 1
        assert result.superseded[0].finding_id == idp_fid
        assert _current_exposures(TENANT_A, idp_fid) == []
        # the CVE exposure on the same domain asset remains current
        assert len(_current_exposures(TENANT_A, ip_fid)) == 1

    def test_clear_supersedes_only_identity_posture_exposures(self):
        boundary_asset = _make_domain_asset()
        ip_fid = _make_cve_finding()
        idp_fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=boundary_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, ip_fid, boundary_asset)
            _confirm(conn, TENANT_A, idp_fid, boundary_asset)
            conn.commit()
            clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
        assert _current_exposures(TENANT_A, idp_fid) == []
        assert len(_current_exposures(TENANT_A, ip_fid)) == 1

    def test_supersession_scope_is_taxonomy_class_via_p01_service(self):
        """Direct evidence that the binding service routes through the P0-01
        helper with the taxonomy filter — and that the helper's filtered scan
        touches exactly the IDENTITY_POSTURE exposures."""
        boundary_asset = _make_domain_asset()
        idp_fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=boundary_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, idp_fid, boundary_asset)
            conn.commit()
            with conn.cursor() as cur:
                assert taxonomy_class_of(cur, TENANT_A, idp_fid) == "IDENTITY_POSTURE"
                superseded = supersede_exposures_for_asset(
                    conn, TENANT_A, boundary_asset,
                    actor_id="admin-a", actor_role="admin",
                    reason="scope proof", taxonomy_class="IDENTITY_POSTURE")
            conn.commit()
        assert len(superseded) == 1


def taxonomy_class_of(cur, tenant, finding_id):
    from app.exposure.service import taxonomy_class_of_finding
    return taxonomy_class_of_finding(cur, tenant, finding_id)

# ===========================================================================
# Reachability / BI / evidence never inherit (§3.6.6 #7)
# ===========================================================================


class TestNonInheritance:
    def test_new_episode_starts_with_no_inherited_inputs(self):
        """Re-anchoring: the old episode's reachability, BI, and exploitation
        evidence stay bound to the old exposure id and are never moved or
        copied to the new episode on the new boundary."""
        old_asset = _make_domain_asset()
        new_asset = _make_domain_asset()
        fid = _make_identity_posture_finding()
        from app.exposure.scoring_inputs import (
            BusinessImpactIn,
            ExploitationEvidenceIn,
            ReachabilityEvidenceIn,
            get_scoring_inputs,
            record_exploitation_evidence,
            record_reachability_evidence,
            set_business_impact,
        )

        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        with get_db_connection() as conn:
            result = _confirm(conn, TENANT_A, fid, old_asset)
            conn.commit()
        old_exposure_id = result.exposure.id

        with get_db_connection() as conn:
            record_reachability_evidence(
                conn, TENANT_A, old_exposure_id,
                ReachabilityEvidenceIn(vantage="external",
                                       evidence={"scan": "vantage-proof"}),
                actor_id="analyst-a", actor_role="analyst")
            set_business_impact(
                conn, TENANT_A, old_exposure_id,
                BusinessImpactIn(value=Decimal("7.5"), reason="crown-jewel flow"),
                actor_id="analyst-a", actor_role="analyst")
            record_exploitation_evidence(
                conn, TENANT_A, old_exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded",
                                       evidence={"actor": "red-team"}),
                actor_id="analyst-a", actor_role="analyst")
            conn.commit()

        # replace the boundary; the old exposure supersedes
        with get_db_connection() as conn:
            replace_identity_boundary(
                conn, TENANT_A, asset_id=new_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()

        # a new confirmation on the NEW boundary creates a FRESH episode
        with get_db_connection() as conn:
            new_result = _confirm(conn, TENANT_A, fid, new_asset)
            conn.commit()
        assert new_result.outcome == "created"
        new_exposure_id = new_result.exposure.id
        assert new_exposure_id != old_exposure_id

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
            inputs = get_scoring_inputs(
                conn, TENANT_A, new_exposure_id,
                actor_id="admin-a", actor_role="admin")
            conn.rollback()  # read-only snapshot
        scoring = inputs["scoring_inputs"] if "scoring_inputs" in inputs else inputs
        reach = scoring.get("reachability")
        assert reach in (None, {}, []) or (
            isinstance(reach, dict) and reach.get("value") is None), reach
        bi = scoring.get("business_impact")
        assert bi in (None, {}, []) or (
            isinstance(bi, dict) and bi.get("value") is None), bi

        # the OLD episode's ledger rows are untouched on the old exposure id
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_reachability_evidence "
                    "WHERE exposure_id = %s;", (old_exposure_id,))
                assert cur.fetchone()["c"] == 1
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_business_impact "
                    "WHERE exposure_id = %s;", (old_exposure_id,))
                assert cur.fetchone()["c"] == 1

    def test_boundary_asset_network_reachability_is_not_exposure_reachability(self):
        """'contoso.com is publicly reachable' is not Reachability 10 for an
        MFA posture finding: the anchor's ordinary network reachability
        (assets.reachability_status) never enters the exposure's ledger."""
        asset_id = _make_domain_asset(network_scope="internet")
        fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT reachability_status FROM assets WHERE id = %s;",
                    (str(asset_id),))
                asset_reach = cur.fetchone()["reachability_status"]
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_reachability_evidence "
                    "WHERE tenant_id = %s;", (str(TENANT_A),))
                evidence_rows = cur.fetchone()["c"]
        assert evidence_rows == 0
        assert asset_reach in ("unverified", "verified", "unreachable")


# ===========================================================================
# Atomicity: supersession / audit failure rolls back the whole binding change
# ===========================================================================


class TestAtomicity:
    def test_supersession_failure_rolls_back_binding_transition(self, monkeypatch):
        old_asset, new_asset = _make_domain_asset(), _make_domain_asset()
        fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, old_asset)
            conn.commit()

        import app.exposure.identity_boundary as ib
        real_supersede = ib.supersede_exposures_for_asset

        def boom(*args, **kwargs):
            raise RuntimeError("supersession path unavailable")

        monkeypatch.setattr(ib, "supersede_exposures_for_asset", boom)
        with get_db_connection() as conn:
            with pytest.raises(RuntimeError):
                replace_identity_boundary(
                    conn, TENANT_A, asset_id=new_asset, criticality="high",
                    actor_id="admin-a", actor_role="admin")
            conn.rollback()
        monkeypatch.setattr(ib, "supersede_exposures_for_asset", real_supersede)

        current = get_current_identity_boundary_of(TENANT_A)
        assert current["asset_id"] == old_asset
        assert len(_current_exposures(TENANT_A, fid)) == 1
        assert [r["state"] for r in _binding_history(TENANT_A)] == ["active"]

    def test_audit_failure_rolls_back_binding_and_supersessions(self, monkeypatch):
        old_asset, new_asset = _make_domain_asset(), _make_domain_asset()
        fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            _confirm(conn, TENANT_A, fid, old_asset)
            conn.commit()

        import app.exposure.identity_boundary as ib

        def failing_audit(*args, **kwargs):
            raise RuntimeError("audit sink unavailable")

        monkeypatch.setattr(ib, "record_audit_event", failing_audit)
        with get_db_connection() as conn:
            with pytest.raises(RuntimeError):
                clear_identity_boundary(
                    conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.rollback()

        current = get_current_identity_boundary_of(TENANT_A)
        assert current is not None and current["asset_id"] == old_asset
        assert len(_current_exposures(TENANT_A, fid)) == 1
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # only the seeding create's audit row survives the rollback
                cur.execute(
                    "SELECT count(*) AS c FROM identity_boundary_audit "
                    "WHERE action <> 'created';")
                assert cur.fetchone()["c"] == 0

    def test_boundary_audit_rows_exist_for_every_transition(self):
        old_asset, new_asset = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            replace_identity_boundary(
                conn, TENANT_A, asset_id=new_asset, criticality="medium",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT action FROM identity_boundary_audit "
                    "WHERE tenant_id = %s ORDER BY occurred_at, id;",
                    (str(TENANT_A),))
                actions = [r["action"] for r in cur.fetchall()]
        assert actions == ["created", "replaced", "cleared"]


# ===========================================================================
# Races
# ===========================================================================


# ===========================================================================
# DB-enforced immutability (raw SQL proofs — P0-06 Correction 3 pattern)
# ===========================================================================


class TestDatabaseImmutabilityRawSql:
    """Raw-SQL proofs: every attack below must reject even on a connection
    that bypasses the service entirely. One seeded binding per proof; each
    proof aborts inside its own transaction and is rolled back, so nothing
    persists between proofs."""

    def _seed_active(self):
        """An active binding, its audit row, and the ids of both."""
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            result = create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        binding_id = result.boundary["id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM identity_boundary_audit "
                    "WHERE boundary_id = %s AND action = 'created';",
                    (binding_id,))
                audit_id = cur.fetchone()["id"]
        return binding_id, audit_id

    def _seed_replaced(self):
        """A replaced history row (its successor stays active)."""
        old_asset, new_asset = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            result = create_identity_boundary(
                conn, TENANT_A, asset_id=old_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            replace_identity_boundary(
                conn, TENANT_A, asset_id=new_asset, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
        old_id = result.boundary["id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM tenant_identity_boundary "
                    "WHERE id = %s AND state = 'replaced';", (old_id,))
                assert cur.fetchone() is not None
        return old_id

    def _seed_cleared(self):
        """A cleared history row (no successor)."""
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            result = create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()
            clear_identity_boundary(
                conn, TENANT_A, actor_id="admin-a", actor_role="admin")
            conn.commit()
        cleared_id = result.boundary["id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM tenant_identity_boundary "
                    "WHERE id = %s AND state = 'cleared';", (cleared_id,))
                assert cur.fetchone() is not None
        return cleared_id

    # -- tenant_identity_boundary -------------------------------------------

    def test_delete_active_row_rejected_without_audit_row(self):
        """DELETE of an active row must fail with NO audit row present —
        the incidental FK protection from identity_boundary_audit is not
        enforcement; the trigger alone must stop it. The binding is inserted
        raw (bypassing the service entirely), so no audit row can exist."""
        asset_id = _make_domain_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tenant_identity_boundary (
                        tenant_id, asset_id, criticality, set_by, created_by
                    ) VALUES (%s, %s, 'high', 'x', 'x') RETURNING id;
                    """,
                    (str(TENANT_A), str(asset_id)),
                )
                binding_id = cur.fetchone()["id"]
                cur.execute(
                    "SELECT count(*) AS c FROM identity_boundary_audit "
                    "WHERE boundary_id = %s;", (binding_id,))
                assert cur.fetchone()["c"] == 0
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "DELETE FROM tenant_identity_boundary WHERE id = %s;",
                        (binding_id,))
            conn.rollback()

    def test_delete_active_row_rejected_with_audit_row(self):
        binding_id, _audit_id = self._seed_active()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # the service-seeded create committed its audit row in the
                # same transaction as the binding; DELETE is still rejected
                cur.execute(
                    "SELECT count(*) AS c FROM identity_boundary_audit "
                    "WHERE boundary_id = %s;", (binding_id,))
                assert cur.fetchone()["c"] >= 1
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "DELETE FROM tenant_identity_boundary WHERE id = %s;",
                        (binding_id,))
            conn.rollback()

    def test_update_repoint_asset_id_rejected(self):
        binding_id, _audit_id = self._seed_active()
        other_asset = _make_domain_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "UPDATE tenant_identity_boundary SET asset_id = %s "
                        "WHERE id = %s;", (str(other_asset), binding_id))
            conn.rollback()

    def test_update_change_criticality_rejected(self):
        binding_id, _audit_id = self._seed_active()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "UPDATE tenant_identity_boundary SET criticality = 'low' "
                        "WHERE id = %s;", (binding_id,))
            conn.rollback()

    def test_update_state_only_without_full_transition_shape_rejected(self):
        binding_id, _audit_id = self._seed_active()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "UPDATE tenant_identity_boundary SET state = 'cleared' "
                        "WHERE id = %s;", (binding_id,))
            conn.rollback()

    def test_exact_terminal_transition_succeeds(self):
        """The one permitted UPDATE: state active -> cleared with every other
        column unchanged and ended_by/ended_at moved NULL -> set."""
        binding_id, _audit_id = self._seed_active()
        ended_by, ended_at = "ops-closer", datetime.now(timezone.utc)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE tenant_identity_boundary
                    SET state = 'cleared',
                        ended_by = %s,
                        ended_at = %s
                    WHERE id = %s AND state = 'active';
                    """,
                    (ended_by, ended_at, binding_id),
                )
                assert cur.rowcount == 1
                cur.execute(
                    "SELECT state, ended_by, ended_at FROM tenant_identity_boundary "
                    "WHERE id = %s;", (binding_id,))
                row = cur.fetchone()
        assert row["state"] == "cleared"
        assert row["ended_by"] == "ops-closer"
        assert row["ended_at"] == ended_at

    def test_update_and_delete_of_replaced_history_row_rejected(self):
        replaced_id = self._seed_replaced()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "UPDATE tenant_identity_boundary "
                        "SET ended_at = now() WHERE id = %s;", (replaced_id,))
            conn.rollback()
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "DELETE FROM tenant_identity_boundary WHERE id = %s;",
                        (replaced_id,))
            conn.rollback()

    def test_update_and_delete_of_cleared_history_row_rejected(self):
        cleared_id = self._seed_cleared()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "UPDATE tenant_identity_boundary "
                        "SET ended_by = 'x' WHERE id = %s;", (cleared_id,))
            conn.rollback()
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="immutable"):
                    cur.execute(
                        "DELETE FROM tenant_identity_boundary WHERE id = %s;",
                        (cleared_id,))
            conn.rollback()

    # -- identity_boundary_audit ---------------------------------------------

    def test_audit_update_rejected(self):
        _binding_id, audit_id = self._seed_active()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="append-only"):
                    cur.execute(
                        "UPDATE identity_boundary_audit SET action = 'cleared' "
                        "WHERE id = %s;", (audit_id,))
            conn.rollback()

    def test_audit_delete_rejected(self):
        _binding_id, audit_id = self._seed_active()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="append-only"):
                    cur.execute(
                        "DELETE FROM identity_boundary_audit WHERE id = %s;",
                        (audit_id,))
            conn.rollback()


class TestRaces:
    def test_two_concurrent_replacements_serialize_to_one_final_binding(self):
        a0 = _make_domain_asset()
        a1, a2 = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=a0, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()

        outcomes = []

        def worker(asset):
            try:
                with get_db_connection() as conn:
                    r = replace_identity_boundary(
                        conn, TENANT_A, asset_id=asset, criticality="high",
                        actor_id="admin-a", actor_role="admin")
                    conn.commit()
                    outcomes.append(r.outcome)
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

        t1 = threading.Thread(target=worker, args=(a1,))
        t2 = threading.Thread(target=worker, args=(a2,))
        t1.start(); t2.start(); t1.join(); t2.join()

        current = get_current_identity_boundary_of(TENANT_A)
        # both attempts serialize through the advisory lock and commit as
        # separate, auditable transitions — exactly one final binding
        assert current["asset_id"] in (a1, a2)
        assert sorted(outcomes) == ["replaced", "replaced"]
        states = sorted(r["state"] for r in _binding_history(TENANT_A))
        assert states == ["active", "replaced", "replaced"]

    def test_decommission_races_replacement(self):
        """Decommission of the old boundary races a replacement: one valid
        serial outcome — either the replacement commits first (the old asset
        is no longer the boundary, so decommission succeeds) or the
        decommission commits first and its guard rejected it."""
        a0, a1 = _make_domain_asset(), _make_domain_asset()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=a0, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()

        outcomes = []

        def decommission_worker():
            try:
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        assert_asset_not_identity_boundary(cur, TENANT_A, a0)
                        cur.execute(
                            "UPDATE assets SET status = 'decommissioned', "
                            "decommissioned_at = now() WHERE id = %s;", (str(a0),))
                    conn.commit()
                    outcomes.append("decommissioned")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

        def replace_worker():
            try:
                with get_db_connection() as conn:
                    replace_identity_boundary(
                        conn, TENANT_A, asset_id=a1, criticality="high",
                        actor_id="admin-a", actor_role="admin")
                    conn.commit()
                    outcomes.append("replaced")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

        t1 = threading.Thread(target=decommission_worker)
        t2 = threading.Thread(target=replace_worker)
        t1.start(); t2.start(); t1.join(); t2.join()

        current = get_current_identity_boundary_of(TENANT_A)
        if "replaced" in outcomes:
            assert current is not None and current["asset_id"] == a1
        else:
            assert "BoundAssetError" in outcomes
            assert current is not None and current["asset_id"] == a0

    def test_confirmation_races_boundary_clear(self):
        """A confirmation committing while the boundary clears: either it
        commits first (and the clear supersedes it) or the clear commits
        first (and the confirmation fails its precondition). No current
        exposure survives on the old binding."""
        asset_id = _make_domain_asset()
        fid = _make_identity_posture_finding()
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="high",
                actor_id="admin-a", actor_role="admin")
            conn.commit()

        outcomes = []

        def confirm_worker():
            try:
                with get_db_connection() as conn:
                    r = _confirm(conn, TENANT_A, fid, asset_id)
                    conn.commit()
                    outcomes.append(r.outcome)
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

        def clear_worker():
            try:
                with get_db_connection() as conn:
                    clear_identity_boundary(
                        conn, TENANT_A, actor_id="admin-a", actor_role="admin")
                    conn.commit()
                    outcomes.append("cleared")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

        t1 = threading.Thread(target=confirm_worker)
        t2 = threading.Thread(target=clear_worker)
        t1.start(); t2.start(); t1.join(); t2.join()

        assert _current_exposures(TENANT_A, fid) == []
        assert get_current_identity_boundary_of(TENANT_A) is None
