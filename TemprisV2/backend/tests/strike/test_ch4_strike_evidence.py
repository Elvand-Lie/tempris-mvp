# backend/tests/strike/test_ch4_strike_evidence.py
"""
Chapter 4 acceptance — evidence promotion into the Ch.3 §3.3.3 contract
(PATCH-01, D-7/D-8, principle 8; Appendix C Q3) and the Ch.3 cross-module
check.

PRD-derived checklist covered here:
  * promotion requires a TERMINAL, OBSERVED operation — failed/inconclusive/
    cancelled/unresolved operations are refused (only real validated
    evidence may affect controlled-validation state);
  * the write-time classification is CONSTRAINED (D-7): basis 'validated' ⇒
    controlled_validation (180d); basis 'observed' ⇒ observed_exploitation
    (365d) ONLY with an attestation naming the actually observed compromise
    — a successful test alone never qualifies;
  * the Ch.3 record is written by the existing Ch.3 command with
    producer='strike' (the closed allowlist), the STRIKE CONTROL PLANE as
    producer (D-8) — never the workspace — and reviewed_by is the
    authenticated actor (server-owned);
  * the evidence binds the EXACT CURRENT confirmed exposure episode
    (Ch.3's own fail-closed gate; resolved/unknown/cross-tenant exposures
    refuse);
  * the link row is immutable and single-source per operation; replay is
    idempotent;
  * Ch.3 cross-module check: after promotion the exposure's scoring-input
    snapshot (read through the FULL app) shows the strike evidence eligible
    — the ER 10.0 pickup path (Flow A step 7→8) is Ch.3's recompute, fed by
    this record.
"""
from __future__ import annotations

import uuid

import pytest

from app.db import get_db_connection
from app.strike import operations as strike_operations
from app.strike import workspaces as strike_workspaces
from tests.strike.conftest import seed_ability, take_engagement_active

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")

VALIDATED_ATTESTATION = (
    "Analyst-reviewed controlled validation against the scoped target; "
    "artifacts hash-verified and consistent with the operation record."
)
OBSERVED_ATTESTATION = (
    "Observed live compromise: the validation payload executed on the target "
    "and returned an interactive result during the engagement window."
)


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


def stub_provision(reservation):
    return f"prov://vm/{reservation['workspace_id']}"


def stub_dispatch(operation):
    return f"eng://{operation['id']}"


@pytest.fixture
def confirmed_exposure(client, admin_headers):
    """One confirmed exposure on an active asset (via the Ch.3 routes — the
    shared full-app client)."""
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, 'strike-validation-anchor', 'server', 'ip',
                          '10.0.0.60', '10.0.0.60', 'internal', 'production', 'high', 'active');
                """,
                (str(asset_id), str(TENANT_A)),
            )
            cur.execute(
                """
                INSERT INTO canonical_vulnerabilities (cve_id, state, assigner_short_name)
                VALUES ('CVE-2026-70001', 'PUBLISHED', 'test-cna')
                ON CONFLICT (cve_id) DO NOTHING;
                """
            )
        conn.commit()

    r = client.post(
        "/api/exposure/findings",
        json={"title": "Strike validated exposure", "severity": "high",
              "canonical_cve_id": "CVE-2026-70001"},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    finding_id = r.json()["id"]
    r = client.post(
        "/api/exposure/confirm",
        json={"finding_id": finding_id, "asset_id": str(asset_id),
              "evidence": {"reference": "strike-e2e-seed"}},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    return {"exposure_id": r.json()["id"], "finding_id": finding_id, "asset_id": asset_id}


def drive_observed_operation(
    strike_client, analyst_headers, admin_headers, monkeypatch, *, asset_id
) -> dict:
    """Engagement → active → live workspace → running operation → completed
    OBSERVED (all provider/engine seams stubbed green)."""
    ids = take_engagement_active(
        strike_client, analyst_headers, admin_headers, asset_id=asset_id
    )
    monkeypatch.setattr(strike_workspaces, "provider_provision", stub_provision)
    r = strike_client.post(
        f"/api/strike/engagements/{ids['engagement_id']}/workspaces",
        json={}, headers=analyst_headers,
    )
    assert r.status_code == 201, r.text
    workspace = r.json()
    assert workspace["state"] == "ready"

    r = strike_client.post(
        f"/api/strike/workspaces/{workspace['id']}/in-use", headers=analyst_headers
    )
    assert r.status_code == 200

    ability_id = seed_ability()
    monkeypatch.setattr(strike_operations, "engine_dispatch", stub_dispatch)
    r = strike_client.post(
        f"/api/strike/engagements/{ids['engagement_id']}/operations",
        json={
            "target_id": ids["target_id"],
            "ability_id": str(ability_id),
            "workspace_id": workspace["id"],
            "params": {},
        },
        headers=analyst_headers,
    )
    assert r.status_code == 201, r.text
    operation = r.json()
    assert operation["state"] == "running"

    r = strike_client.post(
        f"/api/strike/operations/{operation['id']}/complete",
        json={"outcome": "OBSERVED", "summary": "validation result collected"},
        headers=analyst_headers,
    )
    assert r.status_code == 200, r.text
    return {"operation": r.json(), "ids": ids, "workspace": workspace}


@pytest.fixture
def observed_operation(strike_client, analyst_headers, admin_headers, monkeypatch, confirmed_exposure):
    return drive_observed_operation(
        strike_client, analyst_headers, admin_headers, monkeypatch,
        asset_id=confirmed_exposure["asset_id"],
    )


def promote(strike_client, analyst_headers, operation_id, exposure_id, *, basis="validated", attestation=VALIDATED_ATTESTATION):
    return strike_client.post(
        "/api/strike/evidence",
        json={
            "operation_id": operation_id,
            "exposure_id": str(exposure_id),
            "basis": basis,
            "attestation": attestation,
        },
        headers=analyst_headers,
    )


# ---------------------------------------------------------------------------
# The happy path — the only score-affecting path STRIKE has
# ---------------------------------------------------------------------------


class TestPromotionHappyPath:
    def test_validated_basis_creates_ch3_record_and_immutable_link(
        self, strike_client, analyst_headers, confirmed_exposure, observed_operation
    ):
        operation = observed_operation["operation"]
        r = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["evidence_kind"] == "controlled_validation"   # D-7 write-time rule
        assert body["outcome"] == "created"
        link = body["link"]
        assert link["reviewed_by"] == "analyst-a"                 # server-owned reviewer
        assert link["attestation"]

        # the Ch.3 record: producer = the STRIKE CONTROL PLANE (D-8),
        # source identity = the operation
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT producer, evidence_kind, source_object_type,
                           source_object_id, reviewed_by, evidence
                    FROM exposure_exploitation_evidence WHERE id = %s;
                    """,
                    (body["evidence_record_id"],),
                )
                row = cur.fetchone()
        assert row["producer"] == "strike"
        assert row["evidence_kind"] == "controlled_validation"
        assert row["source_object_type"] == "strike_operation"
        assert row["source_object_id"] == operation["id"]
        assert row["reviewed_by"] == "analyst-a"
        assert row["evidence"]["producer_plane"] == "strike_control_plane"
        assert row["evidence"]["strike_engagement_id"]

        # the link row is immutable
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(Exception, match="immutable"):
                    cur.execute(
                        "UPDATE strike_evidence_links SET evidence_kind = 'x' WHERE id = %s;",
                        (link["id"],),
                    )
                conn.rollback()

    def test_observed_basis_requires_a_real_compromise_attestation(
        self, strike_client, analyst_headers, confirmed_exposure, observed_operation
    ):
        operation = observed_operation["operation"]
        # a bare "it worked" never qualifies (a successful test alone is not
        # an observed compromise)
        r = promote(
            strike_client, analyst_headers, operation["id"],
            confirmed_exposure["exposure_id"],
            basis="observed", attestation="it worked",
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "evidence_promotion_refused"

        # an attestation naming the actually observed compromise event does
        r = promote(
            strike_client, analyst_headers, operation["id"],
            confirmed_exposure["exposure_id"],
            basis="observed", attestation=OBSERVED_ATTESTATION,
        )
        assert r.status_code == 201, r.text
        assert r.json()["evidence_kind"] == "observed_exploitation"

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT evidence_kind FROM exposure_exploitation_evidence WHERE id = %s;",
                    (r.json()["evidence_record_id"],),
                )
                assert cur.fetchone()["evidence_kind"] == "observed_exploitation"

    def test_replay_is_idempotent_single_record(
        self, strike_client, analyst_headers, confirmed_exposure, observed_operation
    ):
        operation = observed_operation["operation"]
        r1 = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r1.status_code == 201
        r2 = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r2.status_code == 201
        assert r2.json()["outcome"] == "replay"
        assert r1.json()["evidence_record_id"] == r2.json()["evidence_record_id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM exposure_exploitation_evidence "
                    "WHERE source_object_type = 'strike_operation' AND source_object_id = %s;",
                    (operation["id"],),
                )
                assert cur.fetchone()["n"] == 1


# ---------------------------------------------------------------------------
# Refusals — observed exploitation is never fabricated
# ---------------------------------------------------------------------------


class TestPromotionRefusals:
    def test_inconclusive_operation_refused(
        self, strike_client, analyst_headers, admin_headers, monkeypatch, confirmed_exposure
    ):
        ids = take_engagement_active(
            strike_client, analyst_headers, admin_headers, asset_id=confirmed_exposure["asset_id"]
        )
        monkeypatch.setattr(strike_workspaces, "provider_provision", stub_provision)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        workspace = r.json()
        strike_client.post(
            f"/api/strike/workspaces/{workspace['id']}/in-use", headers=analyst_headers
        )
        ability_id = seed_ability()
        monkeypatch.setattr(strike_operations, "engine_dispatch", stub_dispatch)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/operations",
            json={
                "target_id": ids["target_id"], "ability_id": str(ability_id),
                "workspace_id": workspace["id"], "params": {},
            },
            headers=analyst_headers,
        )
        operation = r.json()
        # the engine could not establish the result
        r = strike_client.post(
            f"/api/strike/operations/{operation['id']}/complete",
            json={"outcome": "INCONCLUSIVE", "summary": "ambiguous result"},
            headers=analyst_headers,
        )
        assert r.status_code == 200
        r = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "evidence_promotion_refused"

    def test_failed_error_operation_refused(
        self, strike_client, analyst_headers, admin_headers, monkeypatch, confirmed_exposure
    ):
        """Engine/transport failure (outcome ERROR) never becomes evidence —
        failed attempts never create a rung."""
        ids = take_engagement_active(
            strike_client, analyst_headers, admin_headers, asset_id=confirmed_exposure["asset_id"]
        )
        monkeypatch.setattr(strike_workspaces, "provider_provision", stub_provision)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        workspace = r.json()
        strike_client.post(
            f"/api/strike/workspaces/{workspace['id']}/in-use", headers=analyst_headers
        )
        ability_id = seed_ability()
        # the shipped default: no engine integrated → dispatch fails ERROR
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/operations",
            json={
                "target_id": ids["target_id"], "ability_id": str(ability_id),
                "workspace_id": workspace["id"], "params": {},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201, r.text
        operation = r.json()
        assert operation["state"] == "failed"
        assert operation["outcome"] == "ERROR"
        r = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "evidence_promotion_refused"

    def test_unresolved_operation_refused(
        self, strike_client, analyst_headers, admin_headers, monkeypatch, confirmed_exposure
    ):
        """A still-running operation is not a validated result."""
        ids = take_engagement_active(
            strike_client, analyst_headers, admin_headers, asset_id=confirmed_exposure["asset_id"]
        )
        monkeypatch.setattr(strike_workspaces, "provider_provision", stub_provision)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/workspaces",
            json={}, headers=analyst_headers,
        )
        workspace = r.json()
        strike_client.post(
            f"/api/strike/workspaces/{workspace['id']}/in-use", headers=analyst_headers
        )
        ability_id = seed_ability()
        monkeypatch.setattr(strike_operations, "engine_dispatch", stub_dispatch)
        r = strike_client.post(
            f"/api/strike/engagements/{ids['engagement_id']}/operations",
            json={
                "target_id": ids["target_id"], "ability_id": str(ability_id),
                "workspace_id": workspace["id"], "params": {},
            },
            headers=analyst_headers,
        )
        operation = r.json()
        assert operation["state"] == "running"
        r = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r.status_code == 422

    def test_unknown_operation_is_identical_404(
        self, strike_client, analyst_headers, confirmed_exposure
    ):
        r = promote(
            strike_client, analyst_headers, str(uuid.uuid4()),
            confirmed_exposure["exposure_id"],
        )
        assert r.status_code == 404

    def test_cross_tenant_or_unknown_exposure_is_identical_404(
        self, strike_client, analyst_headers, observed_operation
    ):
        operation = observed_operation["operation"]
        r = promote(
            strike_client, analyst_headers, operation["id"], str(uuid.uuid4())
        )
        assert r.status_code == 404  # Ch.3's fail-closed identical not-found

    def test_resolved_episode_refused_by_ch3_gate(
        self, strike_client, analyst_headers, confirmed_exposure, observed_operation
    ):
        """The exact-exposure rule: the episode must be CURRENT confirmed.
        A resolved episode refuses (Ch.3 owns the gate and its conflict
        surface — the episode exists but is no longer current)."""
        exposure_id = confirmed_exposure["exposure_id"]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE asset_exposures SET status = 'resolved'
                    WHERE tenant_id = %s AND id = %s;
                    """,
                    (str(TENANT_A), str(exposure_id)),
                )
            conn.commit()

        operation = observed_operation["operation"]
        r = promote(strike_client, analyst_headers, operation["id"], exposure_id)
        assert r.status_code == 409  # not a CURRENT confirmed episode (Ch.3)
        assert r.json()["detail"]["code"] == "exposure_conflict"


# ---------------------------------------------------------------------------
# Ch.3 cross-module check — the record feeds the ER recompute
# ---------------------------------------------------------------------------


class TestCh3CrossModulePickup:
    def test_scoring_inputs_snapshot_shows_eligible_strike_evidence(
        self, client, strike_client, analyst_headers, confirmed_exposure, observed_operation
    ):
        operation = observed_operation["operation"]
        r = promote(
            strike_client, analyst_headers, operation["id"], confirmed_exposure["exposure_id"]
        )
        assert r.status_code == 201

        # read through the FULL app: the Ch.3 scoring-input snapshot carries
        # the strike record with producer, kind, and eligibility
        r = client.get(
            f"/api/exposure/{confirmed_exposure['exposure_id']}/scoring-inputs",
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        snapshot = r.json()
        evidence_rows = snapshot["exploitation_evidence"]
        assert evidence_rows, "the strike evidence must appear in the Ch.3 ledger"
        entry = next(
            e for e in evidence_rows if e["record"]["producer"] == "strike"
        )
        assert entry["record"]["evidence_kind"] == "controlled_validation"
        assert entry["eligible"] is True
        assert entry["ttl_days"] == 180
