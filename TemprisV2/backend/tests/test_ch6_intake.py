# backend/tests/test_ch6_intake.py
"""
Focused suite for Chapter 6 — Intake & Triage (PRD-000 v1.11 Ch.6).

Covers: closed intake taxonomy; the record lifecycle (submitted →
under_review → confirmed | rejected | duplicate | needs_info); evidence- and
anchor-required confirmation; the exposure-history duplicate rules (current ⇒
duplicate 409 + reference, resolved ⇒ recurrence, false_positive ⇒ fresh
re-review, superseded ⇒ anchor re-resolution); connectors/STRIKE/VDP as
intake sources that never create findings; PATCH-07 source-event replay
identity; analyst+ authority; tenant isolation; audit.
"""
from __future__ import annotations

import uuid

import pytest

from app.db import get_db_connection
from app.exposure.models import ExposureResolve
from app.exposure.service import resolve_exposure
from tests.conftest import TENANT_A, TENANT_B


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def create_asset_in_db(
    tenant_id: uuid.UUID = TENANT_A,
    name: str = "intake-anchor-01",
    status: str = "active",
) -> uuid.UUID:
    asset_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    id, tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, %s, 'server', 'ip', '10.0.0.50', '10.0.0.50',
                          'internal', 'production', 'medium', %s);
                """,
                (str(asset_id), str(tenant_id), name, status),
            )
        conn.commit()
    return asset_id


def seed_cve(cve_id: str = "CVE-2026-60001") -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO canonical_vulnerabilities (cve_id, state, assigner_short_name)
                VALUES (%s, 'PUBLISHED', 'test-cna')
                ON CONFLICT (cve_id) DO NOTHING;
                """,
                (cve_id,),
            )
        conn.commit()
    return cve_id


def fetch_audit_events(tenant_id: uuid.UUID, event_name: str) -> list[dict]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, event_name, details, created_at
                FROM audit_events
                WHERE tenant_id = %s AND event_name = %s
                ORDER BY created_at DESC;
                """,
                (str(tenant_id), event_name),
            )
            return [dict(r) for r in cur.fetchall()]


def finding_count(tenant_id: uuid.UUID) -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE tenant_id = %s;",
                (str(tenant_id),),
            )
            return cur.fetchone()["n"]


def insert_historical_registration(
    tenant_id: uuid.UUID = TENANT_A,
    name: str = "historical-sink",
    adapter: str = "entra_authentication_methods",
) -> str:
    """A registration written directly to the DB: rows must stay
    readable and keep admitting records through the operator relay."""
    registration_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO intake_connector_registrations (
                    id, tenant_id, name, adapter, status, destination_routing,
                    payload_semantics, created_by
                ) VALUES (%s, %s, %s, %s, 'active', '{"queue": "intake"}'::jsonb,
                          'historical registration', 'analyst-a')
                ON CONFLICT (tenant_id, name) DO UPDATE SET status = 'active';
                """,
                (str(registration_id), str(tenant_id), name, adapter),
            )
        conn.commit()
    return str(registration_id)


def submit_intake(
    client,
    headers,
    *,
    source="MANUAL",
    title="Broken access control on /admin",
    severity="high",
    payload=None,
    taxonomy=None,
    canonical_cve_id=None,
    asset_id=None,
    registration_id=None,
    event_id=None,
):
    body = {
        "source": source,
        "title": title,
        "severity": severity,
        "payload": payload if payload is not None else {"report": "idors"},
    }
    if taxonomy:
        body["taxonomy"] = taxonomy
    if canonical_cve_id:
        body["canonical_cve_id"] = canonical_cve_id
    if asset_id:
        body["asset_id"] = str(asset_id)
    if registration_id:
        body["source_registration_id"] = registration_id
    if event_id:
        body["source_event_id"] = event_id
    return client.post("/api/intake", json=body, headers=headers)


def move_to_review(client, headers, record_id, taxonomy=("BLFLAW", None, "IDOR")):
    """submit → under_review → classified (the confirmation precondition)."""
    r = client.post(f"/api/intake/{record_id}/start-review", json={}, headers=headers)
    assert r.status_code == 200, r.text
    cls, sub, typ = taxonomy
    taxonomy_body = {"taxonomy": {"taxonomy_class": cls}}
    if sub is not None:
        taxonomy_body["taxonomy"]["taxonomy_subclass"] = sub
    if typ is not None:
        taxonomy_body["taxonomy"]["taxonomy_subtype"] = typ
    # the rationale is mandatory — every classification is an append-only decision
    taxonomy_body["rationale"] = "test fixture: classification rationale"
    r = client.post(f"/api/intake/{record_id}/classify", json=taxonomy_body, headers=headers)
    assert r.status_code == 200, r.text


def confirm_intake(client, headers, record_id, asset_id, **overrides):
    body = {
        "asset_id": str(asset_id),
        "evidence": {"reference": "report-42", "observed": "admin panel reachable"},
        **overrides,
    }
    return client.post(f"/api/intake/{record_id}/confirm", json=body, headers=headers)


@pytest.fixture
def tenant_a_analyst(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def tenant_b_admin(auth_headers_tenant_b_admin):
    return auth_headers_tenant_b_admin


# ---------------------------------------------------------------------------
# Creation, sources, closed taxonomy
# ---------------------------------------------------------------------------


class TestIntakeCreation:
    def test_manual_record_created_tenant_stamped_never_a_finding(self, client, tenant_a_analyst):
        before = finding_count(TENANT_A)
        r = submit_intake(client, tenant_a_analyst)
        assert r.status_code == 201, r.text
        assert r.headers["X-Intake-Outcome"] == "created"
        record = r.json()
        assert record["tenant_id"] == str(TENANT_A)
        assert record["state"] == "submitted"
        assert record["requested_by"] == "analyst-a"
        assert record["payload_digest"]
        assert record["finding_id"] is None and record["exposure_id"] is None
        assert finding_count(TENANT_A) == before  # an intake record is NOT a finding
        assert fetch_audit_events(TENANT_A, "intake.created")

    def test_source_vocabulary_is_closed(self, client, tenant_a_analyst):
        r = submit_intake(client, tenant_a_analyst, source="SCOUT")
        assert r.status_code == 422  # SCOUT has its own confirmation path (Ch.2/Ch.3)

    def test_arbitrary_taxonomy_rejected_at_intake(self, client, tenant_a_analyst):
        r = submit_intake(client, tenant_a_analyst, taxonomy={"taxonomy_class": "WEIRD_CLASS"})
        assert r.status_code == 422

    def test_strike_discovery_enters_intake_as_a_record(self, client, tenant_a_analyst):
        before = finding_count(TENANT_A)
        r = submit_intake(
            client, tenant_a_analyst,
            source="STRIKE_DISCOVERY",
            title="Credential replay on admin flow",
            payload={
                "operation_id": "op-abc-123",
                "artifact_refs": ["artifact-9"],
                "engagement": "purple-team-q4",
            },
            taxonomy={"taxonomy_class": "IDENTITY_POSTURE", "taxonomy_subclass": "AUTH_FLOW_ABUSE"},
        )
        assert r.status_code == 201, r.text
        record = r.json()
        assert record["source"] == "STRIKE_DISCOVERY"
        assert record["state"] == "submitted"
        assert finding_count(TENANT_A) == before  # Flow C: no direct finding creation

    def test_connector_requires_an_active_registration(self, client, tenant_a_analyst):
        r = submit_intake(
            client, tenant_a_analyst, source="CONNECTOR",
            payload={"observations": [1, 2, 3]},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["code"] == "connector_registration"

        registration_id = insert_historical_registration(name="entra-sync")
        r = submit_intake(
            client, tenant_a_analyst, source="CONNECTOR",
            payload={"observations": [1, 2, 3]},
            registration_id=registration_id,
        )
        assert r.status_code == 201, r.text
        assert r.json()["source_registration_id"] == registration_id

    def test_connector_registration_is_tenant_scoped(self, client, tenant_a_analyst, tenant_b_admin):
        registration_id = insert_historical_registration(
            tenant_id=TENANT_B, name="b-connector"
        )
        r = submit_intake(
            client, tenant_a_analyst, source="CONNECTOR",
            payload={}, registration_id=registration_id,
        )
        assert r.status_code == 404  # another tenant's registration is invisible

    def test_registration_creation_succeeds_and_is_tenant_visible(
        self, client, tenant_a_analyst
    ):
        # v1: registrations are admission records; no adapter executes yet.
        r = client.post(
            "/api/intake/connectors",
            json={"name": "reg-my-custom-plugin", "adapter": "my-custom-plugin",
                  "destination_routing": {"queue": "intake"},
                  "payload_semantics": "routing stored as a note"},
            headers=tenant_a_analyst,
        )
        assert r.status_code == 201, r.text
        created = r.json()
        assert created["name"] == "reg-my-custom-plugin"
        assert created["adapter"] == "my-custom-plugin"
        assert created["status"] == "active"
        assert created["destination_routing"] == {"queue": "intake"}
        listing = client.get("/api/intake/connectors", headers=tenant_a_analyst)
        assert listing.status_code == 200
        assert "reg-my-custom-plugin" in {c["name"] for c in listing.json()}

        # CONNECTOR submission through the created registration enters as an
        # intake RECORD — never a finding.
        before = finding_count(TENANT_A)
        submit = submit_intake(
            client, tenant_a_analyst, source="CONNECTOR",
            title="connector payload",
            payload={"observations": [1, 2, 3]},
            registration_id=created["id"],
        )
        assert submit.status_code == 201, submit.text
        record = submit.json()
        assert record["source_registration_id"] == created["id"]
        assert record["finding_id"] is None and record["exposure_id"] is None
        assert finding_count(TENANT_A) == before

    def test_historical_registration_still_admits_records_via_the_relay(
        self, client, tenant_a_analyst
    ):
        # the operator relay (the only v1 path) keeps working against a
        # HISTORICAL registration: observation payloads enter as intake
        # RECORDS — never findings — and the replay identity still holds
        before = finding_count(TENANT_A)
        registration_id = insert_historical_registration(
            name="aev-primary", adapter="aev_verdicts"
        )
        r = submit_intake(
            client, tenant_a_analyst, source="CONNECTOR",
            title="AEV verdict: credential replay observed",
            payload={"verdict": "observed", "engagement": "eng-7"},
            registration_id=registration_id, event_id="aev-evt-1",
        )
        assert r.status_code == 201, r.text
        record = r.json()
        assert record["source"] == "CONNECTOR"
        assert record["state"] == "submitted"
        assert record["finding_id"] is None and record["exposure_id"] is None
        assert finding_count(TENANT_A) == before

        # identical replay returns the original record, never a new episode
        replay = submit_intake(
            client, tenant_a_analyst, source="CONNECTOR",
            title="AEV verdict: credential replay observed",
            payload={"verdict": "observed", "engagement": "eng-7"},
            registration_id=registration_id, event_id="aev-evt-1",
        )
        assert replay.status_code == 200
        assert replay.headers["X-Intake-Outcome"] == "replay"
        assert replay.json()["id"] == record["id"]

    def test_event_identity_requires_registration(self, client, tenant_a_analyst):
        body = {
            "source": "VDP", "title": "x", "severity": "low",
            "payload": {}, "source_event_id": "evt-1",
        }
        r = client.post("/api/intake", json=body, headers=tenant_a_analyst)
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# PATCH-07 replay identity
# ---------------------------------------------------------------------------


class TestSourceEventReplay:
    def test_identical_replay_returns_the_original_outcome(self, client, tenant_a_analyst):
        first = submit_intake(
            client, tenant_a_analyst, source="THREAT_PACK",
            payload={"pack": "lockbit-2026-04"}, event_id="evt-77",
            registration_id="strike-workspace-1",
        )
        assert first.status_code == 201
        replay = submit_intake(
            client, tenant_a_analyst, source="THREAT_PACK",
            payload={"pack": "lockbit-2026-04"}, event_id="evt-77",
            registration_id="strike-workspace-1",
        )
        assert replay.status_code == 200
        assert replay.headers["X-Intake-Outcome"] == "replay"
        assert replay.json()["id"] == first.json()["id"]

    def test_conflicting_payload_under_same_event_id_is_a_409(self, client, tenant_a_analyst):
        submit_intake(
            client, tenant_a_analyst, source="THREAT_PACK",
            payload={"pack": "a"}, event_id="evt-88",
            registration_id="strike-workspace-1",
        )
        conflict = submit_intake(
            client, tenant_a_analyst, source="THREAT_PACK",
            payload={"pack": "DIFFERENT"}, event_id="evt-88",
            registration_id="strike-workspace-1",
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "intake_event_conflict"


# ---------------------------------------------------------------------------
# Lifecycle: review, classify, info, reject
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_full_review_lifecycle(self, client, tenant_a_analyst):
        record_id = submit_intake(client, tenant_a_analyst).json()["id"]

        r = client.post(
            f"/api/intake/{record_id}/classify",
            json={
                "taxonomy": {"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
                "rationale": "test fixture: invoice export lacks an ownership check",
            },
            headers=tenant_a_analyst,
        )
        assert r.status_code == 200  # classification allowed before review starts
        r = client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        assert r.status_code == 200
        assert r.json()["state"] == "under_review"

        r = client.post(
            f"/api/intake/{record_id}/request-info",
            json={"deficiency": "no reproduction steps supplied"},
            headers=tenant_a_analyst,
        )
        assert r.status_code == 200
        assert r.json()["state"] == "needs_info"
        assert r.json()["deficiency"] == "no reproduction steps supplied"

        r = client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        assert r.status_code == 200
        assert r.json()["state"] == "under_review"

        events = client.get(f"/api/intake/{record_id}/events", headers=tenant_a_analyst).json()
        assert [e["event"] for e in events] == [
            "created", "classified", "review_started", "info_requested", "review_started",
        ]

    def test_reject_requires_reason_and_is_terminal(self, client, tenant_a_analyst):
        record_id = submit_intake(client, tenant_a_analyst).json()["id"]
        r = client.post(
            f"/api/intake/{record_id}/reject",
            json={"reason": "not a security issue — test traffic"},
            headers=tenant_a_analyst,
        )
        assert r.status_code == 200
        assert r.json()["state"] == "rejected"
        r = client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        assert r.status_code == 409

    def test_confirm_from_submitted_fails_closed(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst,
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "intake_state"

    def test_unclassified_record_cannot_confirm(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        record_id = submit_intake(client, tenant_a_analyst).json()["id"]
        client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert "unclassified" in r.json()["detail"]["message"]

    def test_needs_info_record_cannot_confirm(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst,
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)
        client.post(
            f"/api/intake/{record_id}/request-info",
            json={"deficiency": "no reproduction steps supplied"},
            headers=tenant_a_analyst,
        )
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "intake_state"
        # the hold is recoverable: back to review, then confirmation succeeds
        client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "confirmed"


# ---------------------------------------------------------------------------
# Append-only classification history (§6:1141/1149)
# ---------------------------------------------------------------------------


class TestClassificationHistory:
    def test_blank_rationale_is_rejected(self, client, tenant_a_analyst):
        record_id = submit_intake(client, tenant_a_analyst).json()["id"]
        r = client.post(
            f"/api/intake/{record_id}/classify",
            json={
                "taxonomy": {"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
                "rationale": "   ",
            },
            headers=tenant_a_analyst,
        )
        assert r.status_code == 422  # the model validator rejects it before any row is touched

    def test_two_sequential_classifications_preserve_prior_new_actor_rationale(
        self, client, tenant_a_analyst
    ):
        record_id = submit_intake(client, tenant_a_analyst).json()["id"]
        r1 = client.post(
            f"/api/intake/{record_id}/classify",
            json={
                "taxonomy": {"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
                "rationale": "first decision: ownership check missing on export",
            },
            headers=tenant_a_analyst,
        )
        assert r1.status_code == 200, r1.text
        first_snapshot = client.get(
            f"/api/intake/{record_id}/events", headers=tenant_a_analyst
        ).json()
        classified_first = [e for e in first_snapshot if e["event"] == "classified"]
        assert len(classified_first) == 1

        # reclassification: the decision changes on the same record
        r2 = client.post(
            f"/api/intake/{record_id}/classify",
            json={
                "taxonomy": {
                    "taxonomy_class": "IDENTITY_POSTURE",
                    "taxonomy_subclass": "MFA_ENROLMENT",
                },
                "rationale": "second decision: it is an identity-flow abuse, not a business flaw",
            },
            headers=tenant_a_analyst,
        )
        assert r2.status_code == 200, r2.text
        assert r2.json()["taxonomy_class"] == "IDENTITY_POSTURE"

        events = [
            e for e in client.get(
                f"/api/intake/{record_id}/events", headers=tenant_a_analyst
            ).json()
            if e["event"] == "classified"
        ]
        assert len(events) == 2  # append-only: the first event was kept, not revised
        assert events[0] == classified_first[0]  # prior history is untouched

        first, second = events
        # actor and timestamp are the event row's own columns
        assert first["actor"] == "analyst-a" and second["actor"] == "analyst-a"
        assert first["created_at"] <= second["created_at"]

        assert first["detail"]["prior"] == {
            "taxonomy_class": None, "taxonomy_subclass": None, "taxonomy_subtype": None,
        }
        assert first["detail"]["prior_unclassified"] is True
        assert first["detail"]["new"]["taxonomy_class"] == "BLFLAW"
        assert first["detail"]["rationale"] == "first decision: ownership check missing on export"

        assert second["detail"]["prior"] == first["detail"]["new"]
        assert second["detail"]["prior_unclassified"] is False
        assert second["detail"]["new"]["taxonomy_class"] == "IDENTITY_POSTURE"
        assert second["detail"]["rationale"] == (
            "second decision: it is an identity-flow abuse, not a business flaw"
        )

        # the projection holds only the CURRENT classification
        record = client.get(f"/api/intake/{record_id}", headers=tenant_a_analyst).json()
        assert record["taxonomy_class"] == "IDENTITY_POSTURE"
        assert record["taxonomy_subclass"] == "MFA_ENROLMENT"


# ---------------------------------------------------------------------------
# Confirmation: the Ch.3/Ch.7 handoff
# ---------------------------------------------------------------------------


class TestConfirmation:
    def test_confirm_creates_finding_and_exposure_via_ch3(
        self, client, tenant_a_analyst, auth_headers_tenant_a_admin
    ):
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst,
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)

        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200, r.text
        assert r.headers["X-Intake-Outcome"] == "confirmed"
        record = r.json()
        assert record["state"] == "confirmed"
        assert record["anchor_state"] == "resolved"
        assert record["finding_id"] and record["exposure_id"]
        assert record["reviewed_by"] == "analyst-a"

        # the exposure is live on the Ch.3 canonical surface
        current = client.get(
            "/api/exposure/current", headers=auth_headers_tenant_a_admin
        ).json()
        assert str(record["exposure_id"]) in {e["exposure_id"] for e in current}
        assert fetch_audit_events(TENANT_A, "intake.confirmed")
        assert fetch_audit_events(TENANT_A, "exposure.confirmed")

        # SPECTRUM (Ch.7) is the consumer surface: the intake-confirmed
        # exposure is visible on the operational queue and its workbench detail
        queue = client.get("/api/spectrum/queue", headers=tenant_a_analyst)
        assert queue.status_code == 200, queue.text
        row = next(
            i for i in queue.json()["items"]
            if i["exposure_id"] == record["exposure_id"]
        )
        assert row["analysis_state"] == "new"  # untouched by intake post-handoff
        assert row["tes"]["state"] in {"FINAL", "PROVISIONAL", "UNSCOREABLE"}
        detail = client.get(
            f"/api/spectrum/exposures/{record['exposure_id']}", headers=tenant_a_analyst
        )
        assert detail.status_code == 200, detail.text

    def test_confirmation_requires_evidence(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst,
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)
        r = client.post(
            f"/api/intake/{record_id}/confirm",
            json={"asset_id": str(asset_id), "evidence": {}},
            headers=tenant_a_analyst,
        )
        assert r.status_code == 422

    def test_confirmation_requires_an_anchor(self, client, tenant_a_analyst):
        record_id = submit_intake(
            client, tenant_a_analyst,
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)
        r = client.post(
            f"/api/intake/{record_id}/confirm",
            json={"evidence": {"reference": "r1"}},
            headers=tenant_a_analyst,
        )
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "anchor_required"

    def test_anchorless_class_is_held_never_confirmed(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst,
            title="Stale service account with ownerless secret",
            taxonomy={"taxonomy_class": "NHI"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id, taxonomy=("NHI", None, None))
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "anchorless_class"
        # held, not silently blocked: the analyst can park it as needs_info
        r = client.post(
            f"/api/intake/{record_id}/request-info",
            json={"deficiency": "NHI anchor semantics undefined (§3.6.6 #8)"},
            headers=tenant_a_analyst,
        )
        assert r.status_code == 200
        assert r.json()["state"] == "needs_info"

    def test_identity_posture_without_boundary_cannot_confirm(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst,
            title="MFA enrolment abuse",
            taxonomy={"taxonomy_class": "IDENTITY_POSTURE", "taxonomy_subclass": "MFA_ENROLMENT"},
        ).json()["id"]
        move_to_review(
            client, tenant_a_analyst, record_id,
            taxonomy=("IDENTITY_POSTURE", "MFA_ENROLMENT", None),
        )
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "identity_boundary_state"

    def test_cve_intake_reuses_the_tenant_cve_finding(
        self, client, tenant_a_analyst, auth_headers_tenant_a_admin
    ):
        cve = seed_cve()
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst, title="Log4j on edge", canonical_cve_id=cve,
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200, r.text
        exposure = r.json()

        # a second, independent intake of the same CVE reuses the finding
        record_id2 = submit_intake(
            client, tenant_a_analyst, title="Log4j on edge (v2 report)", canonical_cve_id=cve,
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id2)
        r2 = confirm_intake(client, tenant_a_analyst, record_id2, asset_id)
        assert r2.status_code == 409  # current exposure ⇒ duplicate
        body = r2.json()["detail"]
        assert body["duplicate_of_exposure_id"] == exposure["exposure_id"]
        # one finding per canonical CVE, always (the shared allocator)
        assert finding_count(TENANT_A) == 1


# ---------------------------------------------------------------------------
# CVE-backed manual intake — no closed-spine classification required
# ---------------------------------------------------------------------------


def get_record_anchor_state(record_id) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT anchor_state FROM intake_records WHERE id = %s;",
                (str(record_id),),
            )
            return cur.fetchone()["anchor_state"]


def finding_cve_for_record(record_id) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT f.canonical_cve_id FROM intake_records r "
                "JOIN findings f ON f.id = r.finding_id WHERE r.id = %s;",
                (str(record_id),),
            )
            return cur.fetchone()["canonical_cve_id"]


class TestCveBackedIntake:
    def test_cve_record_confirms_without_classification(
        self, client, tenant_a_analyst, auth_headers_tenant_a_admin
    ):
        cve = seed_cve("CVE-2026-61001")
        asset_id = create_asset_in_db(name="cve-anchor-active")
        record_id = submit_intake(
            client, tenant_a_analyst, title="Kafka CVE on edge broker",
            canonical_cve_id=cve, asset_id=asset_id,
        ).json()["id"]

        r = client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "under_review"
        assert get_record_anchor_state(record_id) == "resolved"

        events = client.get(f"/api/intake/{record_id}/events", headers=tenant_a_analyst).json()
        started = next(e for e in events if e["event"] == "review_started")
        assert started["detail"]["anchor_resolved"] is True
        assert started["detail"]["anchor"] == {
            "asset_id": str(asset_id), "status": "active",
        }
        assert started["detail"]["canonical_cve"] == {"cve_id": cve, "state": "PUBLISHED"}

        # the record was never classified — confirmation must not require it
        assert client.get(f"/api/intake/{record_id}", headers=tenant_a_analyst).json()[
            "taxonomy_class"
        ] is None
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200, r.text
        record = r.json()
        assert record["state"] == "confirmed"
        assert record["anchor_state"] == "resolved"
        assert finding_cve_for_record(record_id) == cve  # the CVE allocator ran

        current = client.get(
            "/api/exposure/current", headers=auth_headers_tenant_a_admin
        ).json()
        assert record["exposure_id"] in {e["exposure_id"] for e in current}

    def test_cve_record_without_asset_stays_unresolved_until_confirm(
        self, client, tenant_a_analyst
    ):
        cve = seed_cve("CVE-2026-61002")
        asset_id = create_asset_in_db(name="cve-anchor-late")
        record_id = submit_intake(
            client, tenant_a_analyst, title="Kafka CVE, no anchor yet",
            canonical_cve_id=cve,
        ).json()["id"]

        r = client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        assert r.status_code == 200, r.text
        assert get_record_anchor_state(record_id) == "unresolved"

        events = client.get(f"/api/intake/{record_id}/events", headers=tenant_a_analyst).json()
        started = next(e for e in events if e["event"] == "review_started")
        assert started["detail"]["anchor_resolved"] is False
        assert started["detail"]["anchor"] is None
        assert started["detail"]["canonical_cve"] == {"cve_id": cve, "state": "PUBLISHED"}

        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "confirmed"
        assert r.json()["anchor_state"] == "resolved"

    def test_non_cve_unclassified_confirm_still_raises(self, client, tenant_a_analyst):
        # pin the unchanged non-CVE requirement (classification on the spine)
        asset_id = create_asset_in_db()
        record_id = submit_intake(
            client, tenant_a_analyst, title="Unclassified non-CVE",
        ).json()["id"]
        client.post(f"/api/intake/{record_id}/start-review", json={}, headers=tenant_a_analyst)
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert "unclassified" in r.json()["detail"]["message"]


# ---------------------------------------------------------------------------
# Duplicate rules over the exposure's lifecycle state (PATCH-06 / D-16)
# ---------------------------------------------------------------------------


def _confirmed_record(client, analyst, asset_id, title="Duplicate probe"):
    record_id = submit_intake(
        client, analyst, title=title,
        taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
    ).json()["id"]
    move_to_review(client, analyst, record_id)
    r = confirm_intake(client, analyst, record_id, asset_id)
    assert r.status_code == 200, r.text
    return r.json()


class TestDuplicateRules:
    # The v1 non-CVE finding identity is (title + closed taxonomy triple):
    # an "exact match" report is the SAME title/class on the SAME anchor —
    # the fact-signature scheme is Ch.6 open decision #2.

    def test_current_exposure_is_a_hard_duplicate_with_reference(
        self, client, tenant_a_analyst
    ):
        asset_id = create_asset_in_db()
        first = _confirmed_record(client, tenant_a_analyst, asset_id)

        before = finding_count(TENANT_A)
        dup_id = submit_intake(
            client, tenant_a_analyst, title="Duplicate probe",
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, dup_id)
        r = confirm_intake(client, tenant_a_analyst, dup_id, asset_id)

        assert r.status_code == 409
        body = r.json()["detail"]
        assert body["code"] == "intake_duplicate"
        assert body["duplicate_of_exposure_id"] == first["exposure_id"]
        record = body["record"]
        assert record["state"] == "duplicate"
        assert record["duplicate_of_exposure_id"] == first["exposure_id"]
        # NO duplicate finding is created merely to have something to link
        assert finding_count(TENANT_A) == before

    def test_resolved_exposure_is_a_recurrence_never_a_409(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        first = _confirmed_record(client, tenant_a_analyst, asset_id, title="Recur probe")

        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, uuid.UUID(first["exposure_id"]),
                ExposureResolve(status="resolved", resolution_reason="fixed in v1.2"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()

        record_id = submit_intake(
            client, tenant_a_analyst, title="Recur probe",
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200, r.text  # recurrence: a NEW episode
        assert r.json()["exposure_id"] != first["exposure_id"]

    def test_false_positive_requires_fresh_re_review(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        first = _confirmed_record(client, tenant_a_analyst, asset_id, title="FP probe")

        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, uuid.UUID(first["exposure_id"]),
                ExposureResolve(status="false_positive", resolution_reason="scanner noise"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()

        record_id = submit_intake(
            client, tenant_a_analyst, title="FP probe",
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)

        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "false_positive_re_review_required"

        # the named, audited analyst re-examination unlocks it — never auto
        r = confirm_intake(
            client, tenant_a_analyst, record_id, asset_id,
            revalidate_prior_judgment=True, note="re-verified: real this time",
        )
        assert r.status_code == 200, r.text
        assert r.json()["exposure_id"] != first["exposure_id"]

    def test_superseded_history_requires_anchor_re_resolution(self, client, tenant_a_analyst):
        asset_id = create_asset_in_db()
        first = _confirmed_record(client, tenant_a_analyst, asset_id, title="Superseded probe")

        with get_db_connection() as conn:
            resolve_exposure(
                conn, TENANT_A, uuid.UUID(first["exposure_id"]),
                ExposureResolve(status="resolved", resolution_reason="temporarily closed"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        # Re-confirm (current episode), then supersede everything on the asset
        # via the Ch.3 supersession command (the decommission path normally
        # does this) so the tuple's history touches 'superseded'.
        from app.exposure.service import supersede_exposures_for_asset
        record_id = submit_intake(
            client, tenant_a_analyst, title="Superseded probe",
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)
        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 200
        with get_db_connection() as conn:
            supersede_exposures_for_asset(
                conn, TENANT_A, asset_id,
                actor_id="admin-a", actor_role="admin", reason="asset moved",
            )
            conn.commit()

        record_id = submit_intake(
            client, tenant_a_analyst, title="Superseded probe",
            taxonomy={"taxonomy_class": "BLFLAW", "taxonomy_subtype": "IDOR"},
        ).json()["id"]
        move_to_review(client, tenant_a_analyst, record_id)

        r = confirm_intake(client, tenant_a_analyst, record_id, asset_id)
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "anchor_re_resolution_required"

        r = confirm_intake(
            client, tenant_a_analyst, record_id, asset_id,
            anchor_re_resolved=True, note="anchor re-verified active after move",
        )
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Authority, isolation
# ---------------------------------------------------------------------------


class TestAuthorityAndIsolation:
    def test_platform_session_blocked(self, client, platform_admin_headers):
        r = client.get("/api/intake", headers=platform_admin_headers)
        assert r.status_code == 403

    def test_cross_tenant_record_is_invisible(self, client, tenant_a_analyst, tenant_b_admin):
        record_id = submit_intake(client, tenant_a_analyst).json()["id"]
        r = client.get(f"/api/intake/{record_id}", headers=tenant_b_admin)
        assert r.status_code == 404
        r = client.post(
            f"/api/intake/{record_id}/start-review", json={}, headers=tenant_b_admin
        )
        assert r.status_code == 404

    def test_queues_filter_by_state_and_source(self, client, tenant_a_analyst):
        record_id = submit_intake(client, tenant_a_analyst, source="VDP").json()["id"]
        listing = client.get(
            "/api/intake", params={"state": "submitted", "source": "VDP"},
            headers=tenant_a_analyst,
        ).json()
        assert record_id in {r["id"] for r in listing}
        other = client.get(
            "/api/intake", params={"state": "confirmed"}, headers=tenant_a_analyst
        ).json()
        assert record_id not in {r["id"] for r in other}
