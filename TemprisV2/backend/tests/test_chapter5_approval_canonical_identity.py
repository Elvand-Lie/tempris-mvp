# backend/tests/test_chapter5_approval_canonical_identity.py
"""
CHAPTER 5 DUAL CONTROL ON CANONICAL USER IDENTITY (migration 038 +
app/approvals.py canonical actor resolution).

Production defect (proven live, P0-1/P0-2 of the 2026-09-22 final
reconciliation): login mints sub = user UUID while the decider authority
check matched LOWER(u.email) = actor_id — every real-session admin got 403
approval_authority_missing — and the approver != proposer compare was a RAW
string compare (service + migration-021 trigger), so the same human could
self-approve across token shapes (email sub vs UUID sub).

Every test here FAILS on the pre-fix behavior:

  * UUID-subject decider is authorized (old: 403 authority error);
  * same human, email-shaped vs UUID-shaped actor id, self-approval refused
    in BOTH shape directions (old: approved, or 403 instead of refusal);
  * the migration-038 trigger refuses the same cross-shape self-approval at
    the DB layer (old trigger: raw compare, no refusal);
  * a different human deciding under any token shape still succeeds;
  * apply still requires the approver (executor check unchanged).
"""
import uuid

import psycopg
import pytest

from app.approvals import (
    ApprovalAuthorityError,
    ApprovalDualControlError,
    SubjectHandler,
    _REGISTRY,
    _canonical_hash,
    apply_approval,
    decide,
    propose,
    register_subject_type,
)
from app.db import get_db_connection
from tests.conftest import TENANT_A

SUBJECT_TYPE = "identity_shape_widget"

ADMIN_EMAIL = "admin-a"        # admin in TENANT_A
SUPER_EMAIL = "superadmin-a"   # superadmin in TENANT_A
ANALYST_EMAIL = "analyst-a"    # analyst in TENANT_A

WIDGET_DDL = """
CREATE TABLE IF NOT EXISTS test_identity_widgets (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name    TEXT NOT NULL,
    value   INTEGER NOT NULL DEFAULT 0
);
"""


@pytest.fixture(scope="module", autouse=True)
def _widget_table():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(WIDGET_DDL)
        conn.commit()
    yield
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS test_identity_widgets;")
        conn.commit()


def _user_uuid(email: str) -> str:
    """The canonical users.id (text) of a seeded fixture user — the value a
    production login mints as the token subject."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id::text AS uid FROM users WHERE LOWER(email) = LOWER(%s);",
                (email,),
            )
            row = cur.fetchone()
    assert row is not None, f"fixture user {email!r} missing"
    return row["uid"]


def _make_widget(tenant=TENANT_A):
    wid = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO test_identity_widgets (id, tenant_id, name) "
                "VALUES (%s, %s, %s);",
                (str(wid), str(tenant), "w"),
            )
        conn.commit()
    return wid


def _widget_version(cur, tenant_id, subject_id):
    cur.execute(
        "SELECT xmin::text AS v FROM test_identity_widgets "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    assert row is not None
    return row["v"]


def _validate_payload(cur, tenant_id, subject_id, payload):
    if set(payload) - {"value"} or not isinstance(payload.get("value"), int):
        raise ValueError("payload must be {'value': <int>}")


class _Handler(SubjectHandler):
    def __init__(self):
        super().__init__(
            validate_payload=_validate_payload,
            current_version=_widget_version,
            rederive_payload=self._rederive,
            apply=self._apply,
        )
        self.payloads = {}

    def remember(self, subject_id, payload):
        self.payloads[subject_id] = payload

    def _rederive(self, cur, tenant_id, subject_id, payload_hash):
        payload = self.payloads.get(subject_id)
        assert payload is not None and _canonical_hash(payload) == payload_hash
        return payload

    def _apply(self, conn, tenant_id, *, subject_id, approval, payload,
               actor_id, actor_role):
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE test_identity_widgets SET value = %s "
                "WHERE tenant_id = %s AND id = %s;",
                (payload["value"], str(tenant_id), subject_id),
            )
            assert cur.rowcount == 1
        return {"applied_value": payload["value"]}


@pytest.fixture()
def handler():
    h = _Handler()
    register_subject_type(SUBJECT_TYPE, h)
    yield h
    _REGISTRY.pop(SUBJECT_TYPE, None)


def _propose_pending(handler, *, proposer_actor, widget=None, value=7):
    widget = widget or _make_widget()
    payload = {"value": value}
    with get_db_connection() as conn:
        row = propose(
            conn, TENANT_A, subject_type=SUBJECT_TYPE,
            subject_id=str(widget), payload=payload,
            actor_id=proposer_actor, actor_role="analyst",
        )
        handler.remember(str(widget), payload)
        conn.commit()
    return row, widget


# ===========================================================================
# Decider authority under the UUID subject login mints (P0-1)
# ===========================================================================


class TestUuidSubjectDeciderAuthorized:
    def test_uuid_subject_decider_is_authorized(self, handler):
        row, _ = _propose_pending(handler, proposer_actor=ANALYST_EMAIL)
        with get_db_connection() as conn:
            dec = decide(
                conn, TENANT_A, row["id"], decision="approved",
                approver_id=_user_uuid(ADMIN_EMAIL), approver_role="admin",
            )
            conn.commit()
        assert dec["state"] == "approved"

    def test_uuid_subject_decider_can_reject_and_cancel(self, handler):
        for decision in ("rejected", "cancelled"):
            row, _ = _propose_pending(handler, proposer_actor=ANALYST_EMAIL)
            with get_db_connection() as conn:
                dec = decide(
                    conn, TENANT_A, row["id"], decision=decision,
                    approver_id=_user_uuid(ADMIN_EMAIL), approver_role="admin",
                )
                conn.commit()
            assert dec["state"] == decision

    def test_unresolvable_actor_still_fails_closed(self, handler):
        row, _ = _propose_pending(handler, proposer_actor=ANALYST_EMAIL)
        with get_db_connection() as conn:
            with pytest.raises(ApprovalAuthorityError):
                decide(
                    conn, TENANT_A, row["id"], decision="approved",
                    approver_id="ghost-actor", approver_role="admin",
                )


# ===========================================================================
# Cross-shape self-approval refused (P0-2, service layer)
# ===========================================================================


class TestCrossShapeSelfApprovalRefused:
    def test_email_proposer_vs_uuid_approver_same_human(self, handler):
        row, _ = _propose_pending(handler, proposer_actor=ADMIN_EMAIL)
        with get_db_connection() as conn:
            with pytest.raises(ApprovalDualControlError, match="self-approval"):
                decide(
                    conn, TENANT_A, row["id"], decision="approved",
                    approver_id=_user_uuid(ADMIN_EMAIL), approver_role="admin",
                )

    def test_uuid_proposer_vs_email_approver_same_human(self, handler):
        row, _ = _propose_pending(
            handler, proposer_actor=_user_uuid(ADMIN_EMAIL))
        with get_db_connection() as conn:
            with pytest.raises(ApprovalDualControlError, match="self-approval"):
                decide(
                    conn, TENANT_A, row["id"], decision="approved",
                    approver_id=ADMIN_EMAIL, approver_role="admin",
                )

    def test_actor_shape_that_resolves_to_no_user_fails_closed(self, handler):
        # login's resolution is `u.id::text = sub` (lowercase UUID text) or
        # the exact email — an id that resolves to no user has no authority,
        # whatever it string-equals.
        row, _ = _propose_pending(handler, proposer_actor=ADMIN_EMAIL)
        with get_db_connection() as conn:
            with pytest.raises(ApprovalAuthorityError):
                decide(
                    conn, TENANT_A, row["id"], decision="approved",
                    approver_id=_user_uuid(ADMIN_EMAIL).upper(),
                    approver_role="admin",
                )


# ===========================================================================
# Cross-shape self-approval refused (P0-2, DB layer — migration 038 trigger)
# ===========================================================================


class TestTriggerCanonicalDualControl:
    def _raw_pending(self, proposer_actor):
        widget = _make_widget()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO chapter5_approvals (tenant_id, subject_type, "
                    "subject_id, subject_version, payload_hash, proposer_id, "
                    "proposer_role) VALUES (%s, %s, %s, '1', 'h', %s, "
                    "'analyst') RETURNING id;",
                    (str(TENANT_A), SUBJECT_TYPE, str(widget),
                     proposer_actor),
                )
                aid = cur.fetchone()["id"]
        return aid

    def test_email_proposer_uuid_approver_refused_by_trigger(self):
        aid = self._raw_pending(ADMIN_EMAIL)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="dual control violated"):
                    cur.execute(
                        "UPDATE chapter5_approvals SET state='approved', "
                        "approver_id=%s, approver_role='admin', decided_at=now() "
                        "WHERE id=%s;",
                        (_user_uuid(ADMIN_EMAIL), aid),
                    )

    def test_uuid_proposer_email_approver_refused_by_trigger(self):
        aid = self._raw_pending(_user_uuid(ADMIN_EMAIL))
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="dual control violated"):
                    cur.execute(
                        "UPDATE chapter5_approvals SET state='approved', "
                        "approver_id=%s, approver_role='admin', decided_at=now() "
                        "WHERE id=%s;",
                        (ADMIN_EMAIL, aid),
                    )

    def test_non_user_actor_ids_keep_raw_string_protection(self):
        aid = self._raw_pending("service:proposer")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.RaiseException,
                                   match="dual control violated"):
                    cur.execute(
                        "UPDATE chapter5_approvals SET state='approved', "
                        "approver_id='service:proposer', approver_role='admin', "
                        "decided_at=now() WHERE id=%s;",
                        (aid,),
                    )

    def test_different_users_cross_shape_admitted_by_trigger(self):
        aid = self._raw_pending(ANALYST_EMAIL)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE chapter5_approvals SET state='approved', "
                    "approver_id=%s, approver_role='admin', decided_at=now() "
                    "WHERE id=%s;",
                    (_user_uuid(ADMIN_EMAIL), aid),
                )
                cur.execute(
                    "SELECT state FROM chapter5_approvals WHERE id=%s;", (aid,))
                assert cur.fetchone()["state"] == "approved"


# ===========================================================================
# Dual control must not block different humans under any token shape
# ===========================================================================


class TestDifferentHumansStillSucceed:
    def test_uuid_proposer_email_approver_different_humans(self, handler):
        row, _ = _propose_pending(handler, proposer_actor=ADMIN_EMAIL)
        with get_db_connection() as conn:
            dec = decide(
                conn, TENANT_A, row["id"], decision="approved",
                approver_id=_user_uuid(SUPER_EMAIL), approver_role="superadmin",
            )
            conn.commit()
        assert dec["state"] == "approved"

    def test_email_proposer_uuid_approver_different_humans(self, handler):
        row, _ = _propose_pending(
            handler, proposer_actor=_user_uuid(SUPER_EMAIL))
        with get_db_connection() as conn:
            dec = decide(
                conn, TENANT_A, row["id"], decision="approved",
                approver_id=ADMIN_EMAIL, approver_role="admin",
            )
            conn.commit()
        assert dec["state"] == "approved"


# ===========================================================================
# Apply: executor-must-be-approver and single-use unchanged
# ===========================================================================


class TestApplyStillRequiresTheApprover:
    def test_apply_by_other_user_refused_even_in_uuid_shape(self, handler):
        row, _ = _propose_pending(handler, proposer_actor=ANALYST_EMAIL)
        with get_db_connection() as conn:
            decide(
                conn, TENANT_A, row["id"], decision="approved",
                approver_id=_user_uuid(ADMIN_EMAIL), approver_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(ApprovalAuthorityError, match="not the approver"):
                apply_approval(
                    conn, TENANT_A, row["id"],
                    actor_id=_user_uuid(SUPER_EMAIL), actor_role="superadmin",
                )

    def test_approver_applies_in_uuid_shape(self, handler):
        row, widget = _propose_pending(handler, proposer_actor=ANALYST_EMAIL)
        with get_db_connection() as conn:
            decide(
                conn, TENANT_A, row["id"], decision="approved",
                approver_id=_user_uuid(ADMIN_EMAIL), approver_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            out = apply_approval(
                conn, TENANT_A, row["id"],
                actor_id=_user_uuid(ADMIN_EMAIL), actor_role="admin",
            )
            conn.commit()
        assert out["approval"]["state"] == "applied"
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT value FROM test_identity_widgets WHERE id=%s;",
                    (str(widget),))
                assert cur.fetchone()["value"] == 7
