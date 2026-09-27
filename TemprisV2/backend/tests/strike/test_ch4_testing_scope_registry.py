# backend/tests/strike/test_ch4_testing_scope_registry.py
"""
Chapter 4 acceptance — tenant testing-scope registry (amended PRD v1.12
Ch.4, the /strike/scopes owning surface).

Covers:
  * STRIKE's OWN strict parser: exact hostname / IP / CIDR only; wildcards
    refused; CIDR host bits refused (Ch.2's CIDR rejection is NOT inherited —
    STRIKE accepts CIDR); normalization is canonical (one terminal dot
    stripped; multiple trailing dots refused);
  * administration authority: Tenant Admin / Tenant Superadmin write,
    analyst refused (403); create and revoke are audited (list is a read,
    not an audited administration event);
  * expiry REQUIRED and future-dated;
  * revocation: write-once, audited, derived-at-read state;
  * tenant isolation: cross-tenant ids are the identical not-found and
    lists never leak the other tenant's entries;
  * no uniqueness on the entry value: expired and revoked entries may be
    recreated;
  * concurrent revocation: the guarded UPDATE makes the second writer lose
    (no attribution overwrite).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.auth import create_test_token
from app.db import get_db_connection
from app.strike.scopes import parse_scope_entry
from tests.conftest import TENANT_A, TENANT_B
from tests.strike.conftest import iso


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


@pytest.fixture
def superadmin_headers():
    token = create_test_token(tenant_id=str(TENANT_A), actor_id="superadmin-a", role="superadmin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


def _truncate():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE strike_testing_scopes;")
        conn.commit()


@pytest.fixture(autouse=True)
def clean_scope_registry(clean_strike):
    _truncate()
    yield
    _truncate()


def future(**kwargs) -> str:
    return iso(datetime.now(timezone.utc) + timedelta(**kwargs))


def scope_payload(entry: str, **kwargs) -> dict:
    payload = {"entry": entry, "expires_at": future(days=7)}
    payload.update(kwargs)
    return payload


def seed_row(*, tenant_id=TENANT_A, value="203.0.113.9", kind="ip",
             expires_in: timedelta = timedelta(days=-1)) -> uuid.UUID:
    """Direct insert (DB-level shape/expired-row tests)."""
    row_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO strike_testing_scopes (
                    id, tenant_id, entry_kind, value, created_by, expires_at
                ) VALUES (%s, %s, %s, %s, 'seed', %s);
                """,
                (str(row_id), str(tenant_id), kind, value,
                 iso(datetime.now(timezone.utc) + expires_in)),
            )
        conn.commit()
    return row_id


# ---------------------------------------------------------------------------
# The strict parser (STRIKE's own — no Ch.2 inheritance)
# ---------------------------------------------------------------------------


class TestParser:
    def test_exact_entries_accepted_and_normalized(self):
        assert parse_scope_entry("10.0.0.0/24") == ("cidr", "10.0.0.0/24")
        assert parse_scope_entry("2001:db8::/32") == ("cidr", "2001:db8::/32")
        assert parse_scope_entry("203.0.113.9") == ("ip", "203.0.113.9")
        assert parse_scope_entry("2001:0DB8::0001") == ("ip", "2001:db8::1")
        assert parse_scope_entry("Target.Example.COM.") == (
            "hostname", "target.example.com"
        )
        # single-label exact private hostnames are valid scope entries
        assert parse_scope_entry("Intranet") == ("hostname", "intranet")

    def test_wildcards_refused(self):
        for bad in ("*.example.com", "10.0.0.*", "example.*", "*"):
            with pytest.raises(Exception) as e:
                parse_scope_entry(bad)
            assert "Wildcard" in str(e.value)

    def test_cidr_host_bits_refused(self):
        with pytest.raises(Exception):
            parse_scope_entry("10.0.0.1/24")

    def test_non_exact_shapes_refused(self):
        for bad in ("", "   ", "https://example.com", "example.com/x",
                    "example.com path", "-bad-.com", "fe80::1%eth0",
                    "x" * 254, None, "example.com..", "123", "1.2.3"):
            with pytest.raises(Exception):
                parse_scope_entry(bad)

    def test_cidr_accepted_where_ch2_rejects(self):
        # the deliberate divergence: STRIKE's parser accepts CIDR targets
        kind, value = parse_scope_entry("192.0.2.0/25")
        assert (kind, value) == ("cidr", "192.0.2.0/25")


# ---------------------------------------------------------------------------
# Administration authority
# ---------------------------------------------------------------------------


class TestAuthority:
    def test_analyst_refused(self, strike_client, analyst_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.0/24"), headers=analyst_headers)
        assert r.status_code == 403
        r = strike_client.get("/api/strike/scopes", headers=analyst_headers)
        assert r.status_code == 403

    def test_admin_and_superadmin_create(self, strike_client, admin_headers, superadmin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.0/24"), headers=admin_headers)
        assert r.status_code == 201, r.text
        assert (r.json()["entry_kind"], r.json()["value"]) == ("cidr", "10.0.0.0/24")
        r = strike_client.post("/api/strike/scopes", json=scope_payload("scan.example.com"), headers=superadmin_headers)
        assert r.status_code == 201, r.text
        assert r.json()["entry_kind"] == "hostname"

    def test_platform_session_blocked(self, strike_client, platform_admin_headers):
        r = strike_client.get("/api/strike/scopes", headers=platform_admin_headers)
        assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Validation + expiry
# ---------------------------------------------------------------------------


class TestValidation:
    def test_expiry_required(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json={"entry": "10.0.0.5"}, headers=admin_headers)
        assert r.status_code == 422

    def test_past_expiry_refused(self, strike_client, admin_headers):
        payload = scope_payload("10.0.0.5", expires_at=iso(datetime.now(timezone.utc) - timedelta(hours=1)))
        r = strike_client.post("/api/strike/scopes", json=payload, headers=admin_headers)
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "scope_entry_invalid"

    def test_wildcard_entry_refused_via_api(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("*.example.com"), headers=admin_headers)
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "scope_entry_invalid"

    def test_state_is_derived_active_on_create(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        assert r.json()["state"] == "active"
        assert r.json()["revoked_at"] is None


# ---------------------------------------------------------------------------
# Revocation + list (derived-at-read history)
# ---------------------------------------------------------------------------


class TestRevokeAndList:
    def test_revoke_once_then_refused(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        entry_id = r.json()["id"]
        r = strike_client.post(
            f"/api/strike/scopes/{entry_id}/revoke",
            json={"reason": "testing window closed"}, headers=admin_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["state"] == "revoked"
        assert body["revoked_by"] == "admin-a"
        assert body["revoke_reason"] == "testing window closed"

        r = strike_client.post(
            f"/api/strike/scopes/{entry_id}/revoke",
            json={"reason": "again"}, headers=admin_headers,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["code"] == "scope_entry_state"

    def test_list_keeps_history_with_derived_states(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        entry_id = r.json()["id"]
        strike_client.post(f"/api/strike/scopes/{entry_id}/revoke", json={"reason": "x"}, headers=admin_headers)
        seed_row(value="10.0.0.6", expires_in=timedelta(days=-1))  # expired

        rows = strike_client.get("/api/strike/scopes", headers=admin_headers).json()
        states = {row["value"]: row["state"] for row in rows}
        assert states == {"10.0.0.5": "revoked", "10.0.0.6": "expired"}

    def test_concurrent_revoke_second_writer_loses(self, strike_client, admin_headers):
        """Simulate two revokers that both passed the not-revoked pre-check
        before either wrote: only the guarded UPDATE (AND revoked_at IS NULL)
        decides, so the loser's write matches zero rows and cannot overwrite
        the winner's attribution."""
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        entry_id = r.json()["id"]

        guarded = (
            """
            UPDATE strike_testing_scopes
            SET revoked_at = now(), revoked_by = %s, revoke_reason = %s
            WHERE id = %s AND tenant_id = %s AND revoked_at IS NULL;
            """
        )
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(guarded, ("racer-1", "first", str(entry_id), str(TENANT_A)))
                assert cur.rowcount == 1
                cur.execute(guarded, ("racer-2", "second", str(entry_id), str(TENANT_A)))
                assert cur.rowcount == 0
            conn.commit()

        rows = strike_client.get("/api/strike/scopes", headers=admin_headers).json()
        assert len(rows) == 1
        assert rows[0]["revoked_by"] == "racer-1"
        assert rows[0]["revoke_reason"] == "first"

    def test_expired_entry_may_be_recreated(self, strike_client, admin_headers):
        seed_row(value="scan.example.com", kind="hostname", expires_in=timedelta(days=-1))
        r = strike_client.post("/api/strike/scopes", json=scope_payload("scan.example.com"), headers=admin_headers)
        assert r.status_code == 201, r.text

    def test_revoked_entry_may_be_recreated(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        entry_id = r.json()["id"]
        strike_client.post(f"/api/strike/scopes/{entry_id}/revoke", json={"reason": "x"}, headers=admin_headers)
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        assert r.status_code == 201, r.text
        assert r.json()["state"] == "active"


# ---------------------------------------------------------------------------
# Tenant isolation + audit
# ---------------------------------------------------------------------------


class TestIsolationAndAudit:
    def test_cross_tenant_is_identical_not_found(self, strike_client, admin_headers, auth_headers_tenant_b_admin):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        entry_id = r.json()["id"]

        r = strike_client.post(
            f"/api/strike/scopes/{entry_id}/revoke",
            json={"reason": "cross"}, headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 404

        rows = strike_client.get("/api/strike/scopes", headers=auth_headers_tenant_b_admin).json()
        assert rows == []

    def test_create_and_revoke_audited(self, strike_client, admin_headers):
        r = strike_client.post("/api/strike/scopes", json=scope_payload("10.0.0.5"), headers=admin_headers)
        entry_id = r.json()["id"]
        strike_client.post(f"/api/strike/scopes/{entry_id}/revoke", json={"reason": "window closed"}, headers=admin_headers)

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_name, asset_id FROM audit_events
                    WHERE tenant_id = %s AND event_name LIKE %s
                    ORDER BY created_at;
                    """,
                    (str(TENANT_A), "strike.scope.%"),
                )
                events = [(row["event_name"], str(row["asset_id"])) for row in cur.fetchall()]
        assert events == [
            ("strike.scope.created", entry_id),
            ("strike.scope.revoked", entry_id),
        ]
