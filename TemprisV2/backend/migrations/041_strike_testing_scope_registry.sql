-- Migration 041: Chapter 4 — the tenant testing-scope registry
-- (amended PRD v1.12 Ch.4, /strike/scopes owning surface).
--
-- The amended model replaces the engagement-scoped target authorization with
-- a tenant-level testing-scope registry administered by Tenant Admin /
-- Tenant Superadmin (create/list/revoke, audited). Each entry is an EXACT
-- hostname, IP, or CIDR — wildcard suffixes are refused by the application's
-- strict parser (the DB CHECK below is a defense-in-depth backstop).
--
-- Lifecycle: an entry is created with a REQUIRED future expires_at and stays
-- in the registry as permanent administration history. Revocation is a
-- write-once transition (revoked_at/revoked_by/revoke_reason); expiry is
-- DERIVED AT READ (never back-written), matching the Ch.2/Ch.4 authorization
-- pattern. There is deliberately NO uniqueness constraint on the entry
-- value: an expired (or revoked) entry may be recreated, and duplicate
-- active entries are an administration reality the registry records rather
-- than hides. Run binding (the resolved-destination pin) is a separate
-- run-bound concept and is NOT this table.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

CREATE TABLE strike_testing_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('hostname', 'ip', 'cidr')),
    -- canonical, normalized rendering of the exact entry (lowercased
    -- hostname; compressed IP; strict network address). The parser owns
    -- validity; this column never stores a raw client string.
    value TEXT NOT NULL,
    note TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revoke_reason TEXT,
    CONSTRAINT ck_strike_testing_scopes_expiry_written CHECK (revoked_at IS NULL OR revoked_by IS NOT NULL)
);

-- wildcard backstop: the application parser is the authority; the database
-- still refuses the canonical wildcard shapes outright.
ALTER TABLE strike_testing_scopes
    ADD CONSTRAINT ck_strike_testing_scopes_no_wildcard
    CHECK (position('*' in value) = 0);

CREATE INDEX ix_strike_testing_scopes_tenant
    ON strike_testing_scopes (tenant_id, created_at DESC);
