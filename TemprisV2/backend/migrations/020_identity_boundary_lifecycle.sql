-- Migration 020: Identity Boundary Lifecycle (P0-07, PRD-000 v1.11 §3.6.6 #7/#8;
-- §3.3.1 supersession rules; §3.3.2 criticality mapping; Appendix C Q15/Q20).
--
-- Forward-only; the whole file runs inside one transaction (migrations/runner.py).
--
-- Establishes the Chapter 3-owned tenant_identity_boundary binding:
--   * tenant_id → asset_id, AT MOST ONE current binding per tenant (partial
--     unique index enforces at-most-one, never existence — the PRD 0..1
--     contract); history rows (replaced/cleared) are retained and immutable;
--   * the binding stores its OWN criticality (design A, §3.6.6 #7): same
--     vocabulary as assets.criticality, same §3.3.2 mapping (10/8/5/2), with
--     who/when provenance — identity-posture TES reads the boundary value;
--     every other exposure on the same domain keeps assets.criticality;
--   * a bound asset cannot be decommissioned until the binding is replaced
--     or cleared (BEFORE-UPDATE guard on assets; transition rows are exempt);
--   * every binding row is written with an actor; every transition is audited
--     by the service inside the same transaction as the binding change and
--     the exposure supersessions.
--
-- Nothing here writes exposure status: supersession is routed through the
-- P0-01 exposure service inside the binding transaction (§3.3.1 authority).
-- NHI, supply-chain, and agentic anchor semantics are NOT defined here
-- (§3.6.6 #8): this binding is the IDENTITY_POSTURE anchor contract only.

-- ---------------------------------------------------------------------------
-- 1. The binding (current state + immutable history in one append-only table)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_identity_boundary (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    asset_id          UUID NOT NULL,
    -- active | replaced | cleared — only 'active' rows are the tenant's
    -- current binding; replaced/cleared rows are retained history
    state             TEXT NOT NULL DEFAULT 'active'
                      CHECK (state IN ('active', 'replaced', 'cleared')),
    -- design A: the binding's own criticality (§3.3.2 vocabulary + mapping),
    -- NOT a read of assets.criticality
    criticality       TEXT NOT NULL CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    -- who/when provenance for the criticality designation
    set_by            TEXT NOT NULL,
    set_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- lifecycle provenance
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- for history rows: the transition that ended this binding's active life.
    -- The succession chain is reconstructible from identity_boundary_audit
    -- (prior_binding_id → boundary_id) plus created_at ordering; no successor
    -- pointer column exists, so closing a row and designating its successor
    -- are independent writes that never collide with the partial unique index.
    ended_by          TEXT,
    ended_at          TIMESTAMPTZ,
    CONSTRAINT fk_tenant_identity_boundary_asset
        FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT ck_tenant_identity_boundary_closed
        CHECK (state = 'active' OR (ended_by IS NOT NULL AND ended_at IS NOT NULL))
);

-- AT MOST ONE current binding per tenant (0..1 — never existence).
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_identity_boundary_active
    ON tenant_identity_boundary (tenant_id) WHERE state = 'active';

CREATE INDEX IF NOT EXISTS idx_tenant_identity_boundary_tenant
    ON tenant_identity_boundary (tenant_id, created_at DESC);

-- History immutability: DELETE is forbidden for EVERY row (active or not —
-- the service never deletes; the incidental FK protection is not enforcement).
-- UPDATE is permitted ONLY as the exact terminal transition:
--   OLD.state = 'active' AND NEW.state IN ('replaced','cleared')
--   AND every other column unchanged (tenant_id, asset_id, criticality,
--   set_by, set_at, created_by, created_at)
--   AND ended_by/ended_at move NULL -> set.
-- Every other UPDATE rejects.
CREATE OR REPLACE FUNCTION tenant_identity_boundary_history_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'tenant_identity_boundary rows are immutable (DELETE forbidden for % row)', OLD.state;
    END IF;
    IF OLD.state = 'active'
       AND NEW.state IN ('replaced', 'cleared')
       AND NEW.tenant_id   IS NOT DISTINCT FROM OLD.tenant_id
       AND NEW.asset_id    IS NOT DISTINCT FROM OLD.asset_id
       AND NEW.criticality IS NOT DISTINCT FROM OLD.criticality
       AND NEW.set_by      IS NOT DISTINCT FROM OLD.set_by
       AND NEW.set_at      IS NOT DISTINCT FROM OLD.set_at
       AND NEW.created_by  IS NOT DISTINCT FROM OLD.created_by
       AND NEW.created_at  IS NOT DISTINCT FROM OLD.created_at
       AND OLD.ended_by  IS NULL AND OLD.ended_at  IS NULL
       AND NEW.ended_by  IS NOT NULL AND NEW.ended_at IS NOT NULL
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'tenant_identity_boundary rows are immutable (UPDATE of % row limited to the exact terminal transition)', OLD.state;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenant_identity_boundary_history_immutable ON tenant_identity_boundary;
CREATE TRIGGER trg_tenant_identity_boundary_history_immutable
    BEFORE UPDATE OR DELETE ON tenant_identity_boundary
    FOR EACH ROW EXECUTE FUNCTION tenant_identity_boundary_history_immutable();

-- ---------------------------------------------------------------------------
-- 2. Decommission guard: a bound asset cannot be decommissioned until the
--    binding is replaced or cleared (§3.6.6 #7). The binding service's own
--    state transition rows are exempt; ordinary asset decommission is not.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION tenant_identity_boundary_guard_decommission() RETURNS trigger AS $$
DECLARE
    boundary_id UUID;
BEGIN
    IF NEW.status = 'decommissioned' AND OLD.status = 'active' THEN
        SELECT id INTO boundary_id
        FROM tenant_identity_boundary
        WHERE tenant_id = NEW.tenant_id AND asset_id = NEW.id AND state = 'active';
        IF boundary_id IS NOT NULL THEN
            RAISE EXCEPTION 'asset % is the active identity boundary (binding %) — replace or clear the binding before decommissioning', NEW.id, boundary_id;
        END IF;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenant_identity_boundary_guard_decommission ON assets;
CREATE TRIGGER trg_tenant_identity_boundary_guard_decommission
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION tenant_identity_boundary_guard_decommission();

-- Append-only audit trail for binding transitions (written by the service in
-- the same transaction; the table itself admits INSERT only).
CREATE TABLE IF NOT EXISTS identity_boundary_audit (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    boundary_id   UUID NOT NULL REFERENCES tenant_identity_boundary(id) ON DELETE RESTRICT,
    action        TEXT NOT NULL CHECK (action IN ('created', 'replaced', 'cleared')),
    actor_id      TEXT NOT NULL,
    actor_role    TEXT NOT NULL,
    details       JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only enforcement for the audit trail: INSERT only. The service
-- writes audit rows in the same transaction as the binding change; UPDATE
-- and DELETE of an audit row are rejected outright.
CREATE OR REPLACE FUNCTION identity_boundary_audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'identity_boundary_audit is append-only (UPDATE forbidden)';
    END IF;
    RAISE EXCEPTION 'identity_boundary_audit is append-only (DELETE forbidden)';
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_identity_boundary_audit_append_only ON identity_boundary_audit;
CREATE TRIGGER trg_identity_boundary_audit_append_only
    BEFORE UPDATE OR DELETE ON identity_boundary_audit
    FOR EACH ROW EXECUTE FUNCTION identity_boundary_audit_append_only();
