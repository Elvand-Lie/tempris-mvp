-- Migration 029: Chapter 4 — STRIKE, part 3 of 3: relays and evidence links
-- (PRD-000 v1.11 Ch.4 principles 5/6/9/10, owned-state table).
--
-- strike_relays — the STRIKE-specific private-network relay (principle 6).
--   NEVER the Chapter 2 Collector: the collector's closed six-frame protocol
--   is frozen (§2.7) and untouched — the relay is a separate, tenant-bound,
--   session-scoped, revocable component. Lifecycle:
--   pending_pairing → paired → active → revoked (TERMINAL). Deploying a
--   relay is itself an engagement event and is audited. The pairing protocol
--   mechanics remain open decision #3; the lifecycle and its revocation
--   semantics are frozen here — revoked is terminal, never reusable. The
--   one-time pairing secret follows the collector enrollment pattern
--   (SHA-256-stored, shown once).
--
-- strike_evidence_links — the immutable bridge between a STRIKE operation and
--   the Chapter 3 §3.3.3 evidence record. Promotion (PATCH-01) happens in the
--   STRIKE control plane: the workspace pushes bounded hashed artifacts, but
--   server-side packaging never authenticates workspace claims — the Ch.3
--   record is created only after explicit authenticated analyst review, with
--   server-side validation of tenant, operation, target, the exact exposure
--   episode, observed_at, and the constrained evidence_kind (testing ⇒
--   controlled_validation; an actually observed compromise ⇒
--   observed_exploitation — a successful test alone never qualifies). The
--   link row is INSERT-only: evidence history is never rewritten.
--   The exposure reference carries a composite FK with ON DELETE CASCADE —
--   the link is derived from the exposure; Ch.3 rows are never deleted in
--   production, and the cascade only serves test-database hygiene.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Relays — STRIKE-specific, tenant-bound, revocable (terminal)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_relays (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL REFERENCES strike_engagements(id) ON DELETE RESTRICT,
    state           TEXT NOT NULL DEFAULT 'pending_pairing'
                    CHECK (state IN ('pending_pairing', 'paired', 'active', 'revoked')),
    -- one-time pairing secret: SHA-256 stored, returned to the operator
    -- exactly once at creation (the collector-enrollment precedent); pairing
    -- presents the secret, the hash proves it
    pairing_secret_hash TEXT,
    paired_at       TIMESTAMPTZ,
    activated_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT,
    revoke_reason   TEXT,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_strike_relay_pending_shape CHECK (
        state <> 'pending_pairing' OR pairing_secret_hash IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_strike_relays_engagement
    ON strike_relays (tenant_id, engagement_id, created_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'strike_relays'::regclass
          AND conname = 'uq_strike_relays_tenant_id'
    ) THEN
        ALTER TABLE strike_relays
            ADD CONSTRAINT uq_strike_relays_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION strike_relay_lifecycle() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'strike_relays are history (DELETE forbidden; state=%)', OLD.state;
    END IF;

    IF NEW.engagement_id IS NOT DISTINCT FROM OLD.engagement_id
       AND NEW.pairing_secret_hash IS NOT DISTINCT FROM OLD.pairing_secret_hash
    THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'strike_relays binding/pairing identity are immutable (relay %)', OLD.id;
    END IF;

    -- ---- legal edges (revoked is TERMINAL) ---------------------------------
    IF OLD.state = 'pending_pairing' AND NEW.state = 'paired' THEN
        IF NEW.paired_at IS NULL THEN
            RAISE EXCEPTION 'relay % pairing requires paired_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'paired' AND NEW.state = 'active' THEN
        IF NEW.activated_at IS NULL THEN
            RAISE EXCEPTION 'relay % activation requires activated_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('pending_pairing', 'paired', 'active') AND NEW.state = 'revoked' THEN
        IF NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL THEN
            RAISE EXCEPTION 'revoking relay % requires revoked_at and revoked_by', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'strike_relays illegal state transition % -> % (relay %)', OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_relay_lifecycle ON strike_relays;
CREATE TRIGGER trg_strike_relay_lifecycle
    BEFORE UPDATE OR DELETE ON strike_relays
    FOR EACH ROW EXECUTE FUNCTION strike_relay_lifecycle();

-- ---------------------------------------------------------------------------
-- 2. Evidence links — the immutable STRIKE → Ch.3 §3.3.3 bridge
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_evidence_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL REFERENCES strike_engagements(id) ON DELETE RESTRICT,
    operation_id    UUID NOT NULL REFERENCES strike_operations(id) ON DELETE RESTRICT,
    -- the EXACT exposure episode this evidence binds (the §3.3.3
    -- exact-exposure rule; CASCADE only for test-database hygiene — Ch.3
    -- never deletes exposures in production)
    exposure_id     UUID NOT NULL,
    -- BY REFERENCE: the Ch.3 evidence record id (exposure_exploitation_evidence.id),
    -- created in the SAME transaction by the Ch.3 record command
    evidence_record_id UUID NOT NULL,
    -- the constrained kind, copied from the Ch.3 record (write-time rule, D-7)
    evidence_kind   TEXT NOT NULL
                    CHECK (evidence_kind IN ('observed_exploitation', 'controlled_validation')),
    -- the authenticated analyst review that gated promotion (PATCH-01)
    reviewed_by     TEXT NOT NULL,
    attestation     TEXT NOT NULL CHECK (length(btrim(attestation)) > 0),
    observed_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_strike_evidence_exposure FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES asset_exposures(tenant_id, id) ON DELETE CASCADE,
    -- one live evidence link per operation: a second promotion of the same
    -- operation is refused (the Ch.3 source-identity rule makes the record
    -- itself single-source too — the two agree by construction)
    CONSTRAINT uq_strike_evidence_operation UNIQUE (operation_id)
);

CREATE INDEX IF NOT EXISTS idx_strike_evidence_engagement
    ON strike_evidence_links (tenant_id, engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_strike_evidence_exposure
    ON strike_evidence_links (tenant_id, exposure_id);

CREATE OR REPLACE FUNCTION strike_evidence_links_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'strike_evidence_links are immutable (TG_OP=%, link %)', TG_OP, COALESCE(OLD.id, NEW.id);
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_evidence_links_immutable ON strike_evidence_links;
CREATE TRIGGER trg_strike_evidence_links_immutable
    BEFORE UPDATE OR DELETE ON strike_evidence_links
    FOR EACH ROW EXECUTE FUNCTION strike_evidence_links_immutable();
