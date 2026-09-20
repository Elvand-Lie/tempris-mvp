-- Migration 027: Chapter 4 — STRIKE (Offensive Security Workspace), part 1 of 3:
-- the authorization core (PRD-000 v1.11 Ch.4, principles 1/3, owned-state table).
--
-- STRIKE is an independent hosted offensive-security workspace system — not
-- SCOUT, not a TES stage, not a SPECTRUM stage, not a Collector capability
-- (principle 1). This migration seeds the module catalogue (the D-13 additive
-- pattern: catalogue rows are added as each module ships; the SPECTRUM
-- precedent seeds the entitlement into the CORE_ASSETS base package so
-- existing tenants hold it) and creates the two authorization objects:
--
--   strike_engagements — the engagement record is PERMANENT audit history and
--     is never destroyed (the workspace is what gets destroyed, not the
--     engagement). Lifecycle: draft → pending_approval → authorized → active
--     → completed / aborted; 'expired' is DERIVED AT READ (Appendix G: the
--     derived states are derived-at-read, matching the Ch.2 authorization
--     pattern) from valid_until — it is never written. The ROE is immutable
--     per engagement; a revised ROE is a new engagement.
--   strike_targets — explicit per-engagement target authorization, the Ch.2
--     shape (§2.3) rebuilt for STRIKE: exact target tuple snapshotted at
--     request, purpose, expires_at required, revocable. Lifecycle
--     pending → approved → revoked, with expiry derived at read from
--     expires_at. V1's auto-signing quick-scan is retired: approval runs
--     exclusively through the Ch.5 dual-control primitive (approver ≠
--     proposer; payload-bound; single-use).
--
-- Linkage to Ch.3 objects (finding/asset/exposure) is BY REFERENCE — UUID
-- columns without foreign keys: STRIKE references these identities, it does
-- not redefine them, and no offensive state is ever stored on
-- assets/findings/exposures. Referential validity is enforced server-side at
-- authorization and evidence-promotion time.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Module catalogue: STRIKE (the D-13 additive pattern)
-- ---------------------------------------------------------------------------

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'STRIKE',
    'STRIKE — Offensive Security Workspace',
    'Engagement-scoped offensive-security workspaces: explicit target authorization, disposable workspaces, controlled validation, and Ch.3 evidence production. STRIKE writes evidence, not TES.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'STRIKE')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Engagements — permanent audit history, never destroyed
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_engagements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    title           TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    purpose         TEXT NOT NULL CHECK (length(btrim(purpose)) > 0),
    -- ROE: scope, methods, credential rules, time window, cleanup, stop
    -- conditions (Ch.4 Inputs). Immutable per engagement (trigger below);
    -- roe_version is the identity of that frozen ROE text.
    roe             JSONB NOT NULL,
    roe_version     TEXT NOT NULL,
    -- authorization window (principle 3: expires_at required). Expiry is
    -- derived at read; the stored state never becomes 'expired'.
    valid_from      TIMESTAMPTZ NOT NULL,
    valid_until     TIMESTAMPTZ NOT NULL,
    -- lifecycle (pinned by trigger to exactly these edges)
    state           TEXT NOT NULL DEFAULT 'draft'
                    CHECK (state IN ('draft', 'pending_approval', 'authorized',
                                     'active', 'completed', 'aborted')),
    requested_by    TEXT NOT NULL,
    requested_role  TEXT NOT NULL,
    submitted_at    TIMESTAMPTZ,
    authorized_at   TIMESTAMPTZ,
    activated_at    TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    aborted_at      TIMESTAMPTZ,
    aborted_by      TEXT,
    abort_reason    TEXT,
    -- the Ch.5 dual-control approval that authorized this engagement
    -- (written exactly once at apply; NULL until then)
    approval_id     UUID,
    -- optional Ch.3 linkage for validation engagements — BY REFERENCE only
    -- (the PRD's linkage rule; no FK, no offensive state on Ch.3 objects)
    finding_id      UUID,
    asset_id        UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_strike_engagement_window CHECK (valid_until > valid_from)
);

CREATE INDEX IF NOT EXISTS idx_strike_engagements_tenant_state
    ON strike_engagements (tenant_id, state, created_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'strike_engagements'::regclass
          AND conname = 'uq_strike_engagements_tenant_id'
    ) THEN
        ALTER TABLE strike_engagements
            ADD CONSTRAINT uq_strike_engagements_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- Engagement lifecycle pinning + immutability. DELETE is forbidden — the
-- engagement record is permanent audit history. The ROE, requester, and
-- window are frozen at creation. The approval binding is written exactly
-- once (at authorization apply).
CREATE OR REPLACE FUNCTION strike_engagement_lifecycle() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'strike_engagements are permanent audit history (DELETE forbidden; state=%)', OLD.state;
    END IF;

    -- frozen at creation: ROE, requester identity, authorization window
    IF NEW.roe            IS NOT DISTINCT FROM OLD.roe
       AND NEW.roe_version IS NOT DISTINCT FROM OLD.roe_version
       AND NEW.requested_by IS NOT DISTINCT FROM OLD.requested_by
       AND NEW.requested_role IS NOT DISTINCT FROM OLD.requested_role
       AND NEW.valid_from  IS NOT DISTINCT FROM OLD.valid_from
       AND NEW.valid_until IS NOT DISTINCT FROM OLD.valid_until
    THEN
        NULL;
    ELSE
        RAISE EXCEPTION
            'strike_engagements ROE/requester/window are immutable (engagement %)', OLD.id;
    END IF;

    -- the approval binding is written exactly once
    IF NEW.approval_id IS DISTINCT FROM OLD.approval_id THEN
        IF OLD.approval_id IS NOT NULL THEN
            RAISE EXCEPTION 'strike_engagement % already carries an approval binding', OLD.id;
        END IF;
    END IF;

    -- ---- legal edges ------------------------------------------------------
    IF OLD.state = 'draft' AND NEW.state = 'pending_approval' THEN
        IF NEW.submitted_at IS NULL THEN
            RAISE EXCEPTION 'submitting engagement % requires submitted_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'pending_approval' AND NEW.state = 'authorized' THEN
        IF NEW.approval_id IS NULL OR NEW.authorized_at IS NULL THEN
            RAISE EXCEPTION
                'authorizing engagement % requires the dual-control approval binding and authorized_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'authorized' AND NEW.state = 'active' THEN
        IF NEW.activated_at IS NULL THEN
            RAISE EXCEPTION 'activating engagement % requires activated_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'active' AND NEW.state = 'completed' THEN
        IF NEW.completed_at IS NULL THEN
            RAISE EXCEPTION 'completing engagement % requires completed_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('draft', 'pending_approval', 'authorized', 'active')
       AND NEW.state = 'aborted' THEN
        IF NEW.aborted_at IS NULL OR NEW.aborted_by IS NULL THEN
            RAISE EXCEPTION 'aborting engagement % requires aborted_at and aborted_by', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'strike_engagements illegal state transition % -> % (engagement %)', OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_engagement_lifecycle ON strike_engagements;
CREATE TRIGGER trg_strike_engagement_lifecycle
    BEFORE UPDATE OR DELETE ON strike_engagements
    FOR EACH ROW EXECUTE FUNCTION strike_engagement_lifecycle();

-- ---------------------------------------------------------------------------
-- 3. Targets — explicit per-engagement authorization (Ch.2 §2.3 shape)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL REFERENCES strike_engagements(id) ON DELETE RESTRICT,
    -- the exact target tuple SNAPSHOT (Ch.2 target-tuple shape) — what was
    -- approved is what was written here; re-resolution can never expand scope
    -- (PATCH-03 pins enforcement to these concrete destinations)
    target_type     TEXT NOT NULL CHECK (length(btrim(target_type)) > 0),
    target_value    TEXT NOT NULL CHECK (length(btrim(target_value)) > 0),
    normalized_target TEXT NOT NULL CHECK (length(btrim(normalized_target)) > 0),
    purpose         TEXT NOT NULL CHECK (length(btrim(purpose)) > 0),
    state           TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'approved', 'revoked')),
    -- expiry is required (principle 3) and derived at read from expires_at
    expires_at      TIMESTAMPTZ NOT NULL,
    requested_by    TEXT NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    approval_id     UUID,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT,
    revoke_reason   TEXT,
    -- enforcement version of this authorization: bumped at every approval or
    -- revocation; operations and workspace egress generations bind to it
    -- (PATCH-03: enforcement binds to the authorization version)
    authorization_version INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_strike_targets_engagement
    ON strike_targets (tenant_id, engagement_id, state);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'strike_targets'::regclass
          AND conname = 'uq_strike_targets_tenant_id'
    ) THEN
        ALTER TABLE strike_targets
            ADD CONSTRAINT uq_strike_targets_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION strike_target_lifecycle() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'strike_targets are authorization history (DELETE forbidden; state=%)', OLD.state;
    END IF;

    -- the request snapshot is frozen: tuple, purpose, window, requester
    IF NEW.target_type       IS NOT DISTINCT FROM OLD.target_type
       AND NEW.target_value  IS NOT DISTINCT FROM OLD.target_value
       AND NEW.normalized_target IS NOT DISTINCT FROM OLD.normalized_target
       AND NEW.purpose       IS NOT DISTINCT FROM OLD.purpose
       AND NEW.expires_at    IS NOT DISTINCT FROM OLD.expires_at
       AND NEW.requested_by  IS NOT DISTINCT FROM OLD.requested_by
       AND NEW.engagement_id IS NOT DISTINCT FROM OLD.engagement_id
    THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'strike_targets request snapshot is immutable (target %)', OLD.id;
    END IF;

    -- approval binding + revocation metadata are written exactly once
    IF NEW.approval_id IS DISTINCT FROM OLD.approval_id
       OR NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
        IF OLD.approval_id IS NOT NULL THEN
            RAISE EXCEPTION 'strike_target % already carries an approval binding', OLD.id;
        END IF;
    END IF;
    IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        IF OLD.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'strike_target % is already revoked', OLD.id;
        END IF;
    END IF;

    -- ---- legal edges ------------------------------------------------------
    IF OLD.state = 'pending' AND NEW.state = 'approved' THEN
        IF NEW.approval_id IS NULL OR NEW.approved_at IS NULL THEN
            RAISE EXCEPTION
                'approving target % requires the dual-control approval binding and approved_at', OLD.id;
        END IF;
        IF NEW.authorization_version <= OLD.authorization_version THEN
            RAISE EXCEPTION 'approving target % must bump the authorization version', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'approved' AND NEW.state = 'revoked' THEN
        IF NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL THEN
            RAISE EXCEPTION 'revoking target % requires revoked_at and revoked_by', OLD.id;
        END IF;
        IF NEW.authorization_version <= OLD.authorization_version THEN
            RAISE EXCEPTION 'revoking target % must bump the authorization version (enforcement-immediate)', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    -- a pending target may be withdrawn directly to revoked (the request is
    -- cancelled; the open Ch.5 approval must be resolved separately)
    IF OLD.state = 'pending' AND NEW.state = 'revoked' THEN
        IF NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL THEN
            RAISE EXCEPTION 'revoking target % requires revoked_at and revoked_by', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'strike_targets illegal state transition % -> % (target %)', OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_target_lifecycle ON strike_targets;
CREATE TRIGGER trg_strike_target_lifecycle
    BEFORE UPDATE OR DELETE ON strike_targets
    FOR EACH ROW EXECUTE FUNCTION strike_target_lifecycle();
