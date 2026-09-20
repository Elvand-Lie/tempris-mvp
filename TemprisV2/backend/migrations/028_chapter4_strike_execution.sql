-- Migration 028: Chapter 4 — STRIKE, part 2 of 3: the execution core —
-- workspaces, operations, artifacts, and the ability allowlist
-- (PRD-000 v1.11 Ch.4 principles 2/4/7/8, owned-state table, PATCH-04/05).
--
-- strike_workspaces — one dedicated disposable workspace per engagement
--   (cardinality lock: ONE live workspace row per engagement at a time — the
--   schema permitting several historical rows is a data-model fact, not a
--   license). Provisioning is RECOVERY-SAFE (PATCH-04): the generation is
--   atomically reserved BEFORE any external provider call, the reservation
--   carries a stable persisted identity, native provider references are
--   recorded when known, and an unknown provisioning outcome stays
--   'provisioning' until reconciled — a blind retry never creates a second
--   VM, and ERROR/provision-failure is never proof of non-execution.
--   Alarm states ('provision_failed', 'destroy_failed') demand operator
--   reconciliation and are never silent; reconciliation is what retires the
--   generation (confirmed fencing of the predecessor).
--   Workspace egress is enforced OUTSIDE the workspace (principle 4); the
--   control plane holds the compiled policy (egress_policy) and its
--   egress_generation, bumped whenever target authorizations change so stale
--   generations cannot reactivate (PATCH-03).
--
-- strike_operations — execution truth. Lifecycle:
--   dispatched → running → (cancelling →) completed / failed / cancelled /
--   cancel_unconfirmed. 'cancelled' is written only when termination is
--   CONFIRMED; an unconfirmed stop becomes 'cancel_unconfirmed' (alarm). The
--   7-state outcome enum (principle 8) is stored, but the classifier never
--   auto-assigns EXPLOITABLE or PREVENTED (the POC A rule); engine/transport
--   failure is outcome ERROR — target truth remains unknown.
--
-- strike_artifacts — immutable on write (hash + size + media type);
--   retention tiered (the retention periods themselves are open decision #5).
--
-- strike_abilities — the approved tool/content allowlist (principle 7):
--   curated, versioned, pinned; nothing runs that is not on it. Seeding is
--   deliberately left to catalog governance (open decision #6) — the table
--   ships EMPTY (fail-closed: nothing is dispatchable until curated).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Workspaces — disposable, one live generation per engagement
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_workspaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL REFERENCES strike_engagements(id) ON DELETE RESTRICT,
    -- sequential workspace generation (PATCH-04): reserved atomically BEFORE
    -- any external provider call; replacement requires confirmed fencing of
    -- the predecessor generation
    generation      INT NOT NULL CHECK (generation > 0),
    state           TEXT NOT NULL DEFAULT 'provisioning'
                    CHECK (state IN ('provisioning', 'ready', 'in_use',
                                     'collecting', 'destroying', 'destroyed',
                                     'destroy_failed', 'provision_failed')),
    -- native provider/engine references (recorded when known; NULL is honest
    -- unknown — never a fabricated ref)
    provider        TEXT,
    provider_workspace_ref TEXT,
    -- compiled egress policy: the approved final destinations pinned at
    -- reservation (principle 4: enforcement lives outside the workspace;
    -- PATCH-03: pinned destinations, generation-bound)
    egress_policy   JSONB NOT NULL DEFAULT '[]'::jsonb,
    egress_generation INT NOT NULL DEFAULT 1,
    reserved_by     TEXT NOT NULL,
    reserved_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    provisioned_at  TIMESTAMPTZ,
    destroying_started_at TIMESTAMPTZ,
    destroyed_at    TIMESTAMPTZ,
    -- alarm bookkeeping (never silent): last failure/reconciliation record
    last_error      TEXT,
    reconciled_by   TEXT,
    reconciled_at   TIMESTAMPTZ,
    reconcile_note  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_strike_workspace_generation UNIQUE (tenant_id, engagement_id, generation)
);

-- THE CARDINALITY LOCK: at most one workspace per engagement outside the
-- terminal states. A second reservation is impossible while any generation
-- is provisioning/ready/in_use/collecting/destroying/alarmed — replacement
-- must first reconcile and fence the standing one (PATCH-04).
CREATE UNIQUE INDEX IF NOT EXISTS uq_strike_workspace_one_live_per_engagement
    ON strike_workspaces (tenant_id, engagement_id)
    WHERE state IN ('provisioning', 'ready', 'in_use', 'collecting',
                    'destroying', 'destroy_failed', 'provision_failed');

CREATE INDEX IF NOT EXISTS idx_strike_workspaces_engagement
    ON strike_workspaces (tenant_id, engagement_id, generation DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'strike_workspaces'::regclass
          AND conname = 'uq_strike_workspaces_tenant_id'
    ) THEN
        ALTER TABLE strike_workspaces
            ADD CONSTRAINT uq_strike_workspaces_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION strike_workspace_lifecycle() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'strike_workspaces are history (DELETE forbidden; state=%)', OLD.state;
    END IF;

    IF NEW.generation IS NOT DISTINCT FROM OLD.generation
       AND NEW.engagement_id IS NOT DISTINCT FROM OLD.engagement_id
    THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'strike_workspaces generation/engagement are immutable (workspace %)', OLD.id;
    END IF;

    -- same-state annotation: live/uncertain/alarmed states record truth
    -- about themselves (last_error, reconciliation bookkeeping, egress
    -- generation bumps on target changes) WITHOUT transitioning — the
    -- lifecycle state itself never moves silently this way, and the
    -- terminal state is frozen
    IF NEW.state = OLD.state AND OLD.state <> 'destroyed' THEN
        RETURN NEW;
    END IF;

    -- ---- legal edges ------------------------------------------------------

    -- operator reconciliation of an UNKNOWN provisioning outcome: fencing
    -- attested (reconciled_by/at/note) retires the generation — releasing
    -- the cardinality lock is exactly what makes reconcile-before-retry
    -- enforceable (PATCH-04)
    IF OLD.state = 'provisioning' AND NEW.state = 'destroyed' THEN
        IF NEW.reconciled_by IS NULL OR NEW.reconciled_at IS NULL OR NEW.reconcile_note IS NULL THEN
            RAISE EXCEPTION
                'retiring unknown-outcome workspace % requires reconciled_by/at/note (operator attestation)', OLD.id;
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'provisioning' AND NEW.state IN ('ready', 'provision_failed') THEN
        IF NEW.state = 'ready' AND (NEW.provisioned_at IS NULL OR NEW.provider IS NULL) THEN
            RAISE EXCEPTION 'workspace % ready requires provisioned_at and provider', OLD.id;
        END IF;
        IF NEW.state = 'provision_failed' AND NEW.last_error IS NULL THEN
            RAISE EXCEPTION 'workspace % provision_failed requires last_error (never silent)', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('ready', 'in_use') AND NEW.state = 'in_use' THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'in_use' AND NEW.state = 'collecting' THEN
        RETURN NEW;
    END IF;

    IF OLD.state IN ('ready', 'in_use', 'collecting') AND NEW.state = 'destroying' THEN
        IF NEW.destroying_started_at IS NULL THEN
            RAISE EXCEPTION 'workspace % entering destroying requires destroying_started_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'destroying' AND NEW.state IN ('destroyed', 'destroy_failed') THEN
        IF NEW.state = 'destroyed' AND NEW.destroyed_at IS NULL THEN
            RAISE EXCEPTION 'workspace % destroyed requires destroyed_at', OLD.id;
        END IF;
        IF NEW.state = 'destroy_failed' AND NEW.last_error IS NULL THEN
            RAISE EXCEPTION 'workspace % destroy_failed requires last_error (never silent)', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    -- alarm resolution: reconciliation confirms fencing and retires the
    -- generation (operator action — the note records what was confirmed)
    IF OLD.state IN ('destroy_failed', 'provision_failed') AND NEW.state = 'destroyed' THEN
        IF NEW.reconciled_by IS NULL OR NEW.reconciled_at IS NULL OR NEW.reconcile_note IS NULL THEN
            RAISE EXCEPTION
                'retiring alarmed workspace % requires reconciled_by/at/note (operator reconciliation)', OLD.id;
        END IF;
        IF NEW.destroyed_at IS NULL THEN
            NEW.destroyed_at := NEW.reconciled_at;
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'strike_workspaces illegal state transition % -> % (workspace %)', OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_workspace_lifecycle ON strike_workspaces;
CREATE TRIGGER trg_strike_workspace_lifecycle
    BEFORE UPDATE OR DELETE ON strike_workspaces
    FOR EACH ROW EXECUTE FUNCTION strike_workspace_lifecycle();

-- ---------------------------------------------------------------------------
-- 2. Abilities — the approved allowlist (ships EMPTY: fail-closed until
--    catalog governance curates it — open decision #6)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_abilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9._-]*$'),
    title           TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    engine          TEXT NOT NULL CHECK (length(btrim(engine)) > 0),
    version         TEXT NOT NULL CHECK (length(btrim(version)) > 0),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 3. Operations — execution truth (7-state outcome; confirmed cancellation)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_operations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL REFERENCES strike_engagements(id) ON DELETE RESTRICT,
    workspace_id    UUID NOT NULL REFERENCES strike_workspaces(id) ON DELETE RESTRICT,
    target_id       UUID NOT NULL REFERENCES strike_targets(id) ON DELETE RESTRICT,
    ability_id      UUID NOT NULL REFERENCES strike_abilities(id) ON DELETE RESTRICT,
    state           TEXT NOT NULL DEFAULT 'dispatched'
                    CHECK (state IN ('dispatched', 'running', 'cancelling',
                                     'completed', 'failed', 'cancelled',
                                     'cancel_unconfirmed')),
    -- the 7-state execution-truth enum (principle 8). EXPLOITABLE/PREVENTED
    -- are representable but the classifier never auto-assigns them (the POC
    -- A rule); NULL while unresolved (dispatched/running/cancelling/
    -- cancel_unconfirmed).
    outcome         TEXT
                    CHECK (outcome IN ('EXPLOITABLE', 'PREVENTED', 'INCONCLUSIVE',
                                       'NOT_EXECUTED', 'UNSUPPORTED', 'ERROR',
                                       'OBSERVED')),
    engine          TEXT NOT NULL,
    engine_operation_ref TEXT,
    -- bounded native engine output (64 KiB cap enforced in the service, the
    -- POC A bound); NULL until a result is collected
    native_output   JSONB,
    output_summary  TEXT,
    requested_by    TEXT NOT NULL,
    dispatched_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    running_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    cancel_requested_at TIMESTAMPTZ,
    cancel_confirmed_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_strike_operation_terminal_outcome CHECK (
        -- terminal states carry their outcome; unresolved states do not
        (state IN ('completed', 'failed') AND outcome IS NOT NULL)
        OR (state IN ('dispatched', 'running', 'cancelling', 'cancelled',
                      'cancel_unconfirmed'))
    )
);

CREATE INDEX IF NOT EXISTS idx_strike_operations_engagement
    ON strike_operations (tenant_id, engagement_id, dispatched_at DESC);
CREATE INDEX IF NOT EXISTS idx_strike_operations_target
    ON strike_operations (tenant_id, target_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'strike_operations'::regclass
          AND conname = 'uq_strike_operations_tenant_id'
    ) THEN
        ALTER TABLE strike_operations
            ADD CONSTRAINT uq_strike_operations_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION strike_operation_lifecycle() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'strike_operations are history (DELETE forbidden; state=%)', OLD.state;
    END IF;

    IF NEW.engagement_id IS NOT DISTINCT FROM OLD.engagement_id
       AND NEW.workspace_id IS NOT DISTINCT FROM OLD.workspace_id
       AND NEW.target_id IS NOT DISTINCT FROM OLD.target_id
       AND NEW.ability_id IS NOT DISTINCT FROM OLD.ability_id
       AND NEW.engine IS NOT DISTINCT FROM OLD.engine
    THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'strike_operations dispatch binding is immutable (operation %)', OLD.id;
    END IF;

    -- ---- legal edges ------------------------------------------------------
    IF OLD.state = 'dispatched' AND NEW.state = 'running' THEN
        IF NEW.running_at IS NULL OR NEW.engine_operation_ref IS NULL THEN
            RAISE EXCEPTION 'operation % running requires running_at and engine_operation_ref', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('dispatched', 'running') AND NEW.state IN ('completed', 'failed') THEN
        IF NEW.completed_at IS NULL THEN
            RAISE EXCEPTION 'operation % terminal requires completed_at', OLD.id;
        END IF;
        IF NEW.state = 'failed' AND NEW.outcome <> 'ERROR' THEN
            RAISE EXCEPTION 'operation % failed must carry outcome ERROR (never PREVENTED/NOT_EXECUTED)', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('dispatched', 'running') AND NEW.state = 'cancelling' THEN
        IF NEW.cancel_requested_at IS NULL THEN
            RAISE EXCEPTION 'operation % cancelling requires cancel_requested_at', OLD.id;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'cancelling' AND NEW.state IN ('cancelled', 'cancel_unconfirmed') THEN
        IF NEW.state = 'cancelled' THEN
            IF NEW.cancel_confirmed_at IS NULL THEN
                RAISE EXCEPTION 'operation % cancelled requires CONFIRMED stop (cancel_confirmed_at)', OLD.id;
            END IF;
        ELSE
            -- the alarm path: unconfirmed stop, operator reconciliation follows
            IF NEW.cancel_confirmed_at IS NOT NULL THEN
                RAISE EXCEPTION 'operation % cancel_unconfirmed must not carry a stop confirmation', OLD.id;
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    -- same-state annotation for the alarm state (reconciliation bookkeeping
    -- while the stop remains unresolved)
    IF NEW.state = OLD.state AND NEW.state = 'cancel_unconfirmed' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'strike_operations illegal state transition % -> % (operation %)', OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_operation_lifecycle ON strike_operations;
CREATE TRIGGER trg_strike_operation_lifecycle
    BEFORE UPDATE OR DELETE ON strike_operations
    FOR EACH ROW EXECUTE FUNCTION strike_operation_lifecycle();

-- ---------------------------------------------------------------------------
-- 3. Artifacts — immutable on write, hashed, retention-tiered
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS strike_artifacts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    engagement_id   UUID NOT NULL REFERENCES strike_engagements(id) ON DELETE RESTRICT,
    operation_id    UUID NOT NULL REFERENCES strike_operations(id) ON DELETE RESTRICT,
    name            TEXT NOT NULL CHECK (length(btrim(name)) > 0),
    media_type      TEXT NOT NULL CHECK (length(btrim(media_type)) > 0),
    size_bytes      BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256          TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    content         BYTEA NOT NULL,
    -- retention tier (the periods themselves are open decision #5; the tier
    -- is recorded at write time and the row is immutable)
    retention_tier  TEXT NOT NULL DEFAULT 'engagement',
    collected_by    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_strike_artifacts_operation
    ON strike_artifacts (tenant_id, operation_id, created_at DESC);

CREATE OR REPLACE FUNCTION strike_artifacts_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'strike_artifacts are immutable on write (TG_OP=%, artifact %)', TG_OP, COALESCE(OLD.id, NEW.id);
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_strike_artifacts_immutable ON strike_artifacts;
CREATE TRIGGER trg_strike_artifacts_immutable
    BEFORE UPDATE OR DELETE ON strike_artifacts
    FOR EACH ROW EXECUTE FUNCTION strike_artifacts_immutable();

-- (the ability allowlist is section 2 — operations above FK-reference it)
