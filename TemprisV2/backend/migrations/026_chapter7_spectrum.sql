-- Migration 026: Chapter 7 — SPECTRUM (Confirmed-Exposure Workbench) (PRD-000 v1.11 Ch.7).
--
-- The analyst workbench over a CONFIRMED exposure. SPECTRUM stores workflow
-- state at the EXPOSURE grain — assignment, analysis process state, notes/
-- history, STRIKE engagement drafts, EDIP handoffs — and NEVER scores:
-- every read is read-through to the Ch.3 recompute (§3.3.6; no score column
-- exists in any table below, and none may be added).
--
-- NAMING (Ch.7 target architecture item 3, binding): the analyst process
-- state column is ``analysis_state`` — never ``status``, which is Ch.3's
-- exposure lifecycle field (asset_exposures.status). The two never gate each
-- other; all exposure-state CHANGES stay owned by the Ch.3 exposure service.
--
-- Small lifecycle: new → assigned → in_analysis → action_required (the
-- EDIP-handoff marker). Journal rows (spectrum_workflow_history) are the
-- workflow narrative — FindingStatusHistory shape, distinct from scoring.
--
-- STRIKE requests are ENGAGEMENT DRAFTS pre-bound to the exposure (Ch.4 owns
-- everything after); EDIP handoffs are recorded in Needs-Decision state and
-- are retryable (Ch.8 owns everything after; upstream truth stays intact).
-- Manual at v1 — no auto-handoff policy (§3.6.6 #9 reserved).
--
-- The module catalogue gains SPECTRUM, seeded into the CORE_ASSETS base
-- package (the ASSETS precedent) so existing tenants hold the entitlement.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Module catalogue: SPECTRUM
-- ---------------------------------------------------------------------------

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'SPECTRUM',
    'SPECTRUM — Confirmed-Exposure Workbench',
    'Analyst workbench over confirmed exposures: queue, read-through TES context, assignment, analysis_state, notes, evidence surface, STRIKE requests, EDIP handoffs.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'SPECTRUM')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Exposure workflow (exposure grain; 1:1 with asset_exposures)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS spectrum_exposure_workflow (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id     UUID NOT NULL,
    -- analyst ownership (net-new in V2; exposure grain — the finding is
    -- grouping/roll-up only and carries NO workflow state)
    assigned_to     TEXT,
    assigned_by     TEXT,
    assigned_at     TIMESTAMPTZ,
    -- the analyst process state — NEVER named 'status' (Ch.3 owns
    -- asset_exposures.status; the two fields never gate each other)
    analysis_state  TEXT NOT NULL DEFAULT 'new'
                    CHECK (analysis_state IN ('new', 'assigned', 'in_analysis', 'action_required')),
    state_changed_by TEXT,
    state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- EDIP-handoff marker timestamp (the handoff row itself lives in
    -- spectrum_edip_handoffs; Ch.8 owns the decision lifecycle)
    edip_handoff_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_spectrum_workflow_exposure UNIQUE (tenant_id, exposure_id),
    CONSTRAINT fk_spectrum_workflow_exposure FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES asset_exposures(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT ck_spectrum_workflow_assigned_shape CHECK (
        (assigned_to IS NULL) OR (assigned_by IS NOT NULL AND assigned_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_spectrum_workflow_assignee
    ON spectrum_exposure_workflow (tenant_id, assigned_to)
    WHERE assigned_to IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_spectrum_workflow_state
    ON spectrum_exposure_workflow (tenant_id, analysis_state);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'spectrum_exposure_workflow'::regclass
          AND conname = 'uq_spectrum_exposure_workflow_tenant_id'
    ) THEN
        ALTER TABLE spectrum_exposure_workflow
            ADD CONSTRAINT uq_spectrum_exposure_workflow_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Workflow history (who/when/note — FindingStatusHistory shape)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS spectrum_workflow_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id  UUID NOT NULL,
    event        TEXT NOT NULL CHECK (length(btrim(event)) > 0),
    actor        TEXT NOT NULL,
    actor_role   TEXT,
    note         TEXT,
    detail       JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_spectrum_history_workflow FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES spectrum_exposure_workflow(tenant_id, exposure_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_spectrum_history_exposure
    ON spectrum_workflow_history (tenant_id, exposure_id, created_at ASC, id ASC);

-- ---------------------------------------------------------------------------
-- 4. STRIKE engagement drafts (pre-bound to the exposure; Ch.4 owns all
--    downstream lifecycle — v1 records only the draft, never silent failure)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS spectrum_strike_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id  UUID NOT NULL,
    -- v1 vocabulary is exactly the draft; STRIKE (Ch.4) extends it forward-only
    state        TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft')),
    requested_by TEXT NOT NULL,
    note         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_spectrum_strike_workflow FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES spectrum_exposure_workflow(tenant_id, exposure_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_spectrum_strike_exposure
    ON spectrum_strike_requests (tenant_id, exposure_id, created_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'spectrum_strike_requests'::regclass
          AND conname = 'uq_spectrum_strike_requests_tenant_id'
    ) THEN
        ALTER TABLE spectrum_strike_requests
            ADD CONSTRAINT uq_spectrum_strike_requests_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. EDIP handoffs (recorded in Needs-Decision state; retryable upstream
--    truth — one OPEN handoff per exposure at a time; Ch.8 owns the decision)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS spectrum_edip_handoffs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id  UUID NOT NULL,
    -- v1 vocabulary is exactly Needs-Decision; EDIP (Ch.8) extends it
    state        TEXT NOT NULL DEFAULT 'NEEDS_DECISION' CHECK (state IN ('NEEDS_DECISION')),
    requested_by TEXT NOT NULL,
    note         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_spectrum_edip_workflow FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES spectrum_exposure_workflow(tenant_id, exposure_id) ON DELETE CASCADE
);

-- one OPEN handoff per exposure: a retry (or a second request) must wait for
-- the decision consumer to resolve the standing one
CREATE UNIQUE INDEX IF NOT EXISTS uq_spectrum_edip_open_per_exposure
    ON spectrum_edip_handoffs (tenant_id, exposure_id)
    WHERE state = 'NEEDS_DECISION';

CREATE INDEX IF NOT EXISTS idx_spectrum_edip_exposure
    ON spectrum_edip_handoffs (tenant_id, exposure_id, created_at DESC);
