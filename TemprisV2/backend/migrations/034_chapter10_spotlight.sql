-- Migration 034: Chapter 10 — CISO / SPOTLIGHT (Executive View) (PRD-000 v1.11 Ch.10).
--
-- SPOTLIGHT is a READ-ONLY consumer: its entire input set is already contract
-- (Ch.3 six-field summaries, Ch.7 workflow state, Ch.8/9 decision/obligation
-- state, Ch.1 feed health). It owns exactly ONE piece of state — its own
-- append-only posture_snapshots (derived data, labeled as such) — and is
-- never the source of record for anything.
--
-- The snapshot is the PostureSnapshot pattern generalized: captured_at,
-- captured_by, payload hash, referenced upstream states. Rows are immutable
-- (DB-enforced: UPDATE/DELETE raise) and payloads carry no scoring internals
-- beyond the public §3.3.5 decomposition conventions already exposed by the
-- read model.
--
-- Severe-exposure visibility is COUNT + MAX based; the V1 aggregate_tes
-- arithmetic mean is retired and no composite index exists anywhere in this
-- schema (PRD Ch.10 design rules 1-2).
--
-- Manual capture only at v1 — scheduled cadence is OPEN (tied to the Ch.9/
-- Ch.4 scheduler decision).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Module catalogue: SPOTLIGHT
-- ---------------------------------------------------------------------------

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'SPOTLIGHT',
    'SPOTLIGHT — Executive View (CISO)',
    'Read-only executive posture view over upstream domains: severe-exposure tiles (counts and maxima, never means), workflow/remediation posture, coverage and feed-quality strip, append-only posture snapshots and trend deltas.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'SPOTLIGHT')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. posture_snapshots — the module's only owned state (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS posture_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    captured_by     TEXT NOT NULL,
    actor_role      TEXT,
    -- sha256 over the canonical JSON of the payload — the integrity seal of
    -- the derived snapshot (the payload is derived data; the hash binds it)
    payload_hash    TEXT NOT NULL,
    -- the derived executive payload itself (tiles at the captured instant)
    payload         JSONB NOT NULL,
    -- referenced upstream states: exposure ids + row versions, feed snapshot
    -- ids, workflow/handoff row ids — drill-down is identity, never a copy
    source_refs     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_posture_snapshots_hash_shape
        CHECK (payload_hash ~* '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_posture_snapshots_tenant_captured
    ON posture_snapshots (tenant_id, captured_at DESC, id DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'posture_snapshots'::regclass
          AND conname = 'uq_posture_snapshots_tenant_id'
    ) THEN
        ALTER TABLE posture_snapshots
            ADD CONSTRAINT uq_posture_snapshots_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- Append-only, DB-enforced (the migration-019 immutable-history precedent):
-- a snapshot is written once and never revised — history cannot be rewritten
-- to flatter a trend.
CREATE OR REPLACE FUNCTION posture_snapshots_forbid_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'posture_snapshots is append-only: % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_posture_snapshots_no_update ON posture_snapshots;
CREATE TRIGGER trg_posture_snapshots_no_update
    BEFORE UPDATE OR DELETE ON posture_snapshots
    FOR EACH ROW EXECUTE FUNCTION posture_snapshots_forbid_mutation();
