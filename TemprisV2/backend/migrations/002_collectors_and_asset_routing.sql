-- 002_collectors_and_asset_routing.sql
-- Tempris V2 Collectors and Asset Routing Foundation

CREATE TABLE IF NOT EXISTS collectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    enrollment_status TEXT NOT NULL DEFAULT 'awaiting_enrollment' CHECK (enrollment_status IN ('awaiting_enrollment', 'enrolled')),
    operator_status TEXT NOT NULL DEFAULT 'active' CHECK (operator_status IN ('active', 'paused', 'quarantined', 'revoked')),
    public_key TEXT,
    enrollment_code_hash TEXT,
    enrollment_code_expires_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    platform_metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_collectors_tenant_status
    ON collectors (tenant_id, operator_status);

CREATE INDEX IF NOT EXISTS idx_collectors_tenant_created
    ON collectors (tenant_id, created_at DESC);

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS collector_id UUID REFERENCES collectors(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_assets_tenant_collector
    ON assets (tenant_id, collector_id);
