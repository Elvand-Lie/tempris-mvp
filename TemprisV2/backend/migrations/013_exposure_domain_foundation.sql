-- Migration 013: Exposure Domain Foundation
-- Establishes the foundational schema for findings, asset applicability reviews,
-- and evidence-bearing confirmed asset exposures with composite tenant integrity.
--
-- Idempotent: uses IF NOT EXISTS and DO blocks throughout.

-- ---------------------------------------------------------------------------
-- 1. Prerequisite Constraint on assets
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'assets'::regclass AND conname = 'uq_assets_tenant_id'
    ) THEN
        ALTER TABLE assets ADD CONSTRAINT uq_assets_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Table: findings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    canonical_cve_id  TEXT REFERENCES canonical_vulnerabilities(cve_id) ON DELETE SET NULL,
    title             TEXT NOT NULL,
    description       TEXT,
    severity          TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'resolved', 'ignored', 'false_positive')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at         TIMESTAMPTZ,
    CONSTRAINT uq_findings_tenant_id UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status ON findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_cve ON findings (tenant_id, canonical_cve_id);

-- ---------------------------------------------------------------------------
-- 3. Table: asset_applicability_reviews
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_applicability_reviews (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    finding_id    UUID NOT NULL,
    asset_id      UUID NOT NULL,
    applicability TEXT NOT NULL CHECK (applicability IN ('NEEDS_REVIEW', 'REFERENCE', 'APPLICABLE', 'NOT_APPLICABLE')),
    reviewed_by   TEXT NOT NULL,
    reason        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_applicability_finding FOREIGN KEY (tenant_id, finding_id) REFERENCES findings(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_applicability_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES assets(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_applicability_lookup ON asset_applicability_reviews (tenant_id, finding_id, asset_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 4. Table: asset_exposures
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_exposures (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    finding_id        UUID NOT NULL,
    asset_id          UUID NOT NULL,
    status            TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'resolved', 'remediated', 'false_positive')),
    evidence          JSONB NOT NULL CHECK (evidence <> '{}'::jsonb AND jsonb_typeof(evidence) = 'object'),
    confirmed_by      TEXT NOT NULL,
    confirmed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    resolved_by       TEXT,
    resolution_reason TEXT,
    CONSTRAINT fk_exposure_finding FOREIGN KEY (tenant_id, finding_id) REFERENCES findings(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_exposure_asset FOREIGN KEY (tenant_id, asset_id) REFERENCES assets(tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_exposures_unique_current
    ON asset_exposures (tenant_id, finding_id, asset_id)
    WHERE status = 'confirmed';
CREATE INDEX IF NOT EXISTS idx_asset_exposures_tenant_status
    ON asset_exposures (tenant_id, status);
