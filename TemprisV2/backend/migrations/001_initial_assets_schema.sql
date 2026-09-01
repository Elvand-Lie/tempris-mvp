-- 001_initial_assets_schema.sql
-- Tempris V2 Initial Schema: Assets, Scan Authorizations, Audit Events

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('ip', 'hostname', 'domain')),
    target_value TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    network_scope TEXT NOT NULL CHECK (network_scope IN ('internet', 'internal')),
    environment TEXT NOT NULL CHECK (environment IN ('production', 'staging', 'development', 'test', 'other')),
    criticality TEXT NOT NULL CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    owner TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'decommissioned')),
    reachability_status TEXT NOT NULL DEFAULT 'unverified' CHECK (reachability_status IN ('unverified', 'verified', 'unreachable')),
    verification_source TEXT,
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decommissioned_at TIMESTAMPTZ
);

-- Partial unique index allowing decommissioned targets to be re-registered
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_tenant_target_active
    ON assets (tenant_id, normalized_target)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_assets_tenant_status
    ON assets (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_assets_tenant_created
    ON assets (tenant_id, created_at DESC);


CREATE TABLE IF NOT EXISTS asset_scan_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('ip', 'hostname', 'domain')),
    normalized_target TEXT NOT NULL,
    network_scope TEXT NOT NULL CHECK (network_scope IN ('internet', 'internal')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'revoked', 'expired')),
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_reason TEXT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_by TEXT,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_authorizations_tenant_asset
    ON asset_scan_authorizations (tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_authorizations_asset_status
    ON asset_scan_authorizations (asset_id, status);


CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    event_name TEXT NOT NULL,
    asset_id UUID,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created
    ON audit_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_asset_created
    ON audit_events (asset_id, created_at DESC)
    WHERE asset_id IS NOT NULL;
