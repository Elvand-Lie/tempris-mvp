-- 043_collector_host_identity.sql
-- PRD V3 §2.12 (2026-09-07): collector-host asset identity, one collector per
-- device whose identity Tempris persists. The Collector ID (Ed25519 key pinned
-- at enrollment) is the identity anchor; the explicit collector_id <-> asset_id
-- bind is a NEW second relationship and must NOT reuse the routing edge
-- assets.collector_id (002: many-to-one, ON DELETE SET NULL). Reported network
-- location is mutable state on the asset, never identity; devices that cannot
-- run a Collector have no guaranteed persistent identity.

-- Explicit identity bind: one collector <-> one host asset, both directions.
CREATE TABLE IF NOT EXISTS collector_host_bindings (
    collector_id UUID PRIMARY KEY REFERENCES collectors(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL UNIQUE REFERENCES assets(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    bound_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_collector_host_bindings_tenant_asset
    ON collector_host_bindings (tenant_id, asset_id);

-- Current network location of the bound host asset (mutable, never identity).
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS network_location JSONB;

-- Fail-closed flag: when a bound host's reported location no longer matches its
-- IP target tuple, scans are blocked until an operator confirms the target.
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS target_validation_state TEXT NOT NULL DEFAULT 'ok'
    CHECK (target_validation_state IN ('ok', 'needs_revalidation'));

-- Append-only observation history: the DHCP problem is at root a history problem.
CREATE TABLE IF NOT EXISTS asset_network_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id UUID NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    network_location JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_net_obs_asset_time
    ON asset_network_observations (asset_id, observed_at DESC);
