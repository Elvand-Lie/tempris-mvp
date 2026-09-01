-- 004_tenancy_and_auth_foundation.sql
-- Tempris V2 Tenancy and Authentication Foundation: Tenants, Users, Memberships, Dynamic Backfill, Foreign Keys

-- 1. Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);

-- 2. Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    password_hash VARCHAR(255), -- NULL only while status = 'pending'
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
    is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_users_password_state CHECK (
        (status = 'pending' AND password_hash IS NULL) OR
        (status IN ('active', 'disabled') AND password_hash IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);

-- 3. Tenant Memberships Table (Relational schema with single active membership constraint)
CREATE TABLE IF NOT EXISTS tenant_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role VARCHAR(32) NOT NULL CHECK (role IN ('analyst', 'admin', 'superadmin')),
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_tenant_user UNIQUE (tenant_id, user_id)
);
-- Partial unique index enforcing at most one active membership per user across all tenants.
-- Disabled historical memberships may coexist.
CREATE UNIQUE INDEX IF NOT EXISTS uq_memberships_user_active ON tenant_memberships (user_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_memberships_user ON tenant_memberships (user_id, status);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON tenant_memberships (tenant_id, status);

-- 4. Dynamically backfill tenants from DISTINCT operational tables union
INSERT INTO tenants (id, name, slug, status, version, created_at, updated_at)
SELECT
    DISTINCT operational_tenants.tenant_id,
    'Tenant ' || substr(operational_tenants.tenant_id::text, 1, 8),
    'tenant-' || operational_tenants.tenant_id::text,
    'active',
    1,
    now(),
    now()
FROM (
    SELECT tenant_id FROM assets
    UNION
    SELECT tenant_id FROM collectors
    UNION
    SELECT tenant_id FROM asset_scan_authorizations
    UNION
    SELECT tenant_id FROM audit_events
) AS operational_tenants
ON CONFLICT (id) DO NOTHING;

-- 5. Explicitly override names and slugs for known production UUIDs
INSERT INTO tenants (id, name, slug, status, version)
VALUES
    ('11111111-1111-1111-1111-111111111111'::uuid, 'Tempris', 'tempris', 'active', 1),
    ('00000000-0000-0000-0000-000000000001'::uuid, 'Legacy Tenant 00000000', 'legacy-tenant-0000', 'active', 1)
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name, slug = EXCLUDED.slug, status = EXCLUDED.status;

-- 6. Apply RESTRICT foreign keys only after backfill completes
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'assets'::regclass AND conname = 'fk_assets_tenant'
    ) THEN
        ALTER TABLE assets
            ADD CONSTRAINT fk_assets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'collectors'::regclass AND conname = 'fk_collectors_tenant'
    ) THEN
        ALTER TABLE collectors
            ADD CONSTRAINT fk_collectors_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'asset_scan_authorizations'::regclass AND conname = 'fk_authorizations_tenant'
    ) THEN
        ALTER TABLE asset_scan_authorizations
            ADD CONSTRAINT fk_authorizations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'audit_events'::regclass AND conname = 'fk_audit_events_tenant'
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
    END IF;
END $$;
