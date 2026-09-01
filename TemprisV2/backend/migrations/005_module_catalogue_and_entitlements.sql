-- 005_module_catalogue_and_entitlements.sql
-- Tempris V2 Module Catalogue, Base Packages, and Tenant Entitlements

-- 1. Modules Catalogue Table
CREATE TABLE IF NOT EXISTS modules (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Packages Table
CREATE TABLE IF NOT EXISTS packages (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. Package-Module Mapping Table
CREATE TABLE IF NOT EXISTS package_modules (
    package_id VARCHAR(64) NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    module_id VARCHAR(64) NOT NULL REFERENCES modules(id) ON DELETE RESTRICT,
    PRIMARY KEY (package_id, module_id)
);

-- 4. Tenant Entitlements Table (Single Base Package + JSONB Overrides)
CREATE TABLE IF NOT EXISTS tenant_entitlements (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
    package_id VARCHAR(64) NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
    module_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INT NOT NULL DEFAULT 1,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tenant_entitlements_pkg ON tenant_entitlements (package_id);

-- 5. Seed Module Catalogue (ASSETS)
INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'ASSETS',
    'Asset Inventory, Scan Authorizations & Reachability Probing',
    'Core asset inventory management, exact-target authorization, and internal collector probing.',
    'active',
    now()
) ON CONFLICT (id) DO NOTHING;

-- 6. Seed Base Package (CORE_ASSETS)
INSERT INTO packages (id, name, description, is_default, version, created_at, updated_at)
VALUES (
    'CORE_ASSETS',
    'Core Assets & Collectors Package',
    'Standard package containing the ASSETS module.',
    TRUE,
    1,
    now(),
    now()
) ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'ASSETS')
ON CONFLICT (package_id, module_id) DO NOTHING;

-- 7. Seed default entitlement (CORE_ASSETS) for all existing tenants
INSERT INTO tenant_entitlements (tenant_id, package_id, module_overrides, version, updated_at)
SELECT id, 'CORE_ASSETS', '{}'::jsonb, 1, now()
FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;
