-- 006_platform_control_tenant.sql
-- Dedicated platform login-context tenant for platform administrators.
--
-- Identity boundary only: this tenant holds platform administrator memberships
-- and nothing else. It intentionally receives NO module entitlement (tenant
-- modules are denied to platform sessions in code as the root defense) and no
-- operational data. The operational Tempris tenant remains
-- 11111111-1111-1111-1111-111111111111 and continues to own Assets/Collectors.

INSERT INTO tenants (id, name, slug, status, version)
VALUES (
    'f0000000-0000-4000-8000-000000000001'::uuid,
    'Tempris Platform Control',
    'tempris-platform-control',
    'active',
    1
)
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name, slug = EXCLUDED.slug, status = EXCLUDED.status;

-- Defensive reconciliation: if any entitlement row was ever accidentally
-- assigned to the Platform Control tenant, remove it. Platform Control must
-- not hold module entitlements.
DELETE FROM tenant_entitlements
WHERE tenant_id = 'f0000000-0000-4000-8000-000000000001'::uuid;
