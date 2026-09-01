-- 003_collector_schema_contract.sql
-- Explicit typed columns for collector hardware/OS inventory and lifecycle timestamps

ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS os VARCHAR(64),
    ADD COLUMN IF NOT EXISTS architecture VARCHAR(64),
    ADD COLUMN IF NOT EXISTS hostname VARCHAR(255),
    ADD COLUMN IF NOT EXISTS version VARCHAR(64),
    ADD COLUMN IF NOT EXISTS enrolled_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Backfill explicit hardware/OS columns from existing platform_metadata JSONB where available
UPDATE collectors
SET
    os = COALESCE(os, platform_metadata->>'os'),
    architecture = COALESCE(architecture, platform_metadata->>'architecture'),
    hostname = COALESCE(hostname, platform_metadata->>'hostname'),
    version = COALESCE(version, platform_metadata->>'agent_version', platform_metadata->>'version')
WHERE platform_metadata IS NOT NULL AND platform_metadata != '{}'::jsonb;

-- Backfill enrolled_at for already enrolled collectors
UPDATE collectors
SET enrolled_at = COALESCE(enrolled_at, updated_at, created_at)
WHERE enrollment_status = 'enrolled' AND enrolled_at IS NULL;

-- Backfill revoked_at for already revoked collectors
UPDATE collectors
SET revoked_at = COALESCE(revoked_at, updated_at)
WHERE operator_status = 'revoked' AND revoked_at IS NULL;
