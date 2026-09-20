-- Migration 016: Exposure Lifecycle Authority (P0-01, PRD-000 v1.11 §3.3.1)
--
-- Establishes the V3 exposure episode lifecycle as the sole status truth:
--   * storage keeps FIVE values: the four V3 write states
--     ('confirmed', 'resolved', 'false_positive', 'superseded') plus legacy
--     'remediated', which remains storage-compatible per PRD §3.3.1/D-16
--     ("V2's CHECK retains the value; V3 never creates it"). Existing legacy
--     rows are preserved byte-for-semantic-value — an unverified legacy
--     remediation claim is NOT promoted to 'resolved' (verified closed).
--   * V3 application write paths (models/services) reject 'remediated'; only
--     the storage layer tolerates it for compatibility.
--   * duplicate current (tenant, finding, asset) exposure triples are
--     validated and reported before the unique-current constraint is
--     (re)installed — never silently discarded.
--   * finding identity: one finding per (tenant, canonical_cve_id) — duplicate
--     concepts are validated loudly before the partial unique index is
--     installed; never discarded.
--
-- Forward-only. The whole file runs inside one transaction (see migrations/runner.py);
-- any failure aborts atomically.

-- ---------------------------------------------------------------------------
-- 1. Validate duplicate current exposure triples BEFORE installing the unique
--    constraint (defence for databases where the 013 partial unique index was
--    dropped; aborts the migration loudly instead of discarding anything)
-- ---------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_asset_exposures_unique_current;

DO $$
DECLARE
    duplicate_groups int;
BEGIN
    SELECT count(*) INTO duplicate_groups
    FROM (
        SELECT tenant_id, finding_id, asset_id
        FROM asset_exposures
        WHERE status = 'confirmed'
        GROUP BY tenant_id, finding_id, asset_id
        HAVING count(*) > 1
    ) duplicates;

    IF duplicate_groups > 0 THEN
        RAISE EXCEPTION
            'migration 016: % duplicate current (tenant, finding, asset) exposure triple(s) exist; resolve duplicates before installing the unique-current constraint',
            duplicate_groups;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Status CHECK: add 'superseded', keep legacy 'remediated' storage-compatible.
--    Drops 013's inline (auto-named) check and installs the five-value one.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    legacy_check_name text;
BEGIN
    SELECT c.conname INTO legacy_check_name
    FROM pg_constraint c
    WHERE c.conrelid = 'asset_exposures'::regclass
      AND c.contype = 'c'
      AND pg_get_constraintdef(c.oid) ILIKE '%remediated%'
      AND c.conname <> 'ck_asset_exposures_status_v3';

    IF legacy_check_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE asset_exposures DROP CONSTRAINT %I', legacy_check_name);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'asset_exposures'::regclass
          AND conname = 'ck_asset_exposures_status_v3'
    ) THEN
        ALTER TABLE asset_exposures
            ADD CONSTRAINT ck_asset_exposures_status_v3
            CHECK (status IN ('confirmed', 'resolved', 'remediated', 'false_positive', 'superseded'));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Unique-current episode constraint: at most one 'confirmed' episode per
--    (tenant, finding, asset); historical episodes coexist.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_exposures_unique_current
    ON asset_exposures (tenant_id, finding_id, asset_id)
    WHERE status = 'confirmed';

-- ---------------------------------------------------------------------------
-- 4. Episode-history index: recurrence / "findings that return" queries walk
--    the full per-tuple history (current + terminal episodes).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_asset_exposures_episode_history
    ON asset_exposures (tenant_id, finding_id, asset_id, confirmed_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- 5. Finding identity: the same vulnerability concept is the same finding
--    (PRD §3.3.1). Validate existing duplicates loudly, then enforce
--    one finding per (tenant, canonical_cve_id) for non-null CVEs.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    duplicate_cve_findings int;
BEGIN
    SELECT count(*) INTO duplicate_cve_findings
    FROM (
        SELECT tenant_id, canonical_cve_id
        FROM findings
        WHERE canonical_cve_id IS NOT NULL
        GROUP BY tenant_id, canonical_cve_id
        HAVING count(*) > 1
    ) duplicates;

    IF duplicate_cve_findings > 0 THEN
        RAISE EXCEPTION
            'migration 016: % (tenant, canonical_cve_id) finding group(s) have more than one finding; resolve duplicates before installing the unique finding-identity constraint',
            duplicate_cve_findings;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_cve_unique
    ON findings (tenant_id, canonical_cve_id)
    WHERE canonical_cve_id IS NOT NULL;
