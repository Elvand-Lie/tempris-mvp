-- Migration 012: Sprint 03 Downstream Freeze & Structural Container Provenance
-- Structural assigning-CNA container provenance for deterministic TES resolution
-- and downstream consumer freeze gate.
--
-- Idempotent: uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS throughout.

-- ---------------------------------------------------------------------------
-- 1. Add structural container provenance to cvss_assessments
-- ---------------------------------------------------------------------------
ALTER TABLE cvss_assessments
    ADD COLUMN IF NOT EXISTS container_role VARCHAR(32),
    ADD COLUMN IF NOT EXISTS provider_org_id TEXT;

-- ---------------------------------------------------------------------------
-- 2. Index for fast deterministic TES lookup
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_cvss_tes_lookup
    ON cvss_assessments (cve_id, cvss_version, container_role, is_current)
    WHERE is_current = TRUE AND cvss_version = '3.1';

-- ---------------------------------------------------------------------------
-- 3. Idempotent backfill for existing cvss_assessments rows (CRIT-1)
-- ---------------------------------------------------------------------------

-- Backfill NVD assessments
UPDATE cvss_assessments
SET container_role = 'nvd',
    provider_org_id = COALESCE(provider_org_id, assessor)
WHERE source = 'nvd' AND container_role IS NULL;

-- Backfill CVE CNA assessments
UPDATE cvss_assessments
SET container_role = 'cna'
WHERE source = 'cve' AND (assessment_type = 'cna' OR assessment_type IS NULL) AND container_role IS NULL;

-- Backfill CVE ADP assessments
UPDATE cvss_assessments
SET container_role = 'adp'
WHERE source = 'cve' AND assessment_type = 'adp' AND container_role IS NULL;
