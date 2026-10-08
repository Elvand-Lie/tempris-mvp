-- CVE-INTEL-01: bound the scenario key expression of idx_cvss_current_assessment.
--
-- Migration 007 defined:
--   CREATE UNIQUE INDEX idx_cvss_current_assessment
--     ON cvss_assessments (cve_id, assessor, cvss_version, COALESCE(scenario, ''))
--     WHERE is_current = TRUE;
-- A real assessment scenario TEXT can exceed the B-tree per-entry limit
-- (~2704 bytes after tuple-header overhead), making any such current-row insert
-- fail with "index row size ... exceeds btree version 4 maximum" while the row
-- itself is far under the 1GB field limit. Replace the index expression with a
-- fixed-size SHA-256 digest (raw BYTEA, 32 bytes) of the same COALESCE'd value:
-- the full scenario TEXT stays stored and untruncated on the row, NULL and
-- empty scenario still share one key (COALESCE semantics preserved), and any
-- two rows colliding on the digest are practically identical scenarios — the
-- theoretical SHA-256 collision probability is the accepted tradeoff.
-- pgcrypto is already established by migration 024.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP INDEX IF EXISTS idx_cvss_current_assessment;

CREATE UNIQUE INDEX IF NOT EXISTS idx_cvss_current_assessment
    ON cvss_assessments (cve_id, assessor, cvss_version,
                         digest(COALESCE(scenario, ''), 'sha256'))
    WHERE is_current = TRUE;
