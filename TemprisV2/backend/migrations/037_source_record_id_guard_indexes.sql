-- Migration 037: normalized-guard lookup indexes on source_record_id
--
-- The vuln-intelligence sync's per-record normalized guard runs
--   SELECT EXISTS (SELECT 1 FROM cvss_assessments WHERE source_record_id = $1)
--       OR EXISTS (SELECT 1 FROM cve_affected     WHERE source_record_id = $2)
--       OR EXISTS (SELECT 1 FROM cve_weaknesses   WHERE source_record_id = $3)
--       OR EXISTS (SELECT 1 FROM cve_references   WHERE source_record_id = $4)
-- before upserting each resolver record. None of those FK columns had an
-- index (only source_artifacts did), so on the production canonical DB each
-- record paid four sequential scans (~0.5 GB combined), stalling the CVE
-- driven chain at <1 committed batch per quarter hour and reproducing the
-- historical KEV failure mode (processed=1000000, created=0).
--
-- Pure index addition: no table, column, constraint, or trigger changes; no
-- data is touched. CONCURRENTLY is not used, matching 023's precedent: the
-- runner applies each migration file inside a single transaction, which
-- cannot host CREATE INDEX CONCURRENTLY; builds run in the controlled
-- migration window with VULN_SYNC_ENABLED=false.

CREATE INDEX IF NOT EXISTS idx_cvss_assessments_source_record_id
    ON cvss_assessments (source_record_id);

CREATE INDEX IF NOT EXISTS idx_cve_affected_source_record_id
    ON cve_affected (source_record_id);

CREATE INDEX IF NOT EXISTS idx_cve_weaknesses_source_record_id
    ON cve_weaknesses (source_record_id);

CREATE INDEX IF NOT EXISTS idx_cve_references_source_record_id
    ON cve_references (source_record_id);
