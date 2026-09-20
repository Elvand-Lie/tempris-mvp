-- Migration 023: P1-02 observability index (bounded item 4)
--
-- Adds an index supporting the per-source coverage queries over
-- vuln_source_records — the enrichment records carry their resolved CVE
-- identity in declared_cve_id (cve_id is only set by the spine-authoritative
-- cve source), so coverage joins like "every active KEV CVE with an NVD
-- record" currently seq-scan the full ~472k-row table on a
-- (source, declared_cve_id) predicate.
--
-- This is a pure index addition: no table, column, constraint, or trigger
-- changes; no data is touched. CONCURRENTLY is not used because the
-- deployment procedure runs migrations inside a transaction against a
-- quiesced target (and 023 is unshipped — it will be applied once, before
-- the table can be large).

CREATE INDEX IF NOT EXISTS idx_vuln_source_records_source_declared_cve_id
    ON vuln_source_records (source, declared_cve_id);
