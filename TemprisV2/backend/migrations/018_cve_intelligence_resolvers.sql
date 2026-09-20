-- Migration 018: CVE intelligence resolvers (P0-03, PRD-000 §3.5 #2)
--
-- Replaces the CVSS-3.1-pinned lookup index from migration 012 with a
-- generation-aware index supporting the full PRD-000 v1.8 §3.5 #2 authority
-- ordering: is_current = TRUE -> newest supported version
-- (4.0 > 3.1 > 3.0 > 2.0) -> within version CNA > NVD > ADP
-- (container_role) -> more than one surviving row is
-- cvss_authority_ambiguous (fail closed).
--
-- Constraints honored:
--   * No assessment provenance is rewritten: no column changes, no row
--     updates. Existing rows (including duplicates that will resolve as
--     ambiguous) are data for the resolver, not migration failures.
--   * Forward-only; idempotent (IF NOT EXISTS / IF EXISTS guards), runs in
--     one transaction (see migrations/runner.py).
--   * The old 012 index is a strict subset shape of the new one; it is
--     dropped to keep one authoritative lookup index. (A non-concurrent
--     DROP of a 3.1-filtered partial index is safe: it no longer serves the
--     resolver and contains no unique constraint.)

-- ---------------------------------------------------------------------------
-- 1. Generation-aware CVSS authority lookup index
--    Leading columns match the resolver's WHERE (cve_id, is_current) and its
--    version-first ordering; container_role supports the role tiebreak.
--    All four supported versions (4.0, 3.1, 3.0, 2.0) are served by this one
--    index — no version is pinned out of the predicate.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_cvss_authority_lookup
    ON cvss_assessments (cve_id, cvss_version, container_role)
    WHERE is_current = TRUE;

-- ---------------------------------------------------------------------------
-- 2. Supersede the CVSS-3.1-only 012 lookup index
-- ---------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_cvss_tes_lookup;
