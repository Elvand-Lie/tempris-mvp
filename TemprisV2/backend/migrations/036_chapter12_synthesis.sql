-- Migration 036: Chapter 12 — SYNTHESIS (Correlation) (PRD-000 v1.11 Ch.12).
--
-- SYNTHESIS is a DETERMINISTIC CORRELATION SERVICE: it correlates truth and
-- never manufactures it. The frozen v1 decision is READ-TIME JOINS ONLY —
-- materialized summaries come later, behind the shared scheduler decision —
-- so this migration owns NO correlation state at all. Every answer is a
-- join over authoritative objects computed at read time, preserving links
-- back to every source row.
--
-- What lands here is the module catalogue entry only:
--   * no synthesis tables (nothing stores "new truth"),
--   * no AI layer (the LLM/chat/narrative surface is Ch.11's SPEAK),
--   * no upstream writes (the last deterministic consumer).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'SYNTHESIS',
    'SYNTHESIS — Deterministic Correlation',
    'Read-time joins over authoritative upstream domains: unremediated serious exposures, remediation recurrence, weakness-class recurrence, evidence-strength vs coverage gaps, accepted-risk vs obligation correlation. Correlates truth; never manufactures it; never stores new truth; has no AI layer.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'SYNTHESIS')
ON CONFLICT DO NOTHING;
