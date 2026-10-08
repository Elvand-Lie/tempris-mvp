-- backend/migrations/039_ch6_intake_classification_append_only.sql
--
-- Chapter 6 — append-only classification history (PRD-000 v1.11 §6:1141/1149).
--
-- The classification store is `intake_record_events` (the naming follows this
-- Chapter's own DDL): every `classified` event now carries the prior and new
-- class/subclass/subtype plus the mandatory rationale in its `detail` JSONB,
-- written on the SAME transaction as the `intake_records` projection update.
-- `intake_records` remains the CURRENT projection only.
--
-- 025 declared this table "append-only actor trail" in a comment but never
-- enforced it. This migration makes the guarantee structural so a prior
-- classification decision cannot be rewritten by any path — the classify flow
-- itself only ever INSERTs.
--
-- Test-suite note: the suites clear state with TRUNCATE, which fires no row
-- triggers (tests/conftest.py, tests/ch10_12_helpers.py, tests/strike/conftest.py
-- all rely on that), so this guard does not obstruct test cleanup. No
-- application path DELETEs intake records or their events, and tenants cannot
-- be deleted while intake records exist (tenants FK is ON DELETE RESTRICT).
-- Reversal: DROP TRIGGER trg_intake_record_events_append_only ON intake_record_events;
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION intake_record_events_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'intake_record_events is append-only: % on event % is not permitted (classification history is immutable)',
        TG_OP, COALESCE(OLD.id::text, '?');
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_intake_record_events_append_only ON intake_record_events;
CREATE TRIGGER trg_intake_record_events_append_only
    BEFORE UPDATE OR DELETE ON intake_record_events
    FOR EACH ROW EXECUTE FUNCTION intake_record_events_append_only();