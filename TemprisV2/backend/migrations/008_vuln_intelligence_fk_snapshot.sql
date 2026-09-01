-- 008_vuln_intelligence_fk_snapshot.sql
-- Sprint 02 correction: enforce vuln_source_records.snapshot_id -> sync_snapshots(id) FK.
-- The Sprint 01 migration declared the column but omitted the REFERENCES constraint.
-- This ALTER safely adds it. All existing rows have either NULL snapshot_id or a valid
-- sync_snapshots(id) reference (enforced by application code).

-- Add the FK constraint if it does not already exist.
-- PostgreSQL does not support IF NOT EXISTS on ALTER TABLE ADD CONSTRAINT,
-- so we use a DO block to check first.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_source_records_snapshot'
          AND table_name = 'vuln_source_records'
    ) THEN
        ALTER TABLE vuln_source_records
            ADD CONSTRAINT fk_source_records_snapshot
            FOREIGN KEY (snapshot_id) REFERENCES sync_snapshots(id);
    END IF;
END
$$;
