-- backend/migrations/011_sprint02_sync_hardening.sql
-- Sprint 02: Synchronization Correctness and Safety
-- Adds is_active and withdrawn_at to kev_entries with partial indexes for high-performance search queries.

ALTER TABLE kev_entries
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS withdrawn_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_kev_entries_active
    ON kev_entries (cve_id)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_kev_entries_declared_active
    ON kev_entries (declared_cve_id)
    WHERE is_active = TRUE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'source_artifacts'
    ) THEN
        ALTER TABLE source_artifacts
            DROP CONSTRAINT IF EXISTS source_artifacts_source_record_id_fkey,
            ADD CONSTRAINT source_artifacts_source_record_id_fkey
                FOREIGN KEY (source_record_id) REFERENCES vuln_source_records(id) ON DELETE CASCADE;
    END IF;
END $$;
