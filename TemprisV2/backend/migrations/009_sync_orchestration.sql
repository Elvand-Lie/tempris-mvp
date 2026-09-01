-- 009_sync_orchestration.sql
-- Sprint 03: Extend sync_state for scheduling configuration, active record
-- counts, and last-known-good snapshot tracking needed by the sync orchestrator.
-- Advisory locks use pg_advisory_xact_lock with source-specific keys.

-- Add scheduling and operational columns to sync_state
ALTER TABLE sync_state
    ADD COLUMN IF NOT EXISTS sync_interval_seconds  INTEGER,
    ADD COLUMN IF NOT EXISTS sync_enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_sync_duration_ms   INTEGER,
    ADD COLUMN IF NOT EXISTS active_record_count     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_good_snapshot_id   UUID REFERENCES sync_snapshots(id),
    ADD COLUMN IF NOT EXISTS next_sync_at            TIMESTAMPTZ;

-- Update default scheduling configuration for each source.
-- Scheduling is disabled by default; interval_seconds carries the default
-- cadence used when scheduling IS enabled.
UPDATE sync_state SET sync_interval_seconds = 1200  WHERE source = 'cve';   -- 20 minutes
UPDATE sync_state SET sync_interval_seconds = 1200  WHERE source = 'nvd';   -- 20 minutes
UPDATE sync_state SET sync_interval_seconds = 1200  WHERE source = 'kev';   -- 20 minutes
UPDATE sync_state SET sync_interval_seconds = 1200  WHERE source = 'osv';   -- 20 minutes
UPDATE sync_state SET sync_interval_seconds = 86400 WHERE source = 'epss';  -- daily
