-- SCOUT Sprint 03: internal asset routing and collector dispatch foundation.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'collectors'::regclass
          AND conname = 'uq_collectors_tenant_id'
    ) THEN
        ALTER TABLE collectors
            ADD CONSTRAINT uq_collectors_tenant_id
            UNIQUE (tenant_id, id);
    END IF;
END $$;

ALTER TABLE scout_jobs
    ADD COLUMN IF NOT EXISTS collector_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'scout_jobs'::regclass
          AND conname = 'fk_scout_job_collector'
    ) THEN
        ALTER TABLE scout_jobs
            ADD CONSTRAINT fk_scout_job_collector
            FOREIGN KEY (tenant_id, collector_id)
            REFERENCES collectors(tenant_id, id) ON DELETE RESTRICT;
    END IF;
END $$;

ALTER TABLE scout_jobs DROP CONSTRAINT IF EXISTS scout_jobs_route_check;
ALTER TABLE scout_jobs ADD CONSTRAINT scout_jobs_route_check
    CHECK (route IN ('CENTRAL_PUBLIC', 'COLLECTOR_INTERNAL'));

ALTER TABLE scout_jobs DROP CONSTRAINT IF EXISTS scout_jobs_network_scope_check;
ALTER TABLE scout_jobs ADD CONSTRAINT scout_jobs_network_scope_check
    CHECK (network_scope IN ('internet', 'internal'));

ALTER TABLE scout_jobs DROP CONSTRAINT IF EXISTS scout_jobs_route_scope_collector_check;
ALTER TABLE scout_jobs ADD CONSTRAINT scout_jobs_route_scope_collector_check
    CHECK (
        (route = 'CENTRAL_PUBLIC' AND network_scope = 'internet' AND collector_id IS NULL) OR
        (route = 'COLLECTOR_INTERNAL' AND network_scope = 'internal' AND collector_id IS NOT NULL)
    );

CREATE INDEX IF NOT EXISTS idx_scout_jobs_tenant_collector
    ON scout_jobs (tenant_id, collector_id);

CREATE OR REPLACE FUNCTION guard_scout_job_binding()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.tenant_id, NEW.asset_id, NEW.authorization_id, NEW.profile, NEW.route,
        NEW.target_type, NEW.normalized_target, NEW.network_scope,
        NEW.authorization_approved_at, NEW.authorization_expires_at,
        NEW.requested_by, NEW.created_at, NEW.collector_id)
       IS DISTINCT FROM
       (OLD.tenant_id, OLD.asset_id, OLD.authorization_id, OLD.profile, OLD.route,
        OLD.target_type, OLD.normalized_target, OLD.network_scope,
        OLD.authorization_approved_at, OLD.authorization_expires_at,
        OLD.requested_by, OLD.created_at, OLD.collector_id) THEN
        RAISE EXCEPTION 'SCOUT job authorization binding is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_guard_scout_job_binding ON scout_jobs;
CREATE TRIGGER trg_guard_scout_job_binding
BEFORE UPDATE ON scout_jobs
FOR EACH ROW EXECUTE FUNCTION guard_scout_job_binding();
