-- SCOUT Sprint 01: minimal tenant-safe public execution persistence.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'asset_scan_authorizations'::regclass
          AND conname = 'uq_asset_scan_authorizations_tenant_asset_id'
    ) THEN
        ALTER TABLE asset_scan_authorizations
            ADD CONSTRAINT uq_asset_scan_authorizations_tenant_asset_id
            UNIQUE (tenant_id, asset_id, id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS scout_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    asset_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    profile TEXT NOT NULL CHECK (profile IN ('SERVICE_DISCOVERY', 'VULNERABILITY_ASSESSMENT')),
    route TEXT NOT NULL DEFAULT 'CENTRAL_PUBLIC' CHECK (route = 'CENTRAL_PUBLIC'),
    target_type TEXT NOT NULL CHECK (target_type IN ('ip', 'hostname', 'domain')),
    normalized_target TEXT NOT NULL,
    network_scope TEXT NOT NULL CHECK (network_scope = 'internet'),
    authorization_approved_at TIMESTAMPTZ NOT NULL,
    authorization_expires_at TIMESTAMPTZ NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    error_code TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_scout_jobs_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_scout_jobs_tenant_asset_id UNIQUE (tenant_id, asset_id, id),
    CONSTRAINT fk_scout_job_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_scout_job_authorization FOREIGN KEY (tenant_id, asset_id, authorization_id)
        REFERENCES asset_scan_authorizations(tenant_id, asset_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_scout_jobs_tenant_created
    ON scout_jobs (tenant_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS scout_tool_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    job_id UUID NOT NULL,
    engine TEXT NOT NULL CHECK (engine IN ('nmap', 'nuclei')),
    ordinal SMALLINT NOT NULL CHECK (ordinal IN (1, 2)),
    state TEXT NOT NULL CHECK (state IN ('available', 'unavailable', 'succeeded', 'failed', 'timed_out', 'output_limited', 'parse_failed')),
    executable_path TEXT,
    engine_version TEXT,
    templates_version TEXT,
    exit_code INTEGER,
    stderr TEXT,
    stdout_bytes INTEGER NOT NULL DEFAULT 0 CHECK (stdout_bytes >= 0 AND stdout_bytes <= 4194304),
    stderr_bytes INTEGER NOT NULL DEFAULT 0 CHECK (stderr_bytes >= 0 AND stderr_bytes <= 4194304),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_scout_tool_runs_tenant_job_id UNIQUE (tenant_id, job_id, id),
    CONSTRAINT uq_scout_tool_runs_job_engine UNIQUE (tenant_id, job_id, engine),
    CONSTRAINT fk_scout_tool_run_job FOREIGN KEY (tenant_id, job_id)
        REFERENCES scout_jobs(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scout_tool_runs_tenant_job
    ON scout_tool_runs (tenant_id, job_id, ordinal);

CREATE TABLE IF NOT EXISTS scout_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    job_id UUID NOT NULL,
    tool_run_id UUID NOT NULL,
    kind TEXT NOT NULL,
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_scout_observation_tool_run FOREIGN KEY (tenant_id, job_id, tool_run_id)
        REFERENCES scout_tool_runs(tenant_id, job_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scout_observations_tenant_job
    ON scout_observations (tenant_id, job_id, created_at, id);

CREATE OR REPLACE FUNCTION guard_scout_job_binding()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.tenant_id, NEW.asset_id, NEW.authorization_id, NEW.profile, NEW.route,
        NEW.target_type, NEW.normalized_target, NEW.network_scope,
        NEW.authorization_approved_at, NEW.authorization_expires_at,
        NEW.requested_by, NEW.created_at)
       IS DISTINCT FROM
       (OLD.tenant_id, OLD.asset_id, OLD.authorization_id, OLD.profile, OLD.route,
        OLD.target_type, OLD.normalized_target, OLD.network_scope,
        OLD.authorization_approved_at, OLD.authorization_expires_at,
        OLD.requested_by, OLD.created_at) THEN
        RAISE EXCEPTION 'SCOUT job authorization binding is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_guard_scout_job_binding ON scout_jobs;
CREATE TRIGGER trg_guard_scout_job_binding
BEFORE UPDATE ON scout_jobs
FOR EACH ROW EXECUTE FUNCTION guard_scout_job_binding();
