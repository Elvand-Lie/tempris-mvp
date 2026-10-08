-- 049: Persist toolchain update-check request lifecycle per collector.
-- Non-destructive: new table only, no changes to existing tables.

CREATE TABLE IF NOT EXISTS collector_toolchain_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    collector_id UUID NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    check_id UUID NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'dispatched'
        CHECK (status IN ('dispatched', 'completed', 'failed', 'timed_out', 'superseded')),
    requested_by TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ NOT NULL,
    result JSONB
);

CREATE INDEX IF NOT EXISTS idx_toolchain_checks_collector_recent
    ON collector_toolchain_checks (collector_id, requested_at DESC);
