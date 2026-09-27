-- Migration 042: Chapter 4 — the run-bound toolbox run record
-- (amended PRD v1.12 Ch.4: choose-tool → run → results model).
--
-- One row per tool run. The unit of work is a RUN, not an engagement: the
-- run carries its own policy snapshot (the active scope entries it was
-- authorized against and the DNS-resolved destination IPs pinned at
-- creation — a hostname entry authorizes only the runtime-resolved IPs).
--
-- State machine — the PRD's MINIMUM run states, enforced in code and
-- backstopped here:
--   queued → running → completed | failed
--   queued → cancelled                        (cancellation before dispatch;
--                                              nothing was ever executed)
--   running → cancel_requested → cancelled | cancel_unconfirmed
--   (scope expiry/revocation mid-run takes the same stop path, with the
--   stop reason recorded; "cancelled" requires the runner's CONFIRMED
--   container stop — an uncertain stop is cancel_unconfirmed and stays
--   visible for reconciliation)
-- ERROR is an execution error code (error_code), never a state;
-- INCONCLUSIVE is a validation label, not a state.
--
-- Retention: inline result is bounded (64 KiB; truncation flagged) and
-- raw_purge_after = created_at + 30 days, while the run/audit metadata is
-- permanent — the row itself is never deleted.
--
-- The legacy V2 engagement/workspace tables are untouched historical data.

CREATE TABLE strike_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    capability TEXT NOT NULL CHECK (capability = 'curl'),
    method TEXT NOT NULL CHECK (method IN ('GET', 'HEAD')),
    -- the exact target: the URL as supplied (when a URL was supplied) and
    -- its resolved host component — one target per run
    target_url TEXT,
    target_host TEXT NOT NULL,
    target_port INT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'queued', 'running', 'completed', 'failed',
        'cancel_requested', 'cancelled', 'cancel_unconfirmed')),
    stop_reason TEXT,
    -- scope enforcement snapshot: {scope_entry_ids, pinned_ips, hostname}
    policy_snapshot JSONB NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    exit_code INT,
    error_code TEXT,
    inline_result TEXT,
    inline_truncated BOOLEAN NOT NULL DEFAULT false,
    raw_purge_after TIMESTAMPTZ,
    runner_id TEXT
);

CREATE INDEX ix_strike_runs_tenant ON strike_runs (tenant_id, created_at DESC);
CREATE INDEX ix_strike_runs_queued ON strike_runs (created_at) WHERE state = 'queued';
