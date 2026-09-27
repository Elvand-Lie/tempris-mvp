-- 048: STRIKE toolbox — execution vantages, the wider tool set, and
-- cursor-based output streaming.
--
-- Three additive changes, no route semantics altered:
--
-- 1. The run records WHICH VANTAGE it executed from. Two vantages exist:
--    'server' (the platform's own hardened sandbox) and 'collector' (an
--    enrolled collector reached over its authenticated WSS). The vantage is
--    pinned into the run at creation and is never changed afterwards, so a
--    run's provenance is permanent. 'collector' is the default so every
--    pre-existing row keeps its meaning.
--
-- 2. The capability CHECK widens to the full toolbox: the Phase-1 five
--    (curl/nmap/nuclei/ffuf/dig) plus httpie, nc, socat, python, bash,
--    chromium and mitmproxy. Method widens by 'POST' (curl/HTTPie request
--    bodies). The user supply chain is unchanged: the argv is still built
--    server-side and the target is still scope-validated before execution.
--
-- 3. Output STREAMING: run output is appended as ordered, bounded chunks so
--    the console can read a growing result with a cursor instead of polling
--    a single terminal blob. The terminal inline_result (64 KiB, migration
--    042) remains the authoritative final summary — chunks are the
--    progress-time view of the same bytes and are purged with the run's raw
--    retention window.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- 1. Execution vantage -------------------------------------------------------

ALTER TABLE strike_runs
    ADD COLUMN IF NOT EXISTS execution_plane TEXT NOT NULL DEFAULT 'collector';

ALTER TABLE strike_runs
    ADD CONSTRAINT ck_strike_runs_execution_plane
    CHECK (execution_plane IN ('server', 'collector'));

-- The selected collector is irrelevant on the SERVER vantage (nothing is
-- dispatched over WSS) and required on the collector vantage. Every
-- pre-existing row is collector-plane, so the default preserves their meaning.

-- 2. The wider tool set ------------------------------------------------------

ALTER TABLE strike_runs DROP CONSTRAINT strike_runs_capability_check;
ALTER TABLE strike_runs DROP CONSTRAINT strike_runs_method_check;

ALTER TABLE strike_runs
    ADD CONSTRAINT strike_runs_capability_check
    CHECK (capability IN (
        -- Phase 1 (migration 045)
        'curl', 'nmap', 'nuclei', 'ffuf', 'dig',
        -- Phase 2 toolbox execution engine
        'httpie', 'nc', 'socat', 'python', 'bash', 'chromium', 'mitmproxy'
    ));

ALTER TABLE strike_runs
    ADD CONSTRAINT strike_runs_method_check
    CHECK (method IN ('GET', 'HEAD', 'POST', 'RUN'));

-- 3. Cursor-based output streaming ------------------------------------------

CREATE TABLE strike_run_output_chunks (
    id BIGSERIAL PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES strike_runs(id) ON DELETE CASCADE,
    -- monotonically increasing per run; the cursor the client echoes back.
    -- assigned as max(seq)+1 inside the inserting transaction, so a run's
    -- chunk stream has one total order even under concurrent writers.
    seq INTEGER NOT NULL,
    stream TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr', 'system')),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_strike_run_output_chunks_run_seq UNIQUE (run_id, seq),
    -- bounded: one chunk may never exceed the 64 KiB inline bound, so a
    -- single read is always cheap and the per-run total stays accountable.
    CONSTRAINT ck_strike_run_output_chunks_bounded
        CHECK (octet_length(content) <= 65536)
);

-- the read path is always "everything after cursor N for one run"
CREATE INDEX ix_strike_run_output_chunks_cursor
    ON strike_run_output_chunks (run_id, seq);
