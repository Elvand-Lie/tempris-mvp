-- 050: STANDARD evidence lifecycle (withdraw/replace lineage).
-- Non-destructive: additive columns/index only. Withdrawal is a tombstone —
-- signed audit evidence is never hard-deleted; EDIP references stay valid
-- because rows persist.

ALTER TABLE standard_control_evidence
    ADD COLUMN IF NOT EXISTS withdrawn_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS withdrawn_by TEXT,
    ADD COLUMN IF NOT EXISTS withdrawn_reason TEXT,
    ADD COLUMN IF NOT EXISTS replaces_evidence_id UUID
        REFERENCES standard_control_evidence(id);

CREATE INDEX IF NOT EXISTS idx_std_evidence_replaces
    ON standard_control_evidence (replaces_evidence_id);
