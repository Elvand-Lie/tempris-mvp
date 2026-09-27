-- 045: Phase 1 toolbox expansion — widen strike_runs beyond the curl slice.
-- Additive: nmap / nuclei / ffuf / dig join curl (all collector-plane);
-- "RUN" is the fixed single mode of every non-HTTP tool. The curl shape
-- (GET/HEAD) is unchanged.
ALTER TABLE strike_runs DROP CONSTRAINT strike_runs_capability_check;
ALTER TABLE strike_runs DROP CONSTRAINT strike_runs_method_check;
ALTER TABLE strike_runs
    ADD CONSTRAINT strike_runs_capability_check
    CHECK (capability IN ('curl', 'nmap', 'nuclei', 'ffuf', 'dig'));
ALTER TABLE strike_runs
    ADD CONSTRAINT strike_runs_method_check
    CHECK (method IN ('GET', 'HEAD', 'RUN'));
