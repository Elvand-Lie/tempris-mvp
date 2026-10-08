# backend/runner/__init__.py
"""
The STRIKE runner service (amended PRD v1.12 Ch.4 — a SEPARATE runner
service on the existing VPS, one unprivileged container per run).

This package is the runner process entry point (``python -m runner.main``),
deliberately outside the API app: the API's control plane never spawns tool
processes. The runner:

  * claims pending runs (guarded UPDATE — one winner);
  * re-derives the run's pinned scope entries at claim time — a revoked or
    expired entry TERMINATES the run and records the stop before anything
    executes;
  * executes the capability through a fixed argv (``execution.py``) inside
    one container with dropped capabilities, no-new-privileges, CPU/memory/
    PID caps, and per-run /32 DOCKER-USER egress limited to the run's
    pinned IPs (externally enforced — the container cannot widen it);
  * writes the bounded result back through the control-plane transitions in
    app.strike.runs (guarded state machine).

NO production deployment or live-run enabling happens from this codebase
change: the runner only ever starts when an operator launches it on the VPS
after the containment canary gate record.
"""
