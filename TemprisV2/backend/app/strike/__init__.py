# backend/app/strike/__init__.py
"""Chapter 4 — STRIKE (Offensive Security Workspace), PRD-000 v1.11 Ch.4.

Domain-local control-plane package. STRIKE is an independent hosted
offensive-security workspace system — not SCOUT (it does not detect), not a
TES stage, not a SPECTRUM stage, not a Collector capability (principle 1).

What this package owns (and nothing else):
  * engagement/target authorization with dual control via the Ch.5 approval
    primitive (``approvals.py`` registers the ``strike_engagement`` and
    ``strike_target`` subject types);
  * the disposable per-engagement workspace lifecycle with recovery-safe
    provisioning (PATCH-04) behind a provider seam (``workspaces.py``);
  * operation dispatch/cancel with execution-truth outcomes and a classifier
    that never auto-assigns EXPLOITABLE/PREVENTED (``operations.py`` /
    ``outcomes.py``);
  * evidence promotion into the Ch.3 §3.3.3 contract (PATCH-01) — the ONLY
    path by which STRIKE affects any score (``evidence.py``);
  * the STRIKE-specific relay lifecycle — the collector is never touched
    (``relays.py``).

STRIKE never confirms exposures, never scores, and never creates findings:
discoveries route through Ch.6 intake (source ``STRIKE_DISCOVERY``, Flow C).
"""
