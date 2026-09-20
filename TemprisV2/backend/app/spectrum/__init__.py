# backend/app/spectrum/__init__.py
"""
Chapter 7 — SPECTRUM (Confirmed-Exposure Workbench) (PRD-000 v1.11 Ch.7).

The analyst workbench over a CONFIRMED exposure: "this is a real exposure on
this tenant. What do we know about it, how serious is it, who owns the
analysis, and what happens next?"

SPECTRUM NEVER STORES SCORES (§3.3.6): every read is read-through to the
Ch.3 recompute. What SPECTRUM owns is workflow state at the EXPOSURE grain —
assignment, ``analysis_state`` (never named 'status'; Ch.3 owns the exposure
lifecycle and the two never gate each other), notes/history, STRIKE engagement
drafts, and EDIP handoffs. No non-CVE finding originates here (Ch.6 owns
intake); Business Impact editing writes the Ch.3 exposure input via the
existing Ch.3 route (storage and score semantics stay Ch.3's).
"""
