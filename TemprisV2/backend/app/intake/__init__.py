# backend/app/intake/__init__.py
"""
Chapter 6 — Intake & Triage / Exposure Review (PRD-000 v1.11 Ch.6).

Intake & Triage answers "is this a legitimate finding, and what does it apply
to?"; SPECTRUM manages what is confirmed. Everything that is not SCOUT enters
here as an intake RECORD — manual reports, connector observations, STRIKE
discoveries, VDP submissions, threat-pack imports — and becomes exactly one of:
a confirmed exposure (the single handoff into Ch.3/Ch.7, via the shared Ch.3
confirmation command), a rejected/duplicate record, or a review item awaiting
more information.
"""
