# backend/app/speak
"""SPEAK — Reports / Deliverables (PRD-000 v1.11 Ch.11).

One authoritative report model over sealed snapshots: generation never
mutates upstream state; every report is content-hash-sealed with template
identity + version and stores the sealed score values it rendered (a §3.3.6
snapshot writer — viewers render from the report, never by recomputation).
Approved/archived reports are non-deletable. The chat/AI surface fails
closed with no model — it never invents content.
"""
