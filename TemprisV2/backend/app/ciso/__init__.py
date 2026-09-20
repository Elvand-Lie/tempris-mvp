# backend/app/ciso
"""CISO / SPOTLIGHT — Executive View (PRD-000 v1.11 Ch.10).

A READ-ONLY consumer over upstream domains. It owns exactly one piece of
state — its own append-only ``posture_snapshots`` — and is never a source of
record. Severe-exposure visibility is count + max based; the V1
``aggregate_tes`` arithmetic mean is retired and no tenant-wide composite
index exists (Ch.10 design rules 1-2).
"""
