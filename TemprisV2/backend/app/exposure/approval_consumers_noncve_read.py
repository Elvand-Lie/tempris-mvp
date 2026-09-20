# backend/app/exposure/approval_consumers_noncve_read.py
"""
P0-08 read-side helpers: the effective non-CVE intrinsic WITH provenance.

The plain derivation path (P0-06 ``current_sss_intrinsic``) reads the current
vrt/rubric derivation. This module extends the read to the approval-backed
paths (P0-08 §3.6.6 #6/#3):

  path 'manual'   — an APPROVED manual SSS proposal published as a
                    derivation (approval id stamped; provenance
                    "approved manual");
  path 'override' — an approved SSS override (provenance "analyst
                    override"; the pre-override derived value is returned
                    alongside so it stays VISIBLE, never hidden);
  paths vrt/rubric — the derived values (provenance "derived").

Read-only; tenant-scoped; no locks; never computes TES math.
"""
from __future__ import annotations

import uuid
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from app.exposure.tes_kernel import FreshnessState, IntrinsicInput, ProvenanceClass


def _provenance_of(path: str) -> ProvenanceClass:
    if path in ("manual", "override"):
        return ProvenanceClass.ANALYST_ENTERED
    return ProvenanceClass.MACHINE_OBSERVED


def _source_of(path: str) -> str:
    return {
        "manual": "sss:manual_approved",
        "override": "sss:analyst_override",
        "rubric": "sss:rubric",
        "vrt": "sss:vrt",
    }.get(path, f"sss:{path}")


def taxonomy_class_of_finding(
    conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> Optional[str]:
    """The finding's non-CVE taxonomy class (latest classification), or None
    for a plain (CVE) finding. Mirrors service.taxonomy_class_of_finding but
    takes a connection (read-model call sites already hold one)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT c.taxonomy_class
            FROM non_cve_classifications c
            WHERE c.tenant_id = %s AND c.finding_id = %s
            ORDER BY c.created_at DESC
            LIMIT 1;
            """,
            (str(tenant_id), str(finding_id)),
        )
        row = cur.fetchone()
    return row["taxonomy_class"] if row is not None else None


def current_sss_intrinsic_with_provenance(
    conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> Optional[IntrinsicInput]:
    """The finding's current effective SSS in P0-04's IntrinsicInput shape,
    extended with the provenance payload the read model renders:

    ``result.source_view`` carries {derivation_id, path, value, approval_id,
    pre_override_derivation_id, pre_override_value}. No current derivation —
    including a still-pending manual proposal — returns None (the caller's
    TES read fails closed UNSCOREABLE; §3.6.4).
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT d.id, d.value, d.path, d.approval_id,
                   d.pre_override_derivation_id, d.created_at,
                   v.version_id AS version_text,
                   pre.value AS pre_override_value
            FROM non_cve_sss_derivations d
            LEFT JOIN sss_derivation_versions v ON v.id = d.version_id_ref
            LEFT JOIN non_cve_sss_derivations pre
              ON pre.id = d.pre_override_derivation_id
             AND pre.tenant_id = d.tenant_id
             AND pre.finding_id = d.finding_id
            WHERE d.tenant_id = %s AND d.finding_id = %s AND d.is_current;
            """,
            (str(tenant_id), str(finding_id)),
        )
        row = cur.fetchone()
    if row is None:
        return None

    # §3.6.6 #2: approval paths (manual/override) carry a NULL version — the
    # derivation label is path + approval id, rendered WITHOUT the versions
    # join; content paths (vrt/rubric) keep the version label.
    if row["path"] in ("manual", "override"):
        derivation_label = f"sss_{row['path']}:approval:{row['approval_id']}"
    else:
        derivation_label = f"sss_{row['path']}:{row['version_text']}"
    intrinsic = IntrinsicInput(
        value=row["value"],
        provenance_class=_provenance_of(row["path"]),
        freshness=FreshnessState.FRESH,
        observed_at=row["created_at"],
        source=_source_of(row["path"]),
        derivation=derivation_label,
    )
    # Attach the provenance payload without disturbing the kernel contract:
    # IntrinsicInput is a frozen dataclass; the read model reads the payload
    # from ``source_view`` (an attribute set post-construction, document here).
    object.__setattr__(
        intrinsic,
        "source_view",
        {
            "derivation_id": str(row["id"]),
            "path": row["path"],
            "value": row["value"],
            "approval_id": (str(row["approval_id"])
                            if row["approval_id"] is not None else None),
            "pre_override_derivation_id": (
                str(row["pre_override_derivation_id"])
                if row["pre_override_derivation_id"] is not None else None),
            "pre_override_value": row["pre_override_value"],
        },
    )
    return intrinsic
