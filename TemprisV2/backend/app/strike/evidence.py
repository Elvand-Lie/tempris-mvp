# backend/app/strike/evidence.py
"""Evidence promotion into the Chapter 3 §3.3.3 contract (PRD-000 v1.11
Ch.4 principles 8/9, PATCH-01, D-7/D-8; Appendix C Q3).

This is the ONLY path by which STRIKE affects any score.

The producer is the STRIKE CONTROL PLANE (an authenticated Ch.5 actor) —
never the workspace: a compromised workspace can fabricate successful
output, so server-side packaging does not authenticate workspace claims
(D-8). Workspace artifacts are hashed inputs; the Ch.3 evidence record is
created here, server-side, only after explicit authenticated analyst review.

Promotion validates server-side, in order (PATCH-01):
  1. the operation exists IN THE CALLER'S TENANT (identical 404 otherwise);
  2. the operation reached a TERMINAL result — evidence referencing a
     missing/failed/unresolved operation is refused;
  3. the operation's execution truth supports the claim: outcome OBSERVED —
     a successful validated run actually observed. INCONCLUSIVE/ERROR/
     NOT_EXECUTED/UNSUPPORTED (and cancelled/unconfirmed states) refuse:
     only real validated evidence may affect controlled-validation state;
  4. the exact exposure episode: delegated to the Ch.3 record command's
     ``_require_current_confirmed_episode`` — the evidence binds ONE
     (finding, asset) episode; there is no tenant-wide promotion path;
  5. the constrained write-time classification (D-7, principle 8):
       basis 'validated'  ⇒ controlled_validation (180d) — STRIKE-controlled
                            testing; the default for validation engagements;
       basis 'observed'   ⇒ observed_exploitation (365d) — evidence of an
                            ACTUALLY OBSERVED compromise/exploitation event;
                            a successful test alone NEVER qualifies, so the
                            attestation must name the observed compromise
                            event (length floor) and the operation must have
                            actually run to OBSERVED.
  6. the Ch.3 record is written by the existing Ch.3 command
     (``record_exploitation_evidence`` with producer='strike' — the closed
     allowlist already reserves it) in the SAME transaction as the immutable
     ``strike_evidence_links`` row: evidence + link + audit commit together.

Replay: the Ch.3 source-identity rule ((tenant, 'strike_operation',
operation id)) makes one operation produce at most one live evidence record;
a repeated promotion replays exactly or is a named conflict — never a
duplicate.
"""
from __future__ import annotations

import uuid

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.scoring_inputs import (
    ExploitationEvidenceIn,
    record_exploitation_evidence,
)
from app.strike.errors import EvidencePromotionError
from app.strike.operations import load_operation

#: minimum attestation substance for an observed_exploitation claim: the
#: analyst must name the observed compromise event — a bare "it worked" is
#: not evidence of an actually observed exploitation (principle 8).
MIN_OBSERVED_ATTESTATION_CHARS = 40


def promote_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Promote one completed operation's validated result to a Ch.3 §3.3.3
    evidence record + immutable STRIKE link row (one transaction)."""
    with conn.cursor(row_factory=dict_row) as cur:
        operation = load_operation(cur, tenant_id, data.operation_id)

        # (2) terminal result only — missing/failed/unresolved refuse
        if operation["state"] == "failed":
            raise EvidencePromotionError(
                f"operation {data.operation_id} FAILED (outcome "
                f"{operation['outcome']}) — failed attempts never create a "
                "rung and never become evidence"
            )
        if operation["state"] in ("dispatched", "running", "cancelling"):
            raise EvidencePromotionError(
                f"operation {data.operation_id} is {operation['state']!r} — "
                "evidence promotes from a terminal operation only"
            )
        if operation["state"] in ("cancelled", "cancel_unconfirmed"):
            raise EvidencePromotionError(
                f"operation {data.operation_id} is {operation['state']!r} — "
                "a cancelled/unconfirmed operation is not a validated result"
            )

        # (3) execution truth must be OBSERVED: the validated run was
        # actually executed and its result collected
        if operation["outcome"] != "OBSERVED":
            raise EvidencePromotionError(
                f"operation {data.operation_id} outcome is "
                f"{operation['outcome']} — only an OBSERVED execution "
                "supports promotion (failure/timeout/silence is never "
                "evidence)"
            )

        # (5) the constrained classification: a successful test alone never
        # qualifies as observed_exploitation
        if data.basis == "observed":
            if len(data.attestation.strip()) < MIN_OBSERVED_ATTESTATION_CHARS:
                raise EvidencePromotionError(
                    "an observed_exploitation claim requires an attestation "
                    f"naming the actually observed compromise event (at least "
                    f"{MIN_OBSERVED_ATTESTATION_CHARS} characters) — a "
                    "successful test alone never qualifies"
                )

    # (4)+(6) the Ch.3 record command validates the exact CURRENT confirmed
    # episode and writes the §3.3.3 record — same transaction as the link.
    # observed_at defaults to the operation's completed_at: a STABLE
    # occurrence time (the Ch.3 replay rule requires stable producers to
    # supply one — a fresh server timestamp per retry would turn a replay
    # into a conflicting-reuse refusal).
    ch3_payload = {
        "producer_module": "STRIKE",
        "producer_plane": "strike_control_plane",
        "strike_engagement_id": str(operation["engagement_id"]),
        "strike_operation_id": str(operation["id"]),
        "operation_outcome": operation["outcome"],
        "engine": operation["engine"],
        "engine_operation_ref": operation["engine_operation_ref"],
        "workspace_id": str(operation["workspace_id"]),
        "target_id": str(operation["target_id"]),
        "attestation": data.attestation,
    }
    evidence_in = ExploitationEvidenceIn(
        basis=data.basis,
        result="succeeded",
        evidence=ch3_payload,
        observed_at=data.observed_at or operation["completed_at"],
    )
    result = record_exploitation_evidence(
        conn, tenant_id, data.exposure_id, evidence_in,
        actor_id=actor_id, actor_role=actor_role,
        producer="strike",
        source_object_type="strike_operation",
        source_object_id=str(operation["id"]),
        reviewed_by=actor_id,
    )
    record = result.record

    with conn.cursor(row_factory=dict_row) as cur:
        # replay: a repeated promotion of the same operation replays the
        # SAME link (the Ch.3 record itself replays by source identity);
        # a link bound to a DIFFERENT record is a named conflict
        cur.execute(
            """
            INSERT INTO strike_evidence_links (
                tenant_id, engagement_id, operation_id, exposure_id,
                evidence_record_id, evidence_kind, reviewed_by, attestation,
                observed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (operation_id) DO NOTHING
            RETURNING *;
            """,
            (
                str(tenant_id), str(operation["engagement_id"]),
                str(operation["id"]), str(data.exposure_id), str(record.id),
                record.evidence_kind, actor_id, data.attestation,
                record.observed_at,
            ),
        )
        link = cur.fetchone()
        outcome = result.outcome
        if link is None:
            cur.execute(
                "SELECT * FROM strike_evidence_links WHERE operation_id = %s;",
                (str(operation["id"]),),
            )
            link = cur.fetchone()
            if str(link["evidence_record_id"]) != str(record.id):
                raise EvidencePromotionError(
                    f"operation {operation['id']} already carries an evidence "
                    "link bound to a different record — conflicting replay "
                    "refused"
                )
            outcome = "replay"
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.evidence_promoted",
            details={
                "operation_id": str(operation["id"]),
                "exposure_id": str(data.exposure_id),
                "evidence_record_id": str(record.id),
                "evidence_kind": record.evidence_kind,
                "link_id": str(link["id"]),
                "ch3_outcome": outcome,
                "reviewed_by": actor_id,
            },
        )
        return {
            "link": dict(link),
            "evidence_record_id": str(record.id),
            "evidence_kind": record.evidence_kind,
            "ch3_outcome": outcome,
        }


def list_evidence_links(
    conn: psycopg.Connection, tenant_id: uuid.UUID, engagement_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT * FROM strike_evidence_links
            WHERE tenant_id = %s AND engagement_id = %s
            ORDER BY created_at DESC, id;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        return cur.fetchall()
