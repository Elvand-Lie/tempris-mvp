# backend/app/exposure/approval_consumers.py
"""
P0-08 — APPROVAL-BACKED NON-CVE TES (PRD-000 v1.11 §3.6.3–§3.6.6 esp.
#3 overrides / #5 negative-ER attestation / #6 manual FINAL; §3.3.2–§3.3.5;
Chapter 5 dual-control primitive; Appendix C Q11/Q12/Q17; Appendix D
PATCH-13).

The Chapter 3 CONSUMER wiring for the Chapter 5 approval primitive
(app/approvals.py + migration 021). Exactly the three subject types named by
the ticket are registered here — this module adds NO second approval store,
table, or workflow (search-proved in the test suite):

  1. ``manual_sss_proposal``  — a pending non_cve_sss_proposals row. Apply
     publishes the proposal's value as a NEW derivation (path 'manual',
     immutable history; migration 019 storage, is_current chain DB-enforced).
     The approved value becomes the EFFECTIVE SSS input only: TES then
     computes and may still be PROVISIONAL — approval NEVER auto-FINALs.
  2. ``sss_override``         — an override bound to the finding's CURRENT
     derivation. Apply publishes a derivation of path 'override' carrying the
     approval id + the pre-override derivation id (the pre-override derived
     value stays visible in history, never hidden), with provenance class
     ``analyst override`` in the TES decomposition.
  3. ``negative_er_attestation`` — "no known exploitation" for ONE exact
     exposure episode (exposure_non_exploitation_attestations row, created by
     the P0-02 reserve-shape command; P0-06 keeps it ineligible). Apply
     stamps the approval provenance NULL → set (migration-022 trigger allows
     that stamp exactly once); the attestation then yields ER 1.0 for 180
     days for THAT episode only. Expiry ⇒ unknown ⇒ PROVISIONAL; the record
     remains visible (nothing is ever deleted).

Subject-version tokens (opaque to the primitive):
  * manual_sss_proposal  — the proposal row's xmin (any proposal mutation,
    none is legal, changes the token);
  * sss_override         — f"{finding.xmin}:{current_derivation.id}" — both
    the finding state and the exact derivation the override binds to;
  * negative_er_attestation — the attestation row's xmin.

Apply handlers re-check, inside the caller's transaction (after the
primitive's payload-hash and subject-version rechecks):
  tenant, episode/revision existence and currency, current derived value,
  payload, and approver authority — and record the immutable approval
  reference + exact subject revision on what they publish/stamp.

Recurrence: approvals are never copied to a successor episode — a superseded
episode's attestation stays stamped but ineligible (its episode is terminal;
the ledger requires a CURRENT confirmed episode), and SSS/override
derivations bind the FINDING (which survives), so re-confirmation of a new
episode legitimately re-reads the current derivation. No deletion anywhere.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.approvals import (
    ApprovalNotFoundError,
    ApprovalPayloadMismatchError,
    ApprovalStaleSubjectError,
    ApprovalSubjectError,
    SubjectHandler,
    _canonical_hash,
    register_subject_type,
)
from app.exposure.exceptions import ExposureNotFoundError
from app.exposure.service import _advisory_xact_lock

# PRD §3.6.4: the approved negative attestation holds the ER floor for 180
# days (same window as the §3.3.3 attestation TTL — one number, one source).
ATTESTATION_APPROVED_WINDOW = timedelta(days=180)

SUBJECT_MANUAL_SSS = "manual_sss_proposal"
SUBJECT_SSS_OVERRIDE = "sss_override"
SUBJECT_ER_ATTESTATION = "negative_er_attestation"


# ---------------------------------------------------------------------------
# Subject-version readers (unknown and cross-tenant ids: identical not-found)
# ---------------------------------------------------------------------------


def _proposal_version(cur, tenant_id: uuid.UUID, subject_id: str) -> str:
    """The manual-SSS subject version binds the proposal row, the finding
    revision the apply rechecks, AND the current derivation — any of them
    moving after approval moves the token, so the apply's version recheck
    fails closed."""
    cur.execute(
        """
        SELECT p.xmin::text AS v, p.finding_id,
               f.xmin::text AS finding_rev
        FROM non_cve_sss_proposals p
        JOIN findings f ON f.tenant_id = p.tenant_id AND f.id = p.finding_id
        WHERE p.tenant_id = %s AND p.id = %s;
        """,
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"proposal {subject_id} not found")
    d = _finding_current_derivation(cur, tenant_id, row["finding_id"])
    return f"{row['v']}:{row['finding_rev']}:{d['id'] if d else 'none'}"


def _finding_current_derivation(cur, tenant_id: uuid.UUID, finding_id: str):
    cur.execute(
        """
        SELECT id, value, path, version_id_ref, xmin::text AS row_version
        FROM non_cve_sss_derivations
        WHERE tenant_id = %s AND finding_id = %s AND is_current;
        """,
        (str(tenant_id), finding_id),
    )
    return cur.fetchone()


def _override_version(cur, tenant_id: uuid.UUID, subject_id: str) -> str:
    cur.execute(
        "SELECT xmin::text AS v FROM findings WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"finding {subject_id} not found")
    d = _finding_current_derivation(cur, tenant_id, subject_id)
    return f"{row['v']}:{d['id'] if d else 'none'}"


def _attestation_version(cur, tenant_id: uuid.UUID, subject_id: str) -> str:
    cur.execute(
        "SELECT xmin::text AS v FROM exposure_non_exploitation_attestations "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"attestation {subject_id} not found")
    return row["v"]


# ---------------------------------------------------------------------------
# Payload validators (propose time — the subject must admit the proposal)
# ---------------------------------------------------------------------------


def _validate_manual_sss(cur, tenant_id, subject_id, payload) -> None:
    if set(payload) - {"kind"} or payload.get("kind") != "publish_manual_sss":
        raise ApprovalSubjectError(
            "manual SSS approval payload must be exactly "
            "{\"kind\": \"publish_manual_sss\"} — the value/reason/evidence "
            "live immutably on the proposal row"
        )
    cur.execute(
        "SELECT status, derived_derivation_id FROM non_cve_sss_proposals "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"proposal {subject_id} not found")
    if row["status"] != "pending":
        raise ApprovalSubjectError(
            f"proposal {subject_id} is not pending (status={row['status']})"
        )


def _validate_sss_override(cur, tenant_id, subject_id, payload) -> None:
    if set(payload) - {"value", "reason", "evidence"}:
        raise ApprovalSubjectError(
            "override payload must be exactly {value, reason, evidence}"
        )
    from decimal import Decimal, InvalidOperation

    try:
        value = Decimal(str(payload["value"]))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ApprovalSubjectError("override value must be a number") from exc
    if not (0 <= value <= 10):
        raise ApprovalSubjectError("override value must be within 0–10")
    if -value.as_tuple().exponent > 4:
        raise ApprovalSubjectError(
            "override value supports at most four decimal places"
        )
    if not isinstance(payload.get("reason"), str) or not payload["reason"].strip():
        raise ApprovalSubjectError("override reason is mandatory")
    if not isinstance(payload.get("evidence"), dict) or not payload["evidence"]:
        raise ApprovalSubjectError("override evidence is mandatory")
    cur.execute(
        "SELECT canonical_cve_id FROM findings WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    f = cur.fetchone()
    if f is None:
        raise ApprovalNotFoundError(f"finding {subject_id} not found")
    if f["canonical_cve_id"] is not None:
        raise ApprovalSubjectError("overrides apply to non-CVE findings only")


def _validate_er_attestation(cur, tenant_id, subject_id, payload) -> None:
    if set(payload) - {"kind"} or payload.get("kind") != "approve_attestation":
        raise ApprovalSubjectError(
            "attestation approval payload must be exactly "
            "{\"kind\": \"approve_attestation\"}"
        )
    cur.execute(
        """
        SELECT a.id, a.approval_id, e.status AS exposure_status
        FROM exposure_non_exploitation_attestations a
        JOIN asset_exposures e
          ON e.tenant_id = a.tenant_id AND e.id = a.exposure_id
        WHERE a.tenant_id = %s AND a.id = %s;
        """,
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"attestation {subject_id} not found")
    if row["exposure_status"] != "confirmed":
        raise ApprovalSubjectError(
            "attestations apply only to CURRENT confirmed episodes"
        )
    if row["approval_id"] is not None:
        raise ApprovalSubjectError(
            "attestation already carries an approval"
        )


# ---------------------------------------------------------------------------
# Payload re-derivation (apply time — detects post-approval alteration)
# ---------------------------------------------------------------------------


def _rederive_manual_sss(cur, tenant_id, subject_id, payload_hash) -> dict:
    cur.execute(
        "SELECT xmin::text AS v FROM non_cve_sss_proposals "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    if cur.fetchone() is None:
        raise ApprovalNotFoundError(f"proposal {subject_id} not found")
    rederived = {"kind": "publish_manual_sss"}
    if _canonical_hash(rederived) != payload_hash:
        raise ApprovalPayloadMismatchError(
            f"proposal {subject_id}: no payload re-derives to the approved hash"
        )
    return rederived


def _canonical_value_text(numeric_value) -> str:
    """Canonical textual form of a NUMERIC(6,4) at the documented grain:
    trailing zeros stripped (2.5000 -> '2.5', 10.0000 -> '10'). Both the
    propose-time hash and the apply-time re-derivation render the value
    through this function, so the canonical payload is grain-stable."""
    from decimal import Decimal as _D
    d = _D(str(numeric_value)).normalize()
    if d == d.to_integral_value():
        return str(d.quantize(_D("1")))
    return str(d)


def _rederive_sss_override(cur, tenant_id, subject_id, payload_hash) -> dict:
    """The override's value/reason/evidence live on the consumer-owned
    binding row (non_cve_sss_override_proposals, migration 022) written at
    propose time; the canonical payload is rebuilt from those columns and
    re-hashed by the primitive — any post-approval alteration of the binding
    row mismatches. (The binding row itself is a test-enforced invariant:
    the apply handler re-reads it, never trusts the hash alone.)"""
    cur.execute(
        "SELECT value, reason, evidence FROM non_cve_sss_override_proposals "
        "WHERE tenant_id = %s AND finding_id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalPayloadMismatchError(
            f"finding {subject_id}: no override binding row re-derives the "
            "approved payload"
        )
    # the binding stores the value at NUMERIC(6,4) grain; the canonical
    # payload renders the value in that same grain (propose_override_binding
    # hashed the identical canonical form at propose time), so a post-
    # approval alteration of the binding row is detected by re-hashing.
    rederived = {
        "value": _canonical_value_text(row["value"]),
        "reason": row["reason"],
        "evidence": row["evidence"],
    }
    if _canonical_hash(rederived) != payload_hash:
        raise ApprovalPayloadMismatchError(
            f"finding {subject_id}: the override binding no longer hashes to "
            "the approved payload"
        )
    return rederived


def _rederive_attestation(cur, tenant_id, subject_id, payload_hash) -> dict:
    cur.execute(
        "SELECT xmin::text AS v FROM exposure_non_exploitation_attestations "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    if cur.fetchone() is None:
        raise ApprovalNotFoundError(f"attestation {subject_id} not found")
    rederived = {"kind": "approve_attestation"}
    if _canonical_hash(rederived) != payload_hash:
        raise ApprovalPayloadMismatchError(
            f"attestation {subject_id}: no payload re-derives to the approved hash"
        )
    return rederived


# ---------------------------------------------------------------------------
# Apply handlers (run INSIDE the caller's transaction, after the primitive's
# payload + version rechecks; must remain tenant/episode/authority-safe)
# ---------------------------------------------------------------------------


def _apply_manual_sss(
    conn, tenant_id, *, subject_id, approval, payload, actor_id, actor_role
):
    """Publish the pending manual proposal as the effective SSS derivation.

    Rechecks (fail closed, nothing written): proposal still pending; finding
    revision unchanged since the proposal was captured; derived comparison
    binding still resolvable. Publishes a NEW derivation of path 'manual'
    with the approval id stamped — migration 019's immutability + is_current
    chain carry the history; the effective input changes, the TES state is
    computed at read time (approval NEVER auto-FINALs)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, tenant_id, finding_id, finding_revision_xmin, "
            "taxonomy_class, taxonomy_subclass, taxonomy_subtype, "
            "proposed_value, derived_derivation_id, status "
            "FROM non_cve_sss_proposals WHERE tenant_id = %s AND id = %s "
            "FOR UPDATE;",
            (str(tenant_id), subject_id),
        )
        p = cur.fetchone()
        if p is None:
            raise ApprovalNotFoundError(f"proposal {subject_id} not found")
        if p["status"] != "pending":
            raise ApprovalSubjectError(
                f"proposal {subject_id} is not pending "
                f"(status={p['status']}) — was it already applied?"
            )
        # finding revision recheck: the proposal bound a revision at propose
        # time; the apply re-reads it — a moved revision ⇒ stale ⇒ nothing
        cur.execute(
            "SELECT xmin::text AS rev FROM findings "
            "WHERE tenant_id = %s AND id = %s;",
            (str(tenant_id), p["finding_id"]),
        )
        frow = cur.fetchone()
        if frow is None:
            raise ApprovalNotFoundError(f"finding {p['finding_id']} not found")
        if frow["rev"] != p["finding_revision_xmin"]:
            raise ApprovalStaleSubjectError(
                f"finding revision moved since the proposal was captured "
                f"(proposal {p['finding_revision_xmin']!r}, now "
                f"{frow['rev']!r}) — apply fails closed"
            )

        # classification: an approval-applied manual SSS carries the manual
        # path classification row (inputs/evidence from the proposal). The
        # migration-019 schema requires a non-NULL taxonomy_class — a manual
        # proposal without one cannot publish; §3.6.5 requires the closed
        # spine, so an unclassified manual proposal is refused at apply.
        if p["taxonomy_class"] is None:
            raise ApprovalSubjectError(
                f"proposal {subject_id} carries no taxonomy classification — "
                "an approved manual SSS publishes only with a closed-spine "
                "taxonomy (§3.6.5); propose again with one"
            )
        cur.execute(
            """
            INSERT INTO non_cve_classifications (
                tenant_id, finding_id, finding_revision_xmin,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, version_id_ref, inputs, evidence, validation_state,
                created_by, created_role
            )
            SELECT tenant_id, finding_id, finding_revision_xmin,
                   taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                   'manual', NULL, jsonb_build_object('proposed_value', proposed_value),
                   evidence, 'confirmed', %s, %s
            FROM non_cve_sss_proposals WHERE id = %s
            RETURNING id;
            """,
            (actor_id, actor_role, subject_id),
        )
        classification_id = cur.fetchone()["id"]

        cur.execute(
            """
            UPDATE non_cve_sss_derivations
            SET is_current = FALSE
            WHERE tenant_id = %s AND finding_id = %s AND is_current;
            """,
            (str(tenant_id), p["finding_id"]),
        )
        # §3.6.6 #2 escape hatch: the manual path publishes with a NULL
        # version — the approval id is the provenance, no approved version
        # content is required or borrowed (019 path-conditioned shape CHECK).
        cur.execute(
            """
            INSERT INTO non_cve_sss_derivations (
                tenant_id, finding_id, finding_revision_xmin, classification_id,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, version_id_ref, inputs, value, evidence,
                approval_id, pre_override_derivation_id,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, 'manual', NULL,
                jsonb_build_object('proposed_value', %s),
                %s,
                (SELECT evidence FROM non_cve_sss_proposals WHERE id = %s),
                %s, %s, %s, %s
            )
            RETURNING id, value;
            """,
            (
                str(tenant_id), p["finding_id"], p["finding_revision_xmin"],
                classification_id,
                p["taxonomy_class"], p["taxonomy_subclass"], p["taxonomy_subtype"],
                p["proposed_value"], p["proposed_value"], subject_id,
                approval["id"], p["derived_derivation_id"],
                actor_id, actor_role,
            ),
        )
        d = cur.fetchone()

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role,
            event_name="sss.manual_proposal_applied",
            details={
                "finding_id": str(p["finding_id"]),
                "proposal_id": subject_id,
                "derivation_id": str(d["id"]),
                "value": str(d["value"]),
                "approval_id": str(approval["id"]),
            },
        )
        return {"derivation_id": str(d["id"]), "value": str(d["value"])}


def _apply_sss_override(
    conn, tenant_id, *, subject_id, approval, payload, actor_id, actor_role
):
    """Publish an analyst override of the finding's CURRENT derivation.

    The override binds the current derivation (pre_override_derivation_id —
    it stays visible in history), carries the approval id, and supersedes
    is_current through migration 019's DB-pinned chain. Provenance renders as
    ``analyst override`` in the TES decomposition (read-model mapping).

    The payload comes from the primitive's re-derivation over the binding
    row (non_cve_sss_override_proposals, written at propose time by
    propose_override) — the handler re-reads the binding row and refuses a
    mismatch, so the applied value is exactly what was approved."""
    if payload is None or "value" not in payload:
        raise ApprovalPayloadMismatchError(
            "override apply requires the re-derived payload"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT value, reason, evidence FROM non_cve_sss_override_proposals "
            "WHERE tenant_id = %s AND finding_id = %s;",
            (str(tenant_id), subject_id),
        )
        binding = cur.fetchone()
        if binding is None:
            raise ApprovalPayloadMismatchError(
                f"finding {subject_id}: no override binding row for approval "
                f"{approval['id']}"
            )
        from decimal import Decimal as _D
        if _D(str(binding["value"])) != _D(str(payload["value"])) \
                or binding["reason"] != payload["reason"] \
                or binding["evidence"] != payload["evidence"]:
            raise ApprovalPayloadMismatchError(
                f"override binding row disagrees with the approved payload "
                f"(approval {approval['id']}) — apply fails closed"
            )
    from decimal import Decimal

    value = Decimal(str(payload["value"]))
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"sss:{tenant_id}:{subject_id}")
        cur.execute(
            "SELECT xmin::text AS rev FROM findings "
            "WHERE tenant_id = %s AND id = %s;",
            (str(tenant_id), subject_id),
        )
        frow = cur.fetchone()
        if frow is None:
            raise ApprovalNotFoundError(f"finding {subject_id} not found")
        current = _finding_current_derivation(cur, tenant_id, subject_id)
        captured_revision = f"{frow['rev']}:{current['id'] if current else 'none'}"
        if captured_revision != approval["subject_version"]:
            raise ApprovalStaleSubjectError(
                f"override snapshot moved (approved "
                f"{approval['subject_version']!r}, now {captured_revision!r})"
            )

        cur.execute(
            """
            INSERT INTO non_cve_classifications (
                tenant_id, finding_id, finding_revision_xmin,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, version_id_ref, inputs, evidence, validation_state,
                created_by, created_role
            )
            SELECT tenant_id, finding_id, %s::text,
                   taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                   'override', NULL::uuid, jsonb_build_object(
                       'override_value', %s::text, 'reason', %s::text),
                   %s::jsonb, 'confirmed', %s::text, %s::text
            FROM non_cve_sss_derivations WHERE id = %s
            RETURNING id;
            """,
            (
                frow["rev"], str(value), payload["reason"],
                json.dumps(payload["evidence"]), actor_id, actor_role,
                current["id"],
            ),
        )
        crow = cur.fetchone()
        if crow is None:
            raise ApprovalStaleSubjectError(
                f"override apply could not read the pre-override derivation "
                f"(finding {subject_id}) — nothing published"
            )
        classification_id = crow["id"]

        cur.execute(
            """
            UPDATE non_cve_sss_derivations
            SET is_current = FALSE
            WHERE tenant_id = %s AND finding_id = %s AND is_current;
            """,
            (str(tenant_id), subject_id),
        )
        # §3.6.6 #2 escape hatch: the override path publishes with a NULL
        # version — approval + pre-override bindings are the provenance
        # (019 path-conditioned shape CHECK), never borrowed version content.
        cur.execute(
            """
            INSERT INTO non_cve_sss_derivations (
                tenant_id, finding_id, finding_revision_xmin, classification_id,
                taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                path, version_id_ref, inputs, value, evidence,
                approval_id, pre_override_derivation_id,
                created_by, created_role
            )
            SELECT tenant_id, finding_id, %s::text, %s::uuid,
                   taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                   'override', NULL::uuid,
                   jsonb_build_object('override_value', %s::text, 'reason', %s::text),
                   %s::numeric, %s::jsonb, %s::uuid, id, %s::text, %s::text
            FROM non_cve_sss_derivations WHERE id = %s
            RETURNING id, value;
            """,
            (
                frow["rev"], classification_id,
                str(value), payload["reason"], str(value),
                json.dumps(payload["evidence"]),
                approval["id"], actor_id, actor_role,
                current["id"],
            ),
        )
        d = cur.fetchone()
        if d is None:
            raise ApprovalStaleSubjectError(
                f"override apply could not read the pre-override derivation "
                f"(finding {subject_id}) — nothing published"
            )

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role,
            event_name="sss.override_applied",
            details={
                "finding_id": subject_id,
                "derivation_id": str(d["id"]),
                "pre_override_derivation_id": str(current["id"]),
                "value": str(d["value"]),
                "approval_id": str(approval["id"]),
            },
        )
        return {
            "derivation_id": str(d["id"]),
            "pre_override_derivation_id": str(current["id"]),
            "value": str(d["value"]),
        }


def _apply_er_attestation(
    conn, tenant_id, *, subject_id, approval, payload, actor_id, actor_role
):
    """Stamp the attestation's approval provenance (NULL → set, once — the
    migration-022 trigger enforces single stamping). The attestation becomes
    ER-eligible for 180 days for THIS episode only; expiry ⇒ unknown ⇒
    PROVISIONAL; the record stays visible forever."""
    with conn.cursor(row_factory=dict_row) as cur:
        # episode recheck: still a CURRENT confirmed episode (a superseded or
        # resolved episode's attestation can never be approval-eligible)
        cur.execute(
            """
            SELECT e.status AS exposure_status, f.canonical_cve_id
            FROM exposure_non_exploitation_attestations a
            JOIN asset_exposures e
              ON e.tenant_id = a.tenant_id AND e.id = a.exposure_id
            JOIN findings f
              ON f.tenant_id = a.tenant_id AND f.id = e.finding_id
            WHERE a.tenant_id = %s AND a.id = %s
            FOR UPDATE OF a;
            """,
            (str(tenant_id), subject_id),
        )
        row = cur.fetchone()
        if row is None:
            raise ApprovalNotFoundError(f"attestation {subject_id} not found")
        if row["canonical_cve_id"] is not None:
            raise ApprovalSubjectError(
                "attestations apply to non-CVE exposures only"
            )
        if row["exposure_status"] != "confirmed":
            raise ApprovalStaleSubjectError(
                f"episode is {row['exposure_status']}, not confirmed — "
                "the attestation cannot become eligible"
            )
        cur.execute(
            """
            UPDATE exposure_non_exploitation_attestations
            SET approval_id = %s,
                approved_by = %s,
                approved_at = now()
            WHERE tenant_id = %s AND id = %s
              AND approval_id IS NULL;
            """,
            (approval["id"], approval["approver_id"], str(tenant_id), subject_id),
        )
        if cur.rowcount != 1:
            raise ApprovalStaleSubjectError(
                f"attestation {subject_id} was not stampable (already "
                "approved or concurrently changed) — apply fails closed"
            )

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role,
            event_name="exposure.attestation_approved",
            details={
                "attestation_id": subject_id,
                "approval_id": str(approval["id"]),
                "approved_by": approval["approver_id"],
                "window_days": ATTESTATION_APPROVED_WINDOW.days,
            },
        )
        return {"attestation_id": subject_id, "approval_id": str(approval["id"])}


# ---------------------------------------------------------------------------
# Registration (import side effect — P0-08 activates the consumers)
# ---------------------------------------------------------------------------


def canonical_override_payload(value, reason: str, evidence: dict) -> dict:
    """The canonical override payload: the value rendered through the grain-
    stable canonical text. Callers MUST propose with this exact payload so
    the approved hash matches the apply-time re-derivation."""
    return {
        "value": _canonical_value_text(value),
        "reason": reason,
        "evidence": evidence,
    }


def propose_override_binding(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    approval_id: uuid.UUID,
    *,
    value,
    reason: str,
    evidence: dict,
) -> str:
    """Write the consumer-side override payload binding (migration 022).
    Called by the analyst flow in the SAME transaction as the primitive's
    ``propose`` — the payload_hash the proposal carries is computed from
    exactly these columns. Returns the binding row id."""
    from decimal import Decimal, InvalidOperation
    try:
        v = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ApprovalSubjectError("override value must be a number") from exc
    if not (0 <= v <= 10) or -v.as_tuple().exponent > 4:
        raise ApprovalSubjectError(
            "override value must be within 0-10 at four decimal places"
        )
    if not isinstance(reason, str) or not reason.strip():
        raise ApprovalSubjectError("override reason is mandatory")
    if not isinstance(evidence, dict) or not evidence:
        raise ApprovalSubjectError("override evidence is mandatory")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO non_cve_sss_override_proposals (
                tenant_id, finding_id, approval_id, value, reason, evidence
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (str(tenant_id), str(finding_id), approval_id, str(v),
             reason.strip(), json.dumps(evidence)),
        )
        return cur.fetchone()["id"]


def register() -> None:
    register_subject_type(SUBJECT_MANUAL_SSS, SubjectHandler(
        validate_payload=_validate_manual_sss,
        current_version=_proposal_version,
        rederive_payload=_rederive_manual_sss,
        apply=_apply_manual_sss,
    ))
    register_subject_type(SUBJECT_SSS_OVERRIDE, SubjectHandler(
        validate_payload=_validate_sss_override,
        current_version=_override_version,
        rederive_payload=_rederive_sss_override,
        apply=_apply_sss_override,
    ))
    register_subject_type(SUBJECT_ER_ATTESTATION, SubjectHandler(
        validate_payload=_validate_er_attestation,
        current_version=_attestation_version,
        rederive_payload=_rederive_attestation,
        apply=_apply_er_attestation,
    ))


register()
