# backend/app/speak/service.py
"""
Service layer for SPEAK reports/deliverables (PRD-000 v1.11 Ch.11).

Binding rules implemented here:

1. A report is a reader, never a writer: the only writes in this module are
   its own rows (reports, report_artifacts) and audit events.
2. Sealing establishes snapshot consistency (PATCH-13): generation runs
   inside ONE caller-owned REPEATABLE READ boundary, captures one ``as_of``,
   renders from that view, and stores the SEALED values together with the
   source identities. A report is a §3.3.6 snapshot writer — downstream
   views render the stored values and never recompute.
3. Regeneration appends a NEW version row (parent chain); the sealed row is
   immutable (DB-enforced).
4. Approved/archived reports cannot be deleted (archive only) — service 409
   plus a DB trigger; only never-approved drafts are deletable.
5. Register-time ownership validation (V1 posture kept): every registered
   exposure must be a CURRENT confirmed episode of the requesting tenant.
6. SPEAK's AI surface is interpretation-only: it reads one coherent view of
   THIS tenant's authoritative state, cites the exact source objects it was
   given, writes only its own audit event, and fails CLOSED with no
   configured model — never invented numbers.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.ciso import service as ciso_service
from app.config import get_speak_llm_config
from app.exposure.tes_read_model import _jsonify, get_exposure_tes
from app.speak import llm, render
from app.speak.errors import (
    ArtifactIntegrityError,
    LlmUnavailableError,
    ReportNotFoundError,
    ReportStateError,
    ScopeValidationError,
)

MAX_SCOPE_EXPOSURES = 500
REPORT_LIST_LIMIT = 200
ARTIFACT_KINDS = ("html", "json", "csv")

_REPORT_COLUMNS = (
    "id, tenant_id, report_type, title, status, version, parent_report_id, "
    "template_id, template_version, as_of, sealed_payload, content_hash, "
    "scope, generated_by, generated_at, approved_by, approved_at, "
    "archived_by, archived_at, created_at, updated_at"
)


def _row_to_dict(row: dict) -> dict:
    d = dict(row)
    d["id"] = str(d["id"])
    d["tenant_id"] = str(d["tenant_id"])
    if d.get("parent_report_id") is not None:
        d["parent_report_id"] = str(d["parent_report_id"])
    return d


def _load_report(cur: psycopg.Cursor, tenant_id: uuid.UUID, report_id: uuid.UUID) -> dict:
    """Tenant-scoped load; unknown and cross-tenant ids are the same
    fail-closed not-found."""
    cur.execute(
        f"SELECT {_REPORT_COLUMNS} FROM reports WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), str(report_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise ReportNotFoundError(f"Report {report_id} not found")
    return row


def _require_sealed(report: dict) -> None:
    if report["sealed_payload"] is None:
        raise ReportStateError(
            f"Report {report['id']} has not been generated yet (no sealed content)"
        )


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------


def register_report(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    report_type: str,
    title: str,
    exposure_ids: Optional[list[uuid.UUID]],
    actor_id: str,
    actor_role: str,
) -> dict:
    """Create the draft. Register-time ownership validation: every exposure
    in the scope must be a CURRENT confirmed episode on an ACTIVE asset of
    THIS tenant (V1's register rule, exposure-grain). The template comes
    from the built-in registry for the type."""
    template = render.BUILTIN_TEMPLATES.get(report_type)
    if template is None:
        raise ScopeValidationError(
            f"unknown report_type {report_type!r}; renderable types: "
            f"{sorted(render.BUILTIN_TEMPLATES)}"
        )

    scoped_ids: list[str] = []
    if exposure_ids:
        # dedupe, preserve order, bound the scope
        seen: set[str] = set()
        for raw in exposure_ids:
            key = str(raw)
            if key not in seen:
                seen.add(key)
                scoped_ids.append(key)
        if len(scoped_ids) > MAX_SCOPE_EXPOSURES:
            raise ScopeValidationError(
                f"scope exceeds the bound of {MAX_SCOPE_EXPOSURES} exposures"
            )
        with conn.cursor() as cur:
            for exposure_id in scoped_ids:
                cur.execute(
                    """
                    SELECT e.id
                    FROM asset_exposures e
                    JOIN assets a
                      ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
                     AND a.status = 'active'
                    WHERE e.tenant_id = %s AND e.id = %s AND e.status = 'confirmed';
                    """,
                    (str(tenant_id), exposure_id),
                )
                if cur.fetchone() is None:
                    # One honest failure for unknown, cross-tenant, resolved
                    # and inactive-asset ids alike — nothing is disclosed.
                    raise ScopeValidationError(
                        f"exposure {exposure_id} is not a current exposure of "
                        "this tenant"
                    )

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO reports (
                tenant_id, report_type, title, status, version,
                template_id, template_version, scope
            ) VALUES (%s, %s, %s, 'draft', 1, %s, %s, %s)
            RETURNING *;
            """,
            (
                str(tenant_id), report_type, title.strip(),
                template["template_id"], template["template_version"],
                json.dumps({"exposure_ids": scoped_ids}),
            ),
        )
        report = cur.fetchone()

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name="speak.report_registered",
        details={"report_id": str(report["id"]), "report_type": report_type,
                 "scope_size": len(scoped_ids)},
    )
    return _row_to_dict(report)


# ---------------------------------------------------------------------------
# Sealing (generation) — one coherent source view
# ---------------------------------------------------------------------------


def _seal_executive_summary(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    actor_id: str, template: dict,
) -> tuple[dict, dict]:
    """Executive summary payload: the Ch.10 tiles consumed DIRECTLY (read-
    through, one boundary) — Ch.11 renders Ch.10's output, it does not
    re-aggregate. source_refs ride along for the seal."""
    payload, source_refs = ciso_service.build_executive_summary(
        conn, tenant_id, as_of=as_of
    )
    payload.update({
        "report_type": "executive_summary",
        "template_id": template["template_id"],
        "template_version": template["template_version"],
        "generated_by": actor_id,
    })
    return payload, source_refs


def _seal_exposure_register(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *, as_of: datetime,
    actor_id: str, template: dict, scope: dict,
) -> tuple[dict, dict]:
    """Technical exposure register: per registered exposure, the recomputed
    TES (sealed state/value/formula_version) plus the source identities the
    value was computed from."""
    entries: list[dict] = []
    refs: list[dict] = []
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id AS exposure_id, e.finding_id, e.asset_id,
                   e.confirmed_at, e.xmin::text AS exposure_version,
                   f.canonical_cve_id, f.title AS finding_title,
                   f.severity AS finding_severity,
                   a.name AS asset_name
            FROM asset_exposures e
            JOIN findings f ON f.tenant_id = e.tenant_id AND f.id = e.finding_id
            JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
            WHERE e.tenant_id = %s AND e.id = ANY(%s);
            """,
            (str(tenant_id), scope.get("exposure_ids", [])),
        )
        by_id = {str(r["exposure_id"]): r for r in cur.fetchall()}

    # sealed in registration order — the scope list is part of the seal
    for exposure_id in scope.get("exposure_ids", []):
        row = by_id.get(exposure_id)
        if row is None:
            # The register validation passed at registration but the episode
            # is no longer current at generation: the report names the
            # omission explicitly rather than rendering a hole (fail closed
            # against silent drift between register and generate).
            entries.append({
                "exposure_id": exposure_id,
                "omitted": "no_longer_a_current_exposure_at_generation",
            })
            continue
        tes = get_exposure_tes(conn, tenant_id, uuid.UUID(exposure_id), as_of=as_of)
        source_view = tes.get("source_view", {})
        entries.append({
            "exposure_id": exposure_id,
            "finding_id": str(row["finding_id"]),
            "asset_id": str(row["asset_id"]),
            "canonical_cve_id": row["canonical_cve_id"],
            "finding_title": row["finding_title"],
            "finding_severity": row["finding_severity"],
            "asset_name": row["asset_name"],
            "confirmed_at": row["confirmed_at"],
            "tes": {
                "state": tes["state"],
                "value": tes["value"],  # sealed exactly as computed
                "display_value": tes["display_value"],
                "formula_version": tes["formula_version"],
            },
        })
        refs.append({
            "exposure_id": exposure_id,
            "exposure_version": source_view.get("exposure_version"),
            "cvss_assessment_id": source_view.get("cvss_assessment_id"),
            "epss_snapshot_id": source_view.get("epss_snapshot_id"),
            "kev_snapshot_id": source_view.get("kev_snapshot_id"),
            "reachability_record_id": source_view.get("reachability_record_id"),
            "business_impact_record_id": source_view.get("business_impact_record_id"),
        })

    payload = {
        "report_type": "exposure_register",
        "template_id": template["template_id"],
        "template_version": template["template_version"],
        "as_of": as_of,
        "authority": "sealed_snapshot_rendered_values",
        "generated_by": actor_id,
        "exposures": entries,
    }
    return payload, {"exposures": refs}


def generate_report(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    report_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    as_of: datetime,
) -> dict:
    """Seal a DRAFT report inside the caller's REPEATABLE READ boundary:
    render values from the one coherent source view, hash the payload,
    publish the three bounded artifacts, stamp the generator. Upstream state
    is only ever read — generation never mutates scoring or workflow state."""
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        if report["sealed_payload"] is not None:
            raise ReportStateError(
                f"report {report_id} is already sealed; use regenerate"
            )
    return _seal_and_publish(
        conn, tenant_id, report, actor_id=actor_id, actor_role=actor_role,
        as_of=as_of, event_name="speak.report_generated",
    )


def regenerate_report(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    report_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    as_of: datetime,
) -> dict:
    """REGENERATION appends a NEW version row (version+1, parent_report_id
    chain) sealed at a FRESH as_of; the parent row — and every earlier
    version — stays byte-identical. History is never rewritten."""
    with conn.cursor(row_factory=dict_row) as cur:
        parent = _load_report(cur, tenant_id, report_id)
        _require_sealed(parent)
        cur.execute(
            """
            INSERT INTO reports (
                tenant_id, report_type, title, status,
                version, parent_report_id,
                template_id, template_version, scope
            ) VALUES (%s, %s, %s, 'draft', %s, %s, %s, %s, %s)
            RETURNING *;
            """,
            (
                str(tenant_id), parent["report_type"], parent["title"],
                parent["version"] + 1, parent["id"],
                parent["template_id"], parent["template_version"],
                json.dumps(parent["scope"]),
            ),
        )
        draft = cur.fetchone()

    result = _seal_and_publish(
        conn, tenant_id, draft, actor_id=actor_id, actor_role=actor_role,
        as_of=as_of, event_name="speak.report_regenerated",
    )
    # the parent identity rides along so the caller sees the version chain
    result["parent_report_id"] = str(parent["id"])
    result["parent_version"] = parent["version"]
    return result


def _seal_and_publish(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    report: dict,
    *,
    actor_id: str,
    actor_role: str,
    as_of: datetime,
    event_name: str,
) -> dict:
    """The shared sealing path: build the sealed payload from the template,
    hash it, render + persist the bounded artifacts, stamp the generator,
    audit. Runs entirely inside the caller's boundary; a failure anywhere
    rolls the whole publication back (only complete sealed artifacts are
    published)."""
    template = {
        "template_id": report["template_id"],
        "template_version": report["template_version"],
    }
    scope = report["scope"] if isinstance(report["scope"], dict) else json.loads(
        report["scope"] or "{}"
    )

    if report["report_type"] == "executive_summary":
        payload, source_refs = _seal_executive_summary(
            conn, tenant_id, as_of=as_of, actor_id=actor_id, template=template,
        )
    else:
        payload, source_refs = _seal_exposure_register(
            conn, tenant_id, as_of=as_of, actor_id=actor_id,
            template=template, scope=scope,
        )
    payload["source_refs"] = _jsonify(source_refs)

    wire_payload = _jsonify(payload)
    content_hash = render.sha256_hex(render.canonical_json(wire_payload))

    artifacts = render.render_artifacts(
        report["report_type"], wire_payload, report["title"]
    )
    artifact_rows = []
    with conn.cursor(row_factory=dict_row) as cur:
        for kind in ARTIFACT_KINDS:
            content = artifacts[kind]
            if len(content) > render.MAX_ARTIFACT_BYTES:
                raise ReportStateError(
                    f"{kind} artifact exceeds the bounded size "
                    f"({len(content)} > {render.MAX_ARTIFACT_BYTES} bytes)"
                )
            cur.execute(
                """
                INSERT INTO report_artifacts (
                    tenant_id, report_id, artifact_kind, content,
                    size_bytes, content_hash, created_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, artifact_kind, size_bytes, content_hash;
                """,
                (
                    str(tenant_id), str(report["id"]), kind,
                    content, len(content),
                    render.sha256_bytes(content), actor_id,
                ),
            )
            artifact_rows.append(dict(cur.fetchone()))

        cur.execute(
            f"""
            UPDATE reports
            SET sealed_payload = %s,
                content_hash = %s,
                as_of = %s,
                generated_by = %s,
                generated_at = %s,
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING {_REPORT_COLUMNS};
            """,
            (
                json.dumps(wire_payload), content_hash, as_of, actor_id, as_of,
                str(tenant_id), str(report["id"]),
            ),
        )
        sealed = cur.fetchone()

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name=event_name,
        details={
            "report_id": str(report["id"]),
            "content_hash": content_hash,
            "as_of": as_of.isoformat(),
        },
    )
    result = _row_to_dict(sealed)
    result["artifacts"] = [
        {**a, "artifact_id": str(a["id"])} for a in artifact_rows
    ]
    return result


# ---------------------------------------------------------------------------
# Lifecycle: approve / archive / delete
# ---------------------------------------------------------------------------


def approve_report(
    conn: psycopg.Connection, tenant_id: uuid.UUID, report_id: uuid.UUID,
    *, actor_id: str, actor_role: str,
) -> dict:
    """draft → approved (admin+ at the route). An unsealed draft cannot be
    approved: approval stamps a sealed deliverable."""
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        _require_sealed(report)
        if report["status"] != "draft":
            raise ReportStateError(
                f"report {report_id} is {report['status']}, not draft"
            )
        cur.execute(
            f"""
            UPDATE reports
            SET status = 'approved', approved_by = %s, approved_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING {_REPORT_COLUMNS};
            """,
            (actor_id, str(tenant_id), str(report_id)),
        )
        approved = cur.fetchone()

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name="speak.report_approved",
        details={"report_id": str(report_id),
                 "content_hash": report["content_hash"]},
    )
    return _row_to_dict(approved)


def archive_report(
    conn: psycopg.Connection, tenant_id: uuid.UUID, report_id: uuid.UUID,
    *, actor_id: str, actor_role: str,
) -> dict:
    """approved → archived (admin+ at the route). Archived reports keep
    their sealed bytes for historical rendering — that is what sealing is
    for."""
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        _require_sealed(report)
        if report["status"] != "approved":
            raise ReportStateError(
                f"report {report_id} is {report['status']}, not approved"
            )
        cur.execute(
            f"""
            UPDATE reports
            SET status = 'archived', archived_by = %s, archived_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING {_REPORT_COLUMNS};
            """,
            (actor_id, str(tenant_id), str(report_id)),
        )
        archived = cur.fetchone()

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name="speak.report_archived",
        details={"report_id": str(report_id)},
    )
    return _row_to_dict(archived)


def delete_report(
    conn: psycopg.Connection, tenant_id: uuid.UUID, report_id: uuid.UUID,
    *, actor_id: str, actor_role: str,
) -> dict:
    """Hard delete retired for anything approved or exported: only a
    never-approved DRAFT is deletable (its artifacts cascade with it). The
    DB trigger enforces the same rule; the audit event outlives the row."""
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        if report["status"] != "draft":
            raise ReportStateError(
                f"report {report_id} is {report['status']}; approved and "
                "archived reports cannot be deleted (archive only)"
            )
        cur.execute(
            "DELETE FROM reports WHERE tenant_id = %s AND id = %s;",
            (str(tenant_id), str(report_id)),
        )

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name="speak.report_deleted",
        details={"report_id": str(report_id)},
    )
    return {"id": str(report_id), "deleted": True}


# ---------------------------------------------------------------------------
# Reads + artifacts + export
# ---------------------------------------------------------------------------


def get_report(
    conn: psycopg.Connection, tenant_id: uuid.UUID, report_id: uuid.UUID
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        cur.execute(
            """
            SELECT id, artifact_kind, size_bytes, content_hash, created_at
            FROM report_artifacts
            WHERE tenant_id = %s AND report_id = %s
            ORDER BY artifact_kind ASC;
            """,
            (str(tenant_id), str(report_id)),
        )
        artifacts = cur.fetchall()
    result = _row_to_dict(report)
    result["artifacts"] = [
        {**dict(a), "id": str(a["id"])} for a in artifacts
    ]
    return result


def list_reports(
    conn: psycopg.Connection, tenant_id: uuid.UUID, *,
    status: Optional[str] = None, report_type: Optional[str] = None,
    limit: int = 50, offset: int = 0,
) -> dict:
    """Bounded, newest-first listing (PRD: report versions are bounded in
    what any single view loads)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT COUNT(*) AS total FROM reports
            WHERE tenant_id = %s
              AND (%s::text IS NULL OR status = %s::text)
              AND (%s::text IS NULL OR report_type = %s::text);
            """,
            (str(tenant_id), status, status, report_type, report_type),
        )
        total = cur.fetchone()["total"]
        cur.execute(
            f"""
            SELECT {_REPORT_COLUMNS} FROM reports
            WHERE tenant_id = %s
              AND (%s::text IS NULL OR status = %s::text)
              AND (%s::text IS NULL OR report_type = %s::text)
            ORDER BY created_at DESC, id DESC
            LIMIT %s OFFSET %s;
            """,
            (str(tenant_id), status, status, report_type, report_type,
             max(1, min(limit, REPORT_LIST_LIMIT)), max(0, offset)),
        )
        rows = cur.fetchall()
    return {"total": total, "items": [_row_to_dict(r) for r in rows]}


def read_artifact(
    conn: psycopg.Connection, tenant_id: uuid.UUID, report_id: uuid.UUID,
    artifact_kind: str, *, actor_id: str, actor_role: str,
) -> dict:
    """Bytes + integrity verification. The stored artifact is returned only
    if its bytes still hash to the sealed content_hash AND the owning
    report's payload still hashes to the report's content_hash. A mismatch
    refuses the download, alarms via the audit chain, and never serves the
    tampered bytes."""
    if artifact_kind not in ARTIFACT_KINDS:
        raise ReportStateError(
            f"unknown artifact kind {artifact_kind!r}; "
            f"kinds: {list(ARTIFACT_KINDS)}"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        _require_sealed(report)
        cur.execute(
            """
            SELECT id, artifact_kind, content, size_bytes, content_hash,
                   created_at, created_by
            FROM report_artifacts
            WHERE tenant_id = %s AND report_id = %s AND artifact_kind = %s;
            """,
            (str(tenant_id), str(report_id), artifact_kind),
        )
        artifact = cur.fetchone()
        if artifact is None:
            raise ReportNotFoundError(
                f"artifact {artifact_kind!r} not found for report {report_id}"
            )

    content = bytes(artifact["content"])
    integrity = {
        "report_id": str(report_id),
        "artifact_kind": artifact_kind,
        "expected_hash": artifact["content_hash"],
        "actual_hash": render.sha256_bytes(content),
    }
    if integrity["actual_hash"] != artifact["content_hash"]:
        record_audit_event(
            conn, tenant_id,
            actor_id=actor_id, actor_role=actor_role,
            event_name="speak.artifact_hash_mismatch",
            details=integrity,
        )
        raise ArtifactIntegrityError(
            f"artifact {artifact_kind} of report {report_id} failed its "
            "integrity check; the download was refused and alarmed"
        )
    # the seal itself: the payload must still hash to the report's seal
    sealed_payload = report["sealed_payload"]
    if not isinstance(sealed_payload, dict):
        sealed_payload = json.loads(sealed_payload)
    if render.sha256_hex(render.canonical_json(sealed_payload)) != report["content_hash"]:
        record_audit_event(
            conn, tenant_id,
            actor_id=actor_id, actor_role=actor_role,
            event_name="speak.report_seal_mismatch",
            details={"report_id": str(report_id),
                     "content_hash": report["content_hash"]},
        )
        raise ArtifactIntegrityError(
            f"report {report_id} failed its seal check; the download was "
            "refused and alarmed"
        )

    return {
        "artifact_id": str(artifact["id"]),
        "artifact_kind": artifact["artifact_kind"],
        "content": content,
        "size_bytes": artifact["size_bytes"],
        "content_hash": artifact["content_hash"],
        "created_at": artifact["created_at"],
        "report_title": report["title"],
        "report_status": report["status"],
    }


def export_report(
    conn: psycopg.Connection, tenant_id: uuid.UUID, report_id: uuid.UUID,
    *, actor_id: str, actor_role: str,
    recipient: Optional[str] = None, note: Optional[str] = None,
) -> dict:
    """Export provenance (who exported, when, to whom, which sealed
    content). Export is an approval-gated act (admin+ at the route) on a
    SEALED report — an export event outlives everything else and is what
    makes the report non-deletable history."""
    with conn.cursor(row_factory=dict_row) as cur:
        report = _load_report(cur, tenant_id, report_id)
        _require_sealed(report)
        if report["status"] == "draft":
            raise ReportStateError(
                f"report {report_id} is an unapproved draft; export requires "
                "an approved (or archived) report"
            )

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name="speak.report_exported",
        details={
            "report_id": str(report_id),
            "content_hash": report["content_hash"],
            "report_status": report["status"],
            "recipient": recipient,
            "note": note,
        },
    )
    return {
        "report_id": str(report_id),
        "exported": True,
        "content_hash": report["content_hash"],
        "exported_by": actor_id,
    }


def speak_chat(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    message: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """The system's only LLM surface (PRD Ch.11 rule 6). One coherent
    read-only view of THIS tenant's authoritative state (the Ch.10 executive
    summary, read inside the caller's boundary) is handed to the model as
    DATA; the answer comes back labeled INTERPRETATION with server-built
    citations — the exact source objects the model was given, never what the
    model claims. No session rows, no message rows; the only write is the
    tenant's own audit-chain event. With no configured provider it fails
    CLOSED: 'unavailable', never invented numbers (the V1 mock-LLM fallback
    is a named defect class and is retired)."""
    config = get_speak_llm_config()
    if config is None:
        raise LlmUnavailableError(
            "SPEAK has no configured LLM provider; the AI surface fails closed "
            "and never invents content (PRD Ch.11 rule 6)"
        )

    as_of = datetime.now(timezone.utc)
    payload, source_refs = ciso_service.build_executive_summary(
        conn, tenant_id, as_of=as_of
    )
    wire_payload = _jsonify(payload)
    messages = llm.build_chat_messages(message, wire_payload)
    answer = llm.chat_completion(messages, config=config)

    record_audit_event(
        conn, tenant_id,
        actor_id=actor_id, actor_role=actor_role,
        event_name="speak.chat_completed",
        details={
            "model": config.model,
            "message_chars": len(message),
            "context": "executive_summary",
            "cited_exposures": len(source_refs.get("exposures", [])),
        },
    )
    return {
        "answer": answer,
        "model": config.model,
        "authority": "interpretation_only",
        "disclaimer": (
            "AI interpretation of the cited authoritative objects; never a "
            "source of record — verify against the sealed reports."
        ),
        "as_of": wire_payload.get("as_of"),
        "citations": _jsonify(source_refs),
    }
