"""Tenant-scoped connections between Tempris exposure and governance modules.

This module deliberately distinguishes recorded facts from missing data.  It does
not infer customer exposure, owners, treatment decisions, deadlines, or business
impact.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from models import (
    Asset,
    AuditLog,
    ChatSession,
    ControlStatus,
    EdipDecision,
    Finding,
    GeneratedReport,
    GrcSignoff,
    GrcState,
    ScanFinding,
    SpotlightReport,
    StrikeAuthorization,
    SurgeSubmission,
    TenantPackage,
)
from services.entitlements import get_tenant_package
from services.exposure_links import (
    active_asset_map,
    candidate_assets,
    confirmed_asset_ids_by_finding,
    is_catalog_finding,
)
from services.kev_loader import _finding_to_dict
from services.tes_engine import calculate_finding_tes


RESOLVED_STATUSES = {"resolved", "mitigated", "closed"}


def _is_open(finding: Finding) -> bool:
    return (finding.status or "").strip().lower() not in RESOLVED_STATUSES


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _date_state(value: str | None, today: date) -> str | None:
    if not value:
        return None
    try:
        due = date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return "invalid"
    days = (due - today).days
    if days < 0:
        return "overdue"
    if days <= 7:
        return "due_soon"
    return "scheduled"


def build_exposure_coverage(db: Session, tenant_id: str) -> dict:
    """Separate confirmed customer exposure from global vulnerability intelligence."""
    assets = active_asset_map(db, tenant_id)
    findings = [
        row for row in db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
        if _is_open(row)
    ]
    links = confirmed_asset_ids_by_finding(db, tenant_id, assets)
    linked = [row for row in findings if links.get(row.id)]
    invalid_links = [
        row for row in findings
        if row.asset_id and row.asset_id not in assets and not links.get(row.id)
    ]

    scored: list[tuple[Finding, float]] = []
    unscored_ids: list[str] = []
    for finding in linked:
        try:
            scored.append((finding, float(calculate_finding_tes(_finding_to_dict(finding)))))
        except (KeyError, TypeError, ValueError):
            unscored_ids.append(finding.id)

    aggregate = round(sum(score for _, score in scored) / len(scored), 2) if scored else None
    unlinked = [row for row in findings if not links.get(row.id)]
    invalid_ids = {row.id for row in invalid_links}
    candidate_cache: dict[str, list[dict]] = {}
    actionable: list[Finding] = []
    catalog_only: list[Finding] = []
    for finding in unlinked:
        candidates = candidate_assets(finding, assets)
        candidate_cache[finding.id] = candidates
        if finding.id in invalid_ids or candidates or not is_catalog_finding(finding):
            actionable.append(finding)
        else:
            catalog_only.append(finding)

    def queue_item(row: Finding) -> dict:
        candidates = candidate_cache.get(row.id, [])
        if row.id in invalid_ids:
            reason = "invalid_asset_link"
        elif candidates:
            reason = "candidate_match"
        else:
            reason = "manual_intake"
        return {
            "finding_id": row.id,
            "cve": row.cve or row.cve_id,
            "title": row.title,
            "vendor": row.vendor,
            "product": row.product,
            "source": row.source or "unknown",
            "priority": row.priority,
            "status": row.status,
            "asset_id": row.asset_id,
            "mapping_reason": reason,
            "candidate_assets": candidates,
        }

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    reason_order = {"invalid_asset_link": 0, "candidate_match": 1, "manual_intake": 2}
    mapping_queue_limit = 50
    mapping_queue = sorted(
        actionable,
        key=lambda row: (
            reason_order[queue_item(row)["mapping_reason"]],
            priority_order.get((row.priority or "").upper(), 4),
            row.id,
        ),
    )[:mapping_queue_limit]
    queued_invalid_ids = {row.id for row in mapping_queue if row.id in invalid_ids}
    queued_unlinked_ids = {row.id for row in mapping_queue if row.id not in invalid_ids}
    linked_asset_ids = {asset_id for ids in links.values() for asset_id in ids}
    confirmed_exposure_count = sum(len(ids) for ids in links.values())
    applicable = len(linked) + len(actionable)
    kev_linked = [row for row in linked if bool(row.cisa_kev)]

    return {
        "status": "available" if scored else "unavailable",
        "aggregate_tes": aggregate,
        "aggregate_scope": "open_asset_linked_scored_findings",
        "open_finding_count": len(findings),
        "asset_linked_count": len(linked),
        "confirmed_exposure_count": confirmed_exposure_count,
        "confirmed_asset_count": len(linked_asset_ids),
        "exposure_applicable_count": applicable,
        "asset_link_coverage_pct": round(len(linked) / applicable * 100, 1) if applicable else None,
        "scored_asset_linked_count": len(scored),
        "scoring_coverage_pct": round(len(scored) / len(linked) * 100, 1) if linked else None,
        "unlinked_count": len(unlinked),
        "mapping_required_count": len(actionable),
        "candidate_match_count": sum(1 for row in actionable if candidate_cache.get(row.id)),
        "catalog_intelligence_count": len(catalog_only),
        "catalog_scope": "reference_only_until_asset_evidence_matches",
        "unlinked_findings": [
            queue_item(row) for row in mapping_queue if row.id in queued_unlinked_ids
        ],
        "invalid_asset_link_count": len(invalid_links),
        "invalid_asset_links": [
            queue_item(row) for row in mapping_queue if row.id in queued_invalid_ids
        ],
        "mapping_queue": [queue_item(row) for row in mapping_queue],
        "mapping_queue_limit": mapping_queue_limit,
        "mapping_queue_returned_count": len(mapping_queue),
        "unscored_finding_ids": unscored_ids,
        "asset_linked_cisa_kev_count": len(kev_linked),
        "asset_linked_cisa_kev_ids": [row.id for row in kev_linked],
        "reason": None if scored else "No open tenant finding has both a valid tenant asset link and complete TES inputs",
    }
def build_deadline_summary(db: Session, tenant_id: str, now: datetime | None = None) -> dict:
    """Return separately named deadline types; never collapse them into 'overdue'."""
    current = now or datetime.now(timezone.utc)
    today = current.date()
    items: list[dict] = []
    findings = db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    for finding in findings:
        if not _is_open(finding):
            continue
        created_at = _as_utc(finding.created_at)
        if created_at and finding.sla:
            due = (created_at + timedelta(days=int(finding.sla))).date().isoformat()
            items.append({
                "finding_id": finding.id,
                "type": "remediation_sla",
                "date": due,
                "state": _date_state(due, today),
                "source": "finding.created_at + finding.sla",
            })
        sss = dict(finding.sss_data or {})
        for key, deadline_type in (("kev_due", "cisa_kev_due"), ("revalidate_by", "edip_revalidation")):
            if sss.get(key):
                items.append({
                    "finding_id": finding.id,
                    "type": deadline_type,
                    "date": str(sss[key]),
                    "state": _date_state(str(sss[key]), today),
                    "source": f"finding.sss_data.{key}",
                })
    counts: dict[str, dict[str, int]] = {}
    for item in items:
        counts.setdefault(item["type"], {})[item["state"]] = (
            counts.setdefault(item["type"], {}).get(item["state"], 0) + 1
        )
    return {"counts": counts, "items": items}


def build_workflow_readiness(db: Session, tenant_id: str) -> dict:
    assets = {
        row.id: row
        for row in db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.status != "decommissioned",
        ).all()
    }
    findings = db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    open_findings = [row for row in findings if _is_open(row)]
    decisions = {
        row.finding_id: row
        for row in db.query(EdipDecision).filter(EdipDecision.tenant_id == tenant_id).all()
    }
    links = confirmed_asset_ids_by_finding(db, tenant_id, assets)
    linked_exposures = [
        (row, asset_id) for row in open_findings
        for asset_id in links.get(row.id, set())
    ]

    def count_sss(key: str) -> int:
        return sum(1 for row in open_findings if (row.sss_data or {}).get(key))

    return {
        "owners": {
            "recorded": sum(1 for _, asset_id in linked_exposures if assets[asset_id].owner),
            "applicable": len(linked_exposures),
            "source": "ASSETS.owner",
        },
        "sla": {
            "recorded": sum(1 for row in open_findings if row.sla),
            "applicable": len(open_findings),
            "source": "SPECTRUM.finding.sla",
            "package_policy": "not_configured",
        },
        "edip": {
            "decisions_recorded": len(decisions),
            "decisions_with_rationale": sum(1 for row in decisions.values() if (row.rationale or "").strip()),
            "applicable": len(open_findings),
            "source": "EDIP explicit analyst decision",
        },
        "business_impact": {
            "recorded": count_sss("business_impact"),
            "applicable": len(open_findings),
            "source": "SSS finding intake/workflow update",
        },
        "effort": {
            "recorded": count_sss("effort"),
            "applicable": len(open_findings),
            "source": "SSS finding intake/workflow update",
        },
        "revalidation": {
            "recorded": count_sss("revalidate_by"),
            "applicable": len(open_findings),
            "source": "EDIP/SSS recorded revalidation date",
        },
        "remediation_verification": {
            "recorded": count_sss("remediation_verification"),
            "applicable": len(open_findings),
            "source": "SPECTRUM workflow update",
        },
        "insurance_tier": {
            "status": "not_configured",
            "reason": "No approved calculation model is recorded",
        },
    }


def _module_probe(name: str, query) -> dict:
    try:
        count, last_activity = query()
        return {
            "name": name,
            "status": "operational",
            "data_status": "recorded" if count else "no_data",
            "record_count": int(count or 0),
            "last_activity": _iso(last_activity),
        }
    except Exception as exc:  # a failed repository query is real degraded telemetry
        return {
            "name": name,
            "status": "degraded",
            "data_status": "unavailable",
            "record_count": None,
            "last_activity": None,
            "reason": exc.__class__.__name__,
        }


def build_module_health(db: Session, tenant_id: str) -> list[dict]:
    """Probe each module's backing repository and report data readiness separately."""
    assignment = get_tenant_package(db, tenant_id)
    enabled = set(assignment["effective_modules"])

    def tenant_count(model, timestamp):
        return lambda: db.query(func.count(model.id), func.max(timestamp)).filter(model.tenant_id == tenant_id).one()

    probes = {
        "SYNTHESIS": tenant_count(Finding, Finding.updated_at),
        "SPECTRUM": tenant_count(Finding, Finding.updated_at),
        "SCOUT": tenant_count(ScanFinding, ScanFinding.discovered_at),
        "STRIKE": tenant_count(StrikeAuthorization, StrikeAuthorization.created_at),
        "STANDARD": tenant_count(ControlStatus, ControlStatus.updated_at),
        "GRC": tenant_count(GrcState, GrcState.updated_at),
        "ASSETS": tenant_count(Asset, Asset.updated_at),
        "SPOTLIGHT": tenant_count(SpotlightReport, SpotlightReport.generated_at),
        "CISO": tenant_count(GeneratedReport, GeneratedReport.created_at),
        "SPEAK": tenant_count(ChatSession, ChatSession.created_at),
        "SSS_EDIP": tenant_count(EdipDecision, EdipDecision.decided_at),
    }
    results = []
    for name, query in probes.items():
        row = _module_probe(name, query)
        row["enabled"] = name in enabled or name in {"SPEAK", "SSS_EDIP"}
        results.append(row)

    if tenant_id == "tempris":
        surge = _module_probe(
            "SURGE",
            lambda: db.query(func.count(SurgeSubmission.id), func.max(SurgeSubmission.created_at)).one(),
        )
        surge["enabled"] = True
        results.append(surge)
    return results


def build_workflow_overview(db: Session, tenant_id: str) -> dict:
    controls = db.query(ControlStatus).filter(ControlStatus.tenant_id == tenant_id).count()
    grc_states = db.query(GrcState).filter(GrcState.tenant_id == tenant_id).count()
    grc_signoffs = db.query(GrcSignoff).filter(GrcSignoff.tenant_id == tenant_id).count()
    package = db.query(TenantPackage).filter(TenantPackage.tenant_id == tenant_id).first()
    return {
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "exposure": build_exposure_coverage(db, tenant_id),
        "deadlines": build_deadline_summary(db, tenant_id),
        "workflow": build_workflow_readiness(db, tenant_id),
        "assurance": {
            "standard_assessments_recorded": controls,
            "grc_state_recorded": bool(grc_states),
            "grc_signoffs_recorded": grc_signoffs,
            "package_assignment_recorded": package is not None,
        },
        "module_health": build_module_health(db, tenant_id),
    }
