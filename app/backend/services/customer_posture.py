"""Canonical, tenant-safe customer exposure and posture aggregation.

This is the only service that defines confirmed customer exposure.  A legacy
``Finding.asset_id`` value remains useful history, but is never confirmation.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models import Asset, AssetExposure, Finding, ScanFinding
from services.exposure_links import (
    CONFIRMED_STATUSES,
    active_asset_map,
    candidate_assets,
    is_catalog_finding,
)
from services.kev_loader import _finding_to_dict
from services.tes_engine import calculate_finding_tes


SCOPE_VERSION = "canonical-customer-exposure-v1"
RESOLVED_STATUSES = {"resolved", "mitigated", "closed"}
REFERENCE_STATUSES = {"reference", "reference_only", "catalogue", "catalog"}
NOT_APPLICABLE_STATUSES = {"not_applicable", "not-applicable"}


def normalised_status(finding: Finding) -> str:
    return (finding.status or "unmitigated").strip().lower()


def is_open(finding: Finding) -> bool:
    return normalised_status(finding) not in RESOLVED_STATUSES


def is_reference_only(finding: Finding) -> bool:
    return normalised_status(finding) in REFERENCE_STATUSES


def is_not_applicable(finding: Finding) -> bool:
    return normalised_status(finding) in NOT_APPLICABLE_STATUSES


def _severity(finding: Finding) -> str:
    priority = (finding.priority or "").upper()
    if priority == "P0":
        return "critical"
    if priority == "P1":
        return "high"
    value = finding.score if finding.score is not None else finding.cvss
    if value is not None and float(value) >= 9:
        return "critical"
    if value is not None and float(value) >= 7:
        return "high"
    if value is not None and float(value) >= 4:
        return "medium"
    return "low"


def canonical_exposure_rows(
    db: Session,
    tenant_id: str,
    *,
    open_only: bool = True,
) -> list[tuple[Finding, Asset, AssetExposure]]:
    """Return only confirmed, same-tenant, active-asset exposure occurrences."""
    findings = {
        row.id: row for row in db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    }
    assets = active_asset_map(db, tenant_id)
    output: list[tuple[Finding, Asset, AssetExposure]] = []
    rows = db.query(AssetExposure).filter(
        AssetExposure.tenant_id == tenant_id,
        AssetExposure.status.in_(CONFIRMED_STATUSES),
    ).all()
    for link in rows:
        finding = findings.get(link.finding_id)
        asset = assets.get(link.asset_id)
        if finding is None or asset is None:
            continue
        if finding.tenant_id != asset.tenant_id or finding.tenant_id != link.tenant_id:
            continue
        if is_reference_only(finding) or is_not_applicable(finding):
            continue
        if open_only and not is_open(finding):
            continue
        output.append((finding, asset, link))
    return output


def build_customer_posture(db: Session, tenant_id: str) -> dict:
    """Build the canonical typed posture used by all executive consumers."""
    as_of = datetime.now(timezone.utc)
    assets = active_asset_map(db, tenant_id)
    findings = db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    canonical_rows = canonical_exposure_rows(db, tenant_id, open_only=True)

    links_by_finding: dict[str, list[tuple[Asset, AssetExposure]]] = defaultdict(list)
    for finding, asset, link in canonical_rows:
        links_by_finding[finding.id].append((asset, link))
    confirmed_findings = [row for row in findings if row.id in links_by_finding]

    explicit_reference = [row for row in findings if is_reference_only(row)]
    not_applicable = [row for row in findings if is_not_applicable(row)]
    resolved = [row for row in findings if not is_open(row)]
    open_unconfirmed = [
        row for row in findings
        if is_open(row)
        and not is_reference_only(row)
        and not is_not_applicable(row)
        and row.id not in links_by_finding
    ]

    candidates: dict[str, list[dict]] = {}
    needs_classification: list[Finding] = []
    derived_reference: list[Finding] = []
    scanner_candidate_ids = {
        row[0] for row in db.query(ScanFinding.normalized_finding_id).filter(
            ScanFinding.tenant_id == tenant_id,
            ScanFinding.normalized_finding_id.isnot(None),
        ).all()
    }
    for finding in open_unconfirmed:
        suggested = candidate_assets(finding, assets)
        candidates[finding.id] = suggested
        if suggested or finding.id in scanner_candidate_ids or not is_catalog_finding(finding):
            needs_classification.append(finding)
        else:
            derived_reference.append(finding)

    score_rows: list[tuple[Finding, float]] = []
    unscoreable_ids: list[str] = []
    for finding in confirmed_findings:
        try:
            score_rows.append((finding, float(calculate_finding_tes(_finding_to_dict(finding)))))
        except (KeyError, TypeError, ValueError):
            unscoreable_ids.append(finding.id)
    aggregate_tes = (
        round(sum(score for _, score in score_rows) / len(score_rows), 2)
        if score_rows else None
    )

    confirmed_pairs = {(row.finding_id, row.asset_id) for _, _, row in canonical_rows}
    evidence_backed_pairs = {
        (row.finding_id, row.asset_id)
        for _, _, row in canonical_rows
        if (row.evidence or "").strip()
        and (row.match_method or "").lower() not in {"legacy", "legacy_import", "imported_legacy"}
    }
    legacy_unverified = [
        row for row in findings
        if row.asset_id in assets and (row.id, row.asset_id) not in confirmed_pairs
    ]
    severities = {row.id: _severity(row) for row in confirmed_findings}

    def queue_item(row: Finding) -> dict:
        suggested = candidates.get(row.id, [])
        return {
            "finding_id": row.id,
            "cve": row.cve or row.cve_id,
            "title": row.title,
            "source": row.source or "unknown",
            "priority": row.priority,
            "status": row.status,
            "legacy_asset_id": row.asset_id,
            "mapping_reason": "suggested_match" if suggested else "unclassified_intake",
            "candidate_assets": suggested,
        }

    return {
        "scope_version": SCOPE_VERSION,
        "scope": "tenant_confirmed_customer_exposure",
        "as_of": as_of.isoformat(),
        "active_asset_count": len(assets),
        "total_stored_finding_count": len(findings),
        "confirmed_open_exposure_count": len(confirmed_findings),
        "confirmed_exposure_link_count": len(canonical_rows),
        "confirmed_asset_count": len({asset.id for _, asset, _ in canonical_rows}),
        "confirmed_critical_count": sum(severities[row.id] == "critical" for row in confirmed_findings),
        "confirmed_high_count": sum(severities[row.id] == "high" for row in confirmed_findings),
        "confirmed_ransomware_linked_count": sum(bool(row.ransomware) for row in confirmed_findings),
        "needs_classification_count": len(needs_classification),
        "suggested_match_count": sum(bool(candidates.get(row.id)) for row in needs_classification),
        "unclassified_intake_count": sum(not candidates.get(row.id) for row in needs_classification),
        "reference_intelligence_count": len(explicit_reference) + len(derived_reference),
        "analyst_reference_count": len(explicit_reference),
        "derived_reference_count": len(derived_reference),
        "not_applicable_count": len(not_applicable),
        "resolved_finding_count": len(resolved),
        "evidence_backed_link_count": len(evidence_backed_pairs),
        "legacy_unverified_link_count": len(legacy_unverified),
        "legacy_unverified_finding_ids": sorted(row.id for row in legacy_unverified),
        "scoreable_finding_count": len(score_rows),
        "unscoreable_finding_ids": sorted(unscoreable_ids),
        "aggregate_tenant_tes": aggregate_tes,
        "mapping_queue": [queue_item(row) for row in needs_classification[:50]],
        "mapping_queue_total": len(needs_classification),
        "confirmed_finding_ids": sorted(row.id for row in confirmed_findings),
        "confirmed_link_pairs": sorted([list(pair) for pair in confirmed_pairs]),
        "asset_linked_cisa_kev_ids": sorted(row.id for row in confirmed_findings if row.cisa_kev),
        "asset_linked_cisa_kev_count": sum(bool(row.cisa_kev) for row in confirmed_findings),
    }
