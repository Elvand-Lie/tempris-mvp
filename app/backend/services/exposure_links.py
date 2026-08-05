"""Tenant-safe many-to-many links between findings and customer assets."""

from __future__ import annotations

import re
from collections import defaultdict
from uuid import uuid4

from sqlalchemy.orm import Session

from models import Asset, AssetExposure, Finding


CONFIRMED_STATUSES = {"confirmed", "accepted"}
CATALOG_SOURCES = {"kev", "cisa", "nvd", "catalog"}
TOKEN_STOPWORDS = {
    "and", "the", "for", "with", "from", "that", "this", "server", "service",
    "application", "system", "platform", "product", "software", "security",
    "vulnerability", "remote", "code", "execution", "missing", "improper",
    "multiple", "before", "after", "version", "versions", "critical", "high",
    "medium", "low", "enterprise", "network", "web", "http", "https",
}


def active_asset_map(db: Session, tenant_id: str) -> dict[str, Asset]:
    return {
        asset.id: asset
        for asset in db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.status != "decommissioned",
        ).all()
    }


def confirmed_asset_ids_by_finding(
    db: Session,
    tenant_id: str,
    assets: dict[str, Asset] | None = None,
) -> dict[str, set[str]]:
    """Return confirmed links, retaining legacy finding.asset_id compatibility."""
    active = assets if assets is not None else active_asset_map(db, tenant_id)
    links: dict[str, set[str]] = defaultdict(set)
    rows = db.query(AssetExposure).filter(
        AssetExposure.tenant_id == tenant_id,
        AssetExposure.status.in_(CONFIRMED_STATUSES),
    ).all()
    for row in rows:
        if row.asset_id in active:
            links[row.finding_id].add(row.asset_id)

    # Existing deployments stored one link directly on findings. Migration 007
    # backfills these rows, while this fallback keeps rolling deploys safe.
    for finding in db.query(Finding).filter(Finding.tenant_id == tenant_id).all():
        if finding.asset_id in active:
            links[finding.id].add(finding.asset_id)
    return dict(links)


def exposure_rows_for_finding(db: Session, tenant_id: str, finding_id: str) -> list[AssetExposure]:
    return db.query(AssetExposure).filter(
        AssetExposure.tenant_id == tenant_id,
        AssetExposure.finding_id == finding_id,
    ).order_by(AssetExposure.created_at.asc(), AssetExposure.asset_id.asc()).all()


def confirm_finding_assets(
    db: Session,
    finding: Finding,
    assets: list[Asset],
    recorded_by: str,
    evidence: str | None = None,
    match_method: str = "manual_confirmation",
) -> list[AssetExposure]:
    """Idempotently confirm one finding on one or more active tenant assets."""
    existing = {
        row.asset_id: row
        for row in exposure_rows_for_finding(db, finding.tenant_id, finding.id)
    }
    confirmed: list[AssetExposure] = []
    for asset in assets:
        row = existing.get(asset.id)
        if row is None:
            row = AssetExposure(
                id=f"EXP-{uuid4().hex[:24].upper()}",
                tenant_id=finding.tenant_id,
                finding_id=finding.id,
                asset_id=asset.id,
            )
            db.add(row)
        row.status = "confirmed"
        row.match_method = match_method
        row.confidence = 1.0
        row.evidence = evidence or "Explicit analyst confirmation"
        row.recorded_by = recorded_by
        confirmed.append(row)

    # Keep the legacy single-link fields populated for older exports and APIs.
    if assets and finding.asset_id not in {asset.id for asset in assets}:
        primary = assets[0]
        finding.asset_id = primary.id
        finding.asset_data = {
            "asset_id": primary.id,
            "name": primary.name,
            "hostname": primary.hostname,
            "ip_address": primary.ip_address,
            "criticality": primary.criticality,
            "owner": primary.owner,
            "environment": primary.environment,
            "source": "tenant_asset_inventory",
        }
    return confirmed


def set_finding_assets(
    db: Session,
    finding: Finding,
    assets: list[Asset],
    recorded_by: str,
    evidence: str | None = None,
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Replace a finding's active asset set and retain removed rows for provenance."""
    existing = {
        row.asset_id: row
        for row in exposure_rows_for_finding(db, finding.tenant_id, finding.id)
    }
    before = sorted(
        asset_id for asset_id, row in existing.items()
        if row.status in CONFIRMED_STATUSES
    )
    if finding.asset_id and finding.asset_id not in before:
        before.append(finding.asset_id)
    selected = {asset.id: asset for asset in assets}
    after = sorted(selected)

    for asset_id, row in existing.items():
        if asset_id not in selected and row.status in CONFIRMED_STATUSES:
            row.status = "removed"
            row.recorded_by = recorded_by
            if evidence:
                row.evidence = evidence

    confirm_finding_assets(db, finding, assets, recorded_by, evidence)
    if assets:
        primary = assets[0]
        finding.asset_id = primary.id
        finding.asset_data = {
            "asset_id": primary.id,
            "name": primary.name,
            "hostname": primary.hostname,
            "ip_address": primary.ip_address,
            "criticality": primary.criticality,
            "owner": primary.owner,
            "environment": primary.environment,
            "source": "tenant_asset_inventory",
        }
    else:
        finding.asset_id = None
        finding.asset_data = None

    before_set = set(before)
    after_set = set(after)
    return (
        before,
        after,
        sorted(after_set - before_set),
        sorted(before_set - after_set),
    )


def is_catalog_finding(finding: Finding) -> bool:
    return bool(finding.cisa_kev) or (finding.source or "").strip().lower() in CATALOG_SOURCES


def _tokens(value: object) -> set[str]:
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    words = re.findall(r"[a-z0-9]+", str(value or "").lower())
    return {
        word for word in words
        if len(word) >= 3 and word not in TOKEN_STOPWORDS and not word.startswith("cve")
    }


def candidate_assets(finding: Finding, assets: dict[str, Asset]) -> list[dict]:
    """Suggest possible links from recorded identity fields; never auto-confirm."""
    vendor_tokens = _tokens(finding.vendor)
    product_tokens = _tokens(finding.product)
    title_tokens = _tokens(finding.title)
    identity_tokens = vendor_tokens | product_tokens
    results: list[dict] = []

    for asset in assets.values():
        asset_tokens = _tokens([
            asset.name, asset.hostname, asset.ip_address, asset.asset_type,
            asset.tags or [], asset.notes,
        ])
        matched_identity = identity_tokens & asset_tokens
        matched_title = title_tokens & asset_tokens
        if identity_tokens:
            coverage = len(matched_identity) / len(identity_tokens)
            vendor_hit = bool(vendor_tokens & asset_tokens)
            product_hit = bool(product_tokens & asset_tokens)
            confidence = (0.45 if vendor_hit else 0.0) + (0.45 * coverage)
            if product_hit:
                confidence += 0.1
        else:
            # Titles are noisier: require two distinctive terms before suggesting.
            confidence = min(0.8, 0.25 * len(matched_title)) if len(matched_title) >= 2 else 0.0
        confidence = min(confidence, 0.95)
        if confidence < 0.55:
            continue
        matched = sorted(matched_identity or matched_title)
        results.append({
            "asset_id": asset.id,
            "name": asset.name,
            "hostname": asset.hostname,
            "environment": asset.environment,
            "owner": asset.owner,
            "confidence": round(confidence, 2),
            "evidence": f"Recorded identity terms matched: {', '.join(matched[:6])}",
        })

    return sorted(results, key=lambda row: (-row["confidence"], row["name"], row["asset_id"]))[:8]
