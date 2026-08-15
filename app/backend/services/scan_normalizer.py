"""Deterministic SCOUT observation-to-finding normalization."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models import Asset, Finding, ScanFinding, ScanJob
from services.exposure_links import confirm_finding_assets
from services.operational_events import record_operational_event


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
OBSERVATION_ENGINES = {"nmap", "builtin_tcp"}


def normalize_target(value: str) -> str:
    raw = (value or "").strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw.split("/")[0].split(":")[0]).strip().lower().rstrip(".")


def exact_asset_matches(db: Session, tenant_id: str, target: str) -> list[Asset]:
    normalized = normalize_target(target)
    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.status != "decommissioned",
    ).all()
    matches = []
    for asset in assets:
        identifiers = {
            normalize_target(asset.ip_address or ""),
            normalize_target(asset.hostname or ""),
            normalize_target(asset.name or ""),
        }
        tags = asset.tags if isinstance(asset.tags, list) else []
        identifiers.update(normalize_target(tag) for tag in tags if isinstance(tag, str))
        identifiers.discard("")
        if normalized in identifiers:
            matches.append(asset)
    return sorted(matches, key=lambda row: row.id)


def _stable_digest(*parts: object) -> str:
    raw = "\x1f".join(str(part or "").strip().lower() for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_vulnerability(observation: dict) -> bool:
    engine = (observation.get("engine") or "").lower()
    if engine in OBSERVATION_ENGINES:
        return False
    severity = (observation.get("risk") or "").lower()
    if severity in {"", "info", "informational"}:
        return False
    metadata = observation.get("metadata") if isinstance(observation.get("metadata"), dict) else {}
    tags = {str(value).lower() for value in metadata.get("tags", [])}
    template_id = (observation.get("template_id") or "").lower()
    detection_only = {"tech", "technology", "fingerprint", "banner", "detect"}
    return not (tags & detection_only or any(token in template_id for token in ("tech-detect", "fingerprint")))


def normalize_observation(
    db: Session,
    *,
    tenant_id: str,
    scan_job: ScanJob,
    observation: dict,
    actor_id: str,
) -> dict:
    now = datetime.now(timezone.utc)
    cve = (observation.get("cve_id") or "").strip().upper()
    if cve and not CVE_PATTERN.fullmatch(cve):
        cve = ""
    template_id = (observation.get("template_id") or "").strip()
    engine = (observation.get("engine") or ("nuclei" if template_id and template_id not in {"nmap-sV", "builtin-tcp"} else "nmap")).lower()
    stable = _stable_digest(
        tenant_id, normalize_target(observation.get("target") or scan_job.target),
        engine, template_id, cve, observation.get("port"), observation.get("service"),
    )
    scan_finding_id = f"SF-{stable[:24].upper()}"
    raw_hash = hashlib.sha256(
        json.dumps(observation, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    row = db.query(ScanFinding).filter(
        ScanFinding.id == scan_finding_id,
        ScanFinding.tenant_id == tenant_id,
    ).first()
    created = row is None
    if row is None:
        row = ScanFinding(id=scan_finding_id, tenant_id=tenant_id, first_seen_at=now)
        db.add(row)
    row.scan_id = scan_job.id
    row.target = observation.get("target") or scan_job.target
    row.port = int(observation.get("port") or 0)
    row.service = str(observation.get("service") or "unknown")[:50]
    row.risk = str(observation.get("risk") or "Info")[:20]
    row.detail = str(observation.get("detail") or "")
    row.status = "observed"
    row.template_id = template_id or None
    row.cve_id = cve or None
    row.matched_at = str(observation.get("matched_at") or "")[:500] or None
    row.raw_result_hash = raw_hash
    row.evidence_metadata = {
        "engine": engine,
        "scan_id": scan_job.id,
        "template_id": template_id or None,
        "metadata": observation.get("metadata") or {},
    }
    row.last_seen_at = now
    if created:
        record_operational_event(
            db, tenant_id=tenant_id, event_type="scanfinding.created",
            resource_type="scan_finding", resource_id=row.id, source_module="SCOUT",
            actor_id=actor_id, correlation_id=scan_job.id,
            metadata={"engine": engine, "target": scan_job.normalized_target},
        )

    if engine in OBSERVATION_ENGINES or not _is_vulnerability({**observation, "engine": engine}):
        return {"scan_finding": row, "finding": None, "exposure": "observation_only"}

    if cve:
        finding = db.query(Finding).filter(
            Finding.tenant_id == tenant_id,
            or_(Finding.cve == cve, Finding.cve_id == cve),
        ).first()
        identity = cve
    else:
        identity = f"template:{template_id or stable[:16]}"
        external_id = f"scout:{identity}"
        finding = db.query(Finding).filter(
            Finding.tenant_id == tenant_id,
            Finding.external_id == external_id,
        ).first()

    finding_created = finding is None
    if finding is None:
        finding = Finding(
            id=f"F-SCN-{_stable_digest(tenant_id, identity)[:13].upper()}",
            tenant_id=tenant_id,
            external_id=f"scout:{identity}",
            cve_id=cve or None,
            cve=cve or None,
            finding_type="standard" if cve else "SSS",
            pipeline="SCOUT",
            verification="CONFIRMED_SCAN_OBSERVATION",
            title=str(observation.get("service") or template_id or cve or "SCOUT vulnerability")[:500],
            description=str(observation.get("detail") or ""),
            status="unmitigated",
            cve_assigned=bool(cve),
            source="scanner",
            sss_data={"source": "nuclei", "template_id": template_id} if not cve else None,
        )
        db.add(finding)
        record_operational_event(
            db, tenant_id=tenant_id, event_type="finding.created",
            resource_type="finding", resource_id=finding.id, source_module="SCOUT",
            actor_id=actor_id, correlation_id=scan_job.id,
            metadata={"source": "nuclei", "cve": cve or None, "template_id": template_id},
        )
    row.normalized_finding_id = finding.id
    matches = exact_asset_matches(db, tenant_id, row.matched_at or row.target)
    exposure_state = "needs_classification"
    if len(matches) == 1:
        evidence = (
            f"Nuclei template {template_id or 'unknown'} matched {row.matched_at or row.target}; "
            f"raw result SHA-256 {raw_hash}"
        )
        links = confirm_finding_assets(
            db, finding, matches, actor_id, evidence=evidence, match_method="nuclei",
        )
        for link in links:
            link.evidence_metadata = {
                "scan_id": scan_job.id,
                "scan_finding_id": row.id,
                "template_id": template_id or None,
                "cve_id": cve or None,
                "matched_at": row.matched_at,
                "raw_result_hash": raw_hash,
            }
        row.asset_id = matches[0].id
        exposure_state = "confirmed"
        record_operational_event(
            db, tenant_id=tenant_id, event_type="finding.asset_confirmed",
            resource_type="finding", resource_id=finding.id, source_module="SCOUT",
            actor_id=actor_id, correlation_id=scan_job.id,
            metadata={"asset_ids": [matches[0].id], "source": "nuclei"},
        )
    elif len(matches) > 1:
        row.evidence_metadata = {**(row.evidence_metadata or {}), "candidate_asset_ids": [asset.id for asset in matches]}
        record_operational_event(
            db, tenant_id=tenant_id, event_type="finding.asset_suggested",
            resource_type="finding", resource_id=finding.id, source_module="SCOUT",
            actor_id=actor_id, correlation_id=scan_job.id,
            metadata={"candidate_asset_ids": [asset.id for asset in matches]},
        )
    record_operational_event(
        db, tenant_id=tenant_id, event_type="scanfinding.normalized",
        resource_type="scan_finding", resource_id=row.id, source_module="SCOUT",
        actor_id=actor_id, correlation_id=scan_job.id,
        metadata={"finding_id": finding.id, "finding_created": finding_created, "exposure_state": exposure_state},
    )
    return {"scan_finding": row, "finding": finding, "exposure": exposure_state}
