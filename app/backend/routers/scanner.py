"""SCOUT Scanner Router — Hardened Production Nuclei + Nmap Integration.

Provides asset-bound vulnerability scanning via Nuclei templates and Nmap port discovery.
Enforces:
- Global feature flag: SCOUT_ACTIVE_SCANNING_ENABLED
- Strict asset binding and approved AssetScanAuthorization requirement
- SSRF prevention, non-global IP rejection, DNS rebinding validation
- Subprocess timeout, kill fallback, bounded buffer capture, and resource cleanup
- Deterministic observation-to-finding normalization
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import shutil
import socket
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from models import Asset, AssetExposure, AssetScanAuthorization, Finding, ScanFinding, ScanJob
from routers.audit import AuditEntry, append_to_audit_log
from routers.auth import get_auth_context, get_current_user, require_role
from services.database import get_db
from services.entitlements import require_module
from services.operational_events import record_operational_event
from services.scan_normalizer import normalize_observation, normalize_target
from services.target_policy import (
    clean_target_input,
    is_ip_globally_routable,
    validate_and_resolve_target,
)


logger = logging.getLogger("tempris.scanner")

router = APIRouter(dependencies=[Depends(require_module("SCOUT"))])


class ScannerOutputLimitExceeded(RuntimeError):
    """Raised when scanner subprocess output exceeds the maximum capture limit."""
    code = "output_limit_exceeded"

    def __init__(self, message: str, stream: str = "stdout"):
        super().__init__(message)
        self.stream = stream


def _is_active_scanning_enabled() -> bool:
    return os.environ.get("SCOUT_ACTIVE_SCANNING_ENABLED", "false").strip().lower() in {"true", "1", "yes"}


def _is_raw_diagnostic_enabled() -> bool:
    return os.environ.get("SCOUT_RAW_DIAGNOSTIC_ENABLED", "false").strip().lower() in {"true", "1", "yes"}


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ── SSRF Protection Helper (Legacy & Direct) ──────────────────────────────────

def _is_blocked_target(host: str) -> bool:
    """Check if a target resolves to a private, loopback, link-local, or restricted IP."""
    res = validate_and_resolve_target(host)
    return not res.is_valid or not res.is_public_scannable


def _clean_host(target: str) -> str:
    return clean_target_input(target)


# ── Scanner Binaries & Subprocess Execution ───────────────────────────────────

NUCLEI_AVAILABLE = shutil.which("nuclei") is not None
NMAP_AVAILABLE = shutil.which("nmap") is not None

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # 10 MB per stream limit


async def _read_stream_bounded(stream: asyncio.StreamReader | None, limit: int, stream_name: str = "stdout") -> bytes:
    """Read from an asyncio StreamReader up to `limit` bytes.

    Raises ScannerOutputLimitExceeded immediately when the next chunk crosses the limit.
    """
    if stream is None:
        return b""
    buffer = bytearray()
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            break
        if len(buffer) + len(chunk) > limit:
            remaining = limit - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            raise ScannerOutputLimitExceeded(
                f"Subprocess stream '{stream_name}' exceeded maximum output limit of {limit} bytes",
                stream=stream_name,
            )
        buffer.extend(chunk)
    return bytes(buffer)


async def _execute_subprocess_safely(
    cmd: list[str],
    timeout_seconds: int,
    max_output_bytes: int = MAX_CAPTURE_BYTES,
) -> tuple[int, bytes, bytes]:
    """Executes a subprocess with hard timeout, forced kill fallback, and immediate streaming overflow abort."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_task = asyncio.create_task(_read_stream_bounded(proc.stdout, max_output_bytes, stream_name="stdout"))
    stderr_task = asyncio.create_task(_read_stream_bounded(proc.stderr, max_output_bytes, stream_name="stderr"))

    async def _cleanup_process():
        try:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=0.5)
                except (asyncio.TimeoutError, Exception):
                    proc.kill()
                    await proc.wait()
        except Exception:
            pass
        stdout_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    try:
        await asyncio.wait_for(
            asyncio.gather(stdout_task, stderr_task, proc.wait()),
            timeout=timeout_seconds,
        )
        stdout = stdout_task.result()
        stderr = stderr_task.result()
        return proc.returncode or 0, stdout, stderr
    except Exception:
        await _cleanup_process()
        raise


# ── Nuclei Scanner Execution ──────────────────────────────────────────────────

async def _run_nuclei_scan(target: str, scan_id: str) -> list[dict]:
    """Run Nuclei vulnerability scanner with server-curated settings."""
    findings = []
    try:
        cmd = [
            "nuclei",
            "-target", target,
            "-json",
            "-silent",
            "-no-color",
            "-timeout", "10",
            "-retries", "1",
            "-rate-limit", "50",
            "-severity", "critical,high,medium,low",
            "-type", "http",
            "-concurrency", "10",
            "-no-interactsh",
            "-disable-update-check",
        ]

        _, stdout, stderr = await _execute_subprocess_safely(cmd, timeout_seconds=120)

        for line in stdout.decode("utf-8", errors="replace").strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
                info = result.get("info", {})
                severity = info.get("severity", "info").lower()

                finding = {
                    "id": f"{scan_id}-{len(findings):04d}",
                    "scan_id": scan_id,
                    "target": target,
                    "port": _extract_port(result.get("matched-at", target)),
                    "service": info.get("name", result.get("template-id", "unknown")),
                    "risk": SEVERITY_MAP.get(severity, "Medium"),
                    "detail": _build_detail(result, info),
                    "status": "new",
                    "template_id": result.get("template-id", ""),
                    "cve_id": _extract_cve(info),
                    "matched_at": result.get("matched-at", ""),
                    "engine": "nuclei",
                    "metadata": {
                        "tags": info.get("tags", []),
                        "classification": info.get("classification", {}),
                        "reference": info.get("reference", []),
                        "matcher_name": result.get("matcher-name", ""),
                        "extracted_results": result.get("extracted-results", []),
                    },
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        if stderr:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            if err_text:
                logger.warning("Nuclei stderr: %s", err_text[:500])

    except asyncio.TimeoutError:
        logger.error("Nuclei scan timed out for target %s", target)
        raise
    except Exception as e:
        logger.error("Nuclei scan error: %s", e)
        raise

    return findings


def _extract_port(matched_at: str) -> int:
    try:
        if "://" in matched_at:
            host_part = matched_at.split("://")[1].split("/")[0]
            if ":" in host_part:
                return int(host_part.split(":")[-1])
            return 443 if matched_at.startswith("https") else 80
    except Exception:
        pass
    return 0


def _extract_cve(info: dict) -> str:
    classification = info.get("classification", {})
    cve_ids = classification.get("cve-id", [])
    if isinstance(cve_ids, list) and cve_ids:
        return cve_ids[0]
    if isinstance(cve_ids, str):
        return cve_ids
    return ""


def _build_detail(result: dict, info: dict) -> str:
    parts = []
    desc = info.get("description", "")
    if desc:
        parts.append(desc[:300])

    matched_at = result.get("matched-at", "")
    if matched_at:
        parts.append(f"Matched: {matched_at}")

    cve = _extract_cve(info)
    if cve:
        parts.append(f"CVE: {cve}")

    refs = info.get("reference", [])
    if isinstance(refs, list) and refs:
        parts.append(f"Ref: {refs[0]}")

    return " | ".join(parts) if parts else info.get("name", "Vulnerability detected")


# ── Nmap Port Discovery Execution ─────────────────────────────────────────────

async def _run_nmap_scan(target: str, scan_id: str) -> list[dict]:
    """Run nmap using TCP connect scan (-sT) on top ports with bounded timing."""
    findings = []
    try:
        cmd = [
            "nmap",
            "-sT",                  # TCP Connect scan (no CAP_NET_RAW / root required)
            "-sV",                  # Service version detection
            "--top-ports", "100",   # Bounded top 100 ports
            "-T3",                  # Normal timing
            "--open",               # Only report open ports
            "-oX", "-",             # XML output to stdout
            target,
        ]

        _, stdout, _ = await _execute_subprocess_safely(cmd, timeout_seconds=90)
        output = stdout.decode("utf-8", errors="replace")

        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(output)
            for host in root.findall(".//host"):
                for port_elem in host.findall(".//port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    service_elem = port_elem.find("service")

                    if state_elem is not None and state_elem.get("state") == "open":
                        service_name = service_elem.get("name", "unknown") if service_elem else "unknown"
                        service_version = service_elem.get("version", "") if service_elem else ""
                        product = service_elem.get("product", "") if service_elem else ""

                        risk = _assess_port_risk(port_id, service_name)
                        detail = f"{product} {service_version}".strip() or f"{service_name} on port {port_id}/{protocol}"

                        findings.append({
                            "id": f"{scan_id}-NM-{port_id}",
                            "scan_id": scan_id,
                            "target": target,
                            "port": port_id,
                            "service": f"{service_name}" + (f" ({product} {service_version})" if product else ""),
                            "risk": risk,
                            "detail": detail,
                            "status": "new",
                            "template_id": "nmap-sV",
                            "cve_id": "",
                            "matched_at": f"{target}:{port_id}",
                            "engine": "nmap",
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                        })
        except ET.ParseError:
            logger.error("Failed to parse nmap XML output")

    except asyncio.TimeoutError:
        logger.error("Nmap scan timed out for %s", target)
        raise
    except Exception as e:
        logger.error("Nmap scan error: %s", e)
        raise

    return findings


DANGEROUS_PORTS = {
    21: "High", 23: "Critical", 25: "Medium", 110: "Medium", 135: "High",
    139: "High", 445: "High", 1433: "Critical", 1521: "Critical",
    3306: "Critical", 3389: "High", 5432: "Critical", 5900: "High",
    6379: "Critical", 8080: "Medium", 9092: "High", 27017: "Critical",
    11211: "Critical",
}


def _assess_port_risk(port: int, service: str) -> str:
    if port in DANGEROUS_PORTS:
        return DANGEROUS_PORTS[port]
    if service in ("telnet", "ftp", "rsh", "rlogin"):
        return "Critical"
    if service in ("mysql", "postgresql", "mongodb", "redis", "memcached"):
        return "Critical"
    if service in ("http", "https", "ssh"):
        return "Low"
    return "Medium"


# ── Fallback: Built-in TCP port scanner ───────────────────────────────────────

PORT_RISK_MAP = {
    21: {"service": "FTP", "risk": "High", "detail": "FTP allows unencrypted file transfer. Credential interception risk."},
    22: {"service": "SSH", "risk": "Medium", "detail": "SSH is secure but may be targeted for brute force if misconfigured."},
    23: {"service": "Telnet", "risk": "Critical", "detail": "Telnet transmits data in plaintext including credentials. Must be disabled."},
    25: {"service": "SMTP", "risk": "Medium", "detail": "Open SMTP relay can be exploited for spam and phishing campaigns."},
    80: {"service": "HTTP", "risk": "Medium", "detail": "HTTP serves unencrypted traffic. Should redirect to HTTPS."},
    443: {"service": "HTTPS", "risk": "Low", "detail": "HTTPS is properly encrypted. Verify TLS configuration."},
    3306: {"service": "MySQL", "risk": "Critical", "detail": "MySQL exposed to network. Database ports must not be publicly accessible."},
    5432: {"service": "PostgreSQL", "risk": "Critical", "detail": "PostgreSQL exposed to network. Database ports must not be publicly accessible."},
    8080: {"service": "HTTP-Alt", "risk": "High", "detail": "Alternative HTTP port often used for admin panels or dev servers."},
    27017: {"service": "MongoDB", "risk": "Critical", "detail": "MongoDB exposed to network. Known target for ransomware attacks."},
    6379: {"service": "Redis", "risk": "Critical", "detail": "Redis exposed without authentication. Data exfiltration risk."},
    9092: {"service": "Kafka", "risk": "High", "detail": "Kafka broker exposed. May allow unauthorized message consumption."},
}


async def _run_builtin_scan(target: str, scan_id: str) -> list[dict]:
    findings = []
    host_clean = _clean_host(target)
    common_ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 9092, 27017]

    async def check_port(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host_clean, port), timeout=1.5
            )
            writer.close()
            await writer.wait_closed()
            port_info = PORT_RISK_MAP.get(port, {"service": "Unknown", "risk": "Medium", "detail": f"Unknown service on port {port}"})
            return {
                "id": f"{scan_id}-P{port}",
                "scan_id": scan_id,
                "target": target,
                "port": port,
                "service": port_info["service"],
                "risk": port_info["risk"],
                "detail": port_info["detail"],
                "status": "new",
                "template_id": "builtin-tcp",
                "cve_id": "",
                "matched_at": f"{target}:{port}",
                "engine": "builtin_tcp",
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            return None

    tasks = [check_port(port) for port in common_ports]
    results = await asyncio.gather(*tasks)
    findings = [r for r in results if r is not None]
    return findings


async def _run_port_scan(target: str, scan_id: str) -> list[dict]:
    if NMAP_AVAILABLE:
        return await _run_nmap_scan(_clean_host(target), scan_id)
    return await _run_builtin_scan(target, scan_id)


def _merge_findings(primary: list[dict], secondary: list[dict]) -> list[dict]:
    seen_ports = {f.get("port") for f in primary if f.get("port")}
    return primary + [f for f in secondary if not f.get("port") or f.get("port") not in seen_ports]


def _engines_for(scan_type: str) -> list[str]:
    engines = []
    if NUCLEI_AVAILABLE and scan_type in ("full", "quick"):
        engines.append("Nuclei")
    if scan_type in ("full", "ports"):
        engines.append("Nmap" if NMAP_AVAILABLE else "Built-in TCP")
    if not engines:
        engines.append("Built-in TCP")
    return engines


# ── Request Models ────────────────────────────────────────────────────────────

class ScanTarget(BaseModel):
    asset_id: Optional[str] = None
    target: Optional[str] = None
    scan_type: str = "full"  # "full", "ports", "quick"
    engine: Optional[str] = None
    profile: Optional[str] = "standard"


class RawDiagnosticScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=500)
    scan_type: str = "quick"


# ── Core Scan Execution Handler ───────────────────────────────────────────────

@router.post("/run")
@router.post("/scan")
async def trigger_scan(
    req: ScanTarget,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Trigger an authorized, asset-bound external attack-surface scan.

    Enforces:
    1. Global active scanning feature flag
    2. Asset ownership and active status
    3. Approved, non-expired AssetScanAuthorization
    4. Target policy & immediate pre-execution DNS validation
    5. Tenant and global concurrency limits
    """
    if not _is_active_scanning_enabled():
        raise HTTPException(
            status_code=503,
            detail="Active scanning is disabled globally on this Tempris instance.",
        )

    scan_type = req.scan_type or "full"
    if scan_type not in {"full", "ports", "quick"}:
        raise HTTPException(status_code=422, detail="scan_type must be full, ports, or quick")

    tenant_id = get_auth_context(user).tenant_id
    user_email = user.get("sub", "unknown")
    now = datetime.now(timezone.utc)

    # 1. Resolve Asset
    asset: Optional[Asset] = None
    if req.asset_id:
        asset = db.query(Asset).filter(
            Asset.id == req.asset_id,
            Asset.tenant_id == tenant_id,
        ).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {req.asset_id} not found")
    elif req.target:
        # Backward-compatibility fallback: resolve active asset matching target
        cleaned_in = clean_target_input(req.target)
        candidates = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.status == "active",
        ).all()
        matched_candidates = [
            a for a in candidates
            if clean_target_input(a.hostname or "") == cleaned_in or clean_target_input(a.ip_address or "") == cleaned_in
        ]
        if len(matched_candidates) == 1:
            asset = matched_candidates[0]
        elif len(matched_candidates) > 1:
            raise HTTPException(
                status_code=400,
                detail="Target matches multiple assets. Explicit asset_id is required.",
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="No active asset found for the specified target. Register the asset and obtain scan authorization first.",
            )
    else:
        raise HTTPException(status_code=400, detail="asset_id is required to trigger a scan.")

    if asset.status != "active":
        raise HTTPException(
            status_code=400,
            detail=f"Asset {asset.id} is {asset.status}. Only active assets can be scanned.",
        )

    # 2. Verify Approved Scan Authorization
    auth = db.query(AssetScanAuthorization).filter(
        AssetScanAuthorization.tenant_id == tenant_id,
        AssetScanAuthorization.asset_id == asset.id,
        AssetScanAuthorization.status == "approved",
    ).order_by(AssetScanAuthorization.approved_at.desc()).first()

    if not auth:
        raise HTTPException(
            status_code=403,
            detail=f"Asset {asset.id} does not have an approved scan authorization. Request approval first.",
        )

    if auth.expires_at and _ensure_utc(auth.expires_at) < now:
        raise HTTPException(
            status_code=403,
            detail=f"Scan authorization for asset {asset.id} expired at {auth.expires_at.isoformat()}. Re-authorization required.",
        )

    # 3. Server-Derive Target & Validate against Policy
    target_to_scan = auth.authorized_target
    val_res = validate_and_resolve_target(target_to_scan)
    if not val_res.is_valid or not val_res.is_public_scannable:
        raise HTTPException(
            status_code=400,
            detail=f"Target validation failed: {val_res.error}",
        )

    canonical_target = val_res.canonical_target

    # If client also passed target, require exact match with authorized target
    if req.target:
        client_clean = clean_target_input(req.target)
        if client_clean != canonical_target:
            raise HTTPException(
                status_code=400,
                detail=f"Provided target '{req.target}' does not match authorized target '{canonical_target}' for asset {asset.id}",
            )

    # 4. Concurrency and Cooldown Checks
    running_tenant_jobs = db.query(ScanJob).filter(
        ScanJob.tenant_id == tenant_id,
        ScanJob.status.in_(["started", "running"]),
    ).count()
    if running_tenant_jobs >= 2:
        raise HTTPException(
            status_code=429,
            detail="Tenant maximum concurrent scans (2) reached. Please wait for running scans to complete.",
        )

    global_running_jobs = db.query(ScanJob).filter(
        ScanJob.status.in_(["started", "running"]),
    ).count()
    if global_running_jobs >= 5:
        raise HTTPException(
            status_code=429,
            detail="System scanner concurrency limit reached. Please retry in a few moments.",
        )

    cooldown_cutoff = now - timedelta(seconds=30)
    recent_job = db.query(ScanJob).filter(
        ScanJob.tenant_id == tenant_id,
        ScanJob.asset_id == asset.id,
        ScanJob.started_at >= cooldown_cutoff,
    ).first()
    if recent_job and user.get("role") != "Superadmin":
        raise HTTPException(
            status_code=429,
            detail=f"Asset {asset.id} was scanned recently. Please wait 30 seconds between scans of the same asset.",
        )

    # 5. Create ScanJob with Immutable Target Provenance
    scan_id = f"SCAN-{uuid4().hex[:20].upper()}"
    engines_used = _engines_for(scan_type)

    job = ScanJob(
        id=scan_id,
        tenant_id=tenant_id,
        asset_id=asset.id,
        scan_authorization_id=auth.id,
        authorized_canonical_target=canonical_target,
        target_kind=val_res.target_kind,
        resolved_ips=val_res.resolved_ips,
        dns_resolved_at=val_res.dns_resolved_at or now,
        initiating_user_id=user_email,
        execution_origin="tempris_central_vps",
        target=canonical_target,
        normalized_target=normalize_target(canonical_target),
        scan_type=scan_type,
        engines=engines_used,
        status="started",
        started_by=user_email,
        authorization_context={
            "requested_by": user_email,
            "request_ip": request.client.host if request.client else None,
            "authorization_id": auth.id,
            "authorized_target": auth.authorized_target,
        },
    )
    db.add(job)
    record_operational_event(
        db,
        tenant_id=tenant_id,
        event_type="scan.started",
        resource_type="scan_job",
        resource_id=scan_id,
        source_module="SCOUT",
        actor_id=user_email,
        correlation_id=scan_id,
        metadata={
            "target": job.normalized_target,
            "asset_id": asset.id,
            "engines": engines_used,
            "resolved_ips": val_res.resolved_ips,
        },
    )
    db.commit()

    all_findings = []
    try:
        if scan_type == "full":
            if NUCLEI_AVAILABLE:
                nuclei_task = asyncio.create_task(_run_nuclei_scan(canonical_target, scan_id))
                port_task = asyncio.create_task(_run_port_scan(canonical_target, scan_id))
                try:
                    nuclei_results, port_results = await asyncio.gather(nuclei_task, port_task)
                    all_findings = _merge_findings(nuclei_results, port_results)
                except Exception:
                    nuclei_task.cancel()
                    port_task.cancel()
                    await asyncio.gather(nuclei_task, port_task, return_exceptions=True)
                    raise
            else:
                all_findings = await _run_port_scan(canonical_target, scan_id)
        elif scan_type == "ports":
            all_findings = await _run_port_scan(canonical_target, scan_id)
        elif scan_type == "quick":
            if NUCLEI_AVAILABLE:
                all_findings = await _run_nuclei_scan(canonical_target, scan_id)
            else:
                all_findings = await _run_builtin_scan(canonical_target, scan_id)

        # Persist observations and normalize
        normalized = []
        for nf in all_findings:
            normalized.append(normalize_observation(
                db,
                tenant_id=tenant_id,
                scan_job=job,
                observation=nf,
                actor_id=user_email,
            ))
    except ScannerOutputLimitExceeded as exc:
        db.rollback()
        failed_job = db.query(ScanJob).filter(
            ScanJob.id == scan_id,
            ScanJob.tenant_id == tenant_id,
        ).first()
        if failed_job:
            failed_job.status = "failed"
            failed_job.failure_reason = "output_limit_exceeded"
            failed_job.error = "Scanner output exceeded maximum buffer limit (output_limit_exceeded)"
            failed_job.completed_at = datetime.now(timezone.utc)
            record_operational_event(
                db,
                tenant_id=tenant_id,
                event_type="scan.failed",
                resource_type="scan_job",
                resource_id=scan_id,
                source_module="SCOUT",
                actor_id=user_email,
                correlation_id=scan_id,
                metadata={
                    "error_type": "output_limit_exceeded",
                    "stream": exc.stream,
                    "detail": str(exc),
                },
            )
            db.commit()
        logger.warning("SCOUT scan output limit exceeded for scan job %s on %s stream", scan_id, exc.stream)
        raise HTTPException(
            status_code=500,
            detail="Scanner output exceeded maximum buffer limit (output_limit_exceeded)",
        ) from exc
    except asyncio.TimeoutError as exc:
        db.rollback()
        failed_job = db.query(ScanJob).filter(
            ScanJob.id == scan_id,
            ScanJob.tenant_id == tenant_id,
        ).first()
        if failed_job:
            failed_job.status = "failed"
            failed_job.failure_reason = "scanner_timeout"
            failed_job.error = "Scanner execution timed out (scanner_timeout)"
            failed_job.completed_at = datetime.now(timezone.utc)
            record_operational_event(
                db,
                tenant_id=tenant_id,
                event_type="scan.failed",
                resource_type="scan_job",
                resource_id=scan_id,
                source_module="SCOUT",
                actor_id=user_email,
                correlation_id=scan_id,
                metadata={"error_type": "scanner_timeout"},
            )
            db.commit()
        logger.warning("SCOUT scan timed out for scan job %s", scan_id)
        raise HTTPException(status_code=504, detail="Scanner execution timed out (scanner_timeout)") from exc
    except asyncio.CancelledError as exc:
        db.rollback()
        failed_job = db.query(ScanJob).filter(
            ScanJob.id == scan_id,
            ScanJob.tenant_id == tenant_id,
        ).first()
        if failed_job:
            failed_job.status = "failed"
            failed_job.failure_reason = "scanner_cancelled"
            failed_job.error = "Scanner execution was cancelled (scanner_cancelled)"
            failed_job.completed_at = datetime.now(timezone.utc)
            record_operational_event(
                db,
                tenant_id=tenant_id,
                event_type="scan.failed",
                resource_type="scan_job",
                resource_id=scan_id,
                source_module="SCOUT",
                actor_id=user_email,
                correlation_id=scan_id,
                metadata={"error_type": "scanner_cancelled"},
            )
            db.commit()
        logger.warning("SCOUT scan cancelled for scan job %s", scan_id)
        raise
    except Exception as exc:
        db.rollback()
        failed_job = db.query(ScanJob).filter(
            ScanJob.id == scan_id,
            ScanJob.tenant_id == tenant_id,
        ).first()
        if failed_job:
            failed_job.status = "failed"
            failed_job.error = str(exc)[:2000]
            failed_job.failure_reason = "scanner_execution_failed"
            failed_job.completed_at = datetime.now(timezone.utc)
            record_operational_event(
                db,
                tenant_id=tenant_id,
                event_type="scan.failed",
                resource_type="scan_job",
                resource_id=scan_id,
                source_module="SCOUT",
                actor_id=user_email,
                correlation_id=scan_id,
                metadata={"error_type": "scanner_execution_failed", "detail": str(exc)[:500]},
            )
            db.commit()
        logger.exception("SCOUT scan execution failed for scan job %s", scan_id)
        raise HTTPException(status_code=500, detail="Scanner execution failed (scanner_execution_failed)") from exc

    job.status = "completed"
    job.result_count = len(all_findings)
    job.completed_at = datetime.now(timezone.utc)
    record_operational_event(
        db,
        tenant_id=tenant_id,
        event_type="scan.zero_results" if not all_findings else "scan.completed",
        resource_type="scan_job",
        resource_id=scan_id,
        source_module="SCOUT",
        actor_id=user_email,
        correlation_id=scan_id,
        metadata={"result_count": len(all_findings)},
    )
    db.commit()

    try:
        from routers.edip import _publish_sss_event
        _publish_sss_event(tenant_id, {"type": "finding.refresh", "scan_id": scan_id})
    except Exception:
        logger.debug("Finding refresh event could not be published", exc_info=True)

    critical_count = len([f for f in all_findings if f.get("risk") == "Critical"])
    high_count = len([f for f in all_findings if f.get("risk") == "High"])
    client_ip = request.client.host if request.client else None

    append_to_audit_log(AuditEntry(
        user=user_email,
        action="SCOUT_SCAN_COMPLETED",
        module="SCOUT",
        detail=f"Scanned {canonical_target} (Asset {asset.id}) via {', '.join(engines_used)}: "
               f"{len(all_findings)} findings ({critical_count} critical, {high_count} high)",
        ip_address=client_ip,
    ))

    return {
        "status": "success",
        "scan_id": scan_id,
        "asset_id": asset.id,
        "target": canonical_target,
        "target_kind": val_res.target_kind,
        "scan_type": scan_type,
        "engines": engines_used,
        "findings_count": len(all_findings),
        "critical": critical_count,
        "high": high_count,
        "findings": all_findings,
        "normalized_findings": sum(item["finding"] is not None for item in normalized),
        "confirmed_exposures": sum(item["exposure"] == "confirmed" for item in normalized),
        "message": f"Scan completed via {', '.join(engines_used)}. "
                   f"Discovered {len(all_findings)} observations on {canonical_target}."
    }


# ── Superadmin Diagnostic Raw Scan Route ──────────────────────────────────────

@router.post("/admin/raw-scan")
async def raw_diagnostic_scan(
    req: RawDiagnosticScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin")),
):
    """Platform Superadmin diagnostic scan route (disabled by default)."""
    if not _is_raw_diagnostic_enabled():
        raise HTTPException(
            status_code=403,
            detail="Raw diagnostic scanning is disabled. Enable via SCOUT_RAW_DIAGNOSTIC_ENABLED=true in environment.",
        )

    val_res = validate_and_resolve_target(req.target)
    if not val_res.is_valid or not val_res.is_public_scannable:
        raise HTTPException(
            status_code=400,
            detail=f"Target rejected by network safety policy: {val_res.error}",
        )

    scan_id = f"DIAG-{uuid4().hex[:16].upper()}"
    findings = await _run_builtin_scan(val_res.canonical_target, scan_id)
    return {
        "status": "success",
        "scan_id": scan_id,
        "target": val_res.canonical_target,
        "findings_count": len(findings),
        "findings": findings,
    }


# ── Query & History Endpoints ─────────────────────────────────────────────────

@router.get("/findings")
def get_scan_findings(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return all findings generated from scans."""
    tenant_id = get_auth_context(user).tenant_id
    db_findings = db.query(ScanFinding).filter(
        ScanFinding.tenant_id == tenant_id,
    ).order_by(ScanFinding.last_seen_at.desc()).limit(200).all()
    return [{
        "id": f.id, "scan_id": f.scan_id, "target": f.target,
        "port": f.port, "service": f.service, "risk": f.risk,
        "detail": f.detail, "status": f.status,
        "observation_type": "vulnerability_match" if f.normalized_finding_id else "scan_observation",
        "normalized_finding_id": f.normalized_finding_id,
        "asset_id": f.asset_id,
        "discovered_at": f.discovered_at.isoformat() if f.discovered_at else ""
    } for f in db_findings]


@router.get("/findings/summary")
def get_scan_summary(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return exact summary statistics for SCOUT external scans."""
    tenant_id = get_auth_context(user).tenant_id
    all_findings = db.query(ScanFinding).filter(ScanFinding.tenant_id == tenant_id).all()
    jobs = db.query(ScanJob).filter(ScanJob.tenant_id == tenant_id).all()

    # Distinguish service observations from vulnerability observations
    service_obs = len([
        f for f in all_findings
        if (getattr(f, "engine", "") or "").lower() in ("nmap", "builtin_tcp", "builtin")
        or (f.template_id or "").startswith(("nmap", "builtin"))
        or (not getattr(f, "cve_id", None) and not getattr(f, "normalized_finding_id", None) and not (f.template_id or "").startswith("cve-"))
    ])
    vuln_obs = len(all_findings) - service_obs

    # Distinct open tenant Findings with qualifying Nuclei ScanFinding and confirmed same-tenant AssetExposure
    from services.customer_posture import RESOLVED_STATUSES, REFERENCE_STATUSES, NOT_APPLICABLE_STATUSES
    EXCLUDED_STATUSES = set(RESOLVED_STATUSES) | set(REFERENCE_STATUSES) | set(NOT_APPLICABLE_STATUSES)

    confirmed_scan_exposures = (
        db.query(func.count(func.distinct(Finding.id)))
        .join(AssetExposure, (AssetExposure.finding_id == Finding.id) & (AssetExposure.tenant_id == tenant_id))
        .join(Asset, (Asset.id == AssetExposure.asset_id) & (Asset.tenant_id == tenant_id))
        .join(
            ScanFinding,
            (ScanFinding.normalized_finding_id == Finding.id)
            & (ScanFinding.asset_id == AssetExposure.asset_id)
            & (ScanFinding.tenant_id == tenant_id),
        )
        .filter(
            Finding.tenant_id == tenant_id,
            AssetExposure.status == "confirmed",
            Asset.status == "active",
            ~func.lower(func.coalesce(Finding.status, "unmitigated")).in_(list(EXCLUDED_STATUSES)),
            (func.lower(func.coalesce(getattr(ScanFinding, "engine", None), "")) == "nuclei")
            | (ScanFinding.template_id.ilike("cve-%")),
        )
        .scalar()
        or 0
    )

    if not all_findings:
        return {
            "scans": len(jobs),
            "total_observations": 0,
            "total": 0,
            "service_observations": 0,
            "vulnerability_observations": 0,
            "critical_observations": 0,
            "high_observations": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "normalized_findings": 0,
            "confirmed_scan_exposures": 0,
        }

    critical_obs = len([f for f in all_findings if f.risk == "Critical"])
    high_obs = len([f for f in all_findings if f.risk == "High"])

    return {
        "scans": len(jobs),
        "total_observations": len(all_findings),
        "total": len(all_findings),  # backward compatibility alias
        "service_observations": service_obs,
        "vulnerability_observations": vuln_obs,
        "critical_observations": critical_obs,
        "high_observations": high_obs,
        "critical": critical_obs,  # backward compatibility alias
        "high": high_obs,  # backward compatibility alias
        "medium": len([f for f in all_findings if f.risk == "Medium"]),
        "low": len([f for f in all_findings if f.risk == "Low"]),
        "normalized_findings": len({f.normalized_finding_id for f in all_findings if f.normalized_finding_id}),
        "confirmed_scan_exposures": confirmed_scan_exposures,
    }


@router.get("/history")
def get_scan_history(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return scan history grouped by scan_id with full target provenance."""
    tenant_id = get_auth_context(user).tenant_id
    jobs = db.query(ScanJob).filter(
        ScanJob.tenant_id == tenant_id,
    ).order_by(ScanJob.started_at.desc()).limit(20).all()
    return [{
        "scan_id": row.id,
        "asset_id": row.asset_id,
        "target": row.target,
        "authorized_target": row.authorized_canonical_target,
        "target_kind": row.target_kind,
        "resolved_ips": row.resolved_ips or [],
        "started_at": row.started_at.isoformat() if row.started_at else "",
        "completed_at": row.completed_at.isoformat() if row.completed_at else "",
        "status": row.status,
        "engines": row.engines or [],
        "findings_count": row.result_count,
        "error": row.error or row.failure_reason,
    } for row in jobs]


@router.get("/engines")
def get_scan_engines(user = Depends(get_current_user)):
    """Return available scanning engines and system status."""
    engines = []
    active_scanning = _is_active_scanning_enabled()
    if NUCLEI_AVAILABLE:
        engines.append({
            "name": "Nuclei",
            "status": "active" if active_scanning else "disabled_globally",
            "type": "vulnerability",
            "description": "Template-based vulnerability scanner with CVE detection",
        })
    if NMAP_AVAILABLE:
        engines.append({
            "name": "Nmap",
            "status": "active" if active_scanning else "disabled_globally",
            "type": "port_discovery",
            "description": "Network port scanner with service version detection (TCP connect mode)",
        })
    engines.append({
        "name": "Built-in TCP",
        "status": "active" if active_scanning else "disabled_globally",
        "type": "port_check",
        "description": "Lightweight TCP port connectivity checker",
    })
    return {
        "active_scanning_enabled": active_scanning,
        "execution_location": "tempris_central_vps",
        "network_scope": "external_public_only",
        "engines": engines,
    }
