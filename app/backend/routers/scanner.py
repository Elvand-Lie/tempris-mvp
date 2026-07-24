"""
SCOUT Scanner Router — Production Nuclei + Nmap Integration
Provides real vulnerability scanning via Nuclei templates and Nmap port discovery.
Falls back to built-in TCP port scanner if Nuclei is unavailable.
"""
from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
import asyncio
import subprocess
import json
import socket
import shutil
import ipaddress
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from services.database import get_db
from models import ScanFinding

logger = logging.getLogger("tempris.scanner")

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("SCOUT"))])

# ── SSRF Protection: blocked IP ranges ────────────────────────────────────────

def _is_blocked_target(host: str) -> bool:
    """Check if a target is a blocked (internal) IP address."""
    # Strip brackets if IPv6
    clean_host = host.replace("[", "").replace("]", "")
    
    def is_blocked_ip(ip_obj) -> bool:
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            return True
        # Check for IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if getattr(ip_obj, "ipv4_mapped", None):
            mapped = ip_obj.ipv4_mapped
            if mapped.is_private or mapped.is_loopback or mapped.is_link_local:
                return True
        return False

    try:
        raw_ip = ipaddress.ip_address(clean_host)
        if is_blocked_ip(raw_ip):
            return True
    except ValueError:
        pass

    try:
        resolved = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            if is_blocked_ip(ip):
                return True
    except (socket.gaierror, ValueError):
        return True
    return False

def _clean_host(target: str) -> str:
    """Strip protocol and path from target string."""
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    return host

# ── Nuclei Integration ────────────────────────────────────────────────────────

NUCLEI_AVAILABLE = shutil.which("nuclei") is not None
NMAP_AVAILABLE = shutil.which("nmap") is not None

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

async def _run_nuclei_scan(target: str, scan_id: str) -> list[dict]:
    """Run Nuclei vulnerability scanner against a target.
    Uses community templates for CVE detection, misconfigurations, and exposures.
    """
    findings = []
    try:
        cmd = [
            "nuclei",
            "-target", target,
            "-json",               # JSON output for structured parsing
            "-silent",             # Suppress banner
            "-no-color",
            "-timeout", "10",      # Per-request timeout
            "-retries", "1",
            "-rate-limit", "50",   # Requests per second
            "-severity", "critical,high,medium,low",
            "-type", "http",       # Focus on HTTP-based checks
            "-concurrency", "15",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=120  # 2 minute max scan time
        )

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
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        if stderr:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            if err_text:
                logger.warning(f"Nuclei stderr: {err_text[:500]}")

    except asyncio.TimeoutError:
        logger.error(f"Nuclei scan timed out for {target}")
    except Exception as e:
        logger.error(f"Nuclei scan error: {e}")

    return findings

def _extract_port(matched_at: str) -> int:
    """Extract port number from Nuclei matched-at URL."""
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
    """Extract CVE ID from Nuclei info classification."""
    classification = info.get("classification", {})
    cve_ids = classification.get("cve-id", [])
    if isinstance(cve_ids, list) and cve_ids:
        return cve_ids[0]
    if isinstance(cve_ids, str):
        return cve_ids
    return ""

def _build_detail(result: dict, info: dict) -> str:
    """Build a human-readable detail string from Nuclei output."""
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


# ── Nmap Port Discovery ──────────────────────────────────────────────────────

async def _run_nmap_scan(target: str, scan_id: str) -> list[dict]:
    """Run nmap for service/version detection on common ports."""
    findings = []
    try:
        cmd = [
            "nmap", "-sV",          # Service version detection
            "--top-ports", "100",   # Top 100 ports
            "-T4",                  # Aggressive timing
            "--open",               # Only open ports
            "-oX", "-",             # XML output to stdout
            target,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
        output = stdout.decode("utf-8", errors="replace")

        # Parse nmap XML output
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
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                        })
        except ET.ParseError:
            logger.error("Failed to parse nmap XML output")

    except asyncio.TimeoutError:
        logger.error(f"Nmap scan timed out for {target}")
    except Exception as e:
        logger.error(f"Nmap scan error: {e}")

    return findings

DANGEROUS_PORTS = {
    21: "High", 23: "Critical", 25: "Medium", 110: "Medium", 135: "High",
    139: "High", 445: "High", 1433: "Critical", 1521: "Critical",
    3306: "Critical", 3389: "High", 5432: "Critical", 5900: "High",
    6379: "Critical", 8080: "Medium", 9092: "High", 27017: "Critical",
    11211: "Critical",
}

def _assess_port_risk(port: int, service: str) -> str:
    """Assess risk level based on port number and service."""
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
    """Fallback TCP port scanner when Nuclei/Nmap are unavailable."""
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
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            return None

    tasks = [check_port(port) for port in common_ports]
    results = await asyncio.gather(*tasks)
    findings = [r for r in results if r is not None]
    return findings


# ── API Endpoints ─────────────────────────────────────────────────────────────

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


class ScanTarget(BaseModel):
    target: str
    scan_type: str = "full"  # "full" (nuclei+nmap), "ports" (nmap only), "quick" (nuclei fast)

@router.post("/scan")
async def trigger_scan(
    target: ScanTarget,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    """Trigger a vulnerability scan against the target using Nuclei + Nmap.
    
    Scan types:
    - full: Nuclei vulnerability detection + Nmap service discovery (recommended)
    - ports: Nmap port/service scan only
    - quick: Nuclei with fast templates only
    """
    host_clean = _clean_host(target.target)
    if _is_blocked_target(host_clean):
        raise HTTPException(
            status_code=403,
            detail="Scanning internal, private, or link-local IP addresses is prohibited."
        )

    scan_id = f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    user_email = user.get("sub", "unknown")
    all_findings = []

    if target.scan_type == "full":
        if NUCLEI_AVAILABLE:
            nuclei_task = _run_nuclei_scan(target.target, scan_id)
            port_task = _run_port_scan(target.target, scan_id)
            nuclei_results, port_results = await asyncio.gather(nuclei_task, port_task)
            all_findings = _merge_findings(nuclei_results, port_results)
        else:
            all_findings = await _run_port_scan(target.target, scan_id)

    elif target.scan_type == "ports":
        all_findings = await _run_port_scan(target.target, scan_id)

    elif target.scan_type == "quick":
        if NUCLEI_AVAILABLE:
            all_findings = await _run_nuclei_scan(target.target, scan_id)
        else:
            all_findings = await _run_builtin_scan(target.target, scan_id)

    # Persist all findings to DB
    for nf in all_findings:
        db.add(ScanFinding(
            id=nf["id"], scan_id=nf["scan_id"], target=nf["target"],
            port=nf.get("port", 0), service=nf["service"], risk=nf["risk"],
            detail=nf["detail"], status=nf["status"]
        ))
    db.commit()

    # Classify results
    critical_count = len([f for f in all_findings if f["risk"] in ("Critical",)])
    high_count = len([f for f in all_findings if f["risk"] == "High"])

    # Audit log
    client_ip = request.client.host if request.client else None
    engines_used = _engines_for(target.scan_type)

    append_to_audit_log(AuditEntry(
        user=user_email,
        action="SCOUT_SCAN_COMPLETED",
        module="SCOUT",
        detail=f"Scanned {target.target} via {', '.join(engines_used)}: "
               f"{len(all_findings)} findings ({critical_count} critical, {high_count} high)",
        ip_address=client_ip
    ))

    return {
        "status": "success",
        "scan_id": scan_id,
        "target": target.target,
        "scan_type": target.scan_type,
        "engines": engines_used,
        "findings_count": len(all_findings),
        "critical": critical_count,
        "high": high_count,
        "findings": all_findings,
        "message": f"Scan completed via {', '.join(engines_used)}. "
                   f"Discovered {len(all_findings)} findings on {target.target}."
    }


@router.get("/findings")
def get_scan_findings(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return all findings generated from scans."""
    db_findings = db.query(ScanFinding).order_by(ScanFinding.discovered_at.desc()).limit(200).all()
    return [{
        "id": f.id, "scan_id": f.scan_id, "target": f.target,
        "port": f.port, "service": f.service, "risk": f.risk,
        "detail": f.detail, "status": f.status,
        "discovered_at": f.discovered_at.isoformat() if f.discovered_at else ""
    } for f in db_findings]


@router.get("/findings/summary")
def get_scan_summary(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return summary stats of scan findings."""
    all_findings = db.query(ScanFinding).all()
    if not all_findings:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "scans": 0}

    scan_ids = set(f.scan_id for f in all_findings)
    return {
        "total": len(all_findings),
        "critical": len([f for f in all_findings if f.risk == "Critical"]),
        "high": len([f for f in all_findings if f.risk == "High"]),
        "medium": len([f for f in all_findings if f.risk == "Medium"]),
        "low": len([f for f in all_findings if f.risk == "Low"]),
        "scans": len(scan_ids)
    }


@router.get("/history")
def get_scan_history(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Return scan history grouped by scan_id."""
    all_findings = db.query(ScanFinding).order_by(ScanFinding.discovered_at.desc()).all()
    scans = {}
    for f in all_findings:
        if f.scan_id not in scans:
            scans[f.scan_id] = {
                "scan_id": f.scan_id,
                "target": f.target,
                "started_at": f.discovered_at.isoformat() if f.discovered_at else "",
                "findings_count": 0,
                "critical": 0,
                "high": 0,
            }
        scans[f.scan_id]["findings_count"] += 1
        if f.risk == "Critical":
            scans[f.scan_id]["critical"] += 1
        elif f.risk == "High":
            scans[f.scan_id]["high"] += 1

    return list(scans.values())[:20]


@router.get("/engines")
def get_scan_engines(user = Depends(get_current_user)):
    """Return available scanning engines."""
    engines = []
    if NUCLEI_AVAILABLE:
        engines.append({"name": "Nuclei", "status": "active", "type": "vulnerability", "description": "Template-based vulnerability scanner with CVE detection"})
    if NMAP_AVAILABLE:
        engines.append({"name": "Nmap", "status": "active", "type": "port_discovery", "description": "Network port scanner with service version detection"})
    engines.append({"name": "Built-in TCP", "status": "active", "type": "port_check", "description": "Lightweight TCP port connectivity checker"})
    return engines

