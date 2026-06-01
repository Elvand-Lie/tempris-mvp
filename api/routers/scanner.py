from fastapi import APIRouter, Request
from pydantic import BaseModel
from routers.audit import append_to_audit_log, AuditEntry
import asyncio
import socket
from datetime import datetime

router = APIRouter()

# In-memory store for scan-generated findings
scan_findings: list[dict] = []

# Common port → service/risk mapping
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

class ScanTarget(BaseModel):
    target: str

async def check_port(host: str, port: int) -> dict | None:
    try:
        # Strip http:// or https:// for port scanning
        host_clean = host.replace("http://", "").replace("https://", "").split("/")[0]
        if ":" in host_clean:
            host_clean = host_clean.split(":")[0]
            
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host_clean, port), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        
        port_info = PORT_RISK_MAP.get(port, {"service": "Unknown", "risk": "Medium", "detail": f"Unknown service on port {port}"})
        return {"port": port, "state": "open", **port_info}
    except Exception:
        return None

@router.post("/scan")
async def trigger_scan(target: ScanTarget, request: Request):
    """Trigger an active port scan against the target and generate findings."""
    try:
        common_ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 9092, 27017]
        tasks = [check_port(target.target, port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        
        # Generate findings from open ports
        new_findings = []
        scan_id = f"SCAN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        for port_result in open_ports:
            finding_id = f"{scan_id}-P{port_result['port']}"
            finding = {
                "id": finding_id,
                "scan_id": scan_id,
                "target": target.target,
                "port": port_result["port"],
                "service": port_result["service"],
                "risk": port_result["risk"],
                "detail": port_result["detail"],
                "state": "open",
                "status": "new",
                "discovered_at": datetime.utcnow().isoformat(),
            }
            new_findings.append(finding)
        
        # Store findings
        scan_findings.extend(new_findings)
        
        message = f"Scan completed. Discovered {len(open_ports)} open ports on {target.target}."
        
        # Audit log with IP
        client_ip = request.headers.get("X-Real-IP", request.client.host if request.client else None)
        append_to_audit_log(AuditEntry(
            user="System",
            action="SCOUT_SCAN_COMPLETED",
            module="SCOUT",
            detail=f"Scanned {target.target}: {len(open_ports)} open ports, {len([f for f in new_findings if f['risk'] in ('Critical', 'High')])} high/critical findings",
            ip_address=client_ip
        ))
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "findings": len(open_ports),
            "open_ports": open_ports,
            "generated_findings": new_findings,
            "message": message
        }
        
    except Exception as e:
        print(f"Active Scan Error: {e}")
        return {"status": "error", "message": str(e)}

@router.get("/findings")
def get_scan_findings():
    """Return all findings generated from scans."""
    return scan_findings

@router.get("/findings/summary")
def get_scan_summary():
    """Return summary stats of scan findings."""
    if not scan_findings:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "scans": 0}
    
    scan_ids = set(f["scan_id"] for f in scan_findings)
    return {
        "total": len(scan_findings),
        "critical": len([f for f in scan_findings if f["risk"] == "Critical"]),
        "high": len([f for f in scan_findings if f["risk"] == "High"]),
        "medium": len([f for f in scan_findings if f["risk"] == "Medium"]),
        "low": len([f for f in scan_findings if f["risk"] == "Low"]),
        "scans": len(scan_ids)
    }
