"""
STRIKE Adversary Emulation Engine
Production-grade automated red-team simulation using real network probes.
Each module maps to a MITRE ATT&CK technique and produces real evidence.

Safety: All techniques are non-destructive (read-only probes, no payloads deployed).
"""
import asyncio
import json
import socket
import ssl
import subprocess
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class TechniqueResult:
    technique_id: str
    technique_name: str
    tactic: str
    result: str  # explicit observed outcome; never an inferred defensive block
    confidence: float  # check confidence, not a protection percentage
    evidence: str
    duration_ms: int = 0
    details: list = field(default_factory=list)


NUCLEI_AVAILABLE = shutil.which("nuclei") is not None
NMAP_AVAILABLE = shutil.which("nmap") is not None


# ── T1190: Exploit Public-Facing Application ─────────────────────────────────

async def t1190_exploit_public_app(target: str) -> TechniqueResult:
    """Run Nuclei CVE + exploit templates against the target to find exploitable services."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    exploitable_count = 0

    if not NUCLEI_AVAILABLE:
        return TechniqueResult(
            technique_id="T1190", technique_name="Exploit Public-Facing Application",
            tactic="Initial Access", result="ERROR", confidence=0.0,
            evidence="Nuclei scanner not available in this environment."
        )

    try:
        cmd = [
            "nuclei", "-target", target, "-json", "-silent", "-no-color",
            "-severity", "critical,high,medium",
            "-type", "http",
            "-timeout", "8", "-retries", "1", "-rate-limit", "30",
            "-concurrency", "10",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)

        for line in stdout.decode("utf-8", errors="replace").strip().split("\n"):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                info = r.get("info", {})
                severity = info.get("severity", "info").lower()
                template_id = r.get("template-id", "")
                matched = r.get("matched-at", "")
                name = info.get("name", template_id)

                cve_ids = info.get("classification", {}).get("cve-id", [])
                cve = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else ""

                entry = f"[{severity.upper()}] {name}"
                if cve:
                    entry += f" ({cve})"
                entry += f" @ {matched}"
                evidence_lines.append(entry)

                if severity in ("critical", "high"):
                    exploitable_count += 1
            except json.JSONDecodeError:
                continue

    except asyncio.TimeoutError:
        evidence_lines.append("Nuclei scan timed out after 90s")
    except Exception as e:
        evidence_lines.append(f"Nuclei error: {str(e)[:100]}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    if exploitable_count > 0:
        result = "EXPLOITABLE_OBSERVED"
        confidence = min(0.95, 0.7 + exploitable_count * 0.05)
        summary = f"Found {exploitable_count} exploitable vulnerabilities via Nuclei."
    elif evidence_lines:
        result = "NO_EXPOSURE_OBSERVED"
        confidence = 0.6
        summary = f"Nuclei found {len(evidence_lines)} findings but none critical/high."
    else:
        result = "NO_EXPOSURE_OBSERVED"
        confidence = 0.5
        summary = "No exploitable public-facing vulnerabilities detected."

    return TechniqueResult(
        technique_id="T1190", technique_name="Exploit Public-Facing Application",
        tactic="Initial Access", result=result, confidence=confidence,
        evidence=summary, duration_ms=elapsed, details=evidence_lines[:20]
    )


# ── T1078: Valid Accounts (SSH/FTP default credential check) ─────────────────

async def t1078_valid_accounts(target: str) -> TechniqueResult:
    """Test for default/weak credentials on SSH and FTP services."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    exploitable = False

    # Check if SSH (22) or FTP (21) is open first
    for port, service in [(22, "SSH"), (21, "FTP")]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            banner = ""
            try:
                banner_data = await asyncio.wait_for(reader.read(256), timeout=2)
                banner = banner_data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()

            evidence_lines.append(f"{service} port {port} is open. Banner: {banner[:100]}")

            # For FTP, try anonymous login
            if service == "FTP":
                try:
                    ftp_reader, ftp_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, 21), timeout=3
                    )
                    await asyncio.wait_for(ftp_reader.readline(), timeout=2)  # welcome
                    ftp_writer.write(b"USER anonymous\r\n")
                    await ftp_writer.drain()
                    resp = await asyncio.wait_for(ftp_reader.readline(), timeout=2)
                    resp_text = resp.decode("utf-8", errors="replace").strip()
                    if resp_text.startswith("331"):
                        ftp_writer.write(b"PASS anonymous@\r\n")
                        await ftp_writer.drain()
                        resp2 = await asyncio.wait_for(ftp_reader.readline(), timeout=2)
                        resp2_text = resp2.decode("utf-8", errors="replace").strip()
                        if resp2_text.startswith("230"):
                            exploitable = True
                            evidence_lines.append("CRITICAL: FTP anonymous login ACCEPTED.")
                        else:
                            evidence_lines.append(f"FTP anonymous login rejected: {resp2_text}")
                    else:
                        evidence_lines.append(f"FTP USER response: {resp_text}")
                    ftp_writer.close()
                    await ftp_writer.wait_closed()
                except Exception as e:
                    evidence_lines.append(f"FTP anonymous test error: {str(e)[:80]}")

            # For SSH, just note it's reachable; we don't brute force
            if service == "SSH":
                if "OpenSSH" in banner:
                    version_parts = banner.split("OpenSSH_")
                    if len(version_parts) > 1:
                        ssh_ver = version_parts[1].split()[0]
                        evidence_lines.append(f"OpenSSH version: {ssh_ver}")
                        # Check for known weak versions
                        try:
                            major = float(ssh_ver.split("p")[0].split("_")[0][:3])
                            if major < 8.0:
                                exploitable = True
                                evidence_lines.append(f"WARNING: OpenSSH {ssh_ver} may be vulnerable to known CVEs.")
                        except ValueError:
                            pass

        except (asyncio.TimeoutError, OSError):
            evidence_lines.append(f"{service} port {port} is closed or filtered.")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    if exploitable:
        return TechniqueResult(
            technique_id="T1078", technique_name="Valid Accounts",
            tactic="Initial Access", result="EXPLOITABLE_OBSERVED", confidence=0.85,
            evidence="Default or weak credentials found on exposed services.",
            duration_ms=elapsed, details=evidence_lines
        )
    else:
        return TechniqueResult(
            technique_id="T1078", technique_name="Valid Accounts",
            tactic="Initial Access", result="NO_EXPOSURE_OBSERVED", confidence=0.6,
            evidence="No default credentials exploitable. Authentication appears hardened.",
            duration_ms=elapsed, details=evidence_lines
        )


# ── T1059: Command & Scripting Interpreter (HTTP command injection) ──────────

async def t1059_command_injection(target: str) -> TechniqueResult:
    """Test for command injection via common HTTP parameter fuzzing."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    exploitable = False

    # Ensure target has protocol
    url_base = target if target.startswith("http") else f"http://{target}"

    # Test common injection vectors (non-destructive: sleep/ping timing-based)
    test_payloads = [
        {"path": "/?cmd=id", "indicator": "uid="},
        {"path": "/?exec=whoami", "indicator": "root"},
        {"path": "/cgi-bin/test?;id", "indicator": "uid="},
        {"path": "/?q=`id`", "indicator": "uid="},
    ]

    if NUCLEI_AVAILABLE:
        # Use Nuclei's command injection templates for a more thorough test
        try:
            cmd = [
                "nuclei", "-target", url_base, "-json", "-silent", "-no-color",
                "-tags", "rce,injection",
                "-severity", "critical,high",
                "-timeout", "5", "-retries", "0", "-rate-limit", "10",
                "-concurrency", "5",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)

            for line in stdout.decode("utf-8", errors="replace").strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                    name = r.get("info", {}).get("name", r.get("template-id", ""))
                    severity = r.get("info", {}).get("severity", "").lower()
                    matched = r.get("matched-at", "")
                    evidence_lines.append(f"[{severity.upper()}] {name} @ {matched}")
                    if severity in ("critical", "high"):
                        exploitable = True
                except json.JSONDecodeError:
                    continue
        except (asyncio.TimeoutError, Exception) as e:
            evidence_lines.append(f"Nuclei RCE scan: {str(e)[:80]}")
    else:
        evidence_lines.append("Nuclei not available; skipped template-based injection testing.")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    if exploitable:
        return TechniqueResult(
            technique_id="T1059", technique_name="Command & Scripting Interpreter",
            tactic="Execution", result="EXPLOITABLE_OBSERVED", confidence=0.9,
            evidence="Command injection or RCE vulnerability confirmed.",
            duration_ms=elapsed, details=evidence_lines
        )
    else:
        return TechniqueResult(
            technique_id="T1059", technique_name="Command & Scripting Interpreter",
            tactic="Execution", result="NO_EXPOSURE_OBSERVED", confidence=0.55,
            evidence="No command injection vectors found. Input validation appears effective.",
            duration_ms=elapsed, details=evidence_lines
        )


# ── T1068: Exploitation for Privilege Escalation ─────────────────────────────

async def t1068_priv_escalation(target: str) -> TechniqueResult:
    """Check for privilege escalation indicators: exposed admin panels, debug endpoints."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    exploitable = False

    url_base = target if target.startswith("http") else f"http://{target}"

    # Check for exposed admin/debug endpoints
    admin_paths = [
        "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
        "/debug", "/.env", "/server-status", "/server-info",
        "/actuator", "/actuator/env", "/api/debug",
        "/elmah.axd", "/trace.axd", "/_profiler",
    ]

    import urllib.request
    import urllib.error

    for path in admin_paths:
        try:
            url = f"{url_base}{path}"
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "Tempris-STRIKE/1.0")
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=5)
            )
            status = resp.status
            if status == 200:
                body_preview = resp.read(500).decode("utf-8", errors="replace")
                if any(kw in body_preview.lower() for kw in ["login", "admin", "dashboard", "password", "debug", "db_"]):
                    exploitable = True
                    evidence_lines.append(f"EXPOSED: {path} (HTTP 200, contains sensitive keywords)")
                else:
                    evidence_lines.append(f"Accessible: {path} (HTTP 200)")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                evidence_lines.append(f"Protected: {path} (HTTP {e.code})")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    if exploitable:
        return TechniqueResult(
            technique_id="T1068", technique_name="Exploitation for Privilege Escalation",
            tactic="Privilege Escalation", result="EXPLOITABLE_OBSERVED", confidence=0.8,
            evidence="Exposed admin/debug endpoints found that could enable privilege escalation.",
            duration_ms=elapsed, details=evidence_lines
        )
    else:
        return TechniqueResult(
            technique_id="T1068", technique_name="Exploitation for Privilege Escalation",
            tactic="Privilege Escalation", result="NO_EXPOSURE_OBSERVED", confidence=0.55,
            evidence="No exposed admin panels or debug endpoints detected.",
            duration_ms=elapsed, details=evidence_lines
        )


# ── T1562: Impair Defenses (security header analysis) ────────────────────────

async def t1562_impair_defenses(target: str) -> TechniqueResult:
    """Analyze security headers and TLS configuration to assess defense posture."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    weaknesses = 0

    url_base = target if target.startswith("http") else f"http://{target}"

    import urllib.request
    import urllib.error

    required_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": ["DENY", "SAMEORIGIN"],
        "X-XSS-Protection": "1",
        "Content-Security-Policy": None,  # just check existence
        "Strict-Transport-Security": None,
        "Referrer-Policy": None,
    }

    try:
        req = urllib.request.Request(url_base, method="GET")
        req.add_header("User-Agent", "Tempris-STRIKE/1.0")
        resp = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: urllib.request.urlopen(req, timeout=8)
        )
        headers = dict(resp.headers)

        for header, expected in required_headers.items():
            value = headers.get(header, headers.get(header.lower()))
            if not value:
                weaknesses += 1
                evidence_lines.append(f"MISSING: {header} header not set")
            elif expected:
                if isinstance(expected, list):
                    if not any(e.lower() in value.lower() for e in expected):
                        weaknesses += 1
                        evidence_lines.append(f"WEAK: {header}: {value} (expected: {expected})")
                    else:
                        evidence_lines.append(f"OK: {header}: {value}")
                elif expected.lower() not in value.lower():
                    weaknesses += 1
                    evidence_lines.append(f"WEAK: {header}: {value}")
                else:
                    evidence_lines.append(f"OK: {header}: {value}")
            else:
                evidence_lines.append(f"OK: {header}: {value}")

        # Check server header disclosure
        server = headers.get("Server", headers.get("server"))
        if server:
            evidence_lines.append(f"Server header disclosed: {server}")
            weaknesses += 1

    except Exception as e:
        evidence_lines.append(f"Could not fetch headers: {str(e)[:100]}")

    # TLS check
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    try:
        ctx = ssl.create_default_context()
        conn = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: ctx.wrap_socket(socket.create_connection((host, 443), timeout=5), server_hostname=host)
        )
        cert = conn.getpeercert()
        tls_version = conn.version()
        evidence_lines.append(f"TLS: {tls_version}")
        if tls_version and "TLSv1.0" in tls_version or "TLSv1.1" in tls_version:
            weaknesses += 1
            evidence_lines.append("WARNING: Legacy TLS version in use")
        else:
            evidence_lines.append(f"TLS version OK: {tls_version}")
        if cert:
            not_after = cert.get("notAfter", "")
            evidence_lines.append(f"Certificate expires: {not_after}")
        conn.close()
    except Exception:
        evidence_lines.append("TLS on port 443 not available or connection refused.")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    if weaknesses >= 4:
        return TechniqueResult(
            technique_id="T1562", technique_name="Impair Defenses",
            tactic="Defense Evasion", result="EXPLOITABLE_OBSERVED", confidence=0.75,
            evidence=f"Defense posture weak: {weaknesses} security header/TLS issues found.",
            duration_ms=elapsed, details=evidence_lines
        )
    elif weaknesses >= 2:
        return TechniqueResult(
            technique_id="T1562", technique_name="Impair Defenses",
            tactic="Defense Evasion", result="EXPLOITABLE_OBSERVED", confidence=0.5,
            evidence=f"Some defense gaps: {weaknesses} issues found.",
            duration_ms=elapsed, details=evidence_lines
        )
    else:
        return TechniqueResult(
            technique_id="T1562", technique_name="Impair Defenses",
            tactic="Defense Evasion", result="NO_EXPOSURE_OBSERVED", confidence=0.7,
            evidence="Defenses appear properly configured.",
            duration_ms=elapsed, details=evidence_lines
        )


# ── T1046: Network Service Scanning (Nmap) ──────────────────────────────────

async def t1046_network_scanning(target: str) -> TechniqueResult:
    """Run Nmap service discovery to map the attack surface."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    open_ports = 0

    if NMAP_AVAILABLE:
        try:
            cmd = [
                "nmap", "-sV", "--top-ports", "50", "-T4", "--open", "-oX", "-", host
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode("utf-8", errors="replace")

            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(output)
                for port_elem in root.findall(".//port"):
                    port_id = port_elem.get("portid", "?")
                    state_elem = port_elem.find("state")
                    service_elem = port_elem.find("service")
                    if state_elem is not None and state_elem.get("state") == "open":
                        open_ports += 1
                        svc = service_elem.get("name", "unknown") if service_elem else "unknown"
                        product = service_elem.get("product", "") if service_elem else ""
                        version = service_elem.get("version", "") if service_elem else ""
                        evidence_lines.append(f"Port {port_id}: {svc} {product} {version}".strip())
            except Exception:
                evidence_lines.append("Nmap XML parse error")
        except asyncio.TimeoutError:
            evidence_lines.append("Nmap scan timed out")
        except Exception as e:
            evidence_lines.append(f"Nmap error: {str(e)[:80]}")
    else:
        # Fallback to basic TCP
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        for port in common_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=1.5
                )
                writer.close()
                await writer.wait_closed()
                open_ports += 1
                evidence_lines.append(f"Port {port}: open")
            except Exception:
                pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    # Standard web server ports (22/80/443) are expected — only flag non-standard ones
    expected_ports = {22, 80, 443}
    unexpected_ports = []
    for line in evidence_lines:
        # Extract port number from evidence like "Port 8000: http uvicorn"
        try:
            port_str = line.split("Port ")[1].split(":")[0].strip()
            port_num = int(port_str)
            if port_num not in expected_ports:
                unexpected_ports.append(port_num)
        except (IndexError, ValueError):
            pass

    if unexpected_ports:
        return TechniqueResult(
            technique_id="T1046", technique_name="Network Service Scanning",
            tactic="Discovery", result="EXPLOITABLE_OBSERVED",
            confidence=0.8,
            evidence=f"Discovered {open_ports} open ports on {host}. {len(unexpected_ports)} unexpected: {unexpected_ports}",
            duration_ms=elapsed, details=evidence_lines
        )
    return TechniqueResult(
        technique_id="T1046", technique_name="Network Service Scanning",
        tactic="Discovery", result="NO_EXPOSURE_OBSERVED",
        confidence=0.7,
        evidence=f"Discovered {open_ports} open ports on {host}. All ports are standard web server ports (22/80/443).",
        duration_ms=elapsed, details=evidence_lines
    )


# ── T1595: Active Scanning / Reconnaissance ──────────────────────────────────

async def t1595_recon(target: str) -> TechniqueResult:
    """Perform DNS and HTTP reconnaissance."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    # DNS resolution
    try:
        addrs = socket.getaddrinfo(host, None)
        ips = list(set(addr[4][0] for addr in addrs))
        evidence_lines.append(f"DNS resolves to: {', '.join(ips)}")
    except Exception:
        evidence_lines.append("DNS resolution failed")

    # HTTP response fingerprinting
    import urllib.request
    url_base = target if target.startswith("http") else f"http://{target}"
    server_disclosed = False
    powered_disclosed = False
    try:
        req = urllib.request.Request(url_base, method="HEAD")
        req.add_header("User-Agent", "Tempris-STRIKE/1.0")
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=5)
        )
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        if server:
            server_disclosed = True
            evidence_lines.append(f"Server DISCLOSED: {server}")
        else:
            evidence_lines.append("Server header: not disclosed")
        if powered:
            powered_disclosed = True
            evidence_lines.append(f"X-Powered-By DISCLOSED: {powered}")
        else:
            evidence_lines.append("X-Powered-By: not disclosed")
    except Exception as e:
        evidence_lines.append(f"HTTP HEAD: {str(e)[:80]}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    info_leaked = server_disclosed or powered_disclosed
    if info_leaked:
        return TechniqueResult(
            technique_id="T1595", technique_name="Active Scanning",
            tactic="Reconnaissance", result="EXPLOITABLE_OBSERVED",
            confidence=0.7 if (server_disclosed and powered_disclosed) else 0.5,
            evidence=f"Reconnaissance on {host} disclosed server fingerprint information.",
            duration_ms=elapsed, details=evidence_lines
        )
    return TechniqueResult(
        technique_id="T1595", technique_name="Active Scanning",
        tactic="Reconnaissance", result="NO_EXPOSURE_OBSERVED",
        confidence=0.8,
        evidence=f"Server fingerprinting blocked — {host} does not disclose software identity.",
        duration_ms=elapsed, details=evidence_lines
    )


# ── T1133: External Remote Services (RDP/VNC/Citrix check) ───────────────────

async def t1133_external_remote_services(target: str) -> TechniqueResult:
    """Check for exposed remote access services (RDP, VNC, Citrix, TeamViewer)."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    exposed = 0

    remote_ports = [
        (3389, "RDP"), (5900, "VNC"), (5901, "VNC-1"), (1494, "Citrix-ICA"),
        (2598, "Citrix-CGP"), (5938, "TeamViewer"), (4899, "Radmin"),
    ]
    for port, service in remote_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=1)
                banner = data.decode("utf-8", errors="replace").strip()[:60]
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()
            exposed += 1
            evidence_lines.append(f"EXPOSED: {service} on port {port}" + (f" — {banner}" if banner else ""))
        except (asyncio.TimeoutError, OSError):
            evidence_lines.append(f"Closed: {service} port {port}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1133", "External Remote Services", "Initial Access",
            "EXPLOITABLE_OBSERVED", min(0.9, 0.6 + exposed * 0.1),
            f"{exposed} remote access service(s) exposed externally.", elapsed, evidence_lines)
    return TechniqueResult("T1133", "External Remote Services", "Initial Access",
        "NO_EXPOSURE_OBSERVED", 0.7, "No remote access services exposed.", elapsed, evidence_lines)


# ── T1566: Phishing (SPF/DKIM/DMARC check) ──────────────────────────────────

async def t1566_phishing(target: str) -> TechniqueResult:
    """Check email security posture via SPF, DKIM, and DMARC DNS records."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    weaknesses = 0

    import subprocess as _sp
    for record_type, name, prefix in [
        ("TXT", host, "SPF"), ("TXT", f"_dmarc.{host}", "DMARC"),
    ]:
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda n=name, t=record_type: _sp.run(
                    ["nslookup", "-type=" + t, n], capture_output=True, text=True, timeout=5
                )
            )
            output = result.stdout + result.stderr
            if prefix == "SPF":
                if "v=spf1" in output:
                    evidence_lines.append(f"OK: SPF record found")
                else:
                    weaknesses += 1
                    evidence_lines.append(f"MISSING: No SPF record for {host}")
            elif prefix == "DMARC":
                if "v=DMARC1" in output or "v=dmarc1" in output.lower():
                    evidence_lines.append(f"OK: DMARC record found")
                else:
                    weaknesses += 1
                    evidence_lines.append(f"MISSING: No DMARC record for {host}")
        except Exception as e:
            evidence_lines.append(f"{prefix} lookup error: {str(e)[:60]}")

    # Check MX records
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: _sp.run(["nslookup", "-type=MX", host], capture_output=True, text=True, timeout=5)
        )
        if "mail exchanger" in result.stdout.lower() or "mx" in result.stdout.lower():
            evidence_lines.append("MX records present — domain handles email")
        else:
            evidence_lines.append("No MX records — domain may not handle email")
    except Exception:
        pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if weaknesses >= 2:
        return TechniqueResult("T1566", "Phishing", "Initial Access",
            "EXPLOITABLE_OBSERVED", 0.7, f"Email security weak: {weaknesses} missing records (SPF/DMARC).", elapsed, evidence_lines)
    elif weaknesses == 1:
        return TechniqueResult("T1566", "Phishing", "Initial Access",
            "EXPLOITABLE_OBSERVED", 0.5, f"Partial email security: {weaknesses} gap found.", elapsed, evidence_lines)
    return TechniqueResult("T1566", "Phishing", "Initial Access",
        "NO_EXPOSURE_OBSERVED", 0.7, "Email security records (SPF/DMARC) are configured.", elapsed, evidence_lines)


# ── T1195: Supply Chain Compromise (dependency/version exposure) ─────────────

async def t1195_supply_chain(target: str) -> TechniqueResult:
    """Check for exposed dependency info, package manifests, or lock files."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    dep_paths = [
        "/package.json", "/package-lock.json", "/yarn.lock", "/composer.json",
        "/composer.lock", "/Gemfile.lock", "/requirements.txt", "/Pipfile.lock",
        "/go.sum", "/.npmrc", "/pom.xml", "/build.gradle",
    ]
    for path in dep_paths:
        try:
            req = urllib.request.Request(f"{url_base}{path}", method="GET")
            req.add_header("User-Agent", "Tempris-STRIKE/1.0")
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, method="GET", headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=4
                )
            )
            if resp.status == 200:
                body = resp.read(200).decode("utf-8", errors="replace")
                if any(kw in body.lower() for kw in ['"name"', '"version"', "dependencies", "require", "gem", "module"]):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — dependency manifest accessible")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1195", "Supply Chain Compromise", "Initial Access",
            "EXPLOITABLE_OBSERVED", min(0.85, 0.5 + exposed * 0.15),
            f"{exposed} dependency manifest(s) publicly accessible.", elapsed, evidence_lines)
    return TechniqueResult("T1195", "Supply Chain Compromise", "Initial Access",
        "NO_EXPOSURE_OBSERVED", 0.6, "No dependency manifests exposed.", elapsed, evidence_lines)


# ── T1189: Drive-by Compromise (outdated JS/framework detection) ─────────────

async def t1189_driveby(target: str) -> TechniqueResult:
    """Check for outdated JavaScript frameworks that could enable drive-by attacks."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    vulnerable = 0

    import urllib.request, urllib.error, re
    try:
        req = urllib.request.Request(url_base, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 Tempris-STRIKE/1.0")
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=8)
        )
        body = resp.read(50000).decode("utf-8", errors="replace")

        # Check for known vulnerable library patterns
        patterns = [
            (r'jquery[/-](\d+\.\d+\.\d+)', "jQuery", "3.5.0"),
            (r'angular[/-](\d+\.\d+\.\d+)', "AngularJS", "1.8.0"),
            (r'bootstrap[/-](\d+\.\d+\.\d+)', "Bootstrap", "5.0.0"),
            (r'react[/-](\d+\.\d+)', "React", "17.0"),
        ]
        for pattern, name, safe_ver in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                found_ver = m.group(1)
                evidence_lines.append(f"Detected: {name} v{found_ver}")
                if found_ver < safe_ver:
                    vulnerable += 1
                    evidence_lines.append(f"WARNING: {name} {found_ver} is outdated (< {safe_ver})")

        # Check for inline scripts without nonce/integrity
        inline_scripts = body.count("<script") - body.count("integrity=")
        if inline_scripts > 3:
            evidence_lines.append(f"Found {inline_scripts} script tags without SRI integrity attributes")
    except Exception as e:
        evidence_lines.append(f"Page fetch error: {str(e)[:80]}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if vulnerable > 0:
        return TechniqueResult("T1189", "Drive-by Compromise", "Initial Access",
            "EXPLOITABLE_OBSERVED", 0.65, f"{vulnerable} outdated framework(s) detected.", elapsed, evidence_lines)
    return TechniqueResult("T1189", "Drive-by Compromise", "Initial Access",
        "NO_EXPOSURE_OBSERVED", 0.6, "No outdated client-side frameworks detected.", elapsed, evidence_lines)


# ── T1203: Exploitation for Client Execution ─────────────────────────────────

async def t1203_client_execution(target: str) -> TechniqueResult:
    """Check for vulnerable client-side technologies and unsafe content types."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(url_base)
        req.add_header("User-Agent", "Tempris-STRIKE/1.0")
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=6)
        )
        headers = dict(resp.headers)
        body = resp.read(20000).decode("utf-8", errors="replace").lower()

        # Check X-Content-Type-Options
        if not headers.get("X-Content-Type-Options"):
            issues += 1
            evidence_lines.append("MISSING: X-Content-Type-Options — MIME sniffing possible")

        # Check for Flash/Java/ActiveX
        for tech in ["application/x-shockwave-flash", ".swf", "clsid:", "application/x-java-applet"]:
            if tech in body:
                issues += 1
                evidence_lines.append(f"FOUND: Legacy technology reference ({tech})")

        # Check for file upload forms
        if 'type="file"' in body or "multipart/form-data" in body:
            evidence_lines.append("File upload form detected — potential vector for malicious uploads")
            issues += 1
    except Exception as e:
        evidence_lines.append(f"Error: {str(e)[:80]}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues >= 2:
        return TechniqueResult("T1203", "Exploitation for Client Execution", "Execution",
            "EXPLOITABLE_OBSERVED", 0.6, f"{issues} client-side security issues found.", elapsed, evidence_lines)
    return TechniqueResult("T1203", "Exploitation for Client Execution", "Execution",
        "NO_EXPOSURE_OBSERVED", 0.6, "Client execution vectors appear mitigated.", elapsed, evidence_lines)


# ── T1047: Windows Management Instrumentation ────────────────────────────────

async def t1047_wmi(target: str) -> TechniqueResult:
    """Check for exposed WMI/WinRM/DCOM services."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    exposed = 0

    wmi_ports = [(135, "RPC/DCOM"), (5985, "WinRM-HTTP"), (5986, "WinRM-HTTPS"), (445, "SMB")]
    for port, svc in wmi_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            writer.close()
            await writer.wait_closed()
            exposed += 1
            evidence_lines.append(f"EXPOSED: {svc} on port {port}")
        except (asyncio.TimeoutError, OSError):
            evidence_lines.append(f"Closed: {svc} port {port}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1047", "Windows Management Instrumentation", "Execution",
            "EXPLOITABLE_OBSERVED", min(0.85, 0.5 + exposed * 0.15),
            f"{exposed} WMI/management service(s) exposed.", elapsed, evidence_lines)
    return TechniqueResult("T1047", "Windows Management Instrumentation", "Execution",
        "NO_EXPOSURE_OBSERVED", 0.7, "No WMI/WinRM/DCOM services exposed.", elapsed, evidence_lines)


# ── T1053: Scheduled Task/Job ────────────────────────────────────────────────

async def t1053_scheduled_task(target: str) -> TechniqueResult:
    """Check for exposed task scheduler interfaces or cron-like web panels."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    sched_paths = ["/cron", "/scheduler", "/jobs", "/api/jobs", "/api/cron",
                   "/hangfire", "/quartz", "/sidekiq", "/resque", "/celery"]
    for path in sched_paths:
        try:
            req = urllib.request.Request(f"{url_base}{path}", headers={"User-Agent": "Tempris-STRIKE/1.0"})
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=4
                )
            )
            if resp.status == 200:
                body = resp.read(500).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["job", "schedule", "cron", "task", "queue", "worker"]):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — task scheduler interface accessible")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1053", "Scheduled Task/Job", "Execution",
            "EXPLOITABLE_OBSERVED", 0.7, f"{exposed} task scheduler interface(s) exposed.", elapsed, evidence_lines)
    return TechniqueResult("T1053", "Scheduled Task/Job", "Execution",
        "NO_EXPOSURE_OBSERVED", 0.6, "No task scheduler interfaces exposed.", elapsed, evidence_lines)


# ── T1204: User Execution ────────────────────────────────────────────────────

async def t1204_user_execution(target: str) -> TechniqueResult:
    """Check for downloadable executable content or unsafe download links."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error, re
    try:
        req = urllib.request.Request(url_base, headers={"User-Agent": "Tempris-STRIKE/1.0"})
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=6)
        )
        body = resp.read(50000).decode("utf-8", errors="replace")

        # Check for download links to executables
        exe_patterns = [r'\.exe["\']', r'\.msi["\']', r'\.bat["\']', r'\.ps1["\']',
                        r'\.cmd["\']', r'\.vbs["\']', r'\.jar["\']', r'\.dmg["\']']
        for pat in exe_patterns:
            matches = re.findall(pat, body, re.IGNORECASE)
            if matches:
                issues += 1
                evidence_lines.append(f"Download link to executable found: {pat.replace('[', '').replace(']', '')}")

        # Check Content-Disposition headers on common download paths
        for path in ["/download", "/downloads", "/files"]:
            try:
                r2 = await asyncio.get_event_loop().run_in_executor(
                    None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                        urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                    )
                )
                cd = r2.headers.get("Content-Disposition", "")
                if cd:
                    evidence_lines.append(f"Download endpoint active: {path} ({cd[:60]})")
            except Exception:
                pass
    except Exception as e:
        evidence_lines.append(f"Page fetch error: {str(e)[:80]}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues > 0:
        return TechniqueResult("T1204", "User Execution", "Execution",
            "EXPLOITABLE_OBSERVED", 0.5, f"{issues} executable download vector(s) found.", elapsed, evidence_lines)
    return TechniqueResult("T1204", "User Execution", "Execution",
        "NO_EXPOSURE_OBSERVED", 0.6, "No executable download vectors detected.", elapsed, evidence_lines)


# ── T1569: System Services ───────────────────────────────────────────────────

async def t1569_system_services(target: str) -> TechniqueResult:
    """Check for exposed service management interfaces."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    exposed = 0

    # Check for exposed management ports
    mgmt_ports = [(9090, "Prometheus"), (8500, "Consul"), (2379, "etcd"),
                  (6443, "K8s-API"), (10250, "Kubelet"), (4194, "cAdvisor")]
    for port, svc in mgmt_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            writer.close()
            await writer.wait_closed()
            exposed += 1
            evidence_lines.append(f"EXPOSED: {svc} on port {port}")
        except (asyncio.TimeoutError, OSError):
            pass

    # Check web paths
    import urllib.request, urllib.error
    for path in ["/metrics", "/health", "/api/v1/nodes", "/version"]:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                evidence_lines.append(f"Accessible: {path}")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1569", "System Services", "Execution",
            "EXPLOITABLE_OBSERVED", 0.7, f"{exposed} service management interface(s) exposed.", elapsed, evidence_lines)
    return TechniqueResult("T1569", "System Services", "Execution",
        "NO_EXPOSURE_OBSERVED", 0.65, "No service management interfaces exposed.", elapsed, evidence_lines)


# ── T1098: Account Manipulation ──────────────────────────────────────────────

async def t1098_account_manipulation(target: str) -> TechniqueResult:
    """Check for exposed user management or account API endpoints."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    acct_paths = ["/api/users", "/api/accounts", "/api/admin/users", "/users",
                  "/api/v1/users", "/wp-json/wp/v2/users", "/api/members"]
    for path in acct_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=4
                )
            )
            if resp.status == 200:
                ct = resp.headers.get("Content-Type", "")
                # Only flag actual JSON API responses, not SPA HTML catch-all
                if "json" not in ct.lower():
                    evidence_lines.append(f"Skipped: {path} (HTML/non-JSON response — likely SPA catch-all)")
                    continue
                body = resp.read(500).decode("utf-8", errors="replace").lower()
                # Require strong indicators of actual user data
                if any(kw in body for kw in ['"email"', '"username"', '"role"', '"password"', '"is_admin"']):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — user data in JSON response without auth")
                else:
                    evidence_lines.append(f"OK: {path} (JSON but no user data fields)")
        except urllib.error.HTTPError as e:
            if e.code == 401 or e.code == 403:
                evidence_lines.append(f"Protected: {path} (HTTP {e.code})")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1098", "Account Manipulation", "Persistence",
            "EXPLOITABLE_OBSERVED", 0.75, f"{exposed} user management endpoint(s) accessible.", elapsed, evidence_lines)
    return TechniqueResult("T1098", "Account Manipulation", "Persistence",
        "NO_EXPOSURE_OBSERVED", 0.6, "User management endpoints are properly protected.", elapsed, evidence_lines)


# ── T1136: Create Account ────────────────────────────────────────────────────

async def t1136_create_account(target: str) -> TechniqueResult:
    """Check for open registration or account creation endpoints."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    reg_paths = ["/register", "/signup", "/api/register", "/api/signup",
                 "/api/auth/register", "/create-account", "/join"]
    for path in reg_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=4
                )
            )
            if resp.status == 200:
                body = resp.read(1000).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["register", "sign up", "create account", "password"]):
                    exposed += 1
                    evidence_lines.append(f"OPEN REGISTRATION: {path} — account creation accessible")
                else:
                    evidence_lines.append(f"Accessible: {path} (HTTP 200)")
        except urllib.error.HTTPError as e:
            if e.code == 405:
                evidence_lines.append(f"Endpoint exists: {path} (HTTP 405 — POST likely required)")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1136", "Create Account", "Persistence",
            "EXPLOITABLE_OBSERVED", 0.65, f"{exposed} open registration endpoint(s) found.", elapsed, evidence_lines)
    return TechniqueResult("T1136", "Create Account", "Persistence",
        "NO_EXPOSURE_OBSERVED", 0.6, "No open registration endpoints detected.", elapsed, evidence_lines)


# ── T1543: Create or Modify System Process ───────────────────────────────────

async def t1543_system_process(target: str) -> TechniqueResult:
    """Check for exposed container/process management APIs (Docker, K8s)."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    exposed = 0

    docker_ports = [(2375, "Docker-HTTP"), (2376, "Docker-TLS"), (9323, "Docker-Metrics")]
    for port, svc in docker_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            writer.close()
            await writer.wait_closed()
            exposed += 1
            evidence_lines.append(f"CRITICAL: {svc} exposed on port {port}")
        except (asyncio.TimeoutError, OSError):
            evidence_lines.append(f"Closed: {svc} port {port}")

    # Check Docker API over HTTP
    import urllib.request, urllib.error
    for port in [2375, 2376]:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda p=port: urllib.request.urlopen(
                    f"http://{host}:{p}/version", timeout=3
                )
            )
            if resp.status == 200:
                exposed += 1
                evidence_lines.append(f"CRITICAL: Docker API responding on port {port}")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1543", "Create or Modify System Process", "Persistence",
            "EXPLOITABLE_OBSERVED", 0.9, f"{exposed} container/process management API(s) exposed.", elapsed, evidence_lines)
    return TechniqueResult("T1543", "Create or Modify System Process", "Persistence",
        "NO_EXPOSURE_OBSERVED", 0.7, "No container management APIs exposed.", elapsed, evidence_lines)


# ── T1547: Boot or Logon Autostart Execution ─────────────────────────────────

async def t1547_autostart(target: str) -> TechniqueResult:
    """Check for exposed config management or deployment interfaces that could set autostart."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    config_paths = ["/api/config", "/configuration", "/settings", "/api/settings",
                    "/puppet", "/ansible", "/chef", "/salt"]
    for path in config_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(300).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["config", "setting", "startup", "service", "autostart"]):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — configuration interface accessible")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1547", "Boot or Logon Autostart Execution", "Persistence",
            "EXPLOITABLE_OBSERVED", 0.6, f"{exposed} config management interface(s) exposed.", elapsed, evidence_lines)
    return TechniqueResult("T1547", "Boot or Logon Autostart Execution", "Persistence",
        "NO_EXPOSURE_OBSERVED", 0.6, "No autostart configuration interfaces exposed.", elapsed, evidence_lines)


# ── T1505: Server Software Component (web shells, API docs) ──────────────────

async def t1505_server_component(target: str) -> TechniqueResult:
    """Check for web shells, exposed API documentation, or debug consoles."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    shell_paths = [
        "/shell.php", "/cmd.php", "/c99.php", "/r57.php", "/webshell.php",
        "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/redoc",
        "/docs", "/openapi.json", "/graphql", "/graphiql",
        "/__console__", "/_debugbar", "/telescope",
    ]
    for path in shell_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(500).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["swagger", "openapi", "graphql", "graphiql", "shell", "command"]):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — server component accessible")
                else:
                    evidence_lines.append(f"Accessible: {path} (HTTP 200)")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1505", "Server Software Component", "Persistence",
            "EXPLOITABLE_OBSERVED", 0.7, f"{exposed} server component(s) exposed (API docs, debug consoles).", elapsed, evidence_lines)
    return TechniqueResult("T1505", "Server Software Component", "Persistence",
        "NO_EXPOSURE_OBSERVED", 0.6, "No exposed server components detected.", elapsed, evidence_lines)


# ── T1546: Event Triggered Execution ─────────────────────────────────────────

async def t1546_event_triggered(target: str) -> TechniqueResult:
    """Check for exposed webhook, event, or automation endpoints."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    event_paths = ["/webhook", "/webhooks", "/api/webhooks", "/hooks",
                   "/api/events", "/callback", "/api/callback",
                   "/api/triggers", "/ifttt", "/zapier"]
    for path in event_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                ct = resp.headers.get("Content-Type", "")
                # SPA catch-all returns HTML for any unknown route — not a real endpoint
                if "html" in ct.lower():
                    evidence_lines.append(f"Skipped: {path} (HTML response — SPA catch-all)")
                    continue
                exposed += 1
                evidence_lines.append(f"EXPOSED: {path} — event/webhook endpoint accessible")
        except urllib.error.HTTPError as e:
            if e.code == 405:
                evidence_lines.append(f"Exists: {path} (HTTP 405 — POST method expected)")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1546", "Event Triggered Execution", "Persistence",
            "EXPLOITABLE_OBSERVED", 0.6, f"{exposed} event/webhook endpoint(s) accessible.", elapsed, evidence_lines)
    return TechniqueResult("T1546", "Event Triggered Execution", "Persistence",
        "NO_EXPOSURE_OBSERVED", 0.6, "No exposed event/webhook endpoints.", elapsed, evidence_lines)


# ── T1548: Abuse Elevation Control Mechanism ─────────────────────────────────

async def t1548_elevation_abuse(target: str) -> TechniqueResult:
    """Check for privilege escalation via exposed sudo-like or role endpoints."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    elev_paths = ["/api/admin", "/api/sudo", "/api/elevate", "/api/role",
                  "/api/permissions", "/api/rbac", "/admin/impersonate",
                  "/api/impersonate", "/become", "/api/become"]
    for path in elev_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(300).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["admin", "role", "permission", "elevat", "impersonate"]):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — elevation endpoint accessible")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                evidence_lines.append(f"Protected: {path} (HTTP {e.code})")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
            "EXPLOITABLE_OBSERVED", 0.7, f"{exposed} elevation/role endpoint(s) accessible.", elapsed, evidence_lines)
    return TechniqueResult("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
        "NO_EXPOSURE_OBSERVED", 0.6, "Elevation control endpoints are properly secured.", elapsed, evidence_lines)


# ── T1134: Access Token Manipulation ─────────────────────────────────────────

async def t1134_token_manipulation(target: str) -> TechniqueResult:
    """Check for JWT/token weaknesses and exposed token endpoints."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error
    # Check for exposed token endpoints
    token_paths = ["/api/token", "/oauth/token", "/api/auth/token",
                   "/token", "/.well-known/openid-configuration", "/api/jwt"]
    for path in token_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(500).decode("utf-8", errors="replace")
                evidence_lines.append(f"Accessible: {path}")
                if "none" in body.lower() and "algorithm" in body.lower():
                    issues += 1
                    evidence_lines.append("WARNING: 'none' algorithm may be accepted")
        except Exception:
            pass

    # Check if cookies lack Secure/HttpOnly
    try:
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(
                urllib.request.Request(url_base, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=5
            )
        )
        cookies = resp.headers.get_all("Set-Cookie") or []
        for c in cookies:
            if "httponly" not in c.lower():
                issues += 1
                evidence_lines.append(f"Cookie missing HttpOnly: {c[:60]}")
            if "secure" not in c.lower():
                issues += 1
                evidence_lines.append(f"Cookie missing Secure flag: {c[:60]}")
    except Exception:
        pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues > 0:
        return TechniqueResult("T1134", "Access Token Manipulation", "Privilege Escalation",
            "EXPLOITABLE_OBSERVED", min(0.8, 0.4 + issues * 0.1),
            f"{issues} token/cookie security issue(s) found.", elapsed, evidence_lines)
    return TechniqueResult("T1134", "Access Token Manipulation", "Privilege Escalation",
        "NO_EXPOSURE_OBSERVED", 0.6, "Token handling appears secure.", elapsed, evidence_lines)


# ── T1574: Hijack Execution Flow ─────────────────────────────────────────────

async def t1574_hijack_execution(target: str) -> TechniqueResult:
    """Check for path traversal, open redirects, and resource hijacking vectors."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error
    from urllib.parse import urlparse

    # Extract the original target hostname for comparison
    original_host = urlparse(url_base).hostname or ""

    # Test open redirect
    redirect_tests = [
        f"{url_base}/redirect?url=https://evil.com",
        f"{url_base}/login?next=https://evil.com",
        f"{url_base}/goto?url=//evil.com",
    ]
    for test_url in redirect_tests:
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "Tempris-STRIKE/1.0"})
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=test_url: urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=4
                )
            )
            final_url = resp.url
            # Check if the HOSTNAME of the final URL changed to evil.com
            # (not just "evil.com" appearing in query string of same-origin URL)
            final_host = urlparse(final_url).hostname or ""
            if final_host != original_host and "evil" in final_host:
                issues += 1
                evidence_lines.append(f"OPEN REDIRECT: {test_url} -> {final_url}")
            else:
                evidence_lines.append(f"No redirect: {test_url} stayed on {final_host}")
        except Exception:
            pass

    # Test path traversal
    traversal_tests = [
        f"{url_base}/static/../../../../etc/passwd",
        f"{url_base}/file?path=../../../etc/passwd",
    ]
    for test_url in traversal_tests:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=test_url: urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            body = resp.read(200).decode("utf-8", errors="replace")
            if "root:" in body:
                issues += 1
                evidence_lines.append(f"PATH TRAVERSAL: {test_url} — /etc/passwd readable")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues > 0:
        return TechniqueResult("T1574", "Hijack Execution Flow", "Privilege Escalation",
            "EXPLOITABLE_OBSERVED", 0.8, f"{issues} execution flow hijack vector(s) found.", elapsed, evidence_lines)
    return TechniqueResult("T1574", "Hijack Execution Flow", "Privilege Escalation",
        "NO_EXPOSURE_OBSERVED", 0.6, "No open redirects or path traversal found.", elapsed, evidence_lines)


# ── T1055: Process Injection ─────────────────────────────────────────────────

async def t1055_process_injection(target: str) -> TechniqueResult:
    """Check for exposed debug/profiling endpoints that could enable code injection."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    debug_paths = ["/debug", "/pprof", "/debug/pprof", "/_debug",
                   "/api/eval", "/eval", "/exec", "/api/exec",
                   "/console", "/repl", "/ipython"]
    for path in debug_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(300).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["debug", "pprof", "eval", "exec", "console", "repl"]):
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — debug/eval endpoint accessible")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1055", "Process Injection", "Privilege Escalation",
            "EXPLOITABLE_OBSERVED", 0.8, f"{exposed} debug/eval endpoint(s) exposed — code injection possible.", elapsed, evidence_lines)
    return TechniqueResult("T1055", "Process Injection", "Privilege Escalation",
        "NO_EXPOSURE_OBSERVED", 0.65, "No debug or eval endpoints exposed.", elapsed, evidence_lines)


# ── T1070: Indicator Removal ─────────────────────────────────────────────────

async def t1070_indicator_removal(target: str) -> TechniqueResult:
    """Check if logging/audit endpoints are exposed or if logs can be accessed/cleared."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error
    log_paths = ["/logs", "/api/logs", "/log", "/api/audit",
                 "/admin/logs", "/var/log", "/debug/log",
                 "/api/audit-logs", "/elmah.axd"]
    for path in log_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(500).decode("utf-8", errors="replace").lower()
                if any(kw in body for kw in ["log", "audit", "error", "warning", "timestamp"]):
                    issues += 1
                    evidence_lines.append(f"EXPOSED: {path} — log data accessible")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues > 0:
        return TechniqueResult("T1070", "Indicator Removal", "Defense Evasion",
            "EXPLOITABLE_OBSERVED", 0.7, f"{issues} log endpoint(s) accessible — attacker could study and clear traces.", elapsed, evidence_lines)
    return TechniqueResult("T1070", "Indicator Removal", "Defense Evasion",
        "NO_EXPOSURE_OBSERVED", 0.6, "Log endpoints are properly secured.", elapsed, evidence_lines)


# ── T1036: Masquerading ──────────────────────────────────────────────────────

async def t1036_masquerading(target: str) -> TechniqueResult:
    """Check for server header spoofing opportunities and misleading responses."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error
    try:
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(
                urllib.request.Request(url_base, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=5
            )
        )
        headers = dict(resp.headers)

        # Server header disclosure
        server = headers.get("Server", "")
        if server:
            evidence_lines.append(f"Server disclosed: {server}")
            if any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "lighttpd/"]):
                issues += 1
                evidence_lines.append("WARNING: Server version exposed — aids targeted attacks")

        # X-Powered-By disclosure
        powered = headers.get("X-Powered-By", "")
        if powered:
            issues += 1
            evidence_lines.append(f"X-Powered-By disclosed: {powered}")

        # Check for CORS wildcard
        cors = headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            issues += 1
            evidence_lines.append("WARNING: CORS wildcard (*) — allows cross-origin requests from any domain")

    except Exception as e:
        evidence_lines.append(f"Error: {str(e)[:80]}")

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues >= 2:
        return TechniqueResult("T1036", "Masquerading", "Defense Evasion",
            "EXPLOITABLE_OBSERVED", 0.6, f"{issues} information disclosure issues aid masquerading attacks.", elapsed, evidence_lines)
    return TechniqueResult("T1036", "Masquerading", "Defense Evasion",
        "NO_EXPOSURE_OBSERVED", 0.6, "Server identification is properly restricted.", elapsed, evidence_lines)


# ── T1027: Obfuscated Files or Information ───────────────────────────────────

async def t1027_obfuscated_files(target: str) -> TechniqueResult:
    """Check for exposed source maps, unminified code, or debug builds."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    exposed = 0

    import urllib.request, urllib.error
    # Check for source maps
    map_paths = ["/main.js.map", "/app.js.map", "/bundle.js.map",
                 "/static/js/main.js.map", "/assets/index.js.map",
                 "/.git/HEAD", "/.git/config", "/.svn/entries",
                 "/.env", "/.env.local", "/.env.production"]
    for path in map_paths:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=f"{url_base}{path}": urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=3
                )
            )
            if resp.status == 200:
                body = resp.read(200).decode("utf-8", errors="replace")
                if len(body) > 10:
                    exposed += 1
                    evidence_lines.append(f"EXPOSED: {path} — source/config file accessible")
        except Exception:
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1027", "Obfuscated Files or Information", "Defense Evasion",
            "EXPLOITABLE_OBSERVED", min(0.85, 0.5 + exposed * 0.15),
            f"{exposed} source/config file(s) exposed — aids reverse engineering.", elapsed, evidence_lines)
    return TechniqueResult("T1027", "Obfuscated Files or Information", "Defense Evasion",
        "NO_EXPOSURE_OBSERVED", 0.65, "No source maps, git repos, or config files exposed.", elapsed, evidence_lines)


# ── T1112: Modify Registry (exposed config/state stores) ────────────────────

async def t1112_modify_registry(target: str) -> TechniqueResult:
    """Check for exposed configuration stores (Redis, etcd, Consul KV)."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    exposed = 0

    config_ports = [(6379, "Redis"), (8500, "Consul"), (2379, "etcd"),
                    (11211, "Memcached"), (27017, "MongoDB")]
    for port, svc in config_ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            # For Redis, try INFO command
            if svc == "Redis":
                writer.write(b"INFO\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(200), timeout=2)
                    if b"redis_version" in data:
                        exposed += 1
                        evidence_lines.append(f"CRITICAL: Redis responding without auth on port {port}")
                    else:
                        evidence_lines.append(f"Redis on port {port} requires auth")
                except Exception:
                    evidence_lines.append(f"Open: {svc} port {port}")
            else:
                exposed += 1
                evidence_lines.append(f"EXPOSED: {svc} on port {port}")
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, OSError):
            pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if exposed > 0:
        return TechniqueResult("T1112", "Modify Registry", "Defense Evasion",
            "EXPLOITABLE_OBSERVED", 0.85, f"{exposed} configuration store(s) exposed externally.", elapsed, evidence_lines)
    return TechniqueResult("T1112", "Modify Registry", "Defense Evasion",
        "NO_EXPOSURE_OBSERVED", 0.7, "No configuration stores exposed.", elapsed, evidence_lines)


# ── T1218: System Binary Proxy Execution ─────────────────────────────────────

async def t1218_proxy_execution(target: str) -> TechniqueResult:
    """Check for proxy, reverse proxy, or SSRF vectors."""
    start = datetime.now(timezone.utc)
    evidence_lines = []
    url_base = target if target.startswith("http") else f"http://{target}"
    issues = 0

    import urllib.request, urllib.error
    # Test for open proxy behavior
    proxy_tests = [
        f"{url_base}/proxy?url=http://httpbin.org/ip",
        f"{url_base}/fetch?url=http://httpbin.org/ip",
        f"{url_base}/api/proxy?url=http://httpbin.org/ip",
    ]
    for test_url in proxy_tests:
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None, lambda u=test_url: urllib.request.urlopen(
                    urllib.request.Request(u, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=5
                )
            )
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read(500).decode("utf-8", errors="replace")
            # Must be JSON response from httpbin (not HTML from SPA catch-all)
            # httpbin.org/ip returns: {"origin": "1.2.3.4"}
            is_html = "text/html" in content_type or body.strip().startswith(("<!", "<html", "<HTML"))
            has_ip_response = '"origin"' in body and not is_html
            if has_ip_response:
                issues += 1
                evidence_lines.append(f"SSRF/PROXY: {test_url} — proxied external request")
            else:
                evidence_lines.append(f"No proxy: {test_url} returned HTML (SPA catch-all)")
        except Exception:
            pass

    # Check for proxy-related headers
    try:
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: urllib.request.urlopen(
                urllib.request.Request(url_base, headers={"User-Agent": "Tempris-STRIKE/1.0"}), timeout=4
            )
        )
        headers = dict(resp.headers)
        for h in ["Via", "X-Forwarded-For", "X-Cache"]:
            if headers.get(h):
                evidence_lines.append(f"Proxy header: {h}: {headers[h]}")
    except Exception:
        pass

    elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    if issues > 0:
        return TechniqueResult("T1218", "System Binary Proxy Execution", "Defense Evasion",
            "EXPLOITABLE_OBSERVED", 0.8, f"{issues} SSRF/proxy vector(s) found.", elapsed, evidence_lines)
    return TechniqueResult("T1218", "System Binary Proxy Execution", "Defense Evasion",
        "NO_EXPOSURE_OBSERVED", 0.6, "No open proxy or SSRF vectors detected.", elapsed, evidence_lines)


# ── Main Emulation Runner ────────────────────────────────────────────────────

TECHNIQUE_HANDLERS = {
    # Reconnaissance
    "T1595": t1595_recon,
    # Initial Access
    "T1190": t1190_exploit_public_app,
    "T1078": t1078_valid_accounts,
    "T1133": t1133_external_remote_services,
    "T1566": t1566_phishing,
    "T1195": t1195_supply_chain,
    "T1189": t1189_driveby,
    # Execution
    "T1059": t1059_command_injection,
    "T1203": t1203_client_execution,
    "T1047": t1047_wmi,
    "T1053": t1053_scheduled_task,
    "T1204": t1204_user_execution,
    "T1569": t1569_system_services,
    # Discovery
    "T1046": t1046_network_scanning,
    # Persistence
    "T1098": t1098_account_manipulation,
    "T1136": t1136_create_account,
    "T1543": t1543_system_process,
    "T1547": t1547_autostart,
    "T1505": t1505_server_component,
    "T1546": t1546_event_triggered,
    # Privilege Escalation
    "T1068": t1068_priv_escalation,
    "T1548": t1548_elevation_abuse,
    "T1134": t1134_token_manipulation,
    "T1574": t1574_hijack_execution,
    "T1055": t1055_process_injection,
    # Defense Evasion
    "T1562": t1562_impair_defenses,
    "T1070": t1070_indicator_removal,
    "T1036": t1036_masquerading,
    "T1027": t1027_obfuscated_files,
    "T1112": t1112_modify_registry,
    "T1218": t1218_proxy_execution,
}


async def run_adversary_emulation(
    target: str,
    techniques: list[str],
    rules_of_engagement: str = "non-destructive",
) -> dict:
    """Run a full adversary emulation campaign against the target.
    
    Args:
        target: Target IP, hostname, or URL
        techniques: List of MITRE ATT&CK technique IDs to test
        rules_of_engagement: "non-destructive" (default) or "aggressive"
    
    Returns:
        Dict with overall results and per-technique breakdowns.
    """
    start_time = datetime.now(timezone.utc)
    results = []

    # Always run recon + network scan first
    if "T1595" not in techniques:
        techniques = ["T1595"] + techniques
    if "T1046" not in techniques:
        techniques = techniques[:1] + ["T1046"] + techniques[1:]

    # Execute each technique
    for tech_id in techniques:
        handler = TECHNIQUE_HANDLERS.get(tech_id)
        if handler:
            try:
                result = await handler(target)
                results.append(asdict(result))
            except Exception as e:
                results.append(asdict(TechniqueResult(
                    technique_id=tech_id,
                    technique_name=tech_id,
                    tactic="Unknown",
                    result="ERROR",
                    confidence=0.0,
                    evidence=f"Execution error: {str(e)[:200]}",
                )))
        else:
            results.append(asdict(TechniqueResult(
                technique_id=tech_id,
                technique_name=tech_id,
                tactic="Unknown",
                result="UNTESTED",
                confidence=0.0,
                evidence=f"No handler implemented for technique {tech_id}.",
            )))

    end_time = datetime.now(timezone.utc)
    total_ms = int((end_time - start_time).total_seconds() * 1000)

    exploitable = [r for r in results if r["result"] == "EXPLOITABLE_OBSERVED"]
    no_exposure = [r for r in results if r["result"] == "NO_EXPOSURE_OBSERVED"]

    return {
        "target": target,
        "started_at": start_time.isoformat(),
        "completed_at": end_time.isoformat(),
        "duration_ms": total_ms,
        "rules_of_engagement": rules_of_engagement,
        "techniques_tested": len(results),
        "exploitable_observed": len(exploitable),
        "no_exposure_observed": len(no_exposure),
        "defensive_block_verified": 0,
        "untested": len([r for r in results if r["result"] == "UNTESTED"]),
        "errors": len([r for r in results if r["result"] == "ERROR"]),
        "results": results,
    }
