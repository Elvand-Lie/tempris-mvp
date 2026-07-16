#!/usr/bin/env python3
"""
SDLC-S01: Dependency Vulnerability Scanner.
Invokes pip-audit on requirements.txt, enforces severity policy, and handles exceptions.
"""
import os
import sys
import json
import subprocess
from datetime import datetime, timezone

EXCEPTIONS_FILE = os.path.join("docs", "security", "dependency_exceptions.json")

def load_exceptions():
    if not os.path.exists(EXCEPTIONS_FILE):
        return []
    try:
        with open(EXCEPTIONS_FILE, "r") as f:
            data = json.load(f)
            return data.get("exceptions", [])
    except Exception as e:
        print(f"Warning: Failed to load exceptions file: {e}")
        return []

def is_exception_valid(exc, pkg, cve):
    if exc.get("package").lower() != pkg.lower():
        return False
    if exc.get("cve").upper() != cve.upper():
        return False
    # Check expiry
    expiry_str = exc.get("expiry")
    if not expiry_str:
        return False
    try:
        expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expiry_dt:
            print(f"Exception for {pkg} {cve} is EXPIRED (expired at {expiry_str})")
            return False
        return True
    except Exception as e:
        print(f"Warning: Invalid expiry date format in exception for {pkg}: {e}")
        return False

def main():
    req_file = os.path.join("app", "backend", "requirements.txt")
    if not os.path.exists(req_file):
        req_file = "requirements.txt"
        
    print(f"--- SDLC-S01: Scanning Dependencies in {req_file} ---")
    
    in_ci = os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"
    mock_mode = (os.environ.get("SCAN_MOCK_FALLBACK") == "1") and not in_ci
    mock_clean = os.environ.get("SCAN_MOCK_CLEAN") == "1"
    
    # 1. Run pip-audit via subprocess or simulate if mock_mode
    if mock_mode:
        print("[SIMULATED] Simulating pip-audit output...")
        if mock_clean:
            pip_audit_data = []
        else:
            # We will return one medium vulnerability (requests) and one high (jinja2)
            pip_audit_data = [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "vulns": [
                        {
                            "id": "CVE-2023-32681",
                            "fix_versions": ["2.31.1"],
                            "description": "Leak of Authorization header on redirect."
                        }
                    ]
                },
                {
                    "name": "jinja2",
                    "version": "3.1.2",
                    "vulns": [
                        {
                            "id": "CVE-2024-22195",
                            "fix_versions": ["3.1.3"],
                            "description": "Server-side template injection via xmlattr filter."
                        }
                    ]
                }
            ]
    else:
        # Check if pip-audit is available
        try:
            # We run pip-audit with json format
            cmd = ["pip-audit", "--format", "json", "-r", req_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.stdout.strip():
                try:
                    pip_audit_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    print("Error: Failed to parse pip-audit JSON output.")
                    print(result.stdout)
                    return 1
            else:
                pip_audit_data = []
        except FileNotFoundError:
            print("TOOL_UNAVAILABLE: pip-audit is not available in the local environment.")
            print("Please install it using: pip install pip-audit")
            print("To run in simulation/test mode, set environment variable SCAN_MOCK_FALLBACK=1")
            return 1
        except Exception as e:
            print(f"Error executing pip-audit: {e}")
            return 1

    exceptions = load_exceptions()
    violations = []
    warnings = []
    
    # Handle list layout or dict layout
    dependencies = []
    if isinstance(pip_audit_data, dict):
        dependencies = pip_audit_data.get("dependencies", [])
    elif isinstance(pip_audit_data, list):
        dependencies = pip_audit_data
    
    for dep in dependencies:
        pkg_name = dep.get("name")
        version = dep.get("version")
        vulns = dep.get("vulns", [])
        
        for vuln in vulns:
            vuln_id = vuln.get("id")
            desc = vuln.get("description", "No description")
            
            # Check exceptions
            has_exception = False
            for exc in exceptions:
                if is_exception_valid(exc, pkg_name, vuln_id):
                    has_exception = True
                    break
                    
            if has_exception:
                warnings.append({
                    "package": pkg_name,
                    "version": version,
                    "id": vuln_id,
                    "description": desc,
                    "status": "EXCEPTION_ALLOWED"
                })
            else:
                violations.append({
                    "package": pkg_name,
                    "version": version,
                    "id": vuln_id,
                    "description": desc,
                    "status": "BLOCKED"
                })

    # Save machine-readable output
    output_dir = os.path.join("artifacts", "security", "dependencies")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "dependency_scan_report.json")
    
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "simulated": mock_mode,
        "violations": violations,
        "warnings": warnings,
        "policy_passed": len(violations) == 0
    }
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("\n--- Vulnerability Scan Summary ---")
    if warnings:
        print(f"Allowed Exceptions ({len(warnings)}):")
        for w in warnings:
            print(f"  * {w['package']} ({w['id']}) - Status: {w['status']}")
            
    if violations:
        print(f"\nBlocked Violations ({len(violations)}):")
        for v in violations:
            print(f"  * {v['package']} ({v['id']}) - Status: {v['status']}")
            print(f"    Description: {v['description']}")
        print("\nCI Policy Check: FAILED due to unmitigated vulnerability findings.")
        return 1
    else:
        print("\nCI Policy Check: PASSED.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
