#!/usr/bin/env python3
"""
SDLC-S02: Secrets Scanner & Rotation Playbook Generator.
Wraps gitleaks, checks against policy allowlists, and enforces secrets compliance.
"""
import os
import sys
import json
import subprocess
from datetime import datetime, timezone

EXCEPTIONS_FILE = os.path.join("docs", "security", "secret_exceptions.json")

PLAYBOOK_MARKDOWN = """# Secrets Rotation Playbook

This playbook defines the incident response procedures for compromised credentials or secrets.

## SLA Response Timeframes
- **Critical (Superadmin/DB passwords, private signing keys):** 2 hours.
- **High (API keys, service accounts):** 6 hours.
- **Medium (Development environment credentials):** 24 hours.

## Standard Rotation Workflow

1. **Detection & Quarantine**
   - Identify the source of the leak (e.g., git commit history, exposed logs).
   - Log the incident in the SIEM / Security incident log system with a unique ticket ID.

2. **Revocation & Provisioning**
   - Generate a new cryptographically secure secret (minimum 32 bytes/characters).
   - Update the configuration management or secret store (e.g., AWS Secrets Manager, HashiCorp Vault).
   - Revoke the compromised token/key on the provider side (e.g., OAuth provider, Database server).

3. **Code Cleanup & Commit Purging**
   - If committed to Git, use `git-filter-repo` or BFG Repo-Cleaner to permanently scrub the secret from all historical commits.
   - Force push the sanitized branches to remote repositories.

4. **Notifications**
   - Notify the affected partners/clients via the secure customer notification channel.
   - Alert the Security Operations Team (SecOps) via Slack `#security-alerts` or email `security@tempris.com`.
"""

def load_exceptions():
    if not os.path.exists(EXCEPTIONS_FILE):
        return []
    try:
        with open(EXCEPTIONS_FILE, "r") as f:
            data = json.load(f)
            return data.get("exceptions", [])
    except Exception as e:
        print(f"Warning: Failed to load exceptions: {e}")
        return []

def is_exception_valid(exc, file_path, secret_type):
    # Normalize paths
    norm_exc = exc.get("file", "").replace("\\", "/")
    norm_file = file_path.replace("\\", "/")
    
    if norm_exc != norm_file:
        return False
    if exc.get("secret_type") != secret_type:
        return False
        
    expiry_str = exc.get("expiry")
    if not expiry_str:
        return False
    try:
        expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expiry_dt:
            print(f"Exception for {file_path} is EXPIRED (expired at {expiry_str})")
            return False
        return True
    except Exception as e:
        print(f"Warning: Invalid expiry date format: {e}")
        return False

def write_playbook():
    docs_dir = os.path.join("docs", "security")
    os.makedirs(docs_dir, exist_ok=True)
    playbook_file = os.path.join(docs_dir, "secrets_rotation_playbook.md")
    with open(playbook_file, "w", encoding="utf-8") as f:
        f.write(PLAYBOOK_MARKDOWN)
    print(f"Secrets Rotation Playbook written/verified at: {playbook_file}")

def main():
    print("--- SDLC-S02: Scanning Repository for Secrets ---")
    write_playbook()
    
    in_ci = os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"
    mock_mode = (os.environ.get("SCAN_MOCK_FALLBACK") == "1") and not in_ci
    mock_clean = os.environ.get("SCAN_MOCK_CLEAN") == "1"
    full_history = "--history" in sys.argv or "-h" in sys.argv
    
    report_file = os.path.join("artifacts", "security", "secrets", "gitleaks_report.json")
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    
    if mock_mode:
        print("[SIMULATED] Simulating gitleaks output...")
        if mock_clean:
            gitleaks_findings = []
        else:
            # We return one exception-matching finding and one unapproved finding
            gitleaks_findings = [
                {
                    "File": "app/backend/index.py",
                    "Description": "Generic Password/Secret Key Assignment",
                    "Match": "jwt_secret = 'dev_mock_key_12345'",
                    "Secret": "dev_mock_key_12345",
                    "StartLine": 50
                },
                {
                    "File": "app/backend/config_leaked.py",
                    "Description": "Generic Password/Secret Key Assignment",
                    "Match": "prod_db_pwd = 'highly_secret_pwd_to_redact'",
                    "Secret": "highly_secret_pwd_to_redact",
                    "StartLine": 12
                }
            ]
    else:
        # Determine Gitleaks commands
        # detect runs scanning history, protect runs staged changes
        cmd = ["gitleaks", "detect", "--report-format", "json", "--report-path", report_file]
        if not full_history:
            # Staged changes / local protection scan
            cmd = ["gitleaks", "protect", "--staged", "--report-format", "json", "--report-path", report_file]
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # Gitleaks returns 0 if no leaks, 1 if leaks found, and other status for errors
            if os.path.exists(report_file) and os.path.getsize(report_file) > 0:
                with open(report_file, "r") as f:
                    gitleaks_findings = json.load(f)
            else:
                gitleaks_findings = []
        except FileNotFoundError:
            print("TOOL_UNAVAILABLE: Gitleaks scanner is not available in the local environment.")
            print("Please install gitleaks or ensure it is in your PATH.")
            print("To run in simulation/test mode, set environment variable SCAN_MOCK_FALLBACK=1")
            return 1
        except Exception as e:
            print(f"Error executing Gitleaks: {e}")
            return 1

    exceptions = load_exceptions()
    violations = []
    warnings = []
    
    for finding in gitleaks_findings:
        file_path = finding.get("File")
        desc = finding.get("Description")
        match_str = finding.get("Match")
        secret_val = finding.get("Secret")
        line_no = finding.get("StartLine", 0)
        
        # Redact secrets in logging output
        redacted_match = match_str.replace(secret_val, "[REDACTED]") if secret_val else "[REDACTED]"
        
        # Validate exception
        has_exc = False
        for exc in exceptions:
            if is_exception_valid(exc, file_path, desc):
                has_exc = True
                break
                
        finding_info = {
            "file": file_path,
            "line": line_no,
            "secret_type": desc,
            "match": redacted_match
        }
        
        if has_exc:
            warnings.append(finding_info)
        else:
            violations.append(finding_info)

    # Save final sanitized scan report
    sanitized_report_path = os.path.join("artifacts", "security", "secrets", "secrets_scan_report.json")
    with open(sanitized_report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "simulated": mock_mode,
            "violations": violations,
            "warnings": warnings,
            "policy_passed": len(violations) == 0
        }, f, indent=2)
        
    if warnings:
        print(f"\nAllowed Secret Exceptions ({len(warnings)}):")
        for w in warnings:
            print(f"  * File: {w['file']}:{w['line']} - Type: {w['secret_type']} (Match: {w['match']})")
            
    if violations:
        print(f"\nUnapproved Leaked Secrets Detected ({len(violations)}):")
        for v in violations:
            print(f"  * File: {v['file']}:{v['line']} - Type: {v['secret_type']} (Match: {v['match']})")
        print("\nCI Secrets Check: FAILED. Unapproved secrets present.")
        return 1
    else:
        print("\nCI Secrets Check: PASSED.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
