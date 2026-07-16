#!/usr/bin/env python3
"""
SEC-I4: Purge Test Artifacts Maintenance and Verification Tool.
Enforces training/demo environment checks, exact tenant scoping, exact allowlisted artifact IDs,
backup creation, and post-cleanup verification.
"""
import os
import sys
import argparse
import sqlite3
import shutil
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description="Purge test and demo artifacts from the database safely.")
    parser.add_argument(
        "--db-path",
        required=True,
        help="Explicit path to the SQLite database file."
    )
    parser.add_argument(
        "--tenant-id",
        required=True,
        help="Exact tenant ID scope for deletion."
    )
    parser.add_argument(
        "--artifact-ids",
        required=True,
        help="Comma-separated list of exact artifact IDs (findings or assets) to purge."
    )
    parser.add_argument(
        "--approval-ref",
        required=True,
        help="Approval reference string (e.g. Change ticket ID)."
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute the deletion. If not provided, runs in dry-run mode."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    db_path = args.db_path
    tenant_id = args.tenant_id
    approval_ref = args.approval_ref
    
    # Split and clean artifact IDs
    artifact_ids = [aid.strip() for aid in args.artifact_ids.split(",") if aid.strip()]
    if not artifact_ids:
        print("Error: No valid artifact IDs provided.", file=sys.stderr)
        return 1

    # 1. Environment policy (allowlist only)
    env = os.environ.get("ENVIRONMENT", "").lower()
    
    # Test-only path: Permit test execution ONLY against test_purge_artifacts.db under ENVIRONMENT=test
    is_test_run = (env == "test" and os.path.basename(db_path) == "test_purge_artifacts.db")
    
    if not is_test_run and env not in ("demo", "training"):
        print(f"Error: Purge tool execution blocked in ENVIRONMENT '{env}'. Permitted only in training or demo environments.", file=sys.stderr)
        return 1

    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Query matching findings
    findings_query = f"SELECT id, cve, title, asset_id FROM findings WHERE tenant_id = ? AND id IN ({','.join(['?']*len(artifact_ids))});"
    cursor.execute(findings_query, [tenant_id] + artifact_ids)
    findings_to_delete = cursor.fetchall()

    # Query matching assets
    assets_query = f"SELECT id, name, hostname FROM assets WHERE tenant_id = ? AND id IN ({','.join(['?']*len(artifact_ids))});"
    cursor.execute(assets_query, [tenant_id] + artifact_ids)
    assets_to_delete = cursor.fetchall()

    # Query matching audit logs
    audit_logs_to_delete = []
    for aid in artifact_ids:
        cursor.execute("SELECT id, action, detail FROM audit_logs WHERE tenant_id = ? AND (action = ? OR detail LIKE ?);", (tenant_id, "TEST_ACTION_PURGE", f"%{aid}%"))
        audit_logs_to_delete.extend(cursor.fetchall())
    
    # Deduplicate audit logs
    audit_logs_to_delete = list({row[0]: row for row in audit_logs_to_delete}.values())

    print("=== SEC-I4 Purge Staging Maintenance Tool ===")
    print(f"Database Path: {db_path}")
    print(f"Tenant Scope: {tenant_id}")
    print(f"Environment: {env or 'unset'}")
    print(f"Approval Reference: {approval_ref}")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY-RUN (No changes will be written)'}")
    print(f"- Findings to delete: {len(findings_to_delete)}")
    for row in findings_to_delete:
        print(f"  * id: {row[0]}, cve: {row[1]}, title: {row[2][:40]}")
    
    print(f"- Assets to delete: {len(assets_to_delete)}")
    for row in assets_to_delete:
        print(f"  * id: {row[0]}, name: {row[1]}, host: {row[2]}")

    print(f"- Audit logs to delete: {len(audit_logs_to_delete)}")
    for row in audit_logs_to_delete:
        print(f"  * id: {row[0]}, action: {row[1]}, detail: {row[2][:50]}")

    total_items = len(findings_to_delete) + len(assets_to_delete) + len(audit_logs_to_delete)
    print(f"Total matching items identified for purge: {total_items}")

    if not args.execute:
        print("\nDry-run complete. Run with --execute to perform DB deletions.")
        conn.close()
        return 0

    if total_items == 0:
        print("\nNo matching items found to purge. Nothing to execute.")
        conn.close()
        return 0

    # Execute flow with database backup
    print("\nExecuting purge. Creating backup first...")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{db_path}.bak_purge_{timestamp}"
    try:
        shutil.copy2(db_path, backup_path)
        print(f"Backup created successfully at: {backup_path}")
    except Exception as e:
        print(f"Fatal: Failed to create database backup: {e}", file=sys.stderr)
        conn.close()
        return 1

    try:
        cursor.execute("BEGIN TRANSACTION;")

        # Delete operations
        if findings_to_delete:
            ids = [row[0] for row in findings_to_delete]
            cursor.execute(f"DELETE FROM findings WHERE tenant_id = ? AND id IN ({','.join(['?']*len(ids))});", [tenant_id] + ids)
            print(f"Purged {cursor.rowcount} findings.")

        if assets_to_delete:
            ids = [row[0] for row in assets_to_delete]
            cursor.execute(f"DELETE FROM assets WHERE tenant_id = ? AND id IN ({','.join(['?']*len(ids))});", [tenant_id] + ids)
            print(f"Purged {cursor.rowcount} assets.")

        if audit_logs_to_delete:
            ids = [row[0] for row in audit_logs_to_delete]
            cursor.execute(f"DELETE FROM audit_logs WHERE tenant_id = ? AND id IN ({','.join(['?']*len(ids))});", [tenant_id] + ids)
            print(f"Purged {cursor.rowcount} audit logs.")

        conn.commit()
        print("Purge completed and transaction committed successfully.")

        # Post-cleanup verification
        print("\nRunning post-cleanup verification...")
        cursor.execute(findings_query, [tenant_id] + artifact_ids)
        v_findings = len(cursor.fetchall())
        cursor.execute(assets_query, [tenant_id] + artifact_ids)
        v_assets = len(cursor.fetchall())

        remaining = v_findings + v_assets
        if remaining == 0:
            print("Verification SUCCESS: 0 matching test artifacts remain in database.")
            conn.close()
            return 0
        else:
            print(f"Verification FAILED: {remaining} matching items still remain in database.", file=sys.stderr)
            conn.close()
            return 1

    except Exception as e:
        print(f"Error during purge execution: {e}. Rolling back...", file=sys.stderr)
        conn.rollback()
        conn.close()
        return 1

if __name__ == "__main__":
    sys.exit(main())
