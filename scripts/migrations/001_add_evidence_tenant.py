#!/usr/bin/env python3
"""
Migration 001: Add tenant_id column and ix_evidence_tenant_framework_control index to control_evidence.
WARNING: Blindly prescribing --mark-legacy-unassigned for all deployments is discouraged.
This option requires a database-copy rehearsal and a custom documented reconciliation strategy
for existing evidence rows before run in production.
"""
import os
import sys
import argparse
import shutil
import sqlite3
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description="Migrate control_evidence to add tenant_id.")
    parser.add_argument(
        "--db-path",
        required=True,
        help="Path to SQLite database file."
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "--legacy-tenant-id",
        help="Tenant ID to assign to existing legacy evidence records."
    )
    group.add_argument(
        "--mark-legacy-unassigned",
        action="store_true",
        help="Mark existing legacy evidence records as unassigned ('legacy-unassigned')."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    db_path = args.db_path
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}", file=sys.stderr)
        return 1

    # Check if table has rows and legacy tenant ID is required
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Check if control_evidence table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='control_evidence';")
    if not cursor.fetchone():
        print("Table 'control_evidence' does not exist. No migration needed.")
        conn.close()
        return 0

    # 2. Check if column already exists
    cursor.execute("PRAGMA table_info(control_evidence);")
    columns = [row[1] for row in cursor.fetchall()]
    
    cursor.execute("PRAGMA index_list(control_evidence);")
    indexes = [row[1] for row in cursor.fetchall()]
    
    has_column = "tenant_id" in columns
    has_index = "ix_evidence_tenant_framework_control" in indexes

    if has_column and has_index:
        print("Migration already applied. Database is up to date.")
        conn.close()
        return 0

    # Count rows before migration
    cursor.execute("SELECT COUNT(*) FROM control_evidence;")
    row_count = cursor.fetchone()[0]

    # If there are existing rows and no legacy tenant choice is provided, reject
    if row_count > 0 and not has_column:
        if not args.legacy_tenant_id and not args.mark_legacy_unassigned:
            print(
                "Error: Existing evidence records found. You must supply either "
                "--legacy-tenant-id <tenant_id> or --mark-legacy-unassigned "
                "to perform the migration.",
                file=sys.stderr
            )
            conn.close()
            return 1

    # If legacy-tenant-id is provided, validate it
    if args.legacy_tenant_id:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "app", "backend"))
        try:
            from routers.auth import USERS
            valid_tenants = {u.get("tenant_id") for u in USERS.values() if u.get("tenant_id")}
        except Exception:
            valid_tenants = {"tempris", "tenantA", "tenantB"}
        
        if args.legacy_tenant_id not in valid_tenants:
            print(
                f"Error: Invalid legacy tenant ID '{args.legacy_tenant_id}'. Must be one of: {', '.join(sorted(valid_tenants))}",
                file=sys.stderr
            )
            conn.close()
            return 1

    conn.close()

    # 3. Create Backup
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{db_path}.bak_{timestamp}"
    print(f"Creating database backup at {backup_path}...")
    try:
        shutil.copy2(db_path, backup_path)
    except Exception as e:
        print(f"Fatal: Failed to create database backup: {e}", file=sys.stderr)
        return 1

    # 4. Perform Migration
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Start transaction
        cursor.execute("BEGIN TRANSACTION;")

        # Determine target legacy tenant value
        legacy_tenant = args.legacy_tenant_id if args.legacy_tenant_id else "legacy-unassigned"

        # Add column if missing
        if not has_column:
            print(f"Adding 'tenant_id' column to control_evidence (default value: {legacy_tenant})...")
            cursor.execute(f"ALTER TABLE control_evidence ADD COLUMN tenant_id VARCHAR(50) NOT NULL DEFAULT '{legacy_tenant}';")

        # Add index if missing
        if not has_index:
            print("Creating composite index ix_evidence_tenant_framework_control...")
            cursor.execute("CREATE INDEX ix_evidence_tenant_framework_control ON control_evidence(tenant_id, framework_id, control_id);")

        # Verify row counts and null values
        cursor.execute("SELECT COUNT(*) FROM control_evidence;")
        post_count = cursor.fetchone()[0]
        if row_count != post_count:
            raise RuntimeError(f"Row count mismatch! Before: {row_count}, After: {post_count}")

        cursor.execute("SELECT COUNT(*) FROM control_evidence WHERE tenant_id IS NULL;")
        null_count = cursor.fetchone()[0]
        if null_count > 0:
            raise RuntimeError(f"Unexpected NULL values found in tenant_id! Count: {null_count}")

        # Verify final schema
        cursor.execute("PRAGMA table_info(control_evidence);")
        final_columns = [row[1] for row in cursor.fetchall()]
        cursor.execute("PRAGMA index_list(control_evidence);")
        final_indexes = [row[1] for row in cursor.fetchall()]
        
        if "tenant_id" not in final_columns or "ix_evidence_tenant_framework_control" not in final_indexes:
            raise RuntimeError("Final schema verification failed! Column or index is missing.")

        # Commit transaction
        conn.commit()
        print("Migration 001 completed successfully.")
        conn.close()
        return 0

    except Exception as e:
        print(f"Error during migration: {e}. Rolling back and restoring backup...", file=sys.stderr)
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        # Restore backup
        try:
            shutil.copy2(backup_path, db_path)
            print("Backup successfully restored.")
        except Exception as re:
            print(f"Fatal: Failed to restore backup! Database may be corrupt. Error: {re}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
