#!/usr/bin/env python3
"""
Reconciliation command to recover or purge interrupted evidence deletions.
"""
import os
import sys
import argparse
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

def parse_args():
    parser = argparse.ArgumentParser(description="Reconcile interrupted evidence deletions.")
    parser.add_argument(
        "--db-path",
        required=True,
        help="Path to SQLite database file."
    )
    parser.add_argument(
        "--evidence-root",
        required=True,
        help="Path to evidence storage root."
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Perform the restore action for crashed deletion transactions."
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="Perform the purge action for finalized deletion transactions."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    db_url = f"sqlite:///{args.db_path}"
    evidence_root = os.path.realpath(args.evidence_root)
    
    quarantine_dir = os.path.join(evidence_root, ".quarantine")
    if not os.path.exists(quarantine_dir):
        print("Quarantine directory does not exist. Nothing to reconcile.")
        return 0

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()

    print(f"Scanning quarantine directory: {quarantine_dir}")
    try:
        q_files = os.listdir(quarantine_dir)
    except Exception as e:
        print(f"Error reading quarantine directory: {e}", file=sys.stderr)
        session.close()
        return 1

    reconciled_count = 0
    purged_count = 0
    is_dry_run = not args.restore and not args.purge

    if is_dry_run:
        print("--- RUNNING IN DRY-RUN MODE (No changes will be applied) ---")

    for filename in q_files:
        # Ignore unknown quarantine contents
        if not filename.endswith(".quarantine"):
            print(f"Skipping unknown file in quarantine: {filename}")
            continue

        quarantine_path = os.path.join(quarantine_dir, filename)
        original_uuid_filename = filename[:-11]  # Strip ".quarantine"

        # Query database to find if the record still exists
        # We look for a record matching this physical filename in file_path
        query = text("""
            SELECT id, file_path, tenant_id 
            FROM control_evidence 
            WHERE file_path LIKE :pattern
        """)
        row = session.execute(query, {"pattern": f"%{original_uuid_filename}"}).fetchone()

        if row:
            rec_id, file_path, tenant_id = row
            # The database record still exists (transaction failed/rolled back) -> RESTORE
            if args.restore:
                print(f"[ACTION] Restoring file for evidence ID {rec_id} to active storage...")
                try:
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    os.replace(quarantine_path, file_path)
                    
                    # Log audit action
                    audit_query = text("""
                        INSERT INTO audit_logs (timestamp, user_email, action, module, detail, ip_address, metadata, hash)
                        VALUES (datetime('now'), 'system-reconciliation', 'EVIDENCE_DELETE_RECONCILED_RESTORED', 'COMPLIANCE', :details, '127.0.0.1', '{}', '')
                    """)
                    session.execute(audit_query, {
                        "details": f"Interrupted deletion recovered. Evidence ID {rec_id} file restored."
                    })
                    session.commit()
                    reconciled_count += 1
                except Exception as e:
                    session.rollback()
                    print(f"Error restoring file {filename}: {e}", file=sys.stderr)
            else:
                print(f"[DRY-RUN] Would restore file for evidence ID {rec_id} to active storage.")
        else:
            # No database record found (transaction committed successfully) -> PURGE
            if args.purge:
                print(f"[ACTION] Purging orphaned quarantine file: {original_uuid_filename}...")
                try:
                    os.remove(quarantine_path)
                    
                    # Log audit action
                    audit_query = text("""
                        INSERT INTO audit_logs (timestamp, user_email, action, module, detail, ip_address, metadata, hash)
                        VALUES (datetime('now'), 'system-reconciliation', 'EVIDENCE_DELETE_RECONCILED_PURGED', 'COMPLIANCE', :details, '127.0.0.1', '{}', '')
                    """)
                    session.execute(audit_query, {
                        "details": f"Interrupted deletion finalized. Quarantined file {original_uuid_filename} purged."
                    })
                    session.commit()
                    purged_count += 1
                except Exception as e:
                    session.rollback()
                    print(f"Error purging file {filename}: {e}", file=sys.stderr)
            else:
                print(f"[DRY-RUN] Would purge orphaned quarantine file: {original_uuid_filename}.")

    session.close()
    if is_dry_run:
        print("Dry-run finished. No files modified.")
    else:
        print(f"Reconciliation run finished. Restored: {reconciled_count}, Purged: {purged_count}.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
