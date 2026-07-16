#!/usr/bin/env python3
"""
Migration 002: Create user_sessions table and indexes.
"""
import os
import sys
import argparse
import shutil
import sqlite3
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description="Create user_sessions table for server-side auth sessions.")
    parser.add_argument(
        "--db-path",
        required=True,
        help="Path to SQLite database file."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    db_path = args.db_path
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Check if user_sessions table already exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_sessions';")
    table_exists = cursor.fetchone() is not None
    
    has_index_subj = False
    has_index_jti = False
    if table_exists:
        cursor.execute("PRAGMA index_list(user_sessions);")
        indexes = [row[1] for row in cursor.fetchall()]
        has_index_subj = "ix_user_sessions_account_subject" in indexes
        has_index_jti = "ix_user_sessions_jti_hash" in indexes

    if table_exists and has_index_subj and has_index_jti:
        print("Migration 002 already applied. user_sessions table and indexes exist.")
        conn.close()
        return 0

    conn.close()

    # 2. Create Backup
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{db_path}.bak_{timestamp}"
    print(f"Creating database backup at {backup_path}...")
    try:
        shutil.copy2(db_path, backup_path)
        # Verify backup is readable
        with open(backup_path, "rb") as f:
            header = f.read(100)
            if len(header) == 0 and os.path.getsize(db_path) > 0:
                raise RuntimeError("Backup file is empty.")
    except Exception as e:
        print(f"Fatal: Failed to create and verify database backup: {e}", file=sys.stderr)
        return 1

    # 3. Perform Migration
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Start transaction
        cursor.execute("BEGIN TRANSACTION;")

        # Count rows before migration if table exists
        row_count = 0
        if table_exists:
            cursor.execute("SELECT COUNT(*) FROM user_sessions;")
            row_count = cursor.fetchone()[0]

        # Create table if missing
        if not table_exists:
            print("Creating 'user_sessions' table...")
            cursor.execute("""
                CREATE TABLE user_sessions (
                    id VARCHAR(50) PRIMARY KEY,
                    account_subject VARCHAR(255) NOT NULL,
                    jti_hash VARCHAR(64) NOT NULL,
                    issued_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL,
                    last_seen_at DATETIME,
                    revoked_at DATETIME,
                    revoking_actor VARCHAR(255),
                    revocation_reason VARCHAR(500),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    user_agent VARCHAR(255)
                );
            """)

        # Create indexes
        if not has_index_subj:
            print("Creating index ix_user_sessions_account_subject...")
            cursor.execute("CREATE INDEX ix_user_sessions_account_subject ON user_sessions(account_subject);")
        if not has_index_jti:
            print("Creating index ix_user_sessions_jti_hash...")
            cursor.execute("CREATE INDEX ix_user_sessions_jti_hash ON user_sessions(jti_hash);")

        # Verify row count is preserved
        cursor.execute("SELECT COUNT(*) FROM user_sessions;")
        post_count = cursor.fetchone()[0]
        if row_count != post_count:
            raise RuntimeError(f"Row count mismatch! Before: {row_count}, After: {post_count}")

        # Verify final schema
        cursor.execute("PRAGMA table_info(user_sessions);")
        columns = [row[1] for row in cursor.fetchall()]
        required_cols = {"id", "account_subject", "jti_hash", "issued_at", "expires_at", "last_seen_at", "revoked_at", "revoking_actor", "revocation_reason", "created_at", "user_agent"}
        missing_cols = required_cols - set(columns)
        if missing_cols:
            raise RuntimeError(f"Missing columns in final schema: {', '.join(missing_cols)}")

        cursor.execute("PRAGMA index_list(user_sessions);")
        final_indexes = [row[1] for row in cursor.fetchall()]
        if "ix_user_sessions_account_subject" not in final_indexes or "ix_user_sessions_jti_hash" not in final_indexes:
            raise RuntimeError("Final indexes verification failed!")

        # Commit transaction
        conn.commit()
        print("Migration 002 completed successfully.")
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
        
        print("\nRECOVERY INSTRUCTIONS:", file=sys.stderr)
        print("The database has been restored from the original backup file.", file=sys.stderr)
        print(f"Backup file: {backup_path}", file=sys.stderr)
        print("Please check database write permissions, ensure no other process is locking the file, and retry.", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
