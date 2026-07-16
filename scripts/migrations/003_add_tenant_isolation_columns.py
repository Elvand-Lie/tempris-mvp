#!/usr/bin/env python3
"""
Migration 003: Evolve schema for Phase 3/4/5 generic findings, partner onboarding,
tenant isolation columns, report registry, AEV shell, and operations queue.
"""
import os
import sys
import shutil
import sqlite3
from datetime import datetime

def main():
    db_path = "tempris.db"
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}", file=sys.stderr)
        return 1

    # 1. Create Backup
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{db_path}.bak_{timestamp}"
    print(f"Creating database backup at {backup_path}...")
    try:
        shutil.copy2(db_path, backup_path)
        with open(backup_path, "rb") as f:
            header = f.read(100)
            if len(header) == 0 and os.path.getsize(db_path) > 0:
                raise RuntimeError("Backup file is empty.")
    except Exception as e:
        print(f"Fatal: Failed to create and verify database backup: {e}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("BEGIN TRANSACTION;")

        # 2. Add tenant_id columns to existing tables if missing
        tables_to_scope = [
            "audit_logs",
            "edip_decisions",
            "strike_authorizations",
            "control_statuses",
            "incident_reports",
            "spotlight_reports",
            "assets",
            "scan_findings",
            "findings",
            "chat_sessions"
        ]

        for table in tables_to_scope:
            cursor.execute(f"PRAGMA table_info({table});")
            columns = [row[1] for row in cursor.fetchall()]
            if "tenant_id" not in columns:
                print(f"Adding 'tenant_id' column to table {table}...")
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id VARCHAR(50) NOT NULL DEFAULT 'tempris';")
                # Create index on tenant_id for performance and query isolation
                cursor.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_tenant_id ON {table}(tenant_id);")

        # 3. Add generic Phase 3/4 finding columns to findings table
        cursor.execute("PRAGMA table_info(findings);")
        finding_columns = [row[1] for row in cursor.fetchall()]
        
        extra_finding_cols = {
            "external_id": "VARCHAR(100)",
            "cve_id": "VARCHAR(50)",
            "finding_type": "VARCHAR(50) NOT NULL DEFAULT 'standard'",
            "subtype": "VARCHAR(50)",
            "pipeline": "VARCHAR(50) NOT NULL DEFAULT 'STANDARD'",
            "verification": "VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED'",
            "score": "FLOAT",
            "decision": "VARCHAR(50)",
            "sla": "INTEGER",
            "patch_available": "BOOLEAN NOT NULL DEFAULT 1",
            "cve_assigned": "BOOLEAN NOT NULL DEFAULT 1",
            "exploited_in_wild": "BOOLEAN NOT NULL DEFAULT 0",
            "ai_assisted": "BOOLEAN NOT NULL DEFAULT 0",
            "engagement_id": "VARCHAR(50)",
            "summary": "TEXT",
            "description": "TEXT",
            "public_reason_codes": "JSON NOT NULL DEFAULT '[]'",
            "updated_at": "DATETIME"
        }

        for col, col_type in extra_finding_cols.items():
            if col not in finding_columns:
                print(f"Adding generic finding column '{col}' to findings table...")
                cursor.execute(f"ALTER TABLE findings ADD COLUMN {col} {col_type};")

        # 4. Create Generic Finding Supporting Tables
        # Generic Relationships
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finding_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id VARCHAR(50) NOT NULL,
                target_id VARCHAR(50) NOT NULL,
                relationship_type VARCHAR(50) NOT NULL,
                metadata TEXT NOT NULL DEFAULT '[]',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_finding_relationships_source ON finding_relationships(source_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_finding_relationships_target ON finding_relationships(target_id);")

        # Finding Sources
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finding_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id VARCHAR(50) NOT NULL,
                source_id VARCHAR(100) NOT NULL,
                publisher VARCHAR(255) NOT NULL,
                retrieved_at DATETIME NOT NULL,
                last_verified_at DATETIME NOT NULL,
                verification_state VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED',
                expiry_date DATETIME,
                analyst_notes TEXT
            );
        """)

        # Finding Disputed Claims
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finding_disputed_claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id VARCHAR(50) NOT NULL,
                source VARCHAR(100) NOT NULL,
                claim_details TEXT NOT NULL,
                disagreement_text TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            );
        """)

        # Finding Controls
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finding_controls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id VARCHAR(50) NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                layer_type VARCHAR(50) NOT NULL,
                priority VARCHAR(5) NOT NULL DEFAULT 'P1',
                status VARCHAR(20) NOT NULL DEFAULT 'not_assessed'
            );
        """)

        # Finding Evidence
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finding_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id VARCHAR(50) NOT NULL,
                filename VARCHAR(255) NOT NULL,
                file_path VARCHAR(500) NOT NULL,
                uploaded_by VARCHAR(255) NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                verification_state VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED'
            );
        """)

        # Finding Status History
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS finding_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id VARCHAR(50) NOT NULL,
                old_status VARCHAR(50) NOT NULL,
                new_status VARCHAR(50) NOT NULL,
                changed_by VARCHAR(255) NOT NULL,
                changed_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                notes TEXT
            );
        """)

        # 5. Create Partner Onboarding & Certification Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS partner_onboarding (
                id VARCHAR(50) PRIMARY KEY,
                partner_id VARCHAR(50) NOT NULL,
                license_verified BOOLEAN NOT NULL DEFAULT 0,
                agreements_signed BOOLEAN NOT NULL DEFAULT 0,
                attendees TEXT NOT NULL DEFAULT '[]',
                provisioning_status VARCHAR(50) NOT NULL DEFAULT 'pending',
                role_assigned VARCHAR(50),
                attendance_checkins TEXT NOT NULL DEFAULT '[]',
                module_checkpoints TEXT NOT NULL DEFAULT '{}',
                pilot_evidence_submitted BOOLEAN NOT NULL DEFAULT 0,
                assessment_result VARCHAR(50),
                certification_number VARCHAR(100),
                expiry_date DATETIME,
                renewal_status VARCHAR(50),
                release_notes_acknowledged BOOLEAN NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            );
        """)

        # 6. Create Report Registry
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS generated_reports (
                id VARCHAR(50) PRIMARY KEY,
                tenant_id VARCHAR(50) NOT NULL,
                engagement_id VARCHAR(50),
                report_type VARCHAR(50) NOT NULL,
                generator_version VARCHAR(20) NOT NULL,
                requested_by VARCHAR(255) NOT NULL,
                approved_by VARCHAR(255),
                source_finding_ids TEXT NOT NULL DEFAULT '[]',
                source_evidence_ids TEXT NOT NULL DEFAULT '[]',
                framework_configuration TEXT NOT NULL DEFAULT '{}',
                content_hash VARCHAR(64) NOT NULL,
                artifact_location VARCHAR(500) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            );
        """)

        # 7. Create AEV Shell & Registry
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS aev_modules (
                id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 0,
                contract_approved BOOLEAN NOT NULL DEFAULT 0,
                owner VARCHAR(255),
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            );
        """)
        
        # Seed initial disabled AEV modules
        aev_mods = [
            ("ATLAS", "ATLAS AI Module", 0, 0, "CSRO"),
            ("APOLLO", "APOLLO Scanning Orchestrator", 0, 0, "CSRO"),
            ("HELIOS", "HELIOS Exploit Validation Engine", 0, 0, "CSRO"),
            ("ORION", "ORION Log Correlation Shell", 0, 0, "CSRO"),
            ("TARA AI", "TARA AI Remediation Assistant", 0, 0, "CSRO")
        ]
        for mid, mname, men, mcon, mown in aev_mods:
            cursor.execute("""
                INSERT OR IGNORE INTO aev_modules (id, name, enabled, contract_approved, owner)
                VALUES (?, ?, ?, ?, ?);
            """, (mid, mname, men, mcon, mown))

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS aev_runs (
                id VARCHAR(50) PRIMARY KEY,
                module_id VARCHAR(50) NOT NULL,
                tenant_id VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'DRAFT',
                authorized_by VARCHAR(255),
                target_input TEXT NOT NULL DEFAULT '{}',
                evidence_generated TEXT NOT NULL DEFAULT '[]',
                safety_gate_passed BOOLEAN NOT NULL DEFAULT 0,
                started_at DATETIME,
                completed_at DATETIME,
                FOREIGN KEY (module_id) REFERENCES aev_modules(id)
            );
        """)

        # 8. Create Operations Change Queue
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS operations_change_queue (
                id VARCHAR(50) PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                runbook_reference VARCHAR(255),
                backup_required BOOLEAN NOT NULL DEFAULT 1,
                rollback_plan TEXT,
                dry_run_output TEXT,
                preflight_passed BOOLEAN NOT NULL DEFAULT 0,
                status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
                approved_by VARCHAR(255),
                approved_at DATETIME,
                evidence_path VARCHAR(500),
                post_verification_template TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            );
        """)

        conn.commit()
        print("Migration 003 completed successfully.")
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
