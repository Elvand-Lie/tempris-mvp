from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
import logging

logger = logging.getLogger("tempris.database")

# H-01: Database URL from environment â€” no hardcoded secrets in production
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./tempris.db"  # dev-only fallback
)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all tables. Called on app startup."""
    import sys
    from sqlalchemy import inspect
    
    # ── SEC-I3 schema verification on startup ──
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        if "user_sessions" not in tables:
            print("FATAL: Database schema is out of date. Table 'user_sessions' is missing. "
                  "Please run: python scripts/migrations/002_create_auth_sessions.py --db-path <db_path>", file=sys.stderr)
            sys.exit(1)
            
        if "control_evidence" in tables:
            columns = [c["name"] for c in inspector.get_columns("control_evidence")]
            indexes = [idx["name"] for idx in inspector.get_indexes("control_evidence")]
            if "tenant_id" not in columns or "ix_evidence_tenant_framework_control" not in indexes:
                print("FATAL: Database schema is out of date. Required column 'tenant_id' or index is missing. "
                      "Please run: python scripts/migrations/001_add_evidence_tenant.py --legacy-tenant-id <tenant_id>", file=sys.stderr)
                sys.exit(1)

        if "findings" in tables:
            finding_columns = {column["name"] for column in inspector.get_columns("findings")}
            finding_indexes = {index["name"] for index in inspector.get_indexes("findings")}
            if "sub_class" not in finding_columns or "ix_findings_sub_class" not in finding_indexes:
                print(
                    "FATAL: Database schema is out of date. Required findings.sub_class "
                    "column or index is missing. Run scripts/migrations/006_add_sss_sub_class.py "
                    "with a verified backup.",
                    file=sys.stderr,
                )
                sys.exit(1)

        tenant_scoped_tables = (
            'grc_states',
            'grc_signoffs',
            'grc_policy_documents',
            'tes_snapshots',
        )
        tenant_scope_failures = []
        with engine.connect() as connection:
            for table in tenant_scoped_tables:
                if table not in tables:
                    continue
                columns = {column['name'] for column in inspector.get_columns(table)}
                indexes = {index['name'] for index in inspector.get_indexes(table)}
                if 'tenant_id' not in columns:
                    tenant_scope_failures.append(f'{table} (tenant_id column missing)')
                    continue
                if f'ix_{table}_tenant_id' not in indexes:
                    tenant_scope_failures.append(f'{table} (tenant index missing)')
                    continue
                unassigned = connection.execute(
                    __import__('sqlalchemy').text(
                        f'SELECT COUNT(*) FROM {table} '
                        "WHERE tenant_id IS NULL OR TRIM(tenant_id) = ''"
                    )
                ).scalar_one()
                if unassigned:
                    tenant_scope_failures.append(f'{table} ({unassigned} unassigned rows)')
        if tenant_scope_failures:
            print(
                'FATAL: Database tenant scope validation failed: '
                + ', '.join(tenant_scope_failures)
                + '. Run scripts/migrations/004_add_grc_tes_tenant_scope.py '
                  '--legacy-tenant-id <tenant_id> with a verified backup.',
                file=sys.stderr,
            )
            sys.exit(1)
    except Exception as e:
        logger.error(f"Startup validation failed: {e}")
        sys.exit(1)

    from models import AuditLog, EdipDecision, StrikeAuthorization, StrikeSimulation
    from models import ControlStatus, ControlEvidence, IncidentReport, SpotlightReport
    from models import SurgeResearcher, SurgeSubmission
    from models import ChatSession, ChatMessage, TesSnapshot
    from models import Asset, AssetExposure, ScanFinding, GrcState, GrcSignoff, GrcPolicyDocument, Finding
    from models import AccountQueryLog, AccountSuspension, RevokedToken, UserSession
    Base.metadata.create_all(bind=engine)
    logger.info("All tables created/verified.")

    # Enforce append-only on audit_logs
    try:
        with engine.connect() as conn:
            conn.execute(
                __import__('sqlalchemy').text(
                    "REVOKE UPDATE, DELETE ON audit_logs FROM tempris;"
                )
            )
            conn.commit()
            logger.info("audit_logs append-only enforced.")
    except Exception as e:
        logger.debug(f"Could not enforce append-only (may already be set): {e}")



