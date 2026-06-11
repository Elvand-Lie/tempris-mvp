from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
import logging

logger = logging.getLogger("tempris.database")

# H-01: Database URL from environment — no hardcoded secrets in production
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
    from models import AuditLog, EdipDecision, StrikeAuthorization, StrikeSimulation
    from models import ControlStatus, ControlEvidence, SpotlightReport
    from models import ChatSession, ChatMessage, TesSnapshot
    from models import Asset, ScanFinding, GrcState, GrcSignoff
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
