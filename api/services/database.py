from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# PostgreSQL running in Docker on the same host
DATABASE_URL = "postgresql://tempris:M8n7b6v5c4x3z21~@172.18.0.3:5432/tempris_db"

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
    Base.metadata.create_all(bind=engine)
    print("DB: All tables created/verified.")
    
    # Enforce append-only on audit_logs
    try:
        with engine.connect() as conn:
            conn.execute(
                __import__('sqlalchemy').text(
                    "REVOKE UPDATE, DELETE ON audit_logs FROM tempris;"
                )
            )
            conn.commit()
            print("DB: audit_logs append-only enforced.")
    except Exception as e:
        print(f"DB: Could not enforce append-only (may already be set): {e}")
