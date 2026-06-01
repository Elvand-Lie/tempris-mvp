from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session
from services.database import get_db
from models import AuditLog
import json
import os
import hashlib

router = APIRouter()

class AuditEntry(BaseModel):
    user: str
    action: str
    module: str
    detail: str

def _compute_hash(prev_hash: str, entry_data: str) -> str:
    """Chain hash for tamper detection."""
    return hashlib.sha256(f"{prev_hash}{entry_data}".encode()).hexdigest()

def seed_audit_log(db: Session):
    """Load TACF seed data from tacf_audit_log.json if DB is empty."""
    existing = db.query(AuditLog).count()
    if existing > 0:
        print(f"TACF: {existing} audit records already in DB, skipping seed.")
        return
    
    seed_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tacf_audit_log.json')
    if os.path.exists(seed_path):
        try:
            with open(seed_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            events = data.get('events', [])
            prev_hash = "0"
            for e in events:
                entry_str = f"{e.get('event_type','')}{e.get('description','')}{e.get('timestamp','')}"
                new_hash = _compute_hash(prev_hash, entry_str)
                record = AuditLog(
                    timestamp=datetime.fromisoformat(e.get("timestamp", datetime.utcnow().isoformat())),
                    user_email=e.get("actor", "system"),
                    action=e.get("event_type", "UNKNOWN"),
                    module=e.get("source_module", "SYSTEM"),
                    detail=e.get("description", ""),
                    metadata_=e.get("metadata", {}),
                    hash=new_hash
                )
                db.add(record)
                prev_hash = new_hash
            db.commit()
            print(f"TACF: Seeded {len(events)} audit events into PostgreSQL.")
        except Exception as ex:
            db.rollback()
            print(f"TACF seed warning: {ex}")

    # System start event
    append_to_audit_log_db(db, AuditEntry(
        user="System", action="SYSTEM_START", module="CORE",
        detail="Tempris Wave 1 Engine initialized."
    ))

def append_to_audit_log_db(db: Session, entry: AuditEntry) -> dict:
    """Append to DB-backed audit log."""
    # Get last hash for chain
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last.hash if last and last.hash else "0"
    entry_str = f"{entry.action}{entry.detail}{datetime.utcnow().isoformat()}"
    new_hash = _compute_hash(prev_hash, entry_str)
    
    record = AuditLog(
        user_email=entry.user,
        action=entry.action,
        module=entry.module,
        detail=entry.detail,
        hash=new_hash
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {
        "id": f"A-{record.id}",
        "timestamp": record.timestamp.isoformat(),
        "user": record.user_email,
        "action": record.action,
        "module": record.module,
        "detail": record.detail,
        "hash": record.hash
    }

# Global helper for other routers (creates its own session)
def append_to_audit_log(entry: AuditEntry):
    """Convenience function for other modules — opens its own DB session."""
    from services.database import SessionLocal
    db = SessionLocal()
    try:
        result = append_to_audit_log_db(db, entry)
        return result
    finally:
        db.close()

@router.get("/log")
def get_audit_log(db: Session = Depends(get_db)):
    """Returns the TACF compliant append-only audit trail."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200).all()
    return [{
        "id": f"A-{log.id}",
        "timestamp": log.timestamp.isoformat() if log.timestamp else "",
        "user": log.user_email,
        "action": log.action,
        "module": log.module,
        "detail": log.detail,
        "hash": log.hash or ""
    } for log in logs]

@router.post("/log")
def log_action(entry: AuditEntry, db: Session = Depends(get_db)):
    """API endpoint to log an action directly."""
    return append_to_audit_log_db(db, entry)
