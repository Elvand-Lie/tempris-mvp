from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from services.database import get_db
from models import AuditLog
from routers.auth import get_current_user, require_role
import json
import os
import hashlib
import logging

logger = logging.getLogger("tempris.audit")

router = APIRouter()


class AuditEntry(BaseModel):
    user: str = "system"
    action: str = ""
    module: str = "SYSTEM"
    detail: str = ""
    ip_address: str | None = None


def _compute_hash(prev_hash: str, entry_str: str) -> str:
    return hashlib.sha256(f"{prev_hash}{entry_str}".encode()).hexdigest()


def seed_audit_log(db: Session):
    """Load TACF seed data from tacf_audit_log.json if DB is empty."""
    existing = db.query(AuditLog).count()
    if existing > 0:
        logger.info(f"TACF: {existing} audit records already in DB, skipping seed.")
        return

    seed_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tacf_audit_log.json')
    if os.path.exists(seed_path):
        with open(seed_path, 'r') as f:
            data = json.load(f)
        events = data.get("events", [])
        if events:
            try:
                prev_hash = "0"
                for e in events:
                    ts_str = e.get('timestamp', '')
                    entry_str = f"{e.get('action','')}{e.get('detail','')}{ts_str}"
                    new_hash = _compute_hash(prev_hash, entry_str)
                    record = AuditLog(
                        timestamp=datetime.fromisoformat(e.get("timestamp", datetime.now(timezone.utc).isoformat())),
                        user_email=e.get("user", "system"),
                        action=e.get("action", ""),
                        module=e.get("module", "SYSTEM"),
                        detail=e.get("detail", ""),
                        ip_address=e.get("ip_address"),
                        hash=new_hash
                    )
                    db.add(record)
                    prev_hash = new_hash
                db.commit()
                logger.info(f"TACF: Seeded {len(events)} audit events into PostgreSQL.")
            except Exception as ex:
                db.rollback()
                logger.warning(f"TACF seed warning: {ex}")

    # System start event
    append_to_audit_log_db(db, AuditEntry(
        user="system", action="SYSTEM_STARTUP", module="CORE",
        detail="Tempris platform initialized. All modules loaded."
    ))


def append_to_audit_log_db(db: Session, entry: AuditEntry) -> dict:
    """Append to DB-backed audit log with hash chain integrity.
    
    Uses row-level locking (SELECT FOR UPDATE) on PostgreSQL to prevent
    concurrent writers from grabbing the same prev_hash, which would break
    the chain. On SQLite, relies on the GIL + single-writer semantics.
    """
    from sqlalchemy import text

    # C-06: Serialize hash chain access to prevent race conditions
    db_url = str(db.bind.url) if db.bind else ""
    if "postgresql" in db_url:
        # PostgreSQL: advisory lock on a fixed key to serialize audit writes
        db.execute(text("SELECT pg_advisory_xact_lock(42)"))

    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last.hash if last and last.hash else "0"
    # C-05 FIX: Use the SAME timestamp for both hashing and storage
    now = datetime.now(timezone.utc)
    entry_str = f"{entry.action}{entry.detail}{now.isoformat()}"
    new_hash = _compute_hash(prev_hash, entry_str)

    record = AuditLog(
        timestamp=now,
        user_email=entry.user,
        action=entry.action,
        module=entry.module,
        detail=entry.detail,
        ip_address=entry.ip_address,
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
        "ip_address": record.ip_address,
        "hash": record.hash
    }


# Global helper for other routers (creates its own session)
def append_to_audit_log(entry: AuditEntry):
    """Convenience function for other modules — opens its own DB session.
    
    Fire-and-forget safe: catches and logs exceptions so audit failures
    never crash the calling endpoint.
    """
    from services.database import SessionLocal
    db = SessionLocal()
    try:
        result = append_to_audit_log_db(db, entry)
        return result
    except Exception as e:
        logger.error(f"TACF audit log write failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return None
    finally:
        db.close()


# ── C-01 FIX: All endpoints require authentication ───────────────────────────

@router.get("/log")
def get_audit_log(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Returns the TACF compliant append-only audit trail. Requires authentication."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200).all()
    return [{
        "id": f"A-{log.id}",
        "timestamp": log.timestamp.isoformat() if log.timestamp else "",
        "user": log.user_email,
        "action": log.action,
        "module": log.module,
        "detail": log.detail,
        "ip_address": log.ip_address or "",
        "hash": log.hash or ""
    } for log in logs]


@router.get("/verify")
def verify_audit_integrity(recompute: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """L4-14: Walk the hash chain and verify audit log integrity.
    If recompute=true, rebuild the hash chain (admin use after data migration)."""
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not logs:
        return {"status": "empty", "records": 0, "intact": True}

    if recompute:
        # Rebuild the entire hash chain from scratch
        prev_hash = "0"
        for log in logs:
            entry_str = f"{log.action}{log.detail}{log.timestamp.isoformat() if log.timestamp else ''}"
            new_hash = _compute_hash(prev_hash, entry_str)
            log.hash = new_hash
            prev_hash = new_hash
        db.commit()
        return {
            "status": "recomputed",
            "records": len(logs),
            "intact": True,
            "mismatches": 0,
            "first_break_at_index": None,
            "latest_hash": logs[-1].hash if logs else None,
        }

    prev_hash = "0"
    broken_at = None
    mismatches = 0
    for i, log in enumerate(logs):
        if not log.hash:
            continue
        entry_str = f"{log.action}{log.detail}{log.timestamp.isoformat() if log.timestamp else ''}"
        expected = _compute_hash(prev_hash, entry_str)
        if expected != log.hash:
            mismatches += 1
            if broken_at is None:
                broken_at = i
        prev_hash = log.hash

    intact = (mismatches == 0)
    return {
        "status": "verified" if intact else "TAMPERED",
        "records": len(logs),
        "intact": intact,
        "mismatches": mismatches,
        "first_break_at_index": broken_at,
        "latest_hash": logs[-1].hash if logs else None,
    }


@router.post("/log")
def log_action(entry: AuditEntry, request: Request = None, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin"))):
    """API endpoint to log an action directly. Requires Superadmin or Admin."""
    if request and not entry.ip_address:
        entry.ip_address = request.headers.get("X-Real-IP", request.client.host if request.client else None)
    return append_to_audit_log_db(db, entry)
