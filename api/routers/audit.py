from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from typing import List
import json
import os

router = APIRouter()

# In-memory append-only log for demo
AUDIT_LOG = []

def _load_tacf_seed():
    """Load TACF seed data from tacf_audit_log.json if available."""
    global AUDIT_LOG
    seed_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tacf_audit_log.json')
    if os.path.exists(seed_path):
        try:
            with open(seed_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            events = data.get('events', [])
            for e in events:
                AUDIT_LOG.append({
                    "id": f"A-{e.get('sequence_num', 0) + 1000}",
                    "timestamp": e.get("timestamp", ""),
                    "user": e.get("actor", "system"),
                    "action": e.get("event_type", "UNKNOWN"),
                    "module": e.get("source_module", "SYSTEM"),
                    "detail": e.get("description", ""),
                    "metadata": e.get("metadata", {}),
                    "immutable": e.get("immutable", True),
                    "hash": e.get("hash", ""),
                })
            print(f"TACF: Loaded {len(events)} seed audit events.")
        except Exception as ex:
            print(f"TACF seed load warning: {ex}")

    # Always ensure at least one system start event
    AUDIT_LOG.append({
        "id": f"A-{1000 + len(AUDIT_LOG) + 1}",
        "timestamp": datetime.utcnow().isoformat(),
        "user": "System",
        "action": "SYSTEM_START",
        "module": "CORE",
        "detail": "Tempris Wave 1 Engine initialized."
    })

_load_tacf_seed()

class AuditEntry(BaseModel):
    user: str
    action: str
    module: str
    detail: str

@router.get("/log")
def get_audit_log():
    """Returns the TACF compliant append-only audit trail."""
    # Return newest first
    return sorted(AUDIT_LOG, key=lambda x: x["timestamp"], reverse=True)

def append_to_audit_log(entry: AuditEntry):
    """Internal function to append to log from other routers."""
    log_record = {
        "id": f"A-{1000 + len(AUDIT_LOG) + 1}",
        "timestamp": datetime.utcnow().isoformat(),
        "user": entry.user,
        "action": entry.action,
        "module": entry.module,
        "detail": entry.detail
    }
    AUDIT_LOG.append(log_record)
    return log_record

@router.post("/log")
def log_action(entry: AuditEntry):
    """API endpoint to log an action directly."""
    return append_to_audit_log(entry)
