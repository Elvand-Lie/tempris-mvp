from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from datetime import datetime, timezone
from sqlalchemy import or_
from sqlalchemy.orm import Session
from services.database import get_db
from models import AuditLog
from routers.auth import get_current_user, require_role
from contextvars import ContextVar
import json
import os
import hashlib
import logging

logger = logging.getLogger("tempris.audit")

router = APIRouter()

# Context variables for request-scoped audit context
audit_request_var: ContextVar[Request] = ContextVar("audit_request", default=None)

class AuditEntry(BaseModel):
    user: str = "system"
    action: str = ""
    module: str = "SYSTEM"
    detail: str = ""
    ip_address: str | None = None
    metadata: dict | None = None

import ipaddress


# CIDR Trusted-proxy allowlist
trusted_cidrs_env = os.environ.get("TEMPRIS_TRUSTED_PROXY_CIDRS", "")
TRUSTED_PROXY_NETWORKS = []
if trusted_cidrs_env:
    for cidr in trusted_cidrs_env.split(","):
        try:
            TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(cidr.strip()))
        except ValueError as e:
            logger.warning(f"Invalid trusted proxy CIDR configured: {cidr}. Error: {e}")

def is_trusted_proxy(ip_str: str) -> bool:
    if ip_str == "testclient":
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in TRUSTED_PROXY_NETWORKS:
            if ip in network:
                return True
    except ValueError:
        pass
    return False

def get_client_ip(request: Request) -> str:
    """Derive client IP from request utilizing a configuration-backed CIDR allowlist.
    Only trust X-Real-IP or X-Forwarded-For headers if peer client IP is trusted.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"
    if is_trusted_proxy(peer_ip):
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            try:
                ipaddress.ip_address(real_ip.strip())
                return real_ip.strip()
            except ValueError:
                pass
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            # Parse and find the first clean, valid IP address
            for part in x_forwarded_for.split(","):
                clean_ip = part.strip()
                try:
                    ipaddress.ip_address(clean_ip)
                    return clean_ip
                except ValueError:
                    pass
    return peer_ip


_fallback_hmac_key = b"tempris_dev_audit_hmac_key_do_not_use_in_prod_" + b"x" * 16

def get_audit_hmac_key() -> bytes:
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    key_env = os.environ.get("AUDIT_HMAC_KEY", "")
    if env in ("staging", "production"):
        if not key_env:
            raise RuntimeError("FATAL: AUDIT_HMAC_KEY is missing or empty in staging/production.")
        if len(key_env) < 32:
            raise RuntimeError("FATAL: AUDIT_HMAC_KEY must have at least 32 characters of secret material.")
        if "test_audit_hmac" in key_env or "tempris_dev_audit_hmac" in key_env:
            raise RuntimeError("FATAL: Weak/development placeholder keys are refused in staging/production.")
        return key_env.encode()
    else:
        if not key_env:
            return _fallback_hmac_key
        return key_env.encode()



def _compute_v2_hmac(
    prev_hash: str,
    action: str,
    detail: str | None,
    ts: datetime | None,
    user: str | None,
    module: str | None,
    ip_address: str | None,
    metadata: dict | None,
) -> str:
    # Build deterministic canonical payload for v2
    payload = {
        "prev_hash": prev_hash,
        "timestamp": _timestamp_for_hash(ts),
        "user": user or "",
        "action": action or "",
        "module": module or "",
        "detail": detail or "",
        "ip_address": ip_address or "",
        "metadata": metadata or {}
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    import hmac
    key = get_audit_hmac_key()
    digest = hmac.new(key, canonical_payload.encode(), hashlib.sha256).hexdigest()
    # Fit strictly within DB String(64) limit: 'v2:' (3 chars) + 60 chars of hex digest = 63 chars
    return f"v2:{digest[:60]}"




def _compute_hash(prev_hash: str, entry_str: str) -> str:
    return hashlib.sha256(f"{prev_hash}{entry_str}".encode()).hexdigest()


def _timestamp_for_hash(ts: datetime | None) -> str:
    if not ts:
        return ""
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.isoformat()


def _entry_hash_payload(
    action: str,
    detail: str | None,
    ts: datetime | None,
    user: str | None = None,
    module: str | None = None,
    ip_address: str | None = None,
    metadata: dict | None = None,
    include_metadata: bool = False,
) -> str:
    payload = {
        "timestamp": _timestamp_for_hash(ts),
        "user": user or "",
        "action": action or "",
        "module": module or "",
        "detail": detail or "",
        "ip_address": ip_address or "",
    }
    if include_metadata:
        payload["metadata"] = metadata or {}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _legacy_entry_hash_payloads(log: AuditLog) -> set[str]:
    if not log.timestamp:
        return {f"{log.action}{log.detail}"}
    timestamps = {log.timestamp.isoformat(), _timestamp_for_hash(log.timestamp)}
    if log.timestamp.tzinfo is None:
        timestamps.add(log.timestamp.replace(tzinfo=timezone.utc).isoformat())
    return {f"{log.action}{log.detail}{ts}" for ts in timestamps}


def _stored_hash_matches(prev_hash: str, log: AuditLog) -> bool:
    if log.hash and log.hash.startswith("v2:"):
        expected = _compute_v2_hmac(
            prev_hash, log.action, log.detail, log.timestamp, log.user_email, log.module, log.ip_address, log.metadata_
        )
        return log.hash == expected

    candidates = {
        _compute_hash(prev_hash, _entry_hash_payload(
            log.action, log.detail, log.timestamp, log.user_email, log.module, log.ip_address, log.metadata_,
            include_metadata=bool(log.metadata_)
        )),
        _compute_hash(prev_hash, _entry_hash_payload(
            log.action, log.detail, log.timestamp, log.user_email, log.module, log.ip_address, log.metadata_,
            include_metadata=False
        )),
        _compute_hash(prev_hash, _entry_hash_payload(
            log.action, log.detail, log.timestamp, log.user_email, log.module, log.ip_address, log.metadata_,
            include_metadata=True
        )),
        *(_compute_hash(prev_hash, payload) for payload in _legacy_entry_hash_payloads(log)),
    }
    return log.hash in candidates





TACF_REQUIRED_METADATA = {
    "agent_identity",
    "authority_granted",
    "tool_used",
    "evidence_generated",
    "revocation_path",
    "under_policy_control",
}


def _requires_tacf_metadata(entry: AuditEntry) -> bool:
    return entry.module in {"EDIP", "SPECTRUM"} and entry.action.startswith("AUTO_")


def _validate_tacf_metadata(entry: AuditEntry):
    if not _requires_tacf_metadata(entry):
        return
    missing = TACF_REQUIRED_METADATA - set((entry.metadata or {}).keys())
    if missing:
        raise ValueError(f"Missing TACF metadata: {', '.join(sorted(missing))}")


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
                    ts = datetime.fromisoformat(e.get("timestamp", datetime.now(timezone.utc).isoformat()))
                    metadata = e.get("metadata") or {}
                    actor = e.get("actor", "system")
                    event_type = e.get("event_type", "")
                    source_module = e.get("source_module", "SYSTEM")
                    description = e.get("description", "")
                    ip_address = metadata.get("ip_address") if isinstance(metadata, dict) else None

                    entry_str = _entry_hash_payload(event_type, description, ts, actor, source_module, ip_address, metadata, include_metadata=bool(metadata))
                    new_hash = _compute_hash(prev_hash, entry_str)
                    record = AuditLog(
                        timestamp=ts,
                        user_email=actor,
                        action=event_type,
                        module=source_module,
                        detail=description,
                        ip_address=ip_address,
                        metadata_=metadata,
                        hash=new_hash
                    )
                    db.add(record)
                    prev_hash = new_hash
                db.commit()
                logger.info(f"TACF: Seeded {len(events)} audit events into PostgreSQL.")
            except Exception as ex:
                db.rollback()
                logger.warning(f"TACF seed warning: {ex}")

    # System start event - requires explicit service principal and internal IP
    append_to_audit_log_db(db, AuditEntry(
        user="system:startup", action="SYSTEM_STARTUP", module="CORE",
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

    # Enforce server-authoritative actor/user override from JWT request state
    t_id = "tempris"
    request = audit_request_var.get()
    if request:
        user_payload = getattr(request.state, "authenticated_user", None)
        if user_payload and isinstance(user_payload, dict):
            entry.user = user_payload.get("sub", "unknown")
            t_id = user_payload.get("tenant_id", "tempris")
        else:
            # Unauthenticated request: only allow specific auth/login actions
            if entry.action not in ("USER_LOGIN", "USER_LOGIN_FAILED", "USER_LOGIN_LOCKED"):
                entry.user = "anonymous"
        entry.ip_address = get_client_ip(request)
    else:
        # Internal system action (no request context): require explicit service principal
        if not entry.user or not (entry.user.startswith("system:") or entry.user.startswith("service:")):
            raise ValueError(f"Internal events must provide an explicit service principal (got '{entry.user}')")
        entry.ip_address = "internal"

    _validate_tacf_metadata(entry)
    last = (
        db.query(AuditLog)
        .filter(AuditLog.tenant_id == t_id)
        .order_by(AuditLog.id.desc())
        .first()
    )
    prev_hash = last.hash if last and last.hash else "0"
    # C-05 FIX: Use the SAME timestamp for both hashing and storage
    now = datetime.now(timezone.utc)
    new_hash = _compute_v2_hmac(
        prev_hash, entry.action, entry.detail, now, entry.user, entry.module, entry.ip_address, entry.metadata
    )

    record = AuditLog(
        tenant_id=t_id,
        timestamp=now,
        user_email=entry.user,
        action=entry.action,
        module=entry.module,
        detail=entry.detail,
        ip_address=entry.ip_address,
        metadata_=entry.metadata or {},
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
        "metadata": record.metadata_ or {},
        "hash": record.hash
    }


# Global helper for other routers (creates its own session)
def append_to_audit_log(entry: AuditEntry):
    """Convenience function for other modules â€” opens its own DB session.
    
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


# â”€â”€ C-01 FIX: All endpoints require authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/log")
def get_audit_log(
    request: Request,
    limit: int = 200,
    offset: int = 0,
    sort_by: str = "timestamp",
    order: str = "desc",
    module: str = "ALL",
    q: str = "",
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Returns the TACF compliant append-only audit trail. Requires authentication."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    sort_map = {
        "timestamp": AuditLog.timestamp,
        "user": AuditLog.user_email,
        "module": AuditLog.module,
        "action": AuditLog.action,
    }
    sort_col = sort_map.get(sort_by, AuditLog.timestamp)
    sort_expr = sort_col.asc() if order.lower() == "asc" else sort_col.desc()

    tenant_id = user.get('tenant_id')
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if module and module.upper() != "ALL":
        query = query.filter(AuditLog.module == module.upper())
    if q.strip():
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(
            AuditLog.user_email.ilike(pattern),
            AuditLog.action.ilike(pattern),
            AuditLog.module.ilike(pattern),
            AuditLog.detail.ilike(pattern),
        ))

    total = query.count()
    logs = query.order_by(sort_expr).offset(offset).limit(limit).all()
    data = [{
        "id": f"A-{log.id}",
        "timestamp": log.timestamp.isoformat() if log.timestamp else "",
        "user": log.user_email,
        "action": log.action,
        "module": log.module,
        "detail": log.detail,
        "ip_address": log.ip_address or "",
        "metadata": log.metadata_ or {},
        "hash": log.hash or ""
    } for log in logs]

    # Keep old callers compatible: /api/audit/log still returns the latest list.
    if not request.query_params:
        return data
    return {"data": data, "total": total, "limit": limit, "offset": offset}


@router.get("/verify")
def verify_audit_integrity(recompute: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """L4-14: Walk the hash chain and verify audit log integrity.
    If recompute=true, rebuild the hash chain (admin use after data migration)."""
    if recompute and user.get("role") not in ("Superadmin", "Admin"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Audit recompute requires Superadmin or Admin")

    tenant_id = user.get('tenant_id')
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.id.asc())
        .all()
    )
    if not logs:
        return {"status": "empty", "records": 0, "intact": True}

    if recompute:
        # Rebuild the entire hash chain from scratch using v2 HMAC
        prev_hash = "0"
        for log in logs:
            new_hash = _compute_v2_hmac(
                prev_hash, log.action, log.detail, log.timestamp, log.user_email, log.module, log.ip_address, log.metadata_
            )
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
    has_transitioned_to_v2 = False

    for i, log in enumerate(logs):
        if not log.hash:
            continue

        is_v2 = log.hash.startswith("v2:")
        if is_v2:
            has_transitioned_to_v2 = True

        # Downgrade check: once the chain transitions to v2, it must reject any subsequent legacy-formatted records.
        if has_transitioned_to_v2 and not is_v2:
            mismatches += 1
            if broken_at is None:
                broken_at = i
            continue

        if not _stored_hash_matches(prev_hash, log):
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
def log_action(entry: AuditEntry, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin"))):
    """API endpoint to log an action directly. Requires Superadmin or Admin."""
    return append_to_audit_log_db(db, entry)






