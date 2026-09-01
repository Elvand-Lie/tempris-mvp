# backend/app/audit.py
import json
import uuid
from typing import Optional, Dict, Any
import psycopg

# Sanitization keys that should never appear in audit details
SENSITIVE_KEYS = {"password", "secret", "token", "authorization", "raw_response", "body", "payload", "cookie", "jwt"}

def sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not details:
        return {}
    sanitized = {}
    for k, v in details.items():
        if k.lower() in SENSITIVE_KEYS:
            continue
        if isinstance(v, dict):
            sanitized[k] = sanitize_details(v)
        else:
            sanitized[k] = v
    return sanitized

def record_audit_event(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    actor_id: str,
    actor_role: str,
    event_name: str,
    asset_id: Optional[uuid.UUID] = None,
    details: Optional[Dict[str, Any]] = None
) -> uuid.UUID:
    """
    Inserts a sanitized audit record using parameterized SQL.
    """
    clean_details = sanitize_details(details)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO audit_events (
                id, tenant_id, actor_id, actor_role, event_name, asset_id, details, created_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s, %s, now()
            )
            RETURNING id;
            """,
            (
                str(tenant_id),
                actor_id,
                actor_role,
                event_name,
                str(asset_id) if asset_id else None,
                json.dumps(clean_details)
            )
        )
        row = cur.fetchone()
        return row["id"] if isinstance(row, dict) else row[0]
