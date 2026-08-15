"""Small, shared writer for structured operational telemetry.

Operational events complement the immutable human audit trail.  Callers control
the surrounding transaction so an event cannot claim a state change that did
not commit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from models import OperationalEvent


def record_operational_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    resource_type: str,
    resource_id: str,
    source_module: str,
    actor_id: str | None = None,
    actor_type: str = "user",
    metadata: dict | None = None,
    correlation_id: str | None = None,
    occurred_at: datetime | None = None,
) -> OperationalEvent:
    row = OperationalEvent(
        id=f"EVT-{uuid4().hex[:24].upper()}",
        tenant_id=tenant_id,
        event_type=event_type,
        occurred_at=occurred_at or datetime.now(timezone.utc),
        actor_type=actor_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        source_module=source_module,
        metadata_=dict(metadata or {}),
        correlation_id=correlation_id,
    )
    db.add(row)
    return row
