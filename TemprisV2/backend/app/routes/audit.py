# backend/app/routes/audit.py
"""
Audit-chain integrity endpoint (PRD-000 Chapter 5, Target architecture item 4
— V1's GET /api/audit/verify, ported and tenant-scoped). Read-only: the chain
is never recomputed or rewritten through the API.
"""
from fastapi import APIRouter, Depends

from app.audit import verify_tenant_audit_chain
from app.auth import AuthContext, get_auth_context
from app.db import get_db_connection

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("/verify")
def verify_audit_chain(auth: AuthContext = Depends(get_auth_context)):
    """Verify the caller tenant's audit hash chain (V1 response shape). Any
    authenticated principal verifies its own tenant only; platform sessions
    verify the Platform Control tenant's chain."""
    with get_db_connection() as conn:
        return verify_tenant_audit_chain(conn, auth.tenant_id)
