from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from services.database import get_db
from services.threat_importer import import_threat_pack, rollback_threat_pack
from routers.auth import require_role, get_auth_context
from typing import Any

router = APIRouter()

@router.post("/import")
def import_threats(
    req: dict[str, Any],
    dry_run: bool = Query(default=False),
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    auth_ctx = get_auth_context(user)
    try:
        res = import_threat_pack(db, req, dry_run=dry_run, requested_by=auth_ctx.user_id)
        if res.get("status") == "failed":
            raise HTTPException(status_code=422, detail=res.get("errors"))
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/rollback")
def rollback_threats(
    pack_name: str = Query(...),
    version: str = Query(...),
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin"))
):
    auth_ctx = get_auth_context(user)
    try:
        return rollback_threat_pack(db, pack_name, version, requested_by=auth_ctx.user_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
