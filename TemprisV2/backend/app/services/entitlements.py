# backend/app/services/entitlements.py
import json
import uuid
from typing import Set
import psycopg

def resolve_effective_modules(conn: psycopg.Connection, tenant_id: uuid.UUID) -> Set[str]:
    """
    Computes effective entitled modules for a tenant in-memory:
    Effective = (Base Package Modules UNION True Overrides) MINUS False Overrides

    Invariants:
    1. If tenant is inactive (tenants.status != 'active') or has no entitlement row, returns set().
    2. Modules with status != 'active' in the catalogue (modules table) are excluded regardless of overrides.
    3. Overrides must be booleans (True adds, False subtracts).
    """
    if not tenant_id:
        return set()

    with conn.cursor() as cur:
        # 1. Query tenant_entitlements joined with active tenants
        cur.execute(
            """
            SELECT te.package_id, te.module_overrides
            FROM tenant_entitlements te
            JOIN tenants t ON t.id = te.tenant_id
            WHERE t.id = %s AND t.status = 'active';
            """,
            (str(tenant_id),)
        )
        te_row = cur.fetchone()
        if not te_row:
            return set()

        package_id = te_row["package_id"]
        raw_overrides = te_row["module_overrides"]
        if isinstance(raw_overrides, dict):
            overrides = raw_overrides
        elif isinstance(raw_overrides, str):
            try:
                overrides = json.loads(raw_overrides)
            except Exception:
                overrides = {}
        else:
            overrides = {}

        # 2. Fetch base package modules that are active in modules catalogue
        cur.execute(
            """
            SELECT pm.module_id
            FROM package_modules pm
            JOIN modules m ON m.id = pm.module_id
            WHERE pm.package_id = %s AND m.status = 'active';
            """,
            (package_id,)
        )
        effective: Set[str] = {r["module_id"] for r in cur.fetchall()}

        # 3. Apply boolean overrides
        if overrides and isinstance(overrides, dict):
            for mod_id, enabled in overrides.items():
                if enabled is True:
                    cur.execute(
                        "SELECT id FROM modules WHERE id = %s AND status = 'active';",
                        (str(mod_id),)
                    )
                    if cur.fetchone():
                        effective.add(str(mod_id))
                elif enabled is False:
                    effective.discard(str(mod_id))

        return effective
