# demo/scripts/nightly_reset.py — host-side nightly baseline restore (WO-10 10d).
# Runs on the demo host (cron), inside the isolated network; it never modifies
# the pinned pack file, only the tenant-scoped database rows.
# Cron example (03:00 nightly):
#   0 3 * * * docker compose -f /opt/terra-demo/docker-compose.yml exec -T api \
#       python /srv/scripts/nightly_reset.py
import hashlib
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "api"))

from app import audit  # noqa: E402
from app.db import PACK_TABLES, init_schema, tenant_conn  # noqa: E402

PACK = pathlib.Path(os.environ.get(
    "DEMO_PACK_PATH",
    pathlib.Path(__file__).resolve().parent.parent / "pack" / "northwind_freight.v1.json",
))
TENANT = os.environ.get("DEMO_TENANT", "terra")


def main() -> None:
    expected = os.environ.get("DEMO_PACK_SHA256", "")
    raw = PACK.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected and digest != expected:
        raise SystemExit("demo pack integrity check failed — NOT resetting")
    pack = json.loads(raw)
    init_schema()
    with tenant_conn(TENANT) as conn:
        with conn.cursor() as cur:
            for table in PACK_TABLES:
                cur.execute(f"DELETE FROM {table}")
            cur.execute("DELETE FROM pack_blobs WHERE tenant_id = %s", (TENANT,))
            for table, key in PACK_TABLES.items():
                for ord_, item in enumerate(pack.get(key, [])):
                    cur.execute(
                        f"INSERT INTO {table} (tenant_id, ord, payload) VALUES (%s, %s, %s)",
                        (TENANT, ord_, json.dumps(item)),
                    )
            for blob in ("journeys", "report", "estate"):
                cur.execute(
                    "INSERT INTO pack_blobs (tenant_id, key, payload) VALUES (%s, %s, %s)",
                    (TENANT, blob, json.dumps(pack.get(blob, {}))),
                )
    audit(TENANT, "nightly-reset", "demo.reset", {"pack": PACK.name, "sha256": digest})
    print(f"nightly reset complete ({digest[:16]}…)")


if __name__ == "__main__":
    main()
