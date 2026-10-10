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

_BASE = pathlib.Path(__file__).resolve().parent.parent
# Repo checkouts keep the package under api/; the API image keeps it at /srv.
# Both candidates go on the path so this runs in either layout without
# depending on PYTHONPATH being set by the cron line.
for _candidate in (_BASE / "api", _BASE):
    sys.path.insert(0, str(_candidate))

from app.auth import audit  # noqa: E402
from app.db import PACK_TABLES, tenant_conn  # noqa: E402

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
    # NOTE: no init_schema() here — the runtime role cannot (and must not)
    # perform schema/role management. Schema bootstrap is a separate admin
    # operation (see docker-compose service `bootstrap`).
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
