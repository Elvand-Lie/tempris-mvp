# demo/api/provision_presenter.py — one-time presenter provisioning (WO-10 10c).
# Usage: python provision_presenter.py <username> <password>
# Prints the TOTP provisioning URI (render as QR for the presenter) and the
# pack SHA-256 to pin in .env. Never stores or prints the password again.
import hashlib
import sys
import pathlib

sys.path.insert(0, pathlib.Path(__file__).parent)

from app.auth import seed_user  # noqa: E402

def main() -> None:
    if len(sys.argv) != 3:
        print("usage: provision_presenter.py <username> <password>")
        raise SystemExit(2)
    username, password = sys.argv[1], sys.argv[2]
    info = seed_user(username, password)
    pack = pathlib.Path(__file__).parent.parent / "pack" / "northwind_freight.v1.json"
    digest = hashlib.sha256(pack.read_bytes()).hexdigest() if pack.exists() else None
    print(f"provisioned: {username} (expires {info['expires_at']})")
    print(f"TOTP URI: {info['totp_provisioning_uri']}")
    if digest:
        print(f"DEMO_PACK_SHA256={digest}")

if __name__ == "__main__":
    main()
