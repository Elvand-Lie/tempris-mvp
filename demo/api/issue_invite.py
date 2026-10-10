# demo/api/issue_invite.py — Tempris admin only. Mint a single-name presenter invite.
# Run on the demo host (it needs DEMO_INVITE_SECRET, which never leaves the host):
#   python issue_invite.py terra-presenter-01 [hours, default 72, max 168]
# Give the code to that presenter only. It enrolls exactly that username, once.
import sys

from app.enroll import INVITE_MAX_TTL_S, mint_invite

if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python issue_invite.py <username> [hours]")
    username = sys.argv[1]
    hours = int(sys.argv[2]) if len(sys.argv) == 3 else 72
    code = mint_invite(username, min(hours * 3600, INVITE_MAX_TTL_S))
    print(f"invite for {username}: {code}")
