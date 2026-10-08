# backend/app/services/membership_lifecycle.py
"""Shared tenant-membership lifecycle rules (ORG-01).

A tenant membership has three states:

    pending   the invitation exists, but the account has never been activated.
              It grants nothing: authorization requires users.status='active'
              AND tenant_memberships.status='active' (app/auth.py), and account
              activation is a distinct step — the tenant Superadmin activates
              within their own tenant (POST /api/org/users/{id}/activate);
              Platform Administrators retain provisioning/bootstrap and
              cross-tenant activation (PRD Ch.5, amended 2026-09-24).
    active    the membership is in force. Usability additionally requires an
              active account.
    disabled  the membership was intentionally disabled (or its invitation was
              revoked). Historical disabled rows may coexist; the single-active
              membership partial unique index (004:48) is unchanged.

This module is the single authority for which membership state an account
state yields, so the invitation creators (tenant org routes and platform
tenant provisioning) cannot drift apart.
"""

# A user may hold at most one outstanding invitation (uq_memberships_user_pending,
# migration 039): platform activation then names exactly one membership.
PENDING_MEMBERSHIP_DETAIL = (
    "User already has a pending organization membership invitation"
)


def membership_status_for_account(account_status: str) -> str:
    """Membership state implied by the account's own activation state.

    A usable account gets an in-force membership; an account that was never
    activated gets a pending invitation; a disabled account gets a disabled
    membership (inviting it back is not an activation).
    """
    if account_status == "active":
        return "active"
    if account_status == "pending":
        return "pending"
    return "disabled"