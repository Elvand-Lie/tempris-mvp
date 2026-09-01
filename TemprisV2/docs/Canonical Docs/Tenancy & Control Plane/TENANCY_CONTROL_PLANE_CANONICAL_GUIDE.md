# Tempris V2 Tenancy & Control Plane Canonical Guide

**Status:** Frozen production foundation as of 2026-08-31.

This guide is the authoritative explanation of V2 tenant ownership, human identity, tenant membership, module entitlement, Organization administration, and Platform Administration. It documents the final production boundary and the reasons it exists.

## 1. Executive mental model

Human authorization is resolved as:

```text
user identity/email
→ one active tenant membership
→ role inside that tenant
→ active tenant state
→ effective module entitlement
→ route-specific authorization
```

Platform administration is a separate control plane:

```text
platform identity
→ Platform Control login context
→ is_platform_admin = true
→ /platform-dashboard
→ tenant metadata, lifecycle, packages, entitlements, pending-user activation
```

A platform administrator does not impersonate a tenant, does not switch tenant context, and cannot use Platform Control to reach tenant Assets, Collectors, or Organization member management.

## 2. Production tenant contexts

| Context | UUID | Owner / identity | State | Operational access |
|---|---|---|---|---|
| Platform Control | `f0000000-0000-4000-8000-000000000001` | `admin@tempris.com`, platform administrator | Active | None; no module entitlement or operational rows |
| Tempris operational tenant | `11111111-1111-1111-1111-111111111111` | `temprisadmin@gmail.com`, tenant `superadmin` | Tenant active; identity pending manual activation | `CORE_ASSETS` package / `ASSETS` module |
| Legacy Tenant | `00000000-0000-0000-0000-000000000001` | None | Disabled and ownerless pending retirement | Historical rows retained, new access denied |

The empty accidental tenant formerly named `Tempris Singapore` was removed after verification that it contained no assets, collectors, scan authorizations, or audit events. Its approved owner membership was attached to the existing Tempris operational tenant containing the real data.

## 3. Tenant isolation

V2 uses shared operational tables with explicit `tenant_id` ownership. It does not create per-customer tables or databases.

The authenticated tenant comes from the validated JWT and current database membership. Client-supplied tenant IDs never establish operational scope. Every Assets and Collectors read or write binds the authenticated tenant ID, and direct access to another tenant's object returns `404` to avoid existence disclosure.

Operational tenant foreign keys use `ON DELETE RESTRICT`. Tenant deletion is not an API operation; tenant lifecycle is active/disabled.

Authoritative implementations:

- [Authentication and request revalidation](../../../backend/app/auth.py)
- [Asset routes](../../../backend/app/routes/assets.py)
- [Collector routes](../../../backend/app/routes/collectors.py)
- [Tenancy foundation migration](../../../backend/migrations/004_tenancy_and_auth_foundation.sql)

## 4. Human identity and membership

The persistent model uses:

- `users` — email identity, password hash, identity state, distinct platform-admin flag;
- `tenant_memberships` — tenant, user, tenant role, and membership state;
- `tenants` — tenant metadata and active/disabled lifecycle.

Tenant roles are exactly:

```text
analyst
admin
superadmin
```

For this phase, the database permits historical disabled memberships but enforces at most one active membership per user through `uq_memberships_user_active`. There is no tenant switcher and no runtime tenant-selection flow.

## 5. Authentication and session revalidation

Login verifies the database-backed scrypt password hash, derives the user's single active membership in an active tenant, and issues a one-hour HS256 JWT containing exactly:

```text
sub
tenant_id
role
iat
exp
```

Every authenticated request re-queries `users`, `tenant_memberships`, and `tenants`. Missing membership, disabled user, disabled tenant, disabled membership, or role mismatch invalidates the session immediately with `401`.

Unknown, pending, and disabled identities execute the timing-equivalent dummy scrypt path and receive a generic authentication failure. JWT contents never grant platform authority; `is_platform_admin` is resolved from the database.

See [auth route](../../../backend/app/routes/auth.py), [auth context](../../../backend/app/auth.py), and [password cryptography](../../../backend/app/auth_crypto.py).

## 6. Pending identity lifecycle

Tenant superadmins may add a member by email. If no identity exists, the transaction creates:

```text
users.status = pending
users.password_hash = NULL
tenant_memberships.status = active
tenant_memberships.role = selected tenant role
```

Pending users cannot log in. A platform administrator manually sets the initial password through Pending User Activation, which changes the identity to active. This is trusted provisioning, not an invitation product.

Intentionally absent:

- public registration;
- invitation-email delivery;
- password reset or account recovery;
- self-activation;
- SSO/SAML.

## 7. Tenant Organization administration

Organization is a tenant-local administrative feature visible only to the current tenant's `superadmin`.

It supports:

- listing members;
- adding by email;
- assigning `analyst`, `admin`, or `superadmin`;
- changing role;
- enabling/disabling membership;
- removing membership.

The backend rejects removal, disabling, or demotion of the last active tenant superadmin with `409`. Platform Control sessions are explicitly denied every Organization member route even though their login-context membership uses the `superadmin` role.

See [Organization routes](../../../backend/app/routes/org.py) and [Organization console](../../../frontend/src/components/OrganizationConsole.tsx).

## 8. Platform Administration

Platform authority requires both:

```text
auth.tenant_id == PLATFORM_TENANT_ID
is_platform_admin == true
```

Platform Control is a login context, not a customer tenant. It is excluded from the platform tenant list and returns `404` if targeted through tenant detail, tenant update, initial-superadmin repair, or entitlement endpoints.

Platform Administration can:

- create operational tenants;
- view and update basic tenant metadata;
- enable or disable tenants;
- assign a base package and module overrides;
- assign the initial trusted tenant-superadmin email;
- activate pending identities.

Selecting a tenant in the dashboard changes only local administrative target state. It never changes the JWT, active membership, or operational tenant identity.

See [Platform routes](../../../backend/app/routes/platform.py), [Platform console](../../../frontend/src/components/PlatformAdminConsole.tsx), and [Platform Control migration](../../../backend/migrations/006_platform_control_tenant.sql).

## 9. Platform and tenant UI separation

Tenant workspace:

```text
/v2-assets/
  Tenant Console
    Assets
    Collectors
    future entitled tenant modules
  Tenant Administration
    Organization — superadmin only
```

Platform control plane:

```text
/v2-assets/platform-login
→ /v2-assets/platform-dashboard
  Tenants
  Packages / Entitlements
  Pending User Activation
```

The platform shell never renders Assets, Collectors, Organization, or tenant-module navigation. An authenticated platform session entering the tenant route is redirected to the platform dashboard. UI hiding is presentation only; backend guards remain authoritative.

See [application shell](../../../frontend/src/App.tsx) and [tenant sidebar](../../../frontend/src/components/Sidebar.tsx).

## 10. Module catalogue, packages, and effective entitlement

Persistent entitlement tables are:

- `modules` — canonical module catalogue;
- `packages` — package catalogue;
- `package_modules` — modules included by each package;
- `tenant_entitlements` — one base package plus validated boolean overrides per tenant.

The authoritative calculation is:

```text
(base package modules ∪ explicit true overrides) − explicit false overrides
= effective module access
```

Frontend terminology maps the tri-state representation as:

| Operator label | Stored meaning | Result |
|---|---|---|
| Inherit Package | key omitted | Use package state |
| Enabled | `true` | Force module on |
| Disabled | `false` | Force module off |

The resolver fails closed for disabled tenants, disabled catalogue modules, or missing tenant entitlements. `ASSETS` currently authorizes both Assets and Collectors. Platform Control always has no entitlement, and the shared module guard rejects Platform Control before resolution as defense in depth.

See [entitlement resolver](../../../backend/app/services/entitlements.py) and [catalogue migration](../../../backend/migrations/005_module_catalogue_and_entitlements.sql).

## 11. Tenant creation and concurrency

Tenant creation is one transaction:

```text
tenant
+ existing or pending user
+ active superadmin membership
+ default entitlement
```

The slug is generated deterministically from the tenant name and receives a numeric suffix when needed. Base package selection comes from the persisted package catalogue; unknown package IDs are rejected.

Tenant and entitlement updates use optimistic concurrency. Callers submit `expected_version`; stale writes return `409` and must reload instead of overwriting a concurrent administrator.

## 12. Collector boundary

Human JWT changes do not alter collector identity. Collectors retain their Ed25519 challenge-response protocol and database-bound `tenant_id`.

Enrollment and WebSocket authentication require an active tenant and effective `ASSETS` entitlement. Disabling a tenant closes its collector sessions with policy code `1008`, fails in-flight verification work as unverified, and rejects future enrollment and connection attempts.

The complete collector protocol and lifecycle remain documented in the [Assets & Collectors canonical guide](../ASSETS%20%26%20Collectors/ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md).

## 13. Audit behavior

Tenant operations write tenant-scoped audit events using the actual authenticated actor and role. Platform actions write under Platform Control with `actor_role = platform_admin` and place the administrative target tenant ID and sanitized before/after information in `details`.

Platform selection never rewrites the actor identity. Audit history is retained when collectors are deleted and is protected from tenant deletion by `ON DELETE RESTRICT`.

## 14. Bootstrap and deployment order

The standalone bootstrap command is:

```bash
python -m app.cli.bootstrap
```

It validates `ADMIN_USERNAME`, `ADMIN_PASSWORD_HASH`, and the exact Platform Control UUID. It creates or reconciles the platform user and Platform Control membership, preserves an existing password unless forced, and removes any accidental Platform Control entitlement.

For a pre-split environment, the safe order is:

1. back up PostgreSQL and verify the backup;
2. apply migration `006_platform_control_tenant.sql`;
3. atomically move the platform administrator membership from the operational tenant to Platform Control;
4. attach the separately approved superadmin to the real operational tenant;
5. run bootstrap as a fail-closed verification step;
6. switch the release atomically and restart the service;
7. verify live platform and tenant boundaries.

Migration 006 never guesses identities or moves production memberships.

## 15. Required security invariants

- Platform administrators cannot access tenant Assets, Collectors, or Organization members.
- Tenant superadmins cannot access Platform Administration.
- Analysts and admins cannot manage Organization membership or Platform Administration.
- Cross-tenant object reads and writes remain masked and scoped.
- Platform Control owns no operational data or module entitlement.
- Tenant selection in Platform Administration is never impersonation.
- One active membership per user remains enforced for this phase.
- Tenant switching remains absent.
- Last-active-superadmin protection remains fail-closed.
- Assets and Collectors contracts remain unchanged except for entitlement enforcement.

## 16. Verification baseline

The frozen foundation passed:

- 167 backend tests;
- 69 frontend tests;
- clean TypeScript and Vite production build;
- independent adversarial review;
- live platform checks: control-plane access `200`, tenant Assets/Collectors/Organization access `403`, Platform Control targeting `404`;
- public V2 health and platform routes `200`;
- V1 isolation checks.

Primary boundary regression coverage is in [identity boundary tests](../../../backend/tests/test_identity_boundary.py), [session revocation tests](../../../backend/tests/test_session_revocation.py), [tenancy isolation tests](../../../backend/tests/test_tenancy_isolation.py), and [frontend component tests](../../../frontend/src/tests/components.test.tsx).

## 17. Why not X?

| Question | Answer |
|---|---|
| Why not per-tenant tables? | Shared schemas with explicit tenant ownership are easier to migrate, query, constrain, and audit safely. |
| Why does Platform Control look like a tenant row? | The existing JWT contract requires one tenant-scoped login context. A dedicated context preserves that contract without granting operational membership. |
| Why not let a platform admin open a customer dashboard? | That is impersonation and creates actor, scope, and audit ambiguity. Administrative targets stay separate from operational identity. |
| Why no tenant switcher? | The approved phase allows one active membership per user. A switcher would add unused token and state complexity. |
| Why can Organization create pending users? | Trusted superadmins need to reserve membership and role before manual activation, without building invitations or onboarding. |
| Why compute effective modules instead of storing them? | Package plus overrides is the source of truth; a materialized effective table would add synchronization failure modes. |
| Why does ASSETS cover Collectors? | Collectors are the routing and verification mechanism supporting the Assets module, not a separately sold module in the frozen model. |

## 18. Maintenance and freeze rule

Do not redesign this foundation during SCOUT, SPECTRUM, or STRIKE implementation. Change it only for a verified security or compatibility defect, and use the smallest compatible correction with backend enforcement and regression coverage.

When a new module is implemented and frozen, create a sibling directory under `docs/Canonical Docs/` rather than expanding this guide into an unrelated module manual.
