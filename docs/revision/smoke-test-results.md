# Smoke Test Results

Execution date: 2026-07-19

Command:

    python scripts/smoke_test.py

Result: Passed with exit code 0.

## Verified Sequence

| Step | Result |
|---|---|
| Application health | 200 |
| Database connection and schema | Temporary SQLite database created |
| Fictional tenant-alpha login | 200 |
| Fictional tenant-beta login | 200 |
| Protected synthesis request | 200 |
| Alpha finding creation | 200 |
| Alpha finding retrieval | 200 and created ID present |
| Alpha request for Beta finding | 404 |
| Alpha audit event | BLFLAW_INTAKE present with authenticated actor |
| Tenant-scoped report generation | 200; artifact created under temporary report root |
| Tenant-scoped CISO summary | 200; tenant-alpha returned |
| Logout/session revocation | 200 |
| Reuse of revoked token | 401 |
| Cleanup | Temporary directory removed automatically |

## Data Safety

- Users, tenants, findings, passwords, tokens, and report data are fictional.
- Tokens and passwords are never printed.
- The database, evidence root, and report root exist only below C:/Tempris/.tmp during execution.
- No purge, sandbox reset, remote scan, network target, production database, or infrastructure command is invoked.
- The prior Windows SQLite cleanup lock was fixed by closing TestClient, disposing the engine, and leaving the temporary working directory before removal.
