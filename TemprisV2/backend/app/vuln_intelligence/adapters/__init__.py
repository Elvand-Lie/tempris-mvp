# backend/app/vuln_intelligence/adapters/__init__.py
"""
Source adapters for the vulnerability intelligence library.

Each adapter parses source-native record shapes into the Sprint 01 repository
primitives. No network I/O — adapters accept raw data (dicts, strings) and
call repository functions within a caller-supplied psycopg Connection.
"""
