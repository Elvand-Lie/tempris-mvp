# backend/app/migrations_check.py
import sys
from pathlib import Path
import psycopg
from app.db import get_db_connection

def ensure_migrations_applied():
    try:
        from migrations.runner import run_migrations
    except ImportError:
        try:
            from backend.migrations.runner import run_migrations
        except ImportError:
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
            from migrations.runner import run_migrations

    try:
        with get_db_connection() as conn:
            run_migrations(conn)
    except Exception as e:
        print(f"Warning: automatic migrations check encountered an error: {e}")

