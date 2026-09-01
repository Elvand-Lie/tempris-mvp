# backend/migrations/runner.py
import os
from pathlib import Path
import psycopg
from dotenv import load_dotenv

load_dotenv()

MIGRATIONS_DIR = Path(__file__).resolve().parent

def run_migrations(conn: psycopg.Connection):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id SERIAL PRIMARY KEY,
                version TEXT NOT NULL UNIQUE,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """)
        conn.commit()

        cur.execute("SELECT version FROM schema_migrations;")
        rows = cur.fetchall()
        applied = {row["version"] if isinstance(row, dict) else row[0] for row in rows}

        sql_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
        for sql_file in sql_files:
            version = sql_file.name
            if version not in applied:
                print(f"Applying migration {version}...")
                sql_content = sql_file.read_text(encoding="utf-8")
                cur.execute(sql_content)
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s);",
                    (version,)
                )
                conn.commit()
                print(f"Applied migration {version}")

def main():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    with psycopg.connect(db_url) as conn:
        run_migrations(conn)

if __name__ == "__main__":
    main()
