# backend/app/db.py
from contextlib import contextmanager
from typing import Generator, Optional
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
import app.config

_pool: Optional[ConnectionPool] = None

def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None or _pool.closed:
        _pool = ConnectionPool(
            conninfo=app.config.DATABASE_URL,
            min_size=2,
            max_size=10,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=True
        )
    return _pool

def init_db():
    get_pool()

def close_db():
    global _pool
    if _pool is not None and not _pool.closed:
        _pool.close()
        _pool = None

@contextmanager
def get_db_connection() -> Generator[psycopg.Connection, None, None]:
    """
    Context manager for borrowing a connection from the pool.
    Ensures rollback on unhandled exception and returns connection to pool.
    """
    p = get_pool()
    with p.connection() as conn:
        yield conn

