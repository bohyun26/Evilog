"""
SQLite-backed store with a REAL bounded connection pool.

The pool is not a simulation: it holds `POOL_SIZE` genuine sqlite3
connections behind an asyncio.Semaphore. When request handlers hold
connections longer than the arrival rate allows, waiters genuinely
queue and genuinely time out. That is what produces the incident
cascade the RCA agent has to diagnose.
"""

import asyncio
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path

from .logging_config import Timer, emit

DB_PATH = os.getenv("DB_PATH", "/tmp/realworld.db")
POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
POOL_TIMEOUT_S = float(os.getenv("DB_POOL_TIMEOUT_S", "2.0"))
SLOW_QUERY_MS = float(os.getenv("SLOW_QUERY_MS", "150"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT DEFAULT '',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    body TEXT DEFAULT '',
    author_id INTEGER NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


# Per-request database accounting.
_db_ms: ContextVar[float] = ContextVar("db_ms", default=0.0)
_db_count: ContextVar[int] = ContextVar("db_count", default=0)


def reset_db_stats() -> None:
    _db_ms.set(0.0)
    _db_count.set(0)


def request_db_stats() -> dict:
    return {"total_ms": round(_db_ms.get(), 2), "count": _db_count.get()}


class PoolTimeout(Exception):
    """Raised when a caller could not acquire a connection in time."""


class ConnectionPool:
    def __init__(self, path: str, size: int):
        self._path = path
        self._size = size
        self._sem = asyncio.Semaphore(size)
        self._free: list[sqlite3.Connection] = []
        self._lock = asyncio.Lock()
        self.in_use = 0

    def _new_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    async def init(self) -> None:
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        conn = self._new_conn()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
        async with self._lock:
            self._free = [self._new_conn() for _ in range(self._size)]
        emit("info", "db.pool.ready", "Connection pool initialised",
             pool_size=self._size, db_path=self._path)

    @asynccontextmanager
    async def acquire(self):
        waited_ms = 0.0
        with Timer() as t:
            try:
                await asyncio.wait_for(self._sem.acquire(), timeout=POOL_TIMEOUT_S)
            except asyncio.TimeoutError:
                waited_ms = round(POOL_TIMEOUT_S * 1000, 2)
                emit("error", "db.pool.timeout",
                     "Timed out waiting for a database connection",
                     waited_ms=waited_ms, pool_size=self._size,
                     in_use=self.in_use)
                raise PoolTimeout(
                    f"no connection available after {waited_ms}ms"
                ) from None
        waited_ms = t.ms

        if waited_ms > 50:
            emit("warn", "db.pool.wait",
                 "Waited for a database connection",
                 waited_ms=waited_ms, pool_size=self._size,
                 in_use=self.in_use)

        async with self._lock:
            conn = self._free.pop()
        self.in_use += 1
        try:
            yield conn
        finally:
            self.in_use -= 1
            async with self._lock:
                self._free.append(conn)
            self._sem.release()

    async def close(self) -> None:
        async with self._lock:
            for conn in self._free:
                conn.close()
            self._free.clear()


pool = ConnectionPool(DB_PATH, POOL_SIZE)


async def query(conn: sqlite3.Connection, sql: str, params=(), *, tag: str = ""):
    """Run a query off the event loop and log it if it is slow."""
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    rows = await loop.run_in_executor(
        None, lambda: conn.execute(sql, params).fetchall()
    )
    ms = round((time.perf_counter() - start) * 1000, 2)
    _db_ms.set(_db_ms.get() + ms)
    _db_count.set(_db_count.get() + 1)
    if ms >= SLOW_QUERY_MS:
        emit("warn", "db.query.slow", "Slow query",
             duration_ms=ms, query_tag=tag or sql.split()[0].lower(),
             rows=len(rows))
    return rows


async def execute(conn: sqlite3.Connection, sql: str, params=()):
    loop = asyncio.get_running_loop()

    def _run():
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid

    return await loop.run_in_executor(None, _run)
