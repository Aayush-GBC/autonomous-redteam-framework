"""
SQLite database connection manager via aiosqlite.

Usage:
    async with Database(path) as db:
        await db.execute("CREATE TABLE IF NOT EXISTS ...")
        await db.fetchall("SELECT * FROM sessions")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite
from loguru import logger


class Database:
    """
    Thin async context manager wrapping aiosqlite.

    Args:
        path: Path to the SQLite database file.
              Directories are created automatically.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn: aiosqlite.Connection | None = None

    async def __aenter__(self) -> "Database":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        logger.debug("Database opened: {}", self.path)
        await self._create_schema()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    async def _create_schema(self) -> None:
        assert self._conn is not None
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                network     TEXT NOT NULL,
                phase       TEXT NOT NULL DEFAULT 'init',
                status      TEXT NOT NULL DEFAULT 'active',
                started_at  TEXT NOT NULL,
                ended_at    TEXT,
                json_blob   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS targets (
                id          TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL REFERENCES sessions(id),
                ip          TEXT NOT NULL,
                hostname    TEXT,
                os_guess    TEXT,
                scanned_at  TEXT NOT NULL,
                json_blob   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vulns (
                id          TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL REFERENCES sessions(id),
                target_id   TEXT NOT NULL REFERENCES targets(id),
                title       TEXT NOT NULL,
                severity    TEXT NOT NULL,
                cvss_score  REAL,
                cve         TEXT,
                json_blob   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exploit_attempts (
                id          TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL REFERENCES sessions(id),
                step        INTEGER NOT NULL,
                module      TEXT NOT NULL,
                status      TEXT NOT NULL,
                started_at  TEXT,
                ended_at    TEXT,
                json_blob   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS loot (
                id          TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL REFERENCES sessions(id),
                target_id   TEXT NOT NULL,
                type        TEXT NOT NULL,
                source      TEXT,
                captured_at TEXT NOT NULL,
                json_blob   TEXT NOT NULL
            );
        """)
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        assert self._conn is not None
        await self._conn.execute(sql, params)
        await self._conn.commit()

    async def fetchone(
        self, sql: str, params: tuple[Any, ...] = ()
    ) -> aiosqlite.Row | None:
        assert self._conn is not None
        async with self._conn.execute(sql, params) as cur:
            return await cur.fetchone()

    async def fetchall(
        self, sql: str, params: tuple[Any, ...] = ()
    ) -> list[aiosqlite.Row]:
        assert self._conn is not None
        async with self._conn.execute(sql, params) as cur:
            return await cur.fetchall()

    async def executemany(
        self, sql: str, data: list[tuple[Any, ...]]
    ) -> None:
        assert self._conn is not None
        await self._conn.executemany(sql, data)
        await self._conn.commit()
