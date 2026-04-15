"""
Repository layer — typed CRUD operations over the Database.

Each repository wraps a Database instance and serialises/deserialises
domain models to/from the JSON blob column.

Usage:
    async with Database(settings.db_path) as db:
        repo = SessionRepository(db)
        await repo.save(session)
        loaded = await repo.load(session.id)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from loguru import logger

from artasf.core.models import EngagementSession, ExploitAttempt, LootItem, Vulnerability

if TYPE_CHECKING:
    from artasf.storage.db import Database


class SessionRepository:
    """
    Persist and retrieve EngagementSession objects.

    The full session is stored as a JSON blob alongside indexed columns
    for fast filtering (phase, status, network, etc.).
    """

    def __init__(self, db: "Database") -> None:
        self._db = db

    async def save(self, session: EngagementSession) -> None:
        """Insert or replace a session record and upsert all its target rows."""
        await self._db.execute(
            """
            INSERT OR REPLACE INTO sessions
                (id, name, network, phase, status, started_at, ended_at, json_blob)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.id,
                session.name,
                session.target_network,
                session.phase.value,
                session.status.value,
                session.started_at.isoformat(),
                session.ended_at.isoformat() if session.ended_at else None,
                session.model_dump_json(),
            ),
        )
        # Upsert target rows so that vulns FK (targets.id) is satisfied.
        if session.targets:
            target_data = [
                (
                    t.id,
                    session.id,
                    t.ip,
                    t.hostname,
                    t.os_guess,
                    t.scanned_at.isoformat(),
                    t.model_dump_json(),
                )
                for t in session.targets
            ]
            await self._db.executemany(
                """
                INSERT OR REPLACE INTO targets
                    (id, session_id, ip, hostname, os_guess, scanned_at, json_blob)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                target_data,
            )
        logger.debug("Session saved to DB: id={}", session.id[:8])

    async def load(self, session_id: str) -> EngagementSession | None:
        """Load a session by ID.  Returns None if not found."""
        row = await self._db.fetchone(
            "SELECT json_blob FROM sessions WHERE id = ?",
            (session_id,),
        )
        if row is None:
            return None
        return EngagementSession.model_validate_json(row["json_blob"])

    async def list_all(self) -> list[EngagementSession]:
        """Return all sessions, newest first."""
        rows = await self._db.fetchall(
            "SELECT json_blob FROM sessions ORDER BY started_at DESC"
        )
        sessions: list[EngagementSession] = []
        for row in rows:
            try:
                sessions.append(EngagementSession.model_validate_json(row["json_blob"]))
            except Exception as exc:
                logger.warning("Could not deserialise session: {}", exc)
        return sessions

    async def delete(self, session_id: str) -> None:
        """Remove a session and all associated rows."""
        for table in ("loot", "exploit_attempts", "vulns", "targets"):
            await self._db.execute(
                f"DELETE FROM {table} WHERE session_id = ?",  # noqa: S608
                (session_id,),
            )
        await self._db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        logger.info("Session {} deleted from DB", session_id[:8])


class VulnRepository:
    """Persist and retrieve Vulnerability objects."""

    def __init__(self, db: "Database") -> None:
        self._db = db

    async def save_all(self, session_id: str, vulns: list[Vulnerability]) -> None:
        data = [
            (
                v.id,
                session_id,
                v.target_id,
                v.title,
                v.severity.value,
                v.cvss_score,
                v.cve,
                v.model_dump_json(),
            )
            for v in vulns
        ]
        await self._db.executemany(
            """
            INSERT OR REPLACE INTO vulns
                (id, session_id, target_id, title, severity, cvss_score, cve, json_blob)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )

    async def load_for_session(self, session_id: str) -> list[Vulnerability]:
        rows = await self._db.fetchall(
            "SELECT json_blob FROM vulns WHERE session_id = ?",
            (session_id,),
        )
        return [Vulnerability.model_validate_json(r["json_blob"]) for r in rows]


class ExploitAttemptRepository:
    """Persist and retrieve ExploitAttempt objects."""

    def __init__(self, db: "Database") -> None:
        self._db = db

    async def save_all(self, session_id: str, attempts: list[ExploitAttempt]) -> None:
        data = [
            (
                a.id,
                session_id,
                a.step,
                a.module,
                a.status.value,
                a.started_at.isoformat() if a.started_at else None,
                a.ended_at.isoformat() if a.ended_at else None,
                a.model_dump_json(),
            )
            for a in attempts
        ]
        await self._db.executemany(
            """
            INSERT OR REPLACE INTO exploit_attempts
                (id, session_id, step, module, status, started_at, ended_at, json_blob)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )

    async def load_for_session(self, session_id: str) -> list[ExploitAttempt]:
        rows = await self._db.fetchall(
            "SELECT json_blob FROM exploit_attempts WHERE session_id = ? ORDER BY step",
            (session_id,),
        )
        return [ExploitAttempt.model_validate_json(r["json_blob"]) for r in rows]


class LootRepository:
    """Persist and retrieve LootItem objects."""

    def __init__(self, db: "Database") -> None:
        self._db = db

    async def save_all(self, items: list[LootItem]) -> None:
        data = [
            (
                item.id,
                item.session_id,
                item.target_id,
                item.type,
                item.source,
                item.captured_at.isoformat(),
                item.model_dump_json(),
            )
            for item in items
        ]
        await self._db.executemany(
            """
            INSERT OR REPLACE INTO loot
                (id, session_id, target_id, type, source, captured_at, json_blob)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )

    async def load_for_session(self, session_id: str) -> list[LootItem]:
        rows = await self._db.fetchall(
            "SELECT json_blob FROM loot WHERE session_id = ?",
            (session_id,),
        )
        return [LootItem.model_validate_json(r["json_blob"]) for r in rows]
