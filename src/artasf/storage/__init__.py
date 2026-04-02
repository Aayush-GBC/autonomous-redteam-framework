"""
Storage layer — SQLite persistence (aiosqlite) + file-based artifact store.

Public API:
    Database          — async context manager wrapping aiosqlite
    SessionRepository — CRUD for EngagementSession
    VulnRepository    — CRUD for Vulnerability lists
    LootRepository    — CRUD for LootItem lists
    FileStore         — manage engagement artifact files (scans, loot, reports)
"""

from artasf.storage.db import Database
from artasf.storage.repos import LootRepository, SessionRepository, VulnRepository
from artasf.storage.file_store import FileStore

__all__ = [
    "Database",
    "FileStore",
    "LootRepository",
    "SessionRepository",
    "VulnRepository",
]
