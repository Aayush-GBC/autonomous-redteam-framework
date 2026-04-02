"""Tests for the storage layer: Database, repositories, and FileStore."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from artasf.core.models import (
    EngagementSession,
    LootItem,
    Port,
    PortState,
    Severity,
    Target,
    Vulnerability,
)
from artasf.storage.db import Database
from artasf.storage.file_store import FileStore
from artasf.storage.repos import LootRepository, SessionRepository, VulnRepository


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def sample_session() -> EngagementSession:
    return EngagementSession(name="test-engagement", target_network="10.0.0.0/24")


@pytest.fixture
def sample_target() -> Target:
    return Target(
        ip="10.0.0.1",
        ports=[Port(number=80, service="http", state=PortState.OPEN)],
    )


@pytest.fixture
def sample_vuln(sample_target: Target) -> Vulnerability:
    return Vulnerability(
        target_id=sample_target.id,
        title="SQL Injection",
        severity=Severity.HIGH,
        cvss_score=8.5,
        cve="CVE-2021-1234",
    )


@pytest.fixture
def sample_loot(sample_session: EngagementSession, sample_target: Target) -> LootItem:
    return LootItem(
        session_id=sample_session.id,
        target_id=sample_target.id,
        type="credential",
        value="admin:password123",
        source="/etc/passwd",
    )


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def test_database_opens_and_creates_schema(tmp_db: Path) -> None:
    async def _run() -> None:
        async with Database(tmp_db) as db:
            rows = await db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            table_names = {r["name"] for r in rows}
        assert "sessions" in table_names
        assert "targets" in table_names
        assert "vulns" in table_names
        assert "exploit_attempts" in table_names
        assert "loot" in table_names

    asyncio.run(_run())


def test_database_creates_parent_dirs(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c" / "test.db"

    async def _run() -> None:
        async with Database(nested) as db:
            await db.execute("SELECT 1")

    asyncio.run(_run())
    assert nested.exists()


def test_database_execute_and_fetchone(tmp_db: Path) -> None:
    async def _run() -> None:
        async with Database(tmp_db) as db:
            await db.execute(
                "INSERT INTO sessions (id, name, network, phase, status, started_at, json_blob) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("abc123", "test", "10.0.0.0/24", "init", "active", "2024-01-01T00:00:00", "{}"),
            )
            row = await db.fetchone("SELECT name FROM sessions WHERE id = ?", ("abc123",))
        assert row is not None
        assert row["name"] == "test"

    asyncio.run(_run())


def test_database_fetchall_empty(tmp_db: Path) -> None:
    async def _run() -> list:
        async with Database(tmp_db) as db:
            return await db.fetchall("SELECT * FROM sessions")

    rows = asyncio.run(_run())
    assert rows == []


def test_database_executemany(tmp_db: Path) -> None:
    async def _run() -> None:
        async with Database(tmp_db) as db:
            data = [
                ("id1", "eng1", "10.0.0.0/24", "init", "active", "2024-01-01T00:00:00", "{}"),
                ("id2", "eng2", "10.0.0.0/24", "init", "active", "2024-01-02T00:00:00", "{}"),
            ]
            await db.executemany(
                "INSERT INTO sessions (id, name, network, phase, status, started_at, json_blob) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                data,
            )
            rows = await db.fetchall("SELECT id FROM sessions ORDER BY id")
        assert [r["id"] for r in rows] == ["id1", "id2"]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# SessionRepository
# ---------------------------------------------------------------------------

def test_session_repo_save_and_load(tmp_db: Path, sample_session: EngagementSession) -> None:
    async def _run() -> EngagementSession | None:
        async with Database(tmp_db) as db:
            repo = SessionRepository(db)
            await repo.save(sample_session)
            return await repo.load(sample_session.id)

    loaded = asyncio.run(_run())
    assert loaded is not None
    assert loaded.id == sample_session.id
    assert loaded.name == sample_session.name
    assert loaded.target_network == sample_session.target_network


def test_session_repo_load_missing(tmp_db: Path) -> None:
    async def _run() -> EngagementSession | None:
        async with Database(tmp_db) as db:
            return await SessionRepository(db).load("nonexistent-id")

    assert asyncio.run(_run()) is None


def test_session_repo_save_replaces(tmp_db: Path, sample_session: EngagementSession) -> None:
    async def _run() -> str:
        async with Database(tmp_db) as db:
            repo = SessionRepository(db)
            await repo.save(sample_session)
            sample_session.name = "updated-name"  # type: ignore[misc]
            await repo.save(sample_session)
            loaded = await repo.load(sample_session.id)
        assert loaded is not None
        return loaded.name

    assert asyncio.run(_run()) == "updated-name"


def test_session_repo_list_all(tmp_db: Path) -> None:
    s1 = EngagementSession(name="first", target_network="10.0.0.0/24")
    s2 = EngagementSession(name="second", target_network="10.0.0.0/24")

    async def _run() -> list[EngagementSession]:
        async with Database(tmp_db) as db:
            repo = SessionRepository(db)
            await repo.save(s1)
            await repo.save(s2)
            return await repo.list_all()

    result = asyncio.run(_run())
    assert len(result) == 2
    names = {s.name for s in result}
    assert names == {"first", "second"}


def test_session_repo_delete(tmp_db: Path, sample_session: EngagementSession) -> None:
    async def _run() -> EngagementSession | None:
        async with Database(tmp_db) as db:
            repo = SessionRepository(db)
            await repo.save(sample_session)
            await repo.delete(sample_session.id)
            return await repo.load(sample_session.id)

    assert asyncio.run(_run()) is None


# ---------------------------------------------------------------------------
# VulnRepository
# ---------------------------------------------------------------------------

def test_vuln_repo_save_and_load(
    tmp_db: Path,
    sample_session: EngagementSession,
    sample_target: Target,
    sample_vuln: Vulnerability,
) -> None:
    async def _run() -> list[Vulnerability]:
        async with Database(tmp_db) as db:
            # Sessions row must exist first (FK constraint)
            await SessionRepository(db).save(sample_session)
            # Targets row must exist (FK on vulns.target_id)
            await db.execute(
                "INSERT INTO targets (id, session_id, ip, scanned_at, json_blob) VALUES (?,?,?,?,?)",
                (sample_target.id, sample_session.id, sample_target.ip,
                 "2024-01-01T00:00:00", sample_target.model_dump_json()),
            )
            repo = VulnRepository(db)
            await repo.save_all(sample_session.id, [sample_vuln])
            return await repo.load_for_session(sample_session.id)

    loaded = asyncio.run(_run())
    assert len(loaded) == 1
    assert loaded[0].title == "SQL Injection"
    assert loaded[0].cvss_score == 8.5


def test_vuln_repo_save_all_empty(tmp_db: Path, sample_session: EngagementSession) -> None:
    async def _run() -> list[Vulnerability]:
        async with Database(tmp_db) as db:
            await SessionRepository(db).save(sample_session)
            repo = VulnRepository(db)
            await repo.save_all(sample_session.id, [])
            return await repo.load_for_session(sample_session.id)

    assert asyncio.run(_run()) == []


# ---------------------------------------------------------------------------
# LootRepository
# ---------------------------------------------------------------------------

def test_loot_repo_save_and_load(
    tmp_db: Path,
    sample_session: EngagementSession,
    sample_loot: LootItem,
) -> None:
    async def _run() -> list[LootItem]:
        async with Database(tmp_db) as db:
            await SessionRepository(db).save(sample_session)
            repo = LootRepository(db)
            await repo.save_all([sample_loot])
            return await repo.load_for_session(sample_session.id)

    loaded = asyncio.run(_run())
    assert len(loaded) == 1
    assert loaded[0].type == "credential"
    assert loaded[0].value == "admin:password123"


def test_loot_repo_load_empty(tmp_db: Path, sample_session: EngagementSession) -> None:
    async def _run() -> list[LootItem]:
        async with Database(tmp_db) as db:
            await SessionRepository(db).save(sample_session)
            return await LootRepository(db).load_for_session(sample_session.id)

    assert asyncio.run(_run()) == []


# ---------------------------------------------------------------------------
# FileStore
# ---------------------------------------------------------------------------

def test_file_store_ensure_dirs(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "arts")
    store.ensure_dirs()
    assert store.scans.exists()
    assert store.loot.exists()
    assert store.reports.exists()
    assert store.sessions.exists()


def test_file_store_save_and_load_loot(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    content = "root:x:0:0:root:/root:/bin/bash"
    path = store.save_loot("shadow.txt", content, target_ip="10.0.0.1")
    assert path.exists()
    assert store.load_loot(path) == content


def test_file_store_list_loot(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    store.save_loot("a.txt", "aaa", target_ip="10.0.0.1")
    store.save_loot("b.txt", "bbb", target_ip="10.0.0.1")
    files = store.list_loot(target_ip="10.0.0.1")
    names = {p.name for p in files}
    assert "a.txt" in names
    assert "b.txt" in names


def test_file_store_list_loot_no_target(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    store.save_loot("x.txt", "xxx", target_ip="10.0.0.2")
    all_files = store.list_loot()
    assert len(all_files) >= 1


def test_file_store_session_json(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    data = '{"id": "abc123", "name": "test"}'
    path = store.save_session_json("abc123", "test-eng", data)
    assert path.exists()
    assert store.load_session_json(path) == data


def test_file_store_list_sessions(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    store.save_session_json("id1", "eng-one", '{"id":"id1"}')
    store.save_session_json("id2", "eng-two", '{"id":"id2"}')
    listed = store.list_sessions()
    assert len(listed) == 2


def test_file_store_save_and_list_reports(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    store.save_report("report.html", "<html><body>test</body></html>")
    reports = store.list_reports()
    assert any(r.name == "report.html" for r in reports)


def test_file_store_safe_name_special_chars(tmp_path: Path) -> None:
    store = FileStore(tmp_path)
    path = store.save_loot("my file:name?.txt", "data", target_ip="192.168.1.1")
    assert path.exists()
    # Special chars should be replaced, not cause filesystem errors
    assert "?" not in path.name
    assert ":" not in path.name
