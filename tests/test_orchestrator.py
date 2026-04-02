"""
Unit tests for Orchestrator — pipeline lifecycle, phase sequencing,
abort handling, persistence, and helpers.

All external I/O (nmap, Claude, MSF, DB, reporting) is mocked so these
tests run without a live lab, API key, or database.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from artasf.core.exceptions import EngagementAborted
from artasf.core.models import (
    AttackPlan,
    AttackStep,
    EngagementSession,
    Port,
    PortState,
    SessionStatus,
    Severity,
    Target,
    Vulnerability,
    WorkflowPhase,
)
from artasf.core.orchestrator import Orchestrator, _get_target_ip, _tcp_fallback


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_target(ip: str = "192.168.56.101") -> Target:
    return Target(
        ip=ip,
        ports=[Port(number=80, service="http", state=PortState.OPEN)],
    )


def _make_vuln(target_id: str) -> Vulnerability:
    return Vulnerability(
        target_id=target_id,
        title="SQL Injection",
        severity=Severity.HIGH,
        description="Classic SQLi in login form",
    )


def _make_plan(session_id: str, target: Target, vuln_id: str) -> AttackPlan:
    step = AttackStep(
        step=1,
        target_id=target.id,
        vuln_id=vuln_id,
        module="exploit/multi/http/sqli",
        rationale="Classic SQLi vector",
    )
    return AttackPlan(session_id=session_id, steps=[step], model_used="claude-sonnet-4-6")


@pytest.fixture
def session() -> EngagementSession:
    return EngagementSession(name="test-eng", target_network="192.168.56.0/24")


@pytest.fixture
def orch(session: EngagementSession) -> Orchestrator:
    return Orchestrator(session)


# ---------------------------------------------------------------------------
# DB / repo mocks reused across tests
# ---------------------------------------------------------------------------

def _mock_db_stack(orch: Orchestrator) -> tuple[MagicMock, MagicMock]:
    """Patch Database and all three repos on *orch* in place."""
    db = MagicMock()
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)

    repo = MagicMock()
    repo.save = AsyncMock()
    repo.save_all = AsyncMock()

    orch._db = db
    orch._session_repo = repo
    orch._vuln_repo = repo
    orch._loot_repo = repo
    return db, repo


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_init_creates_abort_event(orch: Orchestrator) -> None:
    assert not orch._abort_event.is_set()


def test_from_settings_creates_orchestrator(tmp_path: Path) -> None:
    with (
        patch("artasf.core.orchestrator.settings") as s,
        patch("artasf.core.orchestrator.configure_logging"),
    ):
        s.engagement_name = "eng"
        s.target_network = "10.0.0.0/24"
        s.artifacts_dir = tmp_path
        s.dry_run = False
        s.ensure_dirs = MagicMock()
        result = Orchestrator.from_settings()
    assert isinstance(result, Orchestrator)
    assert result.session.target_network == "10.0.0.0/24"


# ---------------------------------------------------------------------------
# Context manager lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aenter_opens_db_and_saves_session(
    tmp_path: Path, session: EngagementSession
) -> None:
    orch = Orchestrator(session)

    db_mock = MagicMock()
    db_mock.__aenter__ = AsyncMock(return_value=db_mock)
    db_mock.__aexit__ = AsyncMock(return_value=False)
    save_mock = AsyncMock()

    with (
        patch("artasf.core.orchestrator.Database", return_value=db_mock),
        patch("artasf.core.orchestrator.SessionRepository") as SR,
        patch("artasf.core.orchestrator.VulnRepository"),
        patch("artasf.core.orchestrator.LootRepository"),
        patch("artasf.core.orchestrator.settings") as s,
        patch.object(orch, "_install_signal_handlers"),
    ):
        s.db_path = tmp_path / "test.db"
        SR.return_value.save = save_mock
        await orch.__aenter__()

    save_mock.assert_awaited_once_with(session)


@pytest.mark.asyncio
async def test_aexit_marks_active_session_as_aborted(session: EngagementSession) -> None:
    orch = Orchestrator(session)
    session.status = SessionStatus.ACTIVE
    _, repo = _mock_db_stack(orch)

    await orch.__aexit__(None, None, None)

    assert session.status == SessionStatus.ABORTED
    assert session.ended_at is not None
    repo.save.assert_awaited()


@pytest.mark.asyncio
async def test_aexit_does_not_overwrite_completed_status(session: EngagementSession) -> None:
    orch = Orchestrator(session)
    session.status = SessionStatus.COMPLETED
    _mock_db_stack(orch)

    await orch.__aexit__(None, None, None)

    assert session.status == SessionStatus.COMPLETED


@pytest.mark.asyncio
async def test_aexit_survives_db_save_failure(session: EngagementSession) -> None:
    orch = Orchestrator(session)
    session.status = SessionStatus.ACTIVE
    db, repo = _mock_db_stack(orch)
    repo.save.side_effect = RuntimeError("disk full")

    # Should not raise
    await orch.__aexit__(None, None, None)


# ---------------------------------------------------------------------------
# _check_abort
# ---------------------------------------------------------------------------

def test_check_abort_raises_when_set(orch: Orchestrator) -> None:
    orch._abort_event.set()
    with pytest.raises(EngagementAborted):
        orch._check_abort()


def test_check_abort_silent_when_clear(orch: Orchestrator) -> None:
    orch._check_abort()  # must not raise


# ---------------------------------------------------------------------------
# _persist
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_persist_saves_session(orch: Orchestrator) -> None:
    _, repo = _mock_db_stack(orch)
    await orch._persist()
    repo.save.assert_awaited_once_with(orch.session)


@pytest.mark.asyncio
async def test_persist_silent_on_error(orch: Orchestrator) -> None:
    _, repo = _mock_db_stack(orch)
    repo.save.side_effect = RuntimeError("boom")
    await orch._persist()  # must not raise


@pytest.mark.asyncio
async def test_persist_noop_without_repo(orch: Orchestrator) -> None:
    orch._session_repo = None
    await orch._persist()  # must not raise


# ---------------------------------------------------------------------------
# Full run() — happy path (dry_run=True → skip exploit/post)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_dry_run_completes(session: EngagementSession) -> None:
    orch = Orchestrator(session)
    _mock_db_stack(orch)

    target = _make_target()
    vuln = _make_vuln(target.id)
    plan = _make_plan(session.id, target, vuln.id)

    with (
        patch("artasf.core.orchestrator.settings") as s,
        patch("artasf.recon.nmap_runner.NmapRunner") as MockRunner,
        patch("artasf.recon.nmap_parser.parse_nmap_xml", return_value=[target]),
        patch("artasf.recon.http_enrich.enrich_http_ports", new=AsyncMock()),
        patch("artasf.recon.dns_enum.enumerate_dns", new=AsyncMock(return_value={})),
        patch("artasf.vulnmap.mapper.VulnMapper") as MockMapper,
        patch("artasf.planner.planner.AIPlanner") as MockPlanner,
        patch("artasf.reporting.render.ReportRenderer") as MockRenderer,
    ):
        s.dry_run = True
        s.nmap_flags = "-sV"
        s.target_network = "192.168.56.0/24"
        s.nmap_timeout_sec = 60
        s.claude_model = "claude-sonnet-4-6"
        s.reports_dir = Path("/tmp/reports")

        runner_inst = MagicMock()
        runner_inst.run = AsyncMock(return_value=Path("/tmp/scan.xml"))
        MockRunner.return_value = runner_inst

        mapper_inst = MagicMock()
        mapper_inst.map = AsyncMock(return_value=[vuln])
        MockMapper.return_value = mapper_inst

        planner_inst = MagicMock()
        planner_inst.plan = AsyncMock(return_value=plan)
        MockPlanner.return_value = planner_inst

        renderer_inst = MagicMock()
        renderer_inst.render_html = AsyncMock(return_value=Path("/tmp/report.html"))
        renderer_inst.render_pdf = AsyncMock(return_value=Path("/tmp/report.pdf"))
        MockRenderer.return_value = renderer_inst

        result = await orch.run()

    assert result.status == SessionStatus.COMPLETED
    assert result.phase == WorkflowPhase.DONE
    assert result.ended_at is not None
    assert result.targets == [target]
    assert vuln in result.vulns
    assert result.plan == plan


# ---------------------------------------------------------------------------
# Full run() — abort path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_abort_sets_aborted_status(session: EngagementSession) -> None:
    orch = Orchestrator(session)
    _mock_db_stack(orch)

    async def _raise_abort(*_: Any, **__: Any) -> None:
        raise EngagementAborted()

    with patch.object(orch, "_run_recon", _raise_abort):
        result = await orch.run()

    assert result.status == SessionStatus.ABORTED
    assert result.phase == WorkflowPhase.FAILED


# ---------------------------------------------------------------------------
# Full run() — unhandled error path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_unhandled_error_sets_failed_status(session: EngagementSession) -> None:
    orch = Orchestrator(session)
    _mock_db_stack(orch)

    async def _raise(*_: Any, **__: Any) -> None:
        raise ValueError("unexpected")

    with patch.object(orch, "_run_recon", _raise):
        result = await orch.run()

    assert result.status == SessionStatus.FAILED
    assert result.phase == WorkflowPhase.FAILED


# ---------------------------------------------------------------------------
# _get_target_ip helper
# ---------------------------------------------------------------------------

def test_get_target_ip_exact_match(session: EngagementSession) -> None:
    t = _make_target("10.0.0.5")
    session.targets = [t]
    assert _get_target_ip(session, t.id) == "10.0.0.5"


def test_get_target_ip_prefix_match(session: EngagementSession) -> None:
    t = _make_target("10.0.0.5")
    session.targets = [t]
    assert _get_target_ip(session, t.id[:8]) == "10.0.0.5"


def test_get_target_ip_single_target_fallback(session: EngagementSession) -> None:
    t = _make_target("10.0.0.5")
    session.targets = [t]
    assert _get_target_ip(session, "nonexistent-id") == "10.0.0.5"


def test_get_target_ip_unknown_returns_loopback(session: EngagementSession) -> None:
    t1 = _make_target("10.0.0.5")
    t2 = _make_target("10.0.0.6")
    session.targets = [t1, t2]
    assert _get_target_ip(session, "nonexistent-id") == "127.0.0.1"


# ---------------------------------------------------------------------------
# _tcp_fallback helper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tcp_fallback_returns_target_on_open_port() -> None:
    async def _mock_open(*_: Any) -> tuple:
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        return MagicMock(), writer

    with patch("asyncio.open_connection", _mock_open):
        targets = await _tcp_fallback("192.168.56.101", ports=[80])

    assert len(targets) == 1
    assert targets[0].ip == "192.168.56.101"
    assert any(p.number == 80 for p in targets[0].ports)


@pytest.mark.asyncio
async def test_tcp_fallback_returns_empty_on_all_closed() -> None:
    async def _mock_open(*_: Any, **__: Any) -> None:
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", _mock_open):
        targets = await _tcp_fallback("192.168.56.101", ports=[80, 443])

    assert targets == []
