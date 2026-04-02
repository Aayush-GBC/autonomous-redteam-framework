"""
Main pipeline orchestrator.

Ties together all pipeline stages:
  INIT → RECON → VULN_MAP → PLANNING (Claude) → EXPLOITING → POST_EXPLOIT → REPORTING → DONE

Usage (from CLI or tests):
    async with Orchestrator.from_settings() as orch:
        session = await orch.run()
"""

from __future__ import annotations

import signal
import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from artasf.core.config import settings
from artasf.core.exceptions import EngagementAborted, WorkflowError
from artasf.core.logging import configure_logging
from artasf.core.models import (
    EngagementSession,
    SessionStatus,
    WorkflowPhase,
)
from artasf.core.workflow import WorkflowStateMachine
from artasf.storage.db import Database
from artasf.storage.repos import LootRepository, SessionRepository, VulnRepository

if TYPE_CHECKING:
    pass


class Orchestrator:
    """
    Central coordinator for an autonomous red-team engagement.

    Each public `_run_*` method corresponds to one workflow phase.
    The orchestrator advances the state machine after each phase completes
    successfully, or calls sm.fail() on unrecoverable errors.
    """

    def __init__(self, session: EngagementSession) -> None:
        self.session = session
        self.sm = WorkflowStateMachine(WorkflowPhase.INIT)
        self._abort_event = asyncio.Event()
        self._db: Database | None = None
        self._session_repo: SessionRepository | None = None
        self._vuln_repo: VulnRepository | None = None
        self._loot_repo: LootRepository | None = None

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_settings(cls) -> "Orchestrator":
        """Create a new orchestrator wired to the global settings singleton."""
        settings.ensure_dirs()
        configure_logging(
            log_dir=settings.artifacts_dir / "logs",
            level="DEBUG" if settings.dry_run else "INFO",
        )
        session = EngagementSession(
            name=settings.engagement_name,
            target_network=settings.target_network,
        )
        logger.info(
            "New engagement session: id={} network={}",
            session.id,
            settings.target_network,
        )
        return cls(session)

    # ------------------------------------------------------------------
    # Context-manager support  (async with Orchestrator.from_settings())
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "Orchestrator":
        self._install_signal_handlers()
        self._db = Database(settings.db_path)
        await self._db.__aenter__()
        self._session_repo = SessionRepository(self._db)
        self._vuln_repo = VulnRepository(self._db)
        self._loot_repo = LootRepository(self._db)
        await self._session_repo.save(self.session)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self.session.status == SessionStatus.ACTIVE:
            self.session.status = SessionStatus.ABORTED
            self.session.ended_at = datetime.now(timezone.utc)
        if self._session_repo is not None:
            try:
                await self._session_repo.save(self.session)
            except Exception as exc:
                logger.warning("Final DB save failed: {}", exc)
        if self._db is not None:
            await self._db.__aexit__(None, None, None)
            self._db = None

    # ------------------------------------------------------------------
    # Top-level run
    # ------------------------------------------------------------------

    async def run(self) -> EngagementSession:
        """Execute the full pipeline and return the completed session."""
        try:
            await self._run_recon()
            await self._run_vuln_map()
            await self._run_planning()

            if not settings.dry_run:
                await self._run_exploiting()
                await self._run_post_exploit()
            else:
                logger.warning("dry_run=True — skipping exploitation phases")
                self.sm.advance(WorkflowPhase.EXPLOITING)
                self.sm.advance(WorkflowPhase.POST_EXPLOIT)
                self.sm.advance(WorkflowPhase.REPORTING)
                self.session.phase = WorkflowPhase.REPORTING

            await self._run_reporting()

            self.sm.advance(WorkflowPhase.DONE)
            self.session.phase = WorkflowPhase.DONE
            self.session.status = SessionStatus.COMPLETED
            self.session.ended_at = datetime.now(timezone.utc)
            logger.success("Engagement complete: session={}", self.session.id)

        except EngagementAborted:
            logger.warning("Engagement aborted by user")
            self.sm.fail("user abort")
            self.session.phase = WorkflowPhase.FAILED
            self.session.status = SessionStatus.ABORTED
            self.session.ended_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.exception("Unhandled error in pipeline: {}", exc)
            self.sm.fail(str(exc))
            self.session.phase = WorkflowPhase.FAILED
            self.session.status = SessionStatus.FAILED
            self.session.ended_at = datetime.now(timezone.utc)

        return self.session

    # ------------------------------------------------------------------
    # Phase runners  (stubs — each module fills these in)
    # ------------------------------------------------------------------

    async def _run_recon(self) -> None:
        self.sm.advance(WorkflowPhase.RECON)
        self.session.phase = WorkflowPhase.RECON
        self._check_abort()

        logger.info("Starting recon on {}", settings.target_network)

        # Lazy import so recon module can be tested independently
        from artasf.recon.nmap_runner import NmapRunner
        from artasf.recon.nmap_parser import parse_nmap_xml
        from artasf.recon.http_enrich import enrich_http_ports
        from artasf.recon.dns_enum import enumerate_dns

        runner = NmapRunner(settings.target_network, flags=settings.nmap_flags)
        xml_path = await runner.run()
        targets = parse_nmap_xml(xml_path)

        # Fallback: if nmap found nothing and target is a specific IP, probe
        # port 80 directly and add a minimal host entry so the pipeline continues
        if not targets and "/" not in settings.target_network:
            targets = await _tcp_fallback(settings.target_network)

        for target in targets:
            await enrich_http_ports(target)

        dns_names = await enumerate_dns(settings.target_network)
        for target in targets:
            if target.ip in dns_names:
                target.hostname = dns_names[target.ip]

        self.session.targets = targets
        logger.info("Recon complete: {} host(s) found", len(targets))
        await self._persist()

    async def _run_vuln_map(self) -> None:
        self.sm.advance(WorkflowPhase.VULN_MAP)
        self.session.phase = WorkflowPhase.VULN_MAP
        self._check_abort()

        logger.info("Mapping vulnerabilities across {} target(s)", len(self.session.targets))

        from artasf.vulnmap.mapper import VulnMapper

        mapper = VulnMapper()
        for target in self.session.targets:
            vulns = await mapper.map(target)
            self.session.vulns.extend(vulns)

        logger.info("Vuln map complete: {} vulnerabilities found", len(self.session.vulns))
        if self._vuln_repo is not None:
            await self._vuln_repo.save_all(self.session.id, self.session.vulns)
        await self._persist()

    async def _run_planning(self) -> None:
        self.sm.advance(WorkflowPhase.PLANNING)
        self.session.phase = WorkflowPhase.PLANNING
        self._check_abort()

        logger.info("Invoking Claude ({}) to build attack plan", settings.claude_model)

        from artasf.planner.planner import AIPlanner

        planner = AIPlanner()
        plan = await planner.plan(self.session)
        self.session.plan = plan

        logger.info(
            "Attack plan ready: {} step(s) | model={}",
            len(plan.steps),
            plan.model_used,
        )
        await self._persist()

    async def _run_exploiting(self) -> None:
        self.sm.advance(WorkflowPhase.EXPLOITING)
        self.session.phase = WorkflowPhase.EXPLOITING
        self._check_abort()

        if self.session.plan is None:
            logger.warning("No attack plan — skipping exploitation")
            return

        logger.info("Starting exploitation ({} steps)", len(self.session.plan.steps))

        from artasf.exploit.executor import ExploitExecutor

        executor = ExploitExecutor(self.session)
        await executor.run_plan(self.session.plan)

        successes = len(self.session.successful_attempts())
        logger.info("Exploitation complete: {}/{} steps succeeded", successes, len(self.session.plan.steps))
        await self._persist()

    async def _run_post_exploit(self) -> None:
        # Only enter post-exploit if we have at least one open session
        if not self.session.successful_attempts():
            logger.info("No successful exploits — skipping post-exploitation")
            # Jump straight to reporting
            self.sm.advance(WorkflowPhase.POST_EXPLOIT)
            self.sm.advance(WorkflowPhase.REPORTING)
            self.session.phase = WorkflowPhase.REPORTING
            return

        self.sm.advance(WorkflowPhase.POST_EXPLOIT)
        self.session.phase = WorkflowPhase.POST_EXPLOIT
        self._check_abort()

        logger.info("Starting post-exploitation")

        from artasf.post.enum import PostEnumerator
        from artasf.post.privesc import PrivescHandler
        from artasf.post.loot import LootCollector
        from artasf.post.webshell import WebShellPostExploit
        from artasf.exploit.msf_rpc import MSFClient

        # Partition successful attempts by access type
        msf_attempts = [
            a for a in self.session.successful_attempts()
            if a.msf_session_id is not None
        ]
        webshell_attempts = [
            a for a in self.session.successful_attempts()
            if a.msf_session_id is None and "cmd_inject" in a.module
        ]

        # ── MSF session post-exploit ──────────────────────────────────────
        if msf_attempts:
            async with MSFClient.connect() as msf:
                for attempt in msf_attempts:
                    sid = attempt.msf_session_id

                    enum = PostEnumerator(sid, self.session, msf)
                    post_data = await enum.collect(msf)
                    self.session.post_data.append(post_data)

                    priv = PrivescHandler(sid, self.session, msf)
                    await priv.attempt(post_data, msf)

                    loot = LootCollector(sid, self.session, msf)
                    items = await loot.collect(post_data, msf)
                    self.session.loot.extend(items)

        # ── Web-shell post-exploit ────────────────────────────────────────
        if webshell_attempts:
            ws_handler = WebShellPostExploit(self.session)
            for attempt in webshell_attempts:
                target_ip = _get_target_ip(self.session, attempt.target_id)
                post_data, items = await ws_handler.collect(attempt, target_ip)
                self.session.post_data.append(post_data)
                self.session.loot.extend(items)

        logger.info(
            "Post-exploitation complete: {} loot items collected",
            len(self.session.loot),
        )
        if self._loot_repo is not None and self.session.loot:
            await self._loot_repo.save_all(self.session.loot)
        await self._persist()

    async def _run_reporting(self) -> None:
        if self.sm.current != WorkflowPhase.REPORTING:
            self.sm.advance(WorkflowPhase.REPORTING)
        self.session.phase = WorkflowPhase.REPORTING
        self._check_abort()

        logger.info("Generating report")

        from artasf.reporting.render import ReportRenderer

        renderer = ReportRenderer(settings.reports_dir)
        html_path = await renderer.render_html(self.session)
        pdf_path  = await renderer.render_pdf(html_path)

        logger.success("Report saved: HTML={} PDF={}", html_path, pdf_path)
        await self._persist()

    # ------------------------------------------------------------------
    # Persistence helper
    # ------------------------------------------------------------------

    async def _persist(self) -> None:
        """Save current session state to the DB.  Silent on failure."""
        if self._session_repo is None:
            return
        try:
            await self._session_repo.save(self.session)
        except Exception as exc:
            logger.warning("DB persist failed (phase={}): {}", self.session.phase, exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_abort(self) -> None:
        """Raise EngagementAborted if SIGINT/SIGTERM was received."""
        if self._abort_event.is_set():
            raise EngagementAborted()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()

        def _handle_signal() -> None:
            logger.warning("Interrupt received — aborting engagement gracefully")
            self._abort_event.set()

        def _signal_cb(signum: int, frame: object) -> None:  # noqa: ARG001
            _handle_signal()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _handle_signal)
            except (NotImplementedError, RuntimeError):
                # Windows: add_signal_handler not supported on ProactorEventLoop
                signal.signal(sig, _signal_cb)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_target_ip(session: "EngagementSession", target_id: str) -> str:
    """Resolve the IP for *target_id*, falling back to the first known target."""
    from artasf.core.models import EngagementSession as _ES  # noqa: F401
    for t in session.targets:
        if t.id == target_id or t.id.startswith(target_id):
            return t.ip
    if len(session.targets) == 1:
        return session.targets[0].ip
    return "127.0.0.1"


async def _tcp_fallback(ip: str, ports: list[int] | None = None) -> "list":
    """
    If nmap returns no hosts for a specific IP, try opening TCP connections
    directly.  Returns a list containing one minimal Target if any port is
    reachable, or an empty list.
    """
    from artasf.core.models import Target, Port, PortState

    check_ports = ports or [80, 443, 8080, 8443]
    open_ports: list[Port] = []

    for port in check_ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3.0
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            service = {80: "http", 443: "https", 8080: "http", 8443: "https"}.get(port, "unknown")
            open_ports.append(Port(number=port, service=service, state=PortState.OPEN))
            logger.info("TCP fallback: {}:{} is open ({})", ip, port, service)
        except Exception:
            pass

    if open_ports:
        logger.warning(
            "nmap found no hosts but TCP fallback found {} open port(s) on {} — "
            "adding host manually (check nmap permissions / VM network)",
            len(open_ports), ip,
        )
        return [Target(ip=ip, ports=open_ports)]

    logger.error(
        "TCP fallback also failed — {} appears unreachable. "
        "Check that the target VM is running and the network adapter is up.",
        ip,
    )
    return []
