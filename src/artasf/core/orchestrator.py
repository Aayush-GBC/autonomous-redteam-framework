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
        return self

    async def __aexit__(self, *_: object) -> None:
        if self.session.status == SessionStatus.ACTIVE:
            self.session.status = SessionStatus.ABORTED
            self.session.ended_at = datetime.now(timezone.utc)

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

        for target in targets:
            await enrich_http_ports(target)

        dns_names = await enumerate_dns(settings.target_network)
        for target in targets:
            if target.ip in dns_names:
                target.hostname = dns_names[target.ip]

        self.session.targets = targets
        logger.info("Recon complete: {} host(s) found", len(targets))

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
        from artasf.exploit.msf_rpc import MSFClient

        async with MSFClient.connect() as msf:
            for attempt in self.session.successful_attempts():
                if attempt.msf_session_id is None:
                    continue
                sid = attempt.msf_session_id

                enum = PostEnumerator(sid, self.session, msf)
                post_data = await enum.collect(msf)
                self.session.post_data.append(post_data)

                priv = PrivescHandler(sid, self.session, msf)
                await priv.attempt(post_data, msf)

                loot = LootCollector(sid, self.session, msf)
                items = await loot.collect(post_data, msf)
                self.session.loot.extend(items)

        logger.info(
            "Post-exploitation complete: {} loot items collected",
            len(self.session.loot),
        )

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
