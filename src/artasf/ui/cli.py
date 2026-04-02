"""
ARTASF command-line interface.

Entry point: artasf (registered in pyproject.toml)

Commands:
  artasf run              — full autonomous pipeline (recon → plan → exploit → report)
  artasf scan             — recon + vuln-map only (no exploitation)
  artasf plan             — load a previous scan and generate an AI attack plan
  artasf report           — (re)generate report from a saved session JSON
  artasf sessions list    — list saved sessions from the database
  artasf sessions show    — print full detail for one session
  artasf sessions delete  — remove a session from the database
  artasf db init          — initialise (or verify) the database schema
  artasf version          — print version and exit
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from artasf import __version__
from artasf.core.config import settings
from artasf.core.logging import configure_logging
from artasf.ui.console_views import (
    console,
    print_banner,
    print_phase,
    print_targets,
    print_vulns,
    print_plan,
    print_attempts,
    print_loot,
    print_summary,
)

app          = typer.Typer(name="artasf", help="Autonomous Red Team Assessment Framework", add_completion=False)
sessions_app = typer.Typer(help="Manage saved engagement sessions.")
db_app       = typer.Typer(help="Database management.")
app.add_typer(sessions_app, name="sessions")
app.add_typer(db_app,       name="db")

err = Console(stderr=True)


# ---------------------------------------------------------------------------
# artasf run
# ---------------------------------------------------------------------------

@app.command()
def run(
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Override target network CIDR (e.g. 192.168.56.0/24). Defaults to TARGET_NETWORK in .env.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Run recon + planning only — do NOT launch any exploits.",
    ),
    name: Optional[str] = typer.Option(
        None, "--name", "-n",
        help="Engagement name (overrides ENGAGEMENT_NAME in .env).",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Directory for reports and artifacts. Defaults to ARTIFACTS_DIR.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable DEBUG logging."),
) -> None:
    """Run the full autonomous engagement pipeline."""
    _apply_overrides(target=target, dry_run=dry_run, name=name, output=output)
    configure_logging(
        log_dir=settings.artifacts_dir / "logs",
        level="DEBUG" if verbose else "INFO",
    )

    print_banner()
    console.print(f"  Target : [cyan]{settings.target_network}[/cyan]")
    console.print(f"  Mode   : [{'yellow' if settings.dry_run else 'green'}]{'DRY RUN' if settings.dry_run else 'LIVE'}[/]")
    console.print()

    from artasf.core.orchestrator import Orchestrator

    async def _run() -> None:
        async with Orchestrator.from_settings() as orch:
            _patch_orchestrator(orch)
            session = await orch.run()

        print_summary(session)
        # Orchestrator already persists to DB + FileStore on each phase;
        # write a final JSON snapshot for use by `plan` / `report` commands.
        _save_session_json(session)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        err.print("\n[yellow]Aborted by user.[/yellow]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# artasf scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Recon + vulnerability mapping only (no exploitation)."""
    _apply_overrides(target=target, dry_run=True)
    configure_logging(log_dir=settings.artifacts_dir / "logs", level="DEBUG" if verbose else "INFO")
    print_banner()

    async def _run() -> None:
        from artasf.recon.nmap_runner import NmapRunner
        from artasf.recon.nmap_parser import parse_nmap_xml
        from artasf.recon.http_enrich import enrich_http_ports
        from artasf.recon.dns_enum import enumerate_dns
        from artasf.vulnmap.mapper import VulnMapper
        from artasf.core.models import EngagementSession
        from artasf.storage.db import Database
        from artasf.storage.repos import SessionRepository, VulnRepository

        settings.ensure_dirs()
        session = EngagementSession(name=settings.engagement_name, target_network=settings.target_network)

        print_phase(session.phase, settings.target_network)
        runner  = NmapRunner(settings.target_network, flags=settings.nmap_flags)
        xml     = await runner.run()
        targets = parse_nmap_xml(xml)

        dns_names = await enumerate_dns(settings.target_network)
        for t in targets:
            if t.ip in dns_names:
                t.hostname = dns_names[t.ip]
            await enrich_http_ports(t)

        session.targets = targets
        print_targets(session)

        mapper = VulnMapper()
        for t in targets:
            session.vulns.extend(await mapper.map(t))

        print_vulns(session)

        async with Database(settings.db_path) as db:
            await SessionRepository(db).save(session)
            await VulnRepository(db).save_all(session.id, session.vulns)

        _save_session_json(session)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# artasf plan
# ---------------------------------------------------------------------------

@app.command()
def plan(
    session_file: Path = typer.Argument(..., help="Path to a saved session JSON (from artasf scan)."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Load a saved scan session and generate an AI attack plan."""
    configure_logging(log_dir=settings.artifacts_dir / "logs", level="DEBUG" if verbose else "INFO")
    print_banner()

    session = _load_session_json(session_file)
    if session is None:
        sys.exit(1)

    async def _run() -> None:
        from artasf.planner.planner import AIPlanner
        from artasf.storage.db import Database
        from artasf.storage.repos import SessionRepository

        console.print(f"  Loaded session [cyan]{session.name}[/cyan] — {len(session.vulns)} vulns\n")
        planner = AIPlanner()
        att_plan = await planner.plan(session)
        session.plan = att_plan
        print_plan(session)

        async with Database(settings.db_path) as db:
            await SessionRepository(db).save(session)

        _save_session_json(session)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# artasf report
# ---------------------------------------------------------------------------

@app.command()
def report(
    session_file: Path = typer.Argument(..., help="Path to a saved session JSON."),
    out_dir: Optional[Path] = typer.Option(None, "--out", "-o", help="Output directory for the report."),
) -> None:
    """(Re)generate HTML and PDF report from a saved session."""
    print_banner()

    session = _load_session_json(session_file)
    if session is None:
        sys.exit(1)

    reports = out_dir or settings.reports_dir
    reports.mkdir(parents=True, exist_ok=True)

    async def _run() -> None:
        from artasf.reporting.render import ReportRenderer
        renderer  = ReportRenderer(reports)
        html_path = await renderer.render_html(session)
        pdf_path  = await renderer.render_pdf(html_path)
        console.print(f"\n  [green]HTML:[/green] {html_path}")
        console.print(f"  [green]PDF :[/green] {pdf_path}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# artasf sessions list / show / delete
# ---------------------------------------------------------------------------

@sessions_app.command("list")
def sessions_list(
    limit: int = typer.Option(20, "--limit", "-n", help="Max sessions to show."),
) -> None:
    """List all saved engagement sessions from the database."""
    from artasf.storage.db import Database
    from artasf.storage.repos import SessionRepository
    from rich.table import Table

    async def _run() -> None:
        async with Database(settings.db_path) as db:
            all_sessions = await SessionRepository(db).list_all()

        if not all_sessions:
            console.print("[yellow]No sessions found in the database.[/yellow]")
            return

        table = Table(title="Saved Sessions", show_lines=True)
        table.add_column("ID (short)", style="dim", width=10)
        table.add_column("Name",    style="cyan")
        table.add_column("Network")
        table.add_column("Phase")
        table.add_column("Status")
        table.add_column("Targets", justify="right")
        table.add_column("Vulns",   justify="right")
        table.add_column("Started")

        for s in all_sessions[:limit]:
            color = {"completed": "green", "active": "yellow",
                     "failed": "red", "aborted": "orange3"}.get(s.status.value, "white")
            table.add_row(
                s.id[:8],
                s.name,
                s.target_network,
                s.phase.value,
                f"[{color}]{s.status.value}[/{color}]",
                str(len(s.targets)),
                str(len(s.vulns)),
                s.started_at.strftime("%Y-%m-%d %H:%M"),
            )

        console.print(table)

    asyncio.run(_run())


@sessions_app.command("show")
def sessions_show(
    id_prefix: str = typer.Argument(..., help="Session ID or unique prefix (min 4 chars)."),
) -> None:
    """Print full detail for one session."""
    from artasf.storage.db import Database
    from artasf.storage.repos import SessionRepository

    async def _run() -> None:
        async with Database(settings.db_path) as db:
            repo = SessionRepository(db)
            all_sessions = await repo.list_all()

        matches = [s for s in all_sessions if s.id.startswith(id_prefix)]
        if not matches:
            err.print(f"[red]No session found with ID prefix:[/red] {id_prefix}")
            raise typer.Exit(1)
        if len(matches) > 1:
            err.print(f"[red]Ambiguous prefix — {len(matches)} sessions match.[/red] Be more specific.")
            raise typer.Exit(1)

        s = matches[0]
        console.print(f"\n[bold cyan]Session[/bold cyan]  {s.id}")
        console.print(f"  Name     : {s.name}")
        console.print(f"  Network  : {s.target_network}")
        console.print(f"  Phase    : {s.phase.value}")
        console.print(f"  Status   : {s.status.value}")
        console.print(f"  Started  : {s.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if s.ended_at:
            console.print(f"  Ended    : {s.ended_at.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print(f"  Targets  : {len(s.targets)}")
        for t in s.targets:
            ports = ", ".join(f"{p.number}/{p.service}" for p in t.ports if p.state.value == "open")
            console.print(f"    • {t.ip}  {ports}")
        console.print(f"  Vulns    : {len(s.vulns)}")
        for v in s.vulns[:10]:
            console.print(f"    • [{v.severity.value}] {v.title}")
        if len(s.vulns) > 10:
            console.print(f"    … and {len(s.vulns) - 10} more")
        console.print(f"  Loot     : {len(s.loot)}")
        for item in s.loot:
            console.print(f"    • [{item.type}] {item.value[:80]}")

    asyncio.run(_run())


@sessions_app.command("delete")
def sessions_delete(
    id_prefix: str = typer.Argument(..., help="Session ID or unique prefix (min 4 chars)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Delete a session from the database (irreversible)."""
    from artasf.storage.db import Database
    from artasf.storage.repos import SessionRepository

    async def _run() -> None:
        async with Database(settings.db_path) as db:
            repo = SessionRepository(db)
            all_sessions = await repo.list_all()

            matches = [s for s in all_sessions if s.id.startswith(id_prefix)]
            if not matches:
                err.print(f"[red]No session found with ID prefix:[/red] {id_prefix}")
                raise typer.Exit(1)
            if len(matches) > 1:
                err.print(f"[red]Ambiguous prefix — {len(matches)} sessions match.[/red] Be more specific.")
                raise typer.Exit(1)

            s = matches[0]
            if not yes:
                typer.confirm(
                    f"Delete session '{s.name}' ({s.id[:8]}, {s.status.value})?",
                    abort=True,
                )
            await repo.delete(s.id)
            console.print(f"[green]Deleted[/green] session {s.id[:8]} ({s.name})")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# artasf db init
# ---------------------------------------------------------------------------

@db_app.command("init")
def db_init() -> None:
    """Initialise (or verify) the database schema."""
    from artasf.storage.db import Database

    async def _run() -> None:
        async with Database(settings.db_path) as _db:
            pass  # __aenter__ runs _create_schema automatically
        console.print(f"[green]Database ready:[/green] {settings.db_path}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# artasf version
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print ARTASF version."""
    console.print(f"artasf [cyan]{__version__}[/cyan]")


# ---------------------------------------------------------------------------
# Orchestrator phase hooks (Rich output after each phase)
# ---------------------------------------------------------------------------

def _patch_orchestrator(orch: object) -> None:
    """Monkey-patch the orchestrator's phase runners to print Rich views."""
    from artasf.core.models import WorkflowPhase

    orig_recon      = orch._run_recon        # type: ignore[attr-defined]
    orig_vulnmap    = orch._run_vuln_map     # type: ignore[attr-defined]
    orig_planning   = orch._run_planning     # type: ignore[attr-defined]
    orig_exploiting = orch._run_exploiting   # type: ignore[attr-defined]
    orig_post       = orch._run_post_exploit # type: ignore[attr-defined]

    async def _recon_hook() -> None:
        print_phase(WorkflowPhase.RECON, settings.target_network)
        await orig_recon()
        print_targets(orch.session)         # type: ignore[attr-defined]

    async def _vulnmap_hook() -> None:
        print_phase(WorkflowPhase.VULN_MAP)
        await orig_vulnmap()
        print_vulns(orch.session)           # type: ignore[attr-defined]

    async def _planning_hook() -> None:
        print_phase(WorkflowPhase.PLANNING, settings.claude_model)
        await orig_planning()
        print_plan(orch.session)            # type: ignore[attr-defined]

    async def _exploiting_hook() -> None:
        print_phase(WorkflowPhase.EXPLOITING)
        await orig_exploiting()
        print_attempts(orch.session)        # type: ignore[attr-defined]

    async def _post_hook() -> None:
        print_phase(WorkflowPhase.POST_EXPLOIT)
        await orig_post()
        print_loot(orch.session)            # type: ignore[attr-defined]

    orch._run_recon        = _recon_hook        # type: ignore[attr-defined]
    orch._run_vuln_map     = _vulnmap_hook      # type: ignore[attr-defined]
    orch._run_planning     = _planning_hook     # type: ignore[attr-defined]
    orch._run_exploiting   = _exploiting_hook   # type: ignore[attr-defined]
    orch._run_post_exploit = _post_hook         # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Session persistence helpers
# ---------------------------------------------------------------------------

def _save_session_json(session: object) -> None:
    """Write a session JSON snapshot via FileStore."""
    from artasf.core.models import EngagementSession
    from artasf.storage.file_store import FileStore
    if not isinstance(session, EngagementSession):
        return
    store = FileStore(settings.artifacts_dir)
    path  = store.save_session_json(session.id, session.name, session.model_dump_json(indent=2))
    console.print(f"\n  [dim]Session saved → {path}[/dim]")


def _load_session_json(path: Path) -> object:
    from artasf.core.models import EngagementSession
    if not path.exists():
        err.print(f"[red]File not found:[/red] {path}")
        return None
    try:
        return EngagementSession.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        err.print(f"[red]Failed to load session:[/red] {exc}")
        return None


# ---------------------------------------------------------------------------
# Settings override helpers
# ---------------------------------------------------------------------------

def _apply_overrides(
    target:  Optional[str]  = None,
    dry_run: bool           = False,
    name:    Optional[str]  = None,
    output:  Optional[Path] = None,
) -> None:
    if target:
        settings.target_network = target       # type: ignore[misc]
    if dry_run:
        settings.dry_run = True                # type: ignore[misc]
    if name:
        settings.engagement_name = name        # type: ignore[misc]
    if output:
        settings.artifacts_dir = output        # type: ignore[misc]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
