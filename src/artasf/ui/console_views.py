"""
Rich terminal views for ARTASF.

All rendering is done via the Rich library.  Functions here are purely
presentational — they read from EngagementSession but never mutate it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

from artasf.core.models import (
    EngagementSession,
    ExploitAttempt,
    ExploitStatus,
    LootItem,
    Severity,
    Vulnerability,
    WorkflowPhase,
)

console = Console()

# Severity → Rich colour
_SEV_COLOUR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

_STATUS_COLOUR: dict[ExploitStatus, str] = {
    ExploitStatus.SUCCESS: "bold green",
    ExploitStatus.FAILED:  "bold red",
    ExploitStatus.SKIPPED: "dim",
    ExploitStatus.TIMEOUT: "yellow",
    ExploitStatus.RUNNING: "bold blue",
    ExploitStatus.PENDING: "dim",
}

_PHASE_ICON: dict[WorkflowPhase, str] = {
    WorkflowPhase.INIT:         "⚙",
    WorkflowPhase.RECON:        "🔍",
    WorkflowPhase.VULN_MAP:     "🗺",
    WorkflowPhase.PLANNING:     "🤖",
    WorkflowPhase.EXPLOITING:   "💥",
    WorkflowPhase.POST_EXPLOIT: "🔑",
    WorkflowPhase.REPORTING:    "📄",
    WorkflowPhase.DONE:         "✅",
    WorkflowPhase.FAILED:       "❌",
}


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner() -> None:
    banner = Text()
    banner.append("\n  ARTASF", style="bold cyan")
    banner.append("  ·  Autonomous Red Team Assessment Framework\n", style="dim")
    console.print(banner)


# ---------------------------------------------------------------------------
# Phase header
# ---------------------------------------------------------------------------

def print_phase(phase: WorkflowPhase, detail: str = "") -> None:
    icon  = _PHASE_ICON.get(phase, "•")
    label = phase.value.replace("_", " ").title()
    msg   = f"{icon}  [bold]{label}[/bold]"
    if detail:
        msg += f"  [dim]{detail}[/dim]"
    console.rule(msg, style="cyan")


# ---------------------------------------------------------------------------
# Recon results
# ---------------------------------------------------------------------------

def print_targets(session: EngagementSession) -> None:
    if not session.targets:
        console.print("[dim]  No hosts found.[/dim]")
        return

    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    tbl.add_column("IP",       style="cyan",  no_wrap=True)
    tbl.add_column("Hostname", style="white")
    tbl.add_column("OS",       style="dim")
    tbl.add_column("Open Ports")

    for t in session.targets:
        ports_str = "  ".join(
            f"[green]{p.number}[/green]/[dim]{p.service}[/dim]"
            for p in t.open_ports()
        )
        tbl.add_row(t.ip, t.hostname or "—", t.os_guess or "?", ports_str or "—")

    console.print(tbl)
    console.print(f"  [dim]Found [bold]{len(session.targets)}[/bold] host(s)[/dim]\n")


# ---------------------------------------------------------------------------
# Vulnerability table
# ---------------------------------------------------------------------------

def print_vulns(session: EngagementSession) -> None:
    if not session.vulns:
        console.print("[dim]  No vulnerabilities mapped.[/dim]")
        return

    target_ip = {t.id: t.ip for t in session.targets}
    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    tbl.add_column("Sev",     width=8)
    tbl.add_column("CVSS",    width=5)
    tbl.add_column("Title")
    tbl.add_column("Host",    style="cyan",  no_wrap=True)
    tbl.add_column("Port",    width=6)
    tbl.add_column("MSF",     width=5)

    # Sort critical → info
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    sorted_vulns = sorted(session.vulns, key=lambda v: order.index(v.severity))

    for v in sorted_vulns:
        colour  = _SEV_COLOUR[v.severity]
        has_msf = "✓" if v.msf_modules() else "—"
        tbl.add_row(
            Text(v.severity.value.upper(), style=colour),
            str(v.cvss_score or "—"),
            v.title,
            target_ip.get(v.target_id, "?"),
            str(v.port) if v.port else "—",
            Text(has_msf, style="green" if has_msf == "✓" else "dim"),
        )

    console.print(tbl)
    crit = sum(1 for v in session.vulns if v.severity == Severity.CRITICAL)
    high = sum(1 for v in session.vulns if v.severity == Severity.HIGH)
    console.print(
        f"  [dim]Total: [bold]{len(session.vulns)}[/bold] vulns  "
        f"([red]{crit} critical[/red]  [yellow]{high} high[/yellow])[/dim]\n"
    )


# ---------------------------------------------------------------------------
# Attack plan
# ---------------------------------------------------------------------------

def print_plan(session: EngagementSession) -> None:
    plan = session.plan
    if plan is None:
        console.print("[dim]  No attack plan generated.[/dim]")
        return

    console.print(f"\n  [dim]Model: {plan.model_used}[/dim]")
    if plan.rationale:
        console.print(Panel(plan.rationale, title="AI Rationale", border_style="cyan", padding=(0, 2)))

    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    tbl.add_column("#",       width=3)
    tbl.add_column("Risk",    width=8)
    tbl.add_column("Module",  style="green")
    tbl.add_column("Params",  style="dim")
    tbl.add_column("Depends", width=7)

    for step in plan.steps:
        colour = _SEV_COLOUR[step.risk_level]
        params = "  ".join(f"{k}={v}" for k, v in step.params.items())
        tbl.add_row(
            str(step.step),
            Text(step.risk_level.value.upper(), style=colour),
            step.module,
            params,
            f"→{step.requires_step}" if step.requires_step else "—",
        )

    console.print(tbl)
    console.print(f"  [dim]{len(plan.steps)} step(s) planned[/dim]\n")


# ---------------------------------------------------------------------------
# Exploit attempt results
# ---------------------------------------------------------------------------

def print_attempts(session: EngagementSession) -> None:
    if not session.attempts:
        console.print("[dim]  No exploit attempts recorded.[/dim]")
        return

    target_ip = {t.id: t.ip for t in session.targets}
    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    tbl.add_column("#",       width=3)
    tbl.add_column("Status",  width=9)
    tbl.add_column("Module",  style="green")
    tbl.add_column("Target",  style="cyan", no_wrap=True)
    tbl.add_column("Session", width=7)

    for a in session.attempts:
        colour = _STATUS_COLOUR.get(a.status, "white")
        tbl.add_row(
            str(a.step),
            Text(a.status.value.upper(), style=colour),
            a.module,
            target_ip.get(a.target_id, "?"),
            str(a.msf_session_id) if a.msf_session_id else "—",
        )

    console.print(tbl)
    ok  = len(session.successful_attempts())
    tot = len(session.attempts)
    console.print(f"  [dim]{ok}/{tot} steps succeeded[/dim]\n")


# ---------------------------------------------------------------------------
# Loot summary
# ---------------------------------------------------------------------------

def print_loot(session: EngagementSession) -> None:
    if not session.loot:
        console.print("[dim]  No loot collected.[/dim]")
        return

    tbl = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    tbl.add_column("Type",   width=12)
    tbl.add_column("Value",  style="yellow")
    tbl.add_column("Source", style="dim")

    for item in session.loot:
        colour = "bold red" if item.type == "credential" else "yellow" if item.type == "hash" else "dim"
        val    = item.value if len(item.value) <= 80 else item.value[0:77] + "..."
        tbl.add_row(Text(item.type.upper(), style=colour), val, item.source)

    console.print(tbl)
    console.print(f"  [dim]{len(session.loot)} loot item(s) collected[/dim]\n")


# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------

def print_summary(session: EngagementSession) -> None:
    dur = ""
    if session.started_at and session.ended_at:
        s  = session.started_at
        e  = session.ended_at
        if s.tzinfo is None:
            s = s.replace(tzinfo=timezone.utc)
        if e.tzinfo is None:
            e = e.replace(tzinfo=timezone.utc)
        secs = int((e - s).total_seconds())
        dur  = f"{secs // 60}m {secs % 60}s"

    status_colour = "green" if session.status.value == "completed" else "red"
    lines = [
        f"[bold]Session:[/bold] {session.name}  [dim]({session.id})[/dim]",
        f"[bold]Status:[/bold]  [{status_colour}]{session.status.value.upper()}[/{status_colour}]"
        + (f"  [dim]{dur}[/dim]" if dur else ""),
        f"[bold]Targets:[/bold] {len(session.targets)}  "
        f"[bold]Vulns:[/bold] {len(session.vulns)}  "
        f"[bold]Exploits:[/bold] {len(session.successful_attempts())}/{len(session.attempts)} succeeded  "
        f"[bold]Loot:[/bold] {len(session.loot)} items",
    ]
    console.print(Panel("\n".join(lines), title="Engagement Complete", border_style=status_colour, padding=(1, 2)))


# ---------------------------------------------------------------------------
# Progress spinner (context manager)
# ---------------------------------------------------------------------------

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
