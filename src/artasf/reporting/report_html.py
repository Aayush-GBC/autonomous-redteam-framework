"""
HTML report builder.

Loads the Jinja2 template, injects a ReportContext derived from the
EngagementSession, and returns the rendered HTML string.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from artasf.core.models import EngagementSession, Severity

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def build_html(session: EngagementSession) -> str:
    """Render the full HTML report for *session* and return it as a string."""
    env = _make_jinja_env()
    template = env.get_template("report.html")

    # Pre-compute template helpers
    target_ip      = {t.id: t.ip for t in session.targets}
    target_vuln_count = _count_vulns_per_target(session)
    vuln_counts    = _severity_counts(session)
    successful_exploits = len(session.successful_attempts())

    # Inline CSS so the HTML file is self-contained
    styles = (_TEMPLATES_DIR / "styles.css").read_text(encoding="utf-8")

    html = template.render(
        session=session,
        target_ip=target_ip,
        target_vuln_count=target_vuln_count,
        vuln_counts=vuln_counts,
        successful_exploits=successful_exploits,
        styles=styles,
    )
    return html


# ---------------------------------------------------------------------------
# Jinja2 environment
# ---------------------------------------------------------------------------

def _make_jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["datefmt"] = _datefmt
    return env


def _datefmt(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _severity_counts(session: EngagementSession) -> object:
    class Counts:
        critical = sum(1 for v in session.vulns if v.severity == Severity.CRITICAL)
        high     = sum(1 for v in session.vulns if v.severity == Severity.HIGH)
        medium   = sum(1 for v in session.vulns if v.severity == Severity.MEDIUM)
        low      = sum(1 for v in session.vulns if v.severity == Severity.LOW)
        info     = sum(1 for v in session.vulns if v.severity == Severity.INFO)
    return Counts()


def _count_vulns_per_target(session: EngagementSession) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in session.vulns:
        counts[v.target_id] = counts.get(v.target_id, 0) + 1
    return counts
