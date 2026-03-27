"""
ReportRenderer — the single entry point for report generation.

Called by the orchestrator's _run_reporting() phase:

    renderer = ReportRenderer(settings.reports_dir)
    html_path = await renderer.render_html(session)
    pdf_path  = await renderer.render_pdf(html_path)
"""

from __future__ import annotations

from pathlib import Path

import anyio
from loguru import logger

from artasf.core.models import EngagementSession
from artasf.reporting.report_html import build_html
from artasf.reporting.report_pdf import html_to_pdf


class ReportRenderer:
    """
    Async facade over the HTML and PDF report builders.

    Args:
        out_dir: Directory where reports are saved.
                 Created automatically if it doesn't exist.
    """

    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir

    async def render_html(self, session: EngagementSession) -> Path:
        """
        Build and save the HTML report.  Returns the saved file path.
        """
        self.out_dir.mkdir(parents=True, exist_ok=True)
        html_path = self.out_dir / f"{session.name}_{session.id[:8]}.html"

        logger.info("Rendering HTML report → {}", html_path.name)

        # build_html is CPU-bound (Jinja2 rendering) — run in thread
        html = await anyio.to_thread.run_sync(lambda: build_html(session))

        html_path.write_text(html, encoding="utf-8")
        logger.success("HTML report saved: {} ({} KB)", html_path.name, html_path.stat().st_size // 1024)
        return html_path

    async def render_pdf(self, html_path: Path) -> Path:
        """
        Convert *html_path* to PDF.  Returns the PDF path.

        If WeasyPrint fails (e.g. missing GTK on Windows) a warning is
        logged and the HTML path is returned instead so the pipeline
        can continue.
        """
        pdf_path = html_path.with_suffix(".pdf")

        try:
            result = await anyio.to_thread.run_sync(
                lambda: html_to_pdf(html_path, pdf_path)
            )
            return result
        except RuntimeError as exc:
            logger.warning(
                "PDF generation skipped ({}). HTML report is still available at {}",
                exc, html_path,
            )
            return html_path
