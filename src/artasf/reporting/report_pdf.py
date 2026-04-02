"""
PDF report generator.

Uses WeasyPrint to convert the rendered HTML into a PDF.
WeasyPrint handles all CSS including the @page / print media rules,
producing a clean dark-themed document.

WeasyPrint requires GTK+ / Pango on the system.  On Windows this means
having the MSYS2/GTK runtime installed, or running inside a Linux container.
If the import fails we fall back gracefully and log a warning.
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger


def html_to_pdf(html_path: Path, pdf_path: Path) -> Path:
    """
    Convert *html_path* to a PDF saved at *pdf_path*.

    Returns *pdf_path* on success.

    Raises:
        RuntimeError: if WeasyPrint is unavailable or conversion fails.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except Exception as exc:
        raise RuntimeError(
            f"WeasyPrint is not available: {exc}\n"
            "On Windows, install GTK3 runtime first: "
            "https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer"
        ) from exc

    logger.info("Generating PDF from {}", html_path.name)
    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    except Exception as exc:
        raise RuntimeError(f"PDF generation failed: {exc}") from exc

    logger.success("PDF saved: {}", pdf_path)
    return pdf_path
