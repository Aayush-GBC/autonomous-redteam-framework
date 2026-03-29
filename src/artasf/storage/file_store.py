"""
File-based artifact store.

Saves and loads raw files produced during an engagement:
  - Nmap XML scans
  - Loot files (SSH keys, config files, /etc/shadow)
  - Rendered HTML/PDF reports

Files are organised under artifacts_dir/:
    scans/      — nmap XML outputs
    loot/       — harvested text files
    reports/    — HTML and PDF reports
    sessions/   — JSON session snapshots

Usage:
    store = FileStore(settings.artifacts_dir)
    path  = store.save_loot("creds.txt", content, target_ip="192.168.56.101")
"""

from __future__ import annotations

import re
from pathlib import Path

from loguru import logger


class FileStore:
    """
    Manages engagement artifact files under a root directory.

    Args:
        root: Base artifacts directory (e.g. Path("artifacts")).
              Sub-directories are created automatically.
    """

    def __init__(self, root: Path) -> None:
        self.root     = root
        self.scans    = root / "scans"
        self.loot     = root / "loot"
        self.reports  = root / "reports"
        self.sessions = root / "sessions"

    def ensure_dirs(self) -> None:
        """Create all artifact subdirectories."""
        for d in (self.scans, self.loot, self.reports, self.sessions):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Loot files
    # ------------------------------------------------------------------

    def save_loot(
        self,
        filename: str,
        content: str,
        target_ip: str = "unknown",
    ) -> Path:
        """
        Write *content* to a loot file and return its path.

        Args:
            filename:  Base file name (e.g. "shadow.txt", "id_rsa").
            content:   Text content to write.
            target_ip: Used to namespace files by target host.
        """
        self.loot.mkdir(parents=True, exist_ok=True)
        safe_ip   = _safe_name(target_ip)
        target_dir = self.loot / safe_ip
        target_dir.mkdir(exist_ok=True)

        path = target_dir / _safe_name(filename)
        path.write_text(content, encoding="utf-8")
        logger.debug("Loot saved: {} ({} bytes)", path, len(content))
        return path

    def load_loot(self, path: Path) -> str:
        """Read a loot file and return its contents."""
        return path.read_text(encoding="utf-8")

    def list_loot(self, target_ip: str | None = None) -> list[Path]:
        """
        List all loot files, optionally filtered by target IP.
        """
        self.loot.mkdir(parents=True, exist_ok=True)
        if target_ip:
            base = self.loot / _safe_name(target_ip)
            if not base.exists():
                return []
            return sorted(base.rglob("*"))
        return sorted(self.loot.rglob("*"))

    # ------------------------------------------------------------------
    # Session JSON snapshots
    # ------------------------------------------------------------------

    def save_session_json(self, session_id: str, name: str, json_data: str) -> Path:
        """Write a session JSON snapshot and return its path."""
        self.sessions.mkdir(parents=True, exist_ok=True)
        path = self.sessions / f"{_safe_name(name)}_{session_id[:8]}.json"
        path.write_text(json_data, encoding="utf-8")
        logger.debug("Session JSON saved: {}", path.name)
        return path

    def load_session_json(self, path: Path) -> str:
        """Read a session JSON file."""
        return path.read_text(encoding="utf-8")

    def list_sessions(self) -> list[Path]:
        """Return all saved session JSON files, newest first."""
        self.sessions.mkdir(parents=True, exist_ok=True)
        return sorted(self.sessions.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def save_report(self, filename: str, content: str) -> Path:
        """Write an HTML report string and return its path."""
        self.reports.mkdir(parents=True, exist_ok=True)
        path = self.reports / filename
        path.write_text(content, encoding="utf-8")
        logger.info("Report saved: {} ({} KB)", path.name, len(content) // 1024)
        return path

    def list_reports(self) -> list[Path]:
        """Return all report files (HTML and PDF)."""
        self.reports.mkdir(parents=True, exist_ok=True)
        return sorted(
            (p for p in self.reports.iterdir() if p.suffix in (".html", ".pdf")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_name(value: str) -> str:
    """Convert an arbitrary string into a safe file/directory name."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)
