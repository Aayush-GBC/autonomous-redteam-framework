"""
Nmap subprocess runner.

Executes nmap against the target network and writes results to an XML file
inside the artifacts directory.  Returns the path to the XML file for the
parser to consume.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from loguru import logger

from artasf.core.config import settings
from artasf.core.exceptions import NmapError


class NmapRunner:
    """
    Async wrapper around the nmap CLI.

    Args:
        target:  IP, hostname, or CIDR range to scan.
        flags:   Additional nmap flags (e.g. "-sV -sC -O --open -T4").
                 The runner always appends ``-oX <xml_path>``.
        out_dir: Where to write the XML file.  Defaults to artifacts_dir/scans.
    """

    def __init__(
        self,
        target: str,
        flags: str | None = None,
        out_dir: Path | None = None,
    ) -> None:
        self.target  = target
        self.flags   = flags or settings.nmap_flags
        self.out_dir = out_dir or (settings.artifacts_dir / "scans")

    async def run(self) -> Path:
        """
        Run nmap and return the path to the resulting XML file.

        Raises:
            NmapError: if nmap is not on PATH or exits non-zero.
        """
        if not shutil.which("nmap"):
            raise NmapError(
                "nmap is not installed or not on PATH. "
                "Install it on the attacker machine: sudo apt install nmap"
            )

        self.out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        xml_path  = self.out_dir / f"scan_{timestamp}.xml"

        cmd = ["nmap"] + self.flags.split() + ["-oX", str(xml_path), self.target]
        logger.info("Running: {}", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise NmapError(f"nmap exited {proc.returncode}: {err}")

        if not xml_path.exists():
            raise NmapError(f"nmap did not produce output file: {xml_path}")

        logger.debug("nmap XML written to {}", xml_path)
        return xml_path
