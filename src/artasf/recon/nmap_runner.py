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
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from artasf.core.config import settings
from artasf.core.exceptions import NmapError

# Extra flags appended when firewall/WAF evasion is requested.
# -f          — fragment IP packets (8-byte fragments)
# --mtu 16    — set custom MTU so each fragment carries only 16 bytes
# --data-length 25 — pad each packet with 25 random bytes to defeat DPI
# --randomize-hosts — scan hosts in random order to avoid rate-limit triggers
_EVASION_FLAGS = "-f --mtu 16 --data-length 25 --randomize-hosts"

# Requires raw-socket access — warn when not running as root/admin
_EVASION_ROOT_NOTE = (
    "Fragmentation (-f/--mtu) requires raw-socket access. "
    "On Linux run as root; on Windows run as Administrator. "
    "If nmap errors with 'requires root privileges', drop --mtu/--data-length "
    "or add -sT (TCP connect scan) as a fallback."
)


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

    async def run(self, firewall_evasion: bool = False) -> Path:
        """
        Run nmap and return the path to the resulting XML file.

        Args:
            firewall_evasion: When True, append packet-fragmentation and
                host-randomisation flags to defeat simple firewalls and WAFs.
                Only enable when your written authorisation explicitly permits
                evasion techniques against the target.

        Raises:
            NmapError: if nmap is not on PATH or exits non-zero.
        """
        if not shutil.which("nmap"):
            raise NmapError(
                "nmap is not installed or not on PATH. "
                "Install it on the attacker machine: sudo apt install nmap"
            )

        self.out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        xml_path  = self.out_dir / f"scan_{timestamp}.xml"

        effective_flags = self.flags
        if firewall_evasion:
            effective_flags = f"{self.flags} {_EVASION_FLAGS}"
            logger.warning(
                "[EVASION] Firewall/WAF evasion mode active — appending: {}",
                _EVASION_FLAGS,
            )
            logger.warning(
                "[EVASION] This scan uses packet fragmentation against {}. "
                "Ensure your written engagement authorisation explicitly permits "
                "evasion techniques before proceeding.",
                self.target,
            )
            logger.debug("[EVASION] Note: {}", _EVASION_ROOT_NOTE)

        cmd = ["nmap"] + effective_flags.split() + ["-oX", str(xml_path), self.target]
        logger.info("Running: {}", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=settings.nmap_timeout_sec
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise NmapError(
                f"nmap timed out after {settings.nmap_timeout_sec}s — "
                "check NMAP_TIMEOUT_SEC in .env or verify the target is reachable"
            )

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise NmapError(f"nmap exited {proc.returncode}: {err}")

        if not xml_path.exists():
            raise NmapError(f"nmap did not produce output file: {xml_path}")

        logger.debug("nmap XML written to {}", xml_path)
        return xml_path
