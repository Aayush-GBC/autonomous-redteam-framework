"""
SessionShell — thin async wrapper over an open MSF shell session.

Every command is run via MSFClient.session_run().  This class handles:
  - Stripping ANSI escape codes from output
  - Timeout enforcement per command
  - Basic error detection (session closed, permission denied)

Usage:
    shell = SessionShell(msf_client, session_id=3)
    whoami = await shell.run("whoami")
    hostname = await shell.run("hostname")
"""

from __future__ import annotations

import re

from loguru import logger

from artasf.core.exceptions import SessionLostError
from artasf.exploit.msf_rpc import MSFClient

_ANSI_RE  = re.compile(r"\x1b\[[0-9;]*[mGKHF]")
_LOST_SIGNALS = ("channel is not open", "session is closed", "invalid session")


class SessionShell:
    """
    Wraps a single open MSF shell/meterpreter session.

    Args:
        msf:        Active MSFClient instance.
        session_id: Metasploit session ID (integer).
        cmd_timeout: Seconds to wait per command (default 15).
    """

    def __init__(
        self,
        msf: MSFClient,
        session_id: int,
        cmd_timeout: int = 15,
    ) -> None:
        self._msf        = msf
        self.session_id  = session_id
        self.cmd_timeout = cmd_timeout

    async def run(self, command: str) -> str:
        """
        Execute *command* in the shell and return cleaned stdout.

        Raises:
            SessionLostError: if the session appears closed.
        """
        logger.debug("session[{}] > {}", self.session_id, command)
        raw = await self._msf.session_run(self.session_id, command, self.cmd_timeout)
        output = _clean(raw)

        if any(sig in output.lower() for sig in _LOST_SIGNALS):
            raise SessionLostError(
                f"Session {self.session_id} appears closed after: {command!r}"
            )

        logger.debug("session[{}] < {} chars", self.session_id, len(output))
        return output

    async def run_safe(self, command: str, default: str = "") -> str:
        """Like run(), but returns *default* instead of raising on error."""
        try:
            return await self.run(command)
        except SessionLostError:
            raise
        except Exception as exc:
            logger.debug("session[{}] command failed ({}): {}", self.session_id, command, exc)
            return default

    async def is_alive(self) -> bool:
        """Return True if the session is still responsive."""
        try:
            sessions = await self._msf.list_sessions()
            return self.session_id in sessions
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(text: str) -> str:
    """Strip ANSI codes and normalise whitespace."""
    return _ANSI_RE.sub("", text).strip()
