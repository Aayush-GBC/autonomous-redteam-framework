"""
PostEnumerator — collect basic situational awareness from a shell session.

Commands run (all non-destructive, read-only):
  whoami / id
  hostname
  uname -a
  cat /etc/os-release
  ip addr / ifconfig fallback
  cat /etc/passwd  (user list)
  env              (environment variables — may contain secrets)

Results are packed into a PostExploitData domain object.
"""

from __future__ import annotations

import re

from loguru import logger

from artasf.core.models import EngagementSession, PostExploitData
from artasf.exploit.msf_rpc import MSFClient
from artasf.post.session import SessionShell


class PostEnumerator:
    """
    Runs situational-awareness commands on an open shell session.

    Args:
        session_id: MSF session ID.
        session:    Active EngagementSession (used to look up target_id).
        msf:        Active MSFClient (injected or resolved lazily).
    """

    def __init__(
        self,
        session_id: int,
        engagement: EngagementSession,
        msf: MSFClient | None = None,
    ) -> None:
        self.session_id = session_id
        self.engagement = engagement
        self._msf       = msf

    async def collect(self, msf: MSFClient | None = None) -> PostExploitData:
        """
        Run all enumeration commands and return a PostExploitData object.

        Args:
            msf: MSFClient to use.  Falls back to self._msf if not provided.
        """
        client = msf or self._msf
        if client is None:
            raise RuntimeError("PostEnumerator requires an MSFClient instance")

        shell  = SessionShell(client, self.session_id)
        target_id = self._resolve_target_id()

        short_id = target_id.split("-")[0]
        logger.info("Post-enum on session {} (target_id={})", self.session_id, short_id)

        whoami   = await shell.run_safe("id")
        hostname = await shell.run_safe("hostname")
        uname    = await shell.run_safe("uname -a")
        os_info  = _parse_os_release(await shell.run_safe("cat /etc/os-release")) or uname
        ifaces   = _parse_ifaces(await shell.run_safe("ip addr 2>/dev/null || ifconfig 2>/dev/null"))
        env_vars = await shell.run_safe("env")

        # Log anything interesting in env
        _flag_interesting_env(env_vars)

        data = PostExploitData(
            target_id=target_id,
            msf_session_id=self.session_id,
            hostname=hostname.splitlines()[0] if hostname else None,
            whoami=whoami.splitlines()[0] if whoami else None,
            os_info=os_info,
            network_ifaces=ifaces,
        )

        logger.info(
            "Enum complete: host={} user={} ifaces={}",
            data.hostname, data.whoami, len(data.network_ifaces),
        )
        return data

    def _resolve_target_id(self) -> str:
        """Find the target_id that has this MSF session's IP."""
        for attempt in self.engagement.attempts:
            if attempt.msf_session_id == self.session_id:
                return attempt.target_id
        # Fallback: first target
        return self.engagement.targets[0].id if self.engagement.targets else "unknown"


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_os_release(text: str) -> str | None:
    """Extract PRETTY_NAME from /etc/os-release output."""
    m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', text)
    return m.group(1).strip() if m else None


def _parse_ifaces(text: str) -> list[str]:
    """Extract IP addresses from ip addr / ifconfig output."""
    # Match IPv4 addresses, skip loopback
    addrs = re.findall(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    return [a for a in addrs if not a.startswith("127.")]


def _flag_interesting_env(env_text: str) -> None:
    """Log any environment variables that look like secrets."""
    interesting = re.compile(
        r"(PASSWORD|PASSWD|SECRET|TOKEN|KEY|API_KEY|DATABASE_URL)=(.+)",
        re.IGNORECASE,
    )
    for m in interesting.finditer(env_text):
        logger.warning("Interesting env var: {}=<redacted>", m.group(1))
