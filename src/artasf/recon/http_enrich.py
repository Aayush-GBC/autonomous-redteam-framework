"""
HTTP enrichment for discovered web ports.

For every open port whose service nmap identifies as http/https (or common
web port numbers), we fire a quick HEAD then GET to pull the server banner,
page title, and interesting headers.  Results are stored directly on the
Target's Port objects as extra metadata (via the banner field) and returned
as HttpMeta objects for the orchestrator to log/store.

Probe strategy (in order):
  1. Initial GET with artasf UA.
  2. On connection-refused / empty body / non-2xx, retry with a realistic
     browser User-Agent and Accept headers (defeats UA-based WAF blocks).
  3. For ports that are neither clearly HTTP nor HTTPS, try both schemes.
  4. On port 80/8080, probe /dvwa/, /admin/, /login in addition to / to
     maximise title discovery against login-gated lab apps.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import httpx
from loguru import logger

from artasf.recon.recon_types import HttpMeta

if TYPE_CHECKING:
    from artasf.core.models import Target

# Port numbers we treat as web even if nmap labels them something else
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 5001, 9090}

# Ports that are ambiguous (could be either HTTP or HTTPS)
_AMBIGUOUS_PORTS = {8080, 8000, 8008, 8888, 3000, 5000, 5001, 9090}

_TITLE_RE  = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE | re.DOTALL)
_TIMEOUT   = httpx.Timeout(8.0, connect=4.0)

# Sent on the first pass — lightweight, identifies as ARTASF
_ARTASF_UA = "artasf-recon/0.1"

# Sent on the browser-spoof retry — defeats UA-based WAF / auth walls
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# Extra paths probed on port 80/8080 to discover login-gated apps
_EXTRA_PATHS = ["/dvwa/", "/admin/", "/login", "/login.php"]


async def enrich_http_ports(target: "Target") -> list[HttpMeta]:
    """
    Probe all web-like open ports on *target* and return metadata.

    The function is best-effort: individual port failures are logged and
    skipped rather than raising.
    """
    results: list[HttpMeta] = []

    async with httpx.AsyncClient(
        verify=False,          # self-signed certs are common in labs
        follow_redirects=True,
        timeout=_TIMEOUT,
        headers={"User-Agent": _ARTASF_UA},
    ) as client:
        for port in target.open_ports():
            if not _is_web_port(port.number, port.service):
                continue
            meta = await _probe_port(client, target.ip, port.number)
            if meta:
                # Store a condensed banner back on the port model
                parts = [p for p in (meta.server, meta.title) if p]
                if parts:
                    port.banner = " | ".join(parts)
                results.append(meta)

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_web_port(number: int, service: str) -> bool:
    if number in _WEB_PORTS:
        return True
    svc = (service or "").lower()
    return any(k in svc for k in ("http", "www", "web", "ssl"))


async def _probe_port(
    client: httpx.AsyncClient, ip: str, port: int
) -> HttpMeta | None:
    """
    Probe a single port.  Returns an HttpMeta on success, None on failure.

    Strategy:
      1. Try primary scheme (https for 443/8443, http otherwise).
      2. On failure/empty, retry with browser headers.
      3. On ports that could be either scheme, also try the alternate scheme.
      4. Once we have a response, probe extra paths if the root title is empty.
    """
    # ── Determine primary scheme ──────────────────────────────────────────
    primary_scheme   = "https" if port in {443, 8443} else "http"
    alternate_scheme = "http"  if primary_scheme == "https" else "https"
    try_alternate    = port in _AMBIGUOUS_PORTS or port in {443, 8443, 80}

    resp, scheme = await _try_get(client, ip, port, primary_scheme, ua="artasf")

    # ── Browser-UA retry ─────────────────────────────────────────────────
    if resp is None or _is_empty_response(resp):
        logger.debug(
            "Port {}:{} — initial probe failed/empty, retrying with browser UA",
            ip, port,
        )
        resp, scheme = await _try_get(client, ip, port, primary_scheme, ua="browser")

    # ── Alternate-scheme fallback ─────────────────────────────────────────
    if resp is None and try_alternate:
        logger.debug(
            "Port {}:{} — trying alternate scheme {}://",
            ip, port, alternate_scheme,
        )
        resp, scheme = await _try_get(client, ip, port, alternate_scheme, ua="browser")

    if resp is None:
        logger.debug("HTTP probe exhausted all strategies for {}:{}", ip, port)
        return None

    headers = dict(resp.headers)
    title   = _extract_title(resp.text)

    # ── Extra path probes ────────────────────────────────────────────────
    # On common web ports, probe /dvwa/, /admin/, /login, /login.php so we
    # find titles even when the root redirects to an empty splash page.
    if not title and port in {80, 8080}:
        title = await _probe_extra_paths(client, ip, port, scheme)

    meta = HttpMeta(
        port=port,
        scheme=scheme,
        status_code=resp.status_code,
        server=headers.get("server"),
        title=title,
        powered_by=headers.get("x-powered-by"),
        redirect_url=str(resp.url) if resp.has_redirect_location else None,
        extra_headers={
            k: v for k, v in headers.items()
            if k.lower() in {"x-frame-options", "content-security-policy",
                              "strict-transport-security", "x-generator"}
        },
    )
    logger.debug(
        "HTTP {}:{} → {} | server={} | title={}",
        scheme, port, resp.status_code, meta.server, meta.title,
    )
    return meta


async def _try_get(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
    scheme: str,
    ua: str = "artasf",
) -> tuple[httpx.Response | None, str]:
    """
    Fire a single GET.  Returns (response, scheme) or (None, scheme) on error.
    *ua* is either "artasf" (default client headers) or "browser" (spoof).
    """
    url = f"{scheme}://{ip}:{port}/"
    extra_headers = _BROWSER_HEADERS if ua == "browser" else {}
    try:
        resp = await client.get(url, headers=extra_headers)
        return resp, scheme
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
        logger.debug("GET {} failed ({}): {}", url, ua, exc)
        return None, scheme
    except Exception as exc:
        logger.debug("GET {} unexpected error ({}): {}", url, ua, exc)
        return None, scheme


async def _probe_extra_paths(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
    scheme: str,
) -> str | None:
    """Try _EXTRA_PATHS to find a non-empty page title on login-gated apps."""
    for path in _EXTRA_PATHS:
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            resp = await client.get(url, headers=_BROWSER_HEADERS)
            title = _extract_title(resp.text)
            if title:
                logger.debug(
                    "Extra path probe found title at {}: {!r}", url, title
                )
                return title
        except Exception:
            pass
    return None


def _is_empty_response(resp: httpx.Response) -> bool:
    """True when the response body is absent or suspiciously short (< 32 bytes)."""
    return not resp.text or len(resp.text.strip()) < 32


def _extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if m:
        return " ".join(m.group(1).split())  # normalise whitespace
    return None
