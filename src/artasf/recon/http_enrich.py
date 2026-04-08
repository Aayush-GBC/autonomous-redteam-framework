"""
HTTP enrichment for discovered web ports.

For every open port whose service nmap identifies as http/https (or common
web port numbers), we fire a quick HEAD then GET to pull the server banner,
page title, and interesting headers.  Results are stored directly on the
Target's Port objects as extra metadata (via the banner field) and returned
as HttpMeta objects for the orchestrator to log/store.
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

_TITLE_RE  = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE | re.DOTALL)
_TIMEOUT   = httpx.Timeout(8.0, connect=4.0)


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
        headers={"User-Agent": "artasf-recon/0.1"},
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
    scheme = "https" if port in {443, 8443} else "http"
    url    = f"{scheme}://{ip}:{port}/"

    try:
        resp = await client.get(url)
    except Exception as exc:
        # Try HTTPS fallback if plain HTTP fails on port 443-ish
        if scheme == "http" and port in {8443, 443}:
            try:
                resp = await client.get(f"https://{ip}:{port}/")
                scheme = "https"
            except Exception:
                logger.debug("HTTP probe failed for {}:{} — {}", ip, port, exc)
                return None
        else:
            logger.debug("HTTP probe failed for {}:{} — {}", ip, port, exc)
            return None

    headers = dict(resp.headers)
    title   = _extract_title(resp.text)

    # Secondary probe: if the root title is empty and this is a common DVWA
    # port, try /dvwa/ to pick up the "Login :: DVWA" title directly.
    if not title and port in {80, 8080}:
        try:
            dvwa_resp = await client.get(f"{scheme}://{ip}:{port}/dvwa/")
            title = _extract_title(dvwa_resp.text) or title
        except Exception:
            pass

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


def _extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if m:
        return " ".join(m.group(1).split())  # normalise whitespace
    return None
