"""
Recon-specific lightweight types that don't belong in the main domain models.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HttpMeta:
    """HTTP metadata grabbed from an open web port."""
    port:         int
    scheme:       str          # "http" or "https"
    status_code:  int | None   = None
    server:       str | None   = None
    title:        str | None   = None
    powered_by:   str | None   = None
    redirect_url: str | None   = None
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class DnsResult:
    """Result of a reverse/forward DNS lookup for a single IP."""
    ip:       str
    hostname: str | None = None
    aliases:  list[str] = field(default_factory=list)
