"""
Internal vulnerability catalog types.

KnownVuln entries live in the offline catalog and are matched against
discovered targets.  They are *not* the same as the domain Vulnerability
model — once matched, a KnownVuln is converted into a Vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class KnownVuln:
    """
    A catalog entry describing a known vulnerability.

    Matching is attempted in order:
      1. port_numbers  — if the port is in this list it's a candidate
      2. service_patterns — regex matched against Port.service
      3. version_patterns — regex matched against Port.version
      4. cpe_patterns     — regex matched against Port.cpe or Target.os_cpe

    At least one pattern list must match (non-empty lists are ANDed per
    category but ORed across categories — so a port match alone is enough
    for generic/catch-all entries, while version_patterns narrow it down).
    """

    id:           str
    title:        str
    description:  str
    cve:          str | None  = None
    cvss_score:   float       = 5.0
    # --- matching ---
    port_numbers:     list[int] = field(default_factory=list)
    service_patterns: list[str] = field(default_factory=list)
    version_patterns: list[str] = field(default_factory=list)
    cpe_patterns:     list[str] = field(default_factory=list)
    # --- exploitation ---
    msf_modules: list[str] = field(default_factory=list)
    edb_ids:     list[str] = field(default_factory=list)
    # --- metadata ---
    requires_auth:  bool = False
    needs_network:  bool = True   # requires direct TCP access
    # tags help the planner group related attacks
    tags: list[str] = field(default_factory=list)
