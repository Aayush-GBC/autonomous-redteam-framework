"""
Vulnerability priority scorer.

Takes a KnownVuln (with its base CVSS score) and the context in which it was
found, and returns:
  - An adjusted priority score  (float, higher = attack sooner)
  - A Severity enum derived from that score

Adjustments on top of CVSS:
  +1.5  — MSF module available (immediately actionable)
  +1.0  — No authentication required
  +0.5  — Running on a web port (80/443/8080) — relevant for web app labs
  -0.5  — Requires authentication (lowers urgency vs unauthenticated vulns)
  -1.0  — Only an info-disclosure / enumeration aid

Score is clamped to [0.0, 10.0].
"""

from __future__ import annotations

from artasf.core.models import Severity
from artasf.vulnmap.vuln_types import KnownVuln

_WEB_PORTS = {80, 443, 8080, 8443, 8000}


def score(known: KnownVuln, matched_port: int | None = None) -> tuple[float, Severity]:
    """
    Return ``(priority_score, severity)`` for *known* found on *matched_port*.
    """
    base = known.cvss_score

    # --- bonuses ---
    if known.msf_modules:
        base += 1.5

    if not known.requires_auth:
        base += 1.0

    if matched_port is not None and matched_port in _WEB_PORTS:
        base += 0.5

    # --- penalties ---
    if known.requires_auth:
        base -= 0.5

    if _is_info_only(known):
        base -= 1.0

    priority = max(0.0, min(10.0, base))
    return priority, _severity_from_score(priority)


def _is_info_only(known: KnownVuln) -> bool:
    info_tags = {"information-disclosure", "user-enumeration"}
    return bool(info_tags.intersection(known.tags)) and not any(
        t in known.tags for t in ("rce", "sqli", "command-injection", "privesc")
    )


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 1.0:
        return Severity.LOW
    return Severity.INFO
