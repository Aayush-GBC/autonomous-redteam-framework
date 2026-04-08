"""
VulnMapper — matches discovered targets against the offline CVE catalog.

For each open port on a target, every KnownVuln in the catalog is checked
via regex patterns on service name, version string, and CPE.  Matches are
converted into Vulnerability domain objects with scored severity and
attached ExploitRef objects.

DVWA-specific app-layer vulns are also injected when an HTTP port's banner
contains "DVWA" or "Damn Vulnerable Web Application".
"""

from __future__ import annotations

import re

from loguru import logger

from artasf.core.models import Port, Target, Vulnerability
from artasf.vulnmap.scoring import score as compute_score
from artasf.vulnmap.sources.exploit_refs import build_exploit_refs
from artasf.vulnmap.sources.offline_cve import CATALOG
from artasf.vulnmap.vuln_types import KnownVuln

# IDs of entries that are DVWA application-specific (injected only when DVWA
# is confirmed via HTTP banner / title)
_DVWA_IDS = {
    "DVWA-SQLI", "DVWA-CMD-INJECT", "DVWA-FILE-UPLOAD",
    "DVWA-XSS-STORED", "DVWA-CSRF", "DVWA-LFI",
}

_DVWA_FINGERPRINTS = re.compile(
    r"(dvwa|damn vulnerable web application)", re.IGNORECASE
)


class VulnMapper:
    """Maps a single Target to a list of Vulnerability objects."""

    async def map(self, target: Target) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        dvwa_confirmed = _detect_dvwa(target)

        if dvwa_confirmed:
            logger.info("DVWA fingerprint detected on {}", target.ip)

        for port in target.open_ports():
            for known in CATALOG:
                # Skip DVWA app vulns unless we confirmed DVWA is running
                if known.id in _DVWA_IDS and not dvwa_confirmed:
                    continue

                if not _matches(known, port, target):
                    continue

                priority, severity = compute_score(known, port.number)
                refs = build_exploit_refs(known)

                vuln = Vulnerability(
                    target_id=target.id,
                    port=port.number,
                    service=port.service,
                    title=known.title,
                    description=known.description,
                    severity=severity,
                    cvss_score=known.cvss_score,
                    cve=known.cve,
                    cpe=port.cpe or target.os_cpe,
                    exploit_refs=refs,
                )
                vulns.append(vuln)
                logger.debug(
                    "  [{}] {} → {} (priority={:.1f})",
                    target.ip, port.number, known.id, priority,
                )

        # De-duplicate: same known.id on the same port
        vulns = _dedupe(vulns)

        logger.info(
            "Target {} — {} vulns mapped ({} critical/high)",
            target.ip,
            len(vulns),
            sum(1 for v in vulns if v.severity.value in ("critical", "high")),
        )
        return vulns


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _matches(known: KnownVuln, port: Port, target: Target) -> bool:
    """Return True if *known* applies to *port* on *target*."""

    # Port number match (quick check first)
    port_ok = (not known.port_numbers) or (port.number in known.port_numbers)

    # Service name match
    svc = (port.service or "").lower()
    svc_ok = (not known.service_patterns) or any(
        re.search(pat, svc, re.IGNORECASE) for pat in known.service_patterns
    )

    # Version string match
    ver = port.version or ""
    ver_ok = (not known.version_patterns) or any(
        re.search(pat, ver, re.IGNORECASE) for pat in known.version_patterns
    )

    # CPE match (port CPE first, fall back to OS CPE)
    cpe = port.cpe or target.os_cpe or ""
    cpe_ok = (not known.cpe_patterns) or any(
        re.search(pat, cpe, re.IGNORECASE) for pat in known.cpe_patterns
    )

    # Rule: port OR service must match, AND (version OR cpe OR neither required)
    if not (port_ok and svc_ok):
        return False

    # If version/CPE patterns are given, only count a category as matched
    # when it actually *has* patterns that pass — not vacuously.
    has_ver_filter = bool(known.version_patterns)
    has_cpe_filter = bool(known.cpe_patterns)
    if has_ver_filter or has_cpe_filter:
        ver_matched = has_ver_filter and ver_ok
        cpe_matched = has_cpe_filter and cpe_ok
        return ver_matched or cpe_matched

    return True


def _detect_dvwa(target: Target) -> bool:
    """Return True if any port banner/version/cpe or target hostname looks like DVWA."""
    if target.hostname and _DVWA_FINGERPRINTS.search(target.hostname):
        return True
    for port in target.open_ports():
        for text in (port.banner, port.version, port.service, port.cpe):
            if text and _DVWA_FINGERPRINTS.search(text):
                return True
    return False


def _dedupe(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Remove duplicate (title, port) pairs, keeping the first occurrence."""
    seen: set[tuple[str, int | None]] = set()
    out: list[Vulnerability] = []
    for v in vulns:
        key = (v.title, v.port)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out
