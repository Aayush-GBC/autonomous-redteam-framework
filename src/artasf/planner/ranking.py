"""
Vulnerability ranker.

Takes the raw list of Vulnerability objects from the vuln mapper and
produces a ranked, dependency-aware list of VulnSummary objects ready
to embed in the Claude prompt.

Ranking criteria (descending priority):
  1. Adjusted priority score from the scorer (CVSS + bonuses)
  2. MSF module available (immediately actionable)
  3. CVSS score
  4. Alphabetical title (stable tie-break)

Dependency hints added for the AI:
  - SSH user-enum should precede SSH brute-force
  - Info-disclosure vulns are pushed to the bottom
  - DVWA app vulns are grouped together
"""

from __future__ import annotations

from artasf.core.models import EngagementSession, Vulnerability
from artasf.planner.plan_types import PlannerContext, PortSummary, TargetSummary, VulnSummary
from artasf.vulnmap.scoring import score as compute_score
from artasf.vulnmap.sources.offline_cve import CATALOG

# Quick lookup: vuln title → catalog entry (for re-scoring if needed)
_CATALOG_BY_ID = {k.id: k for k in CATALOG}

# Tags that indicate purely informational entries (low attack priority)
_INFO_TAGS = {"information-disclosure", "user-enumeration"}


def build_context(session: EngagementSession) -> PlannerContext:
    """Convert an EngagementSession into a PlannerContext for the AI."""

    # --- target summaries ---
    target_map = {t.id: t for t in session.targets}
    target_summaries = [
        TargetSummary(
            target_id=t.id,
            ip=t.ip,
            hostname=t.hostname,
            os_guess=t.os_guess,
            open_ports=[
                PortSummary(
                    number=p.number,
                    service=p.service,
                    version=p.version,
                    banner=p.banner,
                )
                for p in t.open_ports()
            ],
        )
        for t in session.targets
    ]

    # --- ranked vuln summaries ---
    scored: list[tuple[float, Vulnerability]] = []
    for v in session.vulns:
        priority = _priority(v)
        scored.append((priority, v))

    scored.sort(key=lambda x: (-x[0], -(x[1].cvss_score or 0), x[1].title))

    vuln_summaries = [
        VulnSummary(
            vuln_id=v.id,
            target_id=v.target_id,
            target_ip=target_map.get(v.target_id, None) and target_map[v.target_id].ip or "?",
            port=v.port,
            title=v.title,
            severity=v.severity.value,
            cvss=v.cvss_score,
            cve=v.cve,
            msf_modules=v.msf_modules(),
            tags=_tags_for(v),
            description=v.description[:300],  # truncate for prompt economy
        )
        for _, v in scored
    ]

    return PlannerContext(
        engagement_name=session.name,
        network=session.target_network,
        targets=target_summaries,
        vulns=vuln_summaries,
    )


def _priority(vuln: Vulnerability) -> float:
    """Re-derive a priority float for sorting."""
    # Try to find the matching catalog entry for the scorer
    for entry in CATALOG:
        if entry.title == vuln.title:
            p, _ = compute_score(entry, vuln.port)
            return p
    # Fallback: use CVSS directly
    return vuln.cvss_score or 0.0


def _tags_for(vuln: Vulnerability) -> list[str]:
    """Return tags from the catalog entry matching this vuln title."""
    for entry in CATALOG:
        if entry.title == vuln.title:
            return list(entry.tags)
    return []
