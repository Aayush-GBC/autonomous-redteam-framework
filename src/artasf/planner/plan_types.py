"""
Planner-internal types.

PlannerContext is the compact, serialisable summary of the engagement state
that gets rendered into the prompt sent to Claude.  It is intentionally
separate from the full EngagementSession so we control exactly what the AI
sees (no UUIDs, no internal timestamps — just actionable intelligence).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PortSummary:
    number:  int
    service: str
    version: str | None = None
    banner:  str | None = None


@dataclass
class TargetSummary:
    target_id: str
    ip:        str
    hostname:  str | None
    os_guess:  str | None
    open_ports: list[PortSummary] = field(default_factory=list)


@dataclass
class VulnSummary:
    vuln_id:     str
    target_id:   str
    target_ip:   str
    port:        int | None
    title:       str
    severity:    str
    cvss:        float | None
    cve:         str | None
    msf_modules: list[str]
    tags:        list[str]
    description: str


@dataclass
class PlannerContext:
    """Everything Claude needs to reason about the engagement."""
    engagement_name: str
    network:         str
    targets:         list[TargetSummary]
    vulns:           list[VulnSummary]   # pre-ranked, highest priority first
    lab_notes:       str = (
        "This is a controlled lab environment. "
        "The target runs DVWA on Ubuntu Server on a host-only network. "
        "All machines are owned by the operator. "
        "Prefer exploits that result in a shell or credential access."
    )
