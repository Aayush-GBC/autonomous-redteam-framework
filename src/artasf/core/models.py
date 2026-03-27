"""
Core domain models for ARTASF.

These Pydantic models are the single source of truth for data flowing
through the pipeline: Target → Port → Vulnerability → ExploitAttempt → PostExploitData.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"


class ExploitStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    SUCCESS   = "success"
    FAILED    = "failed"
    SKIPPED   = "skipped"
    TIMEOUT   = "timeout"


class SessionStatus(str, Enum):
    ACTIVE    = "active"
    COMPLETED = "completed"
    FAILED    = "failed"
    ABORTED   = "aborted"


class WorkflowPhase(str, Enum):
    INIT         = "init"
    RECON        = "recon"
    VULN_MAP     = "vuln_map"
    PLANNING     = "planning"
    EXPLOITING   = "exploiting"
    POST_EXPLOIT = "post_exploit"
    REPORTING    = "reporting"
    DONE         = "done"
    FAILED       = "failed"


# ---------------------------------------------------------------------------
# Recon models
# ---------------------------------------------------------------------------

class Port(BaseModel):
    number:   int
    protocol: str = "tcp"
    state:    PortState = PortState.OPEN
    service:  str = "unknown"
    version:  str | None = None
    banner:   str | None = None
    cpe:      str | None = None  # Common Platform Enumeration string from nmap


class Target(BaseModel):
    id:        str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip:        str
    hostname:  str | None = None
    os_guess:  str | None = None
    os_cpe:    str | None = None
    ports:     list[Port] = Field(default_factory=list)
    tags:      list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=_now)

    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    def has_service(self, name: str) -> bool:
        return any(name.lower() in (p.service or "").lower() for p in self.open_ports())


# ---------------------------------------------------------------------------
# Vulnerability models
# ---------------------------------------------------------------------------

class ExploitRef(BaseModel):
    """A reference to a known exploit (Metasploit module, EDB-ID, URL)."""
    type:        str   # "msf", "edb", "url", "cve"
    value:       str
    description: str | None = None


class Vulnerability(BaseModel):
    id:          str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id:   str
    port:        int | None = None
    service:     str | None = None
    title:       str
    description: str = ""
    severity:    Severity = Severity.MEDIUM
    cvss_score:  float | None = None
    cve:         str | None = None
    cpe:         str | None = None
    exploit_refs: list[ExploitRef] = Field(default_factory=list)
    confirmed:   bool = False   # True once an exploit succeeds against it
    found_at:    datetime = Field(default_factory=_now)

    def msf_modules(self) -> list[str]:
        return [r.value for r in self.exploit_refs if r.type == "msf"]


# ---------------------------------------------------------------------------
# Planning models
# ---------------------------------------------------------------------------

class AttackStep(BaseModel):
    """A single ordered step in the AI-generated attack plan."""
    step:          int
    vuln_id:       str
    target_id:     str
    rationale:     str
    module:        str              # MSF module path or custom handler tag
    params:        dict[str, Any] = Field(default_factory=dict)
    risk_level:    Severity = Severity.MEDIUM
    requires_step: int | None = None  # dependency ordering


class AttackPlan(BaseModel):
    id:           str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id:   str
    steps:        list[AttackStep]
    rationale:    str = ""           # Claude's top-level reasoning
    created_at:   datetime = Field(default_factory=_now)
    model_used:   str = ""


# ---------------------------------------------------------------------------
# Exploit models
# ---------------------------------------------------------------------------

class ExploitAttempt(BaseModel):
    id:           str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id:   str
    vuln_id:      str
    target_id:    str
    step:         int
    module:       str
    params:       dict[str, Any] = Field(default_factory=dict)
    status:       ExploitStatus = ExploitStatus.PENDING
    output:       str | None = None
    error:        str | None = None
    msf_session_id: int | None = None
    started_at:   datetime | None = None
    ended_at:     datetime | None = None

    def duration_seconds(self) -> float | None:
        start = self.started_at
        end = self.ended_at
        if start is not None and end is not None:
            return (end - start).total_seconds()
        return None


# ---------------------------------------------------------------------------
# Post-exploitation models
# ---------------------------------------------------------------------------

class LootItem(BaseModel):
    id:         str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    target_id:  str
    type:       str          # "credential", "file", "hash", "token"
    value:      str
    source:     str = ""     # where it was extracted from
    captured_at: datetime = Field(default_factory=_now)


class PostExploitData(BaseModel):
    target_id:        str
    msf_session_id:   int
    hostname:         str | None = None
    whoami:           str | None = None
    os_info:          str | None = None
    network_ifaces:   list[str] = Field(default_factory=list)
    loot:             list[LootItem] = Field(default_factory=list)
    privesc_achieved: bool = False
    privesc_method:   str | None = None


# ---------------------------------------------------------------------------
# Engagement session
# ---------------------------------------------------------------------------

class EngagementSession(BaseModel):
    id:           str = Field(default_factory=lambda: str(uuid.uuid4()))
    name:         str
    target_network: str
    targets:      list[Target] = Field(default_factory=list)
    vulns:        list[Vulnerability] = Field(default_factory=list)
    plan:         AttackPlan | None = None
    attempts:     list[ExploitAttempt] = Field(default_factory=list)
    post_data:    list[PostExploitData] = Field(default_factory=list)
    loot:         list[LootItem] = Field(default_factory=list)
    phase:        WorkflowPhase = WorkflowPhase.INIT
    status:       SessionStatus = SessionStatus.ACTIVE
    started_at:   datetime = Field(default_factory=_now)
    ended_at:     datetime | None = None

    def successful_attempts(self) -> list[ExploitAttempt]:
        return [a for a in self.attempts if a.status == ExploitStatus.SUCCESS]
