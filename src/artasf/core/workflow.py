"""
Workflow state machine for ARTASF.

Defines the legal phase transitions and guards against invalid jumps.
The orchestrator calls advance() / fail() to move through the pipeline.
"""

from __future__ import annotations

from loguru import logger

from artasf.core.exceptions import WorkflowError
from artasf.core.models import WorkflowPhase


# Directed graph of allowed transitions
_TRANSITIONS: dict[WorkflowPhase, list[WorkflowPhase]] = {
    WorkflowPhase.INIT:         [WorkflowPhase.RECON,        WorkflowPhase.FAILED],
    WorkflowPhase.RECON:        [WorkflowPhase.VULN_MAP,     WorkflowPhase.FAILED],
    WorkflowPhase.VULN_MAP:     [WorkflowPhase.PLANNING,     WorkflowPhase.FAILED],
    WorkflowPhase.PLANNING:     [WorkflowPhase.EXPLOITING,   WorkflowPhase.FAILED],
    WorkflowPhase.EXPLOITING:   [WorkflowPhase.POST_EXPLOIT, WorkflowPhase.REPORTING, WorkflowPhase.FAILED],
    WorkflowPhase.POST_EXPLOIT: [WorkflowPhase.REPORTING,    WorkflowPhase.FAILED],
    WorkflowPhase.REPORTING:    [WorkflowPhase.DONE,         WorkflowPhase.FAILED],
    WorkflowPhase.DONE:         [],
    WorkflowPhase.FAILED:       [],
}

# Human-readable labels shown in the terminal
PHASE_LABELS: dict[WorkflowPhase, str] = {
    WorkflowPhase.INIT:         "Initialising",
    WorkflowPhase.RECON:        "Reconnaissance",
    WorkflowPhase.VULN_MAP:     "Vulnerability Mapping",
    WorkflowPhase.PLANNING:     "AI Attack Planning",
    WorkflowPhase.EXPLOITING:   "Exploitation",
    WorkflowPhase.POST_EXPLOIT: "Post-Exploitation",
    WorkflowPhase.REPORTING:    "Report Generation",
    WorkflowPhase.DONE:         "Done",
    WorkflowPhase.FAILED:       "Failed",
}


class WorkflowStateMachine:
    """
    Tracks the current workflow phase and enforces legal transitions.

    Example:
        sm = WorkflowStateMachine()
        sm.advance(WorkflowPhase.RECON)
        sm.advance(WorkflowPhase.VULN_MAP)
        print(sm.current)   # WorkflowPhase.VULN_MAP
    """

    def __init__(self, initial: WorkflowPhase = WorkflowPhase.INIT) -> None:
        self._phase = initial

    @property
    def current(self) -> WorkflowPhase:
        return self._phase

    @property
    def label(self) -> str:
        return PHASE_LABELS[self._phase]

    @property
    def is_terminal(self) -> bool:
        return self._phase in (WorkflowPhase.DONE, WorkflowPhase.FAILED)

    def can_advance_to(self, target: WorkflowPhase) -> bool:
        return target in _TRANSITIONS.get(self._phase, [])

    def advance(self, target: WorkflowPhase) -> None:
        """Move to *target* phase, raising WorkflowError if not allowed."""
        if not self.can_advance_to(target):
            raise WorkflowError(
                f"Illegal transition: {self._phase.value} → {target.value}. "
                f"Allowed: {[p.value for p in _TRANSITIONS.get(self._phase, [])]}"
            )
        logger.info(
            "Phase transition: [{}] → [{}]",
            PHASE_LABELS[self._phase],
            PHASE_LABELS[target],
        )
        self._phase = target

    def fail(self, reason: str = "") -> None:
        """Unconditionally move to FAILED (always allowed from any non-terminal phase)."""
        if self.is_terminal:
            return
        logger.error("Workflow failed at phase [{}]: {}", self.label, reason)
        self._phase = WorkflowPhase.FAILED
