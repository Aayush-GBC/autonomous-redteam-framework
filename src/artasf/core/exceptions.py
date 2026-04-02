"""Custom exception hierarchy for ARTASF."""


class ARTASFError(Exception):
    """Base exception for all framework errors."""


# --- Configuration -----------------------------------------------------------

class ConfigError(ARTASFError):
    """Raised when required configuration is missing or invalid."""


# --- Recon -------------------------------------------------------------------

class ReconError(ARTASFError):
    """Raised when a reconnaissance operation fails."""


class NmapError(ReconError):
    """nmap subprocess failed or produced unparseable output."""


class DNSError(ReconError):
    """DNS enumeration failed."""


# --- Vulnerability mapping ---------------------------------------------------

class VulnMapError(ARTASFError):
    """Raised when vulnerability mapping fails."""


# --- Planning (AI) -----------------------------------------------------------

class PlannerError(ARTASFError):
    """Raised when the AI planner cannot produce a valid plan."""


class AIResponseError(PlannerError):
    """Claude returned a response that could not be parsed into an AttackPlan."""


# --- Exploit -----------------------------------------------------------------

class ExploitError(ARTASFError):
    """Raised when an exploit attempt encounters a fatal error."""


class MSFConnectionError(ExploitError):
    """Cannot connect to Metasploit RPC daemon."""


class MSFModuleError(ExploitError):
    """Metasploit module launch or execution failed."""


class ExploitTimeout(ExploitError):
    """Exploit attempt exceeded the configured timeout."""


# --- Post-exploitation -------------------------------------------------------

class PostExploitError(ARTASFError):
    """Raised when post-exploitation actions fail."""


class SessionLostError(PostExploitError):
    """MSF session died unexpectedly."""


# --- Storage -----------------------------------------------------------------

class StorageError(ARTASFError):
    """Raised when database or file-store operations fail."""


# --- Reporting ---------------------------------------------------------------

class ReportError(ARTASFError):
    """Raised when report generation fails."""


# --- Workflow / Orchestrator -------------------------------------------------

class WorkflowError(ARTASFError):
    """Raised when an illegal phase transition is attempted."""


class EngagementAborted(ARTASFError):
    """Raised to signal a clean abort of the engagement (e.g. CTRL-C)."""
