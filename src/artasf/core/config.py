"""
Framework configuration — loaded from environment variables / .env file.

Usage:
    from artasf.core.config import settings
    print(settings.msf_host)
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ARTASFSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Anthropic / Claude
    # ------------------------------------------------------------------
    anthropic_api_key: str | None = Field(default=None, description="Anthropic API key (sk-ant-...)")
    claude_model: str = Field(
        default="claude-sonnet-4-6",
        description="Claude model ID used for autonomous planning",
    )
    # Maximum tokens Claude may use for a single planning response
    planner_max_tokens: int = Field(default=4096)

    # ------------------------------------------------------------------
    # Metasploit RPC
    # ------------------------------------------------------------------
    msf_host:     str  = Field(default="127.0.0.1")
    msf_port:     int  = Field(default=55553)
    msf_password: str  = Field(default="msf")
    msf_ssl:      bool = Field(default=True)

    # ------------------------------------------------------------------
    # Engagement / target
    # ------------------------------------------------------------------
    target_network: str = Field(
        default="192.168.56.0/24",
        description="CIDR range to scan (host-only lab network)",
    )
    engagement_name: str = Field(default="lab-engagement")
    # Attacker IP used as LHOST for reverse shells
    lhost: str = Field(default="", description="Attacker machine IP (reverse shell callback)")

    # ------------------------------------------------------------------
    # Behaviour limits
    # ------------------------------------------------------------------
    max_exploit_attempts: int   = Field(default=3)
    exploit_timeout_sec:  int   = Field(default=60)
    # When True, recon and planning run but no exploits are launched
    dry_run:              bool  = Field(default=False)
    # Nmap flags passed verbatim (in addition to -oX)
    nmap_flags:           str   = Field(default="-sV -sC --open -T4")

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    artifacts_dir: Path = Field(default=Path("artifacts"))

    @property
    def db_path(self) -> Path:
        return self.artifacts_dir / "artasf.db"

    @property
    def reports_dir(self) -> Path:
        return self.artifacts_dir / "reports"

    @property
    def loot_dir(self) -> Path:
        return self.artifacts_dir / "loot"

    @field_validator("artifacts_dir", mode="before")
    @classmethod
    def _coerce_path(cls, v: object) -> Path:
        return Path(str(v))

    def ensure_dirs(self) -> None:
        """Create artifact subdirectories if they don't exist."""
        for d in (self.artifacts_dir, self.reports_dir, self.loot_dir):
            d.mkdir(parents=True, exist_ok=True)


# Module-level singleton — import this everywhere.
settings = ARTASFSettings()
