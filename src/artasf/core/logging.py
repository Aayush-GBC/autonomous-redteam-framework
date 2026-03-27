"""
Structured logging setup using loguru.

Call configure_logging() once at startup (done by the orchestrator).
All other modules just do:  from loguru import logger
"""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger


def configure_logging(
    log_dir: Path | None = None,
    level: str = "INFO",
    json_file: bool = True,
) -> None:
    """
    Set up loguru sinks:
      - Colourised stdout (human-readable, no JSON)
      - Rotating JSON file in log_dir (machine-readable, for post-processing)
    """
    logger.remove()  # drop the default stderr sink

    # --- stdout sink (pretty) ---
    logger.add(
        sys.stdout,
        level=level,
        colorize=True,
        format=(
            "<green>{time:HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        backtrace=True,
        diagnose=True,
    )

    # --- JSON file sink ---
    if json_file and log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_dir / "artasf_{time:YYYY-MM-DD}.jsonl",
            level="DEBUG",
            serialize=True,       # emit as JSON Lines
            rotation="100 MB",
            retention="14 days",
            compression="gz",
            backtrace=True,
            diagnose=False,       # no sensitive local vars in files
        )

    logger.debug("Logging configured (level={}, json_file={})", level, json_file)
