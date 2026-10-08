"""Small, typed run configuration.

Deliberately minimal (CLAUDE.md section 10): no database, no external
service, no network configuration. Extend only when a later phase has a
concrete, justified need.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from gomemforensics.common.logging import LogLevel


class ConfidenceMode(str, Enum):
    """Reserved for future use by detection/reporting (not enforced yet).

    Intended to let an investigator control how aggressively low-confidence
    artifacts are surfaced once detection/scoring (Phase 6+) exists:

    - ``STRICT``:     surface HIGH/MEDIUM confidence artifacts only.
    - ``STANDARD``:   surface HIGH/MEDIUM/LOW, hide UNKNOWN by default.
    - ``PERMISSIVE``: surface everything, including UNKNOWN.
    """

    STRICT = "strict"
    STANDARD = "standard"
    PERMISSIVE = "permissive"


@dataclass
class GoMemForensicsConfig:
    """Top-level run configuration with sensible, forensic-safe defaults."""

    log_level: LogLevel = LogLevel.NORMAL
    output_directory: Path = field(default_factory=lambda: Path("reports"))
    report_directory: Path = field(default_factory=lambda: Path("reports"))
    max_workers: int = 1
    confidence_mode: ConfidenceMode = ConfidenceMode.STANDARD
