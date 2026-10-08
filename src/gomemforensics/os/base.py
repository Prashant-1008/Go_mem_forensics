"""Operating-system abstraction interface.

At this phase, an OS profile only describes itself - name, support status,
and which architectures this project currently targets on it. Process
enumeration, memory-layer access, and any other Volatility-backed behavior
is explicitly Phase 1 work and must not be added here yet (CLAUDE.md
section 39, "do not invent Volatility APIs").
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class OperatingSystemProfile(ABC):
    """Describes one supported (or planned) target operating system."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable OS name (e.g. ``"Windows"``, ``"Linux"``)."""

    @property
    @abstractmethod
    def supported(self) -> bool:
        """Whether this OS is a current implementation target.

        Per CLAUDE.md section 51, supported OS/architecture combinations
        must be documented based on actual testing, not asserted broadly.
        This flag reflects project *scope* (is analysis for this OS being
        built at all), not a claim that analysis has been validated - that
        distinction belongs to the per-capability confidence/validation
        records introduced in later phases.
        """

    @property
    @abstractmethod
    def supported_architectures(self) -> tuple[str, ...]:
        """Architecture names (matching ``ArchitectureLayout.architecture_name``)
        this project currently targets for this OS."""
