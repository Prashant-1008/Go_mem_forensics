"""Architecture abstraction interface.

This module defines only structural, well-documented ISA-level facts and
identifiers (pointer size, register names, a calling-convention label, and a
disassembler configuration descriptor). It does not implement ABI-aware
backward analysis, stack unwinding, or any Go-runtime-specific offset - those
are later-phase concerns built on top of this interface.

No Go runtime structure offsets are defined anywhere in this module
(CLAUDE.md section 40: never invent offsets).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class InstructionDecoderConfig:
    """Describes which disassembly engine/arch/mode a later phase should use.

    Deliberately stores plain string identifiers rather than importing and
    embedding Capstone's own enum constants, so this module has no hard
    dependency on Capstone and no ABI/decoding logic is implied. The
    ABI-aware backward analyzer introduced in Phase 4 is responsible for
    mapping these identifiers onto real Capstone constants.
    """

    engine: str
    arch: str
    mode: str


class ArchitectureLayout(ABC):
    """Abstract description of an instruction-set architecture.

    Concrete subclasses describe a single architecture's foundational
    facts. Nothing in this class - or its subclasses in Phase 0 - performs
    analysis; it exists so later phases (function/goroutine analysis,
    ABI-aware backward analysis, stack unwinding) have a single, consistent
    seam for architecture-dependent behavior instead of scattering
    conditionals across analyzer code.
    """

    @property
    @abstractmethod
    def architecture_name(self) -> str:
        """Short, canonical architecture identifier (e.g. ``"x86_64"``)."""

    @property
    @abstractmethod
    def is_supported(self) -> bool:
        """Whether this architecture has a working analysis implementation.

        ``False`` means the layout exists only as a future extension point;
        every other property on such a layout raises ``NotImplementedError``
        rather than returning a value that might be mistaken for a verified
        fact.
        """

    @property
    @abstractmethod
    def pointer_size(self) -> int:
        """Pointer size in bytes (e.g. 8 for 64-bit architectures)."""

    @property
    @abstractmethod
    def word_size(self) -> int:
        """Native machine word size in bytes."""

    @property
    @abstractmethod
    def endianness(self) -> str:
        """Byte order: ``"little"`` or ``"big"``."""

    @property
    @abstractmethod
    def registers(self) -> tuple[str, ...]:
        """General-purpose register names, in architecture-defined order."""

    @property
    @abstractmethod
    def calling_convention_name(self) -> str:
        """Human-readable label for the platform/Go calling convention(s).

        This is a descriptive label only. Actual ABI-aware argument
        recovery (register vs. stack placement, per Go version) is
        implemented by the ABI backward analyzer added in a later phase.
        """

    @property
    @abstractmethod
    def instruction_decoder_config(self) -> InstructionDecoderConfig:
        """Disassembler configuration to be used by later-phase analyzers."""
