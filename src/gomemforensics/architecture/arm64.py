"""ARM64 architecture layout - future extension point only.

Per the approved implementation plan, ARM64 support is Phase 10 work and is
explicitly NOT implemented yet. CLAUDE.md section 51 requires that this
project never represent ARM64 as inherited from the reference paper (which
is x86-64-only) or claim support before it exists.

Every property below raises :class:`NotImplementedError` with a clear
explanation rather than returning a value, so nothing about ARM64 can be
mistaken for a verified, working fact.
"""

from __future__ import annotations

from gomemforensics.architecture.base import ArchitectureLayout, InstructionDecoderConfig

_NOT_IMPLEMENTED_MESSAGE = (
    "ARM64 support is not implemented. It is planned as Phase 10 future "
    "work per the approved GoMemForensics implementation plan and must not "
    "be assumed to behave like x86-64."
)


class ARM64Layout(ArchitectureLayout):
    """Placeholder architecture layout for ARM64 (AArch64).

    Exists solely so later phases have a class to extend; it performs no
    analysis and asserts no ISA facts as verified.
    """

    @property
    def architecture_name(self) -> str:
        return "arm64"

    @property
    def is_supported(self) -> bool:
        return False

    @property
    def pointer_size(self) -> int:
        raise NotImplementedError(_NOT_IMPLEMENTED_MESSAGE)

    @property
    def word_size(self) -> int:
        raise NotImplementedError(_NOT_IMPLEMENTED_MESSAGE)

    @property
    def endianness(self) -> str:
        raise NotImplementedError(_NOT_IMPLEMENTED_MESSAGE)

    @property
    def registers(self) -> tuple[str, ...]:
        raise NotImplementedError(_NOT_IMPLEMENTED_MESSAGE)

    @property
    def calling_convention_name(self) -> str:
        raise NotImplementedError(_NOT_IMPLEMENTED_MESSAGE)

    @property
    def instruction_decoder_config(self) -> InstructionDecoderConfig:
        raise NotImplementedError(_NOT_IMPLEMENTED_MESSAGE)
