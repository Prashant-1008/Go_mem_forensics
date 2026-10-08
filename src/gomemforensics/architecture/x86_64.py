"""x86-64 architecture layout and Go ABI argument-location assignment.

x86-64 is the first fully-described architecture (CLAUDE.md section 7,
Phase 1 priority). All values below are well-documented, public ISA facts
(register names, pointer width) - not Go-runtime-specific offsets, which are
never hardcoded per CLAUDE.md section 40.

The Go ABI argument-register order and assignment algorithm (Phase 4) are
verified against the local go1.26.2 install's authoritative specification,
``cmd/compile/abi-internal.md``:

- amd64 integer argument/result register sequence (9 registers, exact
  order): "RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11" (section "amd64
  architecture").
- Register-assignment algorithm (section "Function call argument and
  result passing"): each argument is assigned *entirely* to registers or
  *entirely* to the stack (never split); assignment fails over to the
  stack when there are not enough remaining registers, and critically -
  a failed (stack-assigned) argument does **not** consume registers that
  a later argument could still use (verified: "reset I ... to the values
  from step 1").
"""

from __future__ import annotations

from dataclasses import dataclass

from gomemforensics.architecture.base import ArchitectureLayout, InstructionDecoderConfig

#: The 16 general-purpose 64-bit registers of the x86-64 ISA.
_X86_64_REGISTERS: tuple[str, ...] = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)

#: Go ABIInternal (>=1.17) integer argument/result register sequence for
#: amd64 - verified verbatim from ``cmd/compile/abi-internal.md``, section
#: "amd64 architecture": "RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11".
#: Floating-point arguments use a separate X0-X14 sequence, which this
#: project does not track (see ``assign_integer_argument_locations``'s
#: docstring) - float/complex arguments are explicitly UNSUPPORTED.
GO_ABI_INTERNAL_AMD64_INT_REGISTERS: tuple[str, ...] = (
    "rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11",
)


class X86_64Layout(ArchitectureLayout):
    """Architecture layout for x86-64 (AMD64 / Intel 64)."""

    @property
    def architecture_name(self) -> str:
        return "x86_64"

    @property
    def is_supported(self) -> bool:
        return True

    @property
    def pointer_size(self) -> int:
        return 8

    @property
    def word_size(self) -> int:
        return 8

    @property
    def endianness(self) -> str:
        return "little"

    @property
    def registers(self) -> tuple[str, ...]:
        return _X86_64_REGISTERS

    @property
    def calling_convention_name(self) -> str:
        # Go's calling convention on x86-64 changed at Go 1.17 (stack-based
        # ABI0 -> register-based ABIInternal). Which one applies to a given
        # binary is a Go-version-dependent decision made by the ABI-aware
        # backward analyzer in a later phase; this label only identifies
        # that x86-64 is dual-ABI, it does not choose between them.
        return "Go ABI0 (stack-based, pre-1.17) / ABIInternal (register-based, 1.17+)"

    @property
    def instruction_decoder_config(self) -> InstructionDecoderConfig:
        return InstructionDecoderConfig(engine="capstone", arch="x86", mode="64")


@dataclass(frozen=True)
class ArgumentLeafLocation:
    """Where one ArgInfo leaf (a single machine word) actually lives.

    For ``kind == "register"``, ``fp_offset`` is still recorded (the
    ArgInfo-declared spill-slot offset) for provenance, but the *value*
    must be read from ``register`` - the spill slot is uninitialized at
    call time (verified: ``cmd/compile/internal/abi/abiutils.go``,
    ``FrameOffset`` doc comment). For ``kind == "stack"``, the value is
    actually at ``fp_offset`` in the caller's frame.
    """

    kind: str  # "register" | "stack"
    fp_offset: int
    size: int
    register: str | None = None


#: Go version ranges known to use ABIInternal (register-based) on amd64 -
#: introduced in Go 1.17 (``cmd/compile/abi-internal.md``). A range that
#: straddles the 1.17 boundary (``"1.16-1.17"``, the widest magic-based
#: range this project can currently distinguish - see
#: :mod:`gomemforensics.go_runtime.version`) is deliberately NOT listed in
#: either set below: the ABI cannot be determined confidently from that
#: evidence alone (CLAUDE.md section 30: "If the version cannot be
#: determined confidently: unknown. Do not guess").
_REGISTER_ABI_VERSION_RANGES = frozenset({"1.18-1.19", "1.20+", "1.22+"})
_STACK_ABI_VERSION_RANGES = frozenset({"1.2-1.15"})


def is_register_based_abi(go_version_range: str | None) -> bool | None:
    """Whether ``go_version_range`` uses Go's register-based ABIInternal on amd64.

    Returns ``True`` (ABIInternal, >=1.17), ``False`` (ABI0, stack-based,
    pre-1.17), or ``None`` when the evidence does not confidently place
    the version on one side of the 1.17 boundary - callers must treat
    ``None`` as "argument-value recovery unsupported for this runtime",
    never default to one strategy.
    """
    if go_version_range in _REGISTER_ABI_VERSION_RANGES:
        return True
    if go_version_range in _STACK_ABI_VERSION_RANGES:
        return False
    return None


def assign_integer_argument_locations(
    arguments: list[list[tuple[int, int]]], num_integer_registers: int
) -> list[list[ArgumentLeafLocation]]:
    """Assign each top-level argument's leaves to registers or the stack.

    Implements the verified Go ABI register-assignment algorithm
    (``cmd/compile/abi-internal.md``, "Function call argument and result
    passing"), restricted to the **integer register class only** - every
    leaf is assumed to occupy exactly one integer-register-width word.
    This is correct for the type shapes this phase actually interprets
    (bool/integer/pointer/map/chan/func -> 1 leaf; string/interface -> 2;
    slice -> 3 - all verified in the algorithm's own base cases). Leaves
    belonging to a struct/array field or a floating-point/complex value
    are **not represented correctly** by this function and must not be
    passed to it - callers restrict argument recovery to the supported
    shapes and mark anything else UNSUPPORTED rather than mis-assigning
    it (approved plan Section 11).

    Args:
        arguments: one ``[(fp_offset, size), ...]`` list per top-level
            argument, in declaration order - directly the ``(leaf.offset,
            leaf.size)`` pairs from :func:`gomemforensics.go_runtime.arginfo.decode_arg_info`.
        num_integer_registers: size of the integer register budget.
            Passing ``0`` degenerates to "everything on the stack", which
            is exactly Go's pre-1.17 ABI0 (stack-based) convention - the
            same function serves both ABI eras.

    Per the verified algorithm: an argument is assigned register
    locations only if *all* of its leaves fit in the remaining register
    budget; otherwise the *entire* argument goes to the stack (using its
    ArgInfo-declared offsets, which are real stack offsets in that case)
    and - critically - the register index is **not** advanced, so a
    later, smaller argument can still use those registers (verified: step
    4, "reset I ... to the values from step 1").
    """
    if num_integer_registers < 0:
        raise ValueError("num_integer_registers must be >= 0")

    results: list[list[ArgumentLeafLocation]] = []
    register_index = 0

    for leaves in arguments:
        if register_index + len(leaves) <= num_integer_registers:
            locations = [
                ArgumentLeafLocation(
                    kind="register",
                    fp_offset=fp_offset,
                    size=size,
                    register=GO_ABI_INTERNAL_AMD64_INT_REGISTERS[register_index + i],
                )
                for i, (fp_offset, size) in enumerate(leaves)
            ]
            register_index += len(leaves)
        else:
            locations = [
                ArgumentLeafLocation(kind="stack", fp_offset=fp_offset, size=size)
                for fp_offset, size in leaves
            ]
            # register_index deliberately NOT advanced - verified rule.
        results.append(locations)

    return results
