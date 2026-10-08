"""x86-64 Capstone-based backward call-site argument analysis.

Approved plan Steps 9-11 (paper Section 3.3.4 - runtime argument recovery
via disassembly, since ArgInfo only ever describes *shape*, never a live
*value*; see the critical semantic note in
:mod:`gomemforensics.go_runtime.arginfo`).

Given a Go function's disassembled instructions, this module locates
``CALL`` instructions and, only where evidenced by a small set of
controlled instruction patterns immediately preceding the call, recovers
the values fed into that call.

**Phase 4.1 correction**: this module simulates register/stack state
across the whole backward window (evidence-gathering, unchanged), but
only ever *reports* a value for a location the target function's
recovered :class:`~gomemforensics.go_runtime.models.ArgumentLocation`
list actually declares as a real argument leaf - see
``known_function_argument_locations`` on :func:`analyze_call_site`. It
never sweeps every ABI-sequence register/stack slot that merely happens
to hold a determined value and labels the result "argument N" - a
pre-4.1 design defect (found via an audit's direct source-level review,
not by a failing test) that could misattribute a live-but-unrelated
register value as a callee argument. When the callee's argument shape is
unresolved or unavailable, ``recovered_arguments`` is always empty and
``CallSiteArtifact.argument_analysis_status`` is
:attr:`~gomemforensics.go_runtime.models.ArgumentRecoveryStatus.UNSUPPORTED`
- never a guessed argument count or index (CLAUDE.md section 40).

Architecture ownership (CLAUDE.md section 7 / approved plan Step 9): this
module is the x86-64-specific backward analyzer. It is never invoked for
another architecture - callers gate on
``ArchitectureLayout.is_supported`` and ``architecture_name == "x86_64"``
before reaching here. As of Phase 4.1, this module itself no longer
makes any ABI-era decision (register-based ABIInternal vs. stack-based
ABI0) - that decision, and the resulting register-vs-stack physical
location for each argument leaf, is resolved entirely upstream by
:mod:`gomemforensics.go_runtime.functab` (via
:func:`gomemforensics.architecture.x86_64.is_register_based_abi` and
:func:`gomemforensics.architecture.x86_64.assign_integer_argument_locations`)
and handed to this module as ready-to-consume
:class:`~gomemforensics.go_runtime.models.ArgumentLocation` objects. This
module only ever reads whichever location kind (``"register"`` or
``"stack"``) each one specifies, never re-derives the ABI era itself.

Scope and honesty boundaries (approved plan Step 11) - every recovered
:class:`~gomemforensics.go_runtime.models.ArgumentArtifact` carries an
:class:`~gomemforensics.go_runtime.models.ArgumentRecoveryStatus`:

  SUPPORTED    - the value comes from one of the patterns below, matched
                 exactly, within the bounded backward window, at a
                 location the callee's ArgInfo shape actually declares.
  EXPERIMENTAL - the pattern was recognized but confidence in the result
                 is reduced (a RIP-relative reference whose backing bytes
                 could not be read; a register value that only arrived via
                 a multi-hop copy chain; a location derived from a
                 truncated ArgInfo shape).
  UNSUPPORTED  - assigned at the *call-site* level
                 (``CallSiteArtifact.argument_analysis_status``) when the
                 callee's argument shape could not be determined at all -
                 no per-argument artifacts are produced in that case.

Recognized instruction patterns, matched via Capstone (x86, 64-bit mode)
instruction/operand inspection only - never by guessing at a value not
present in the instruction stream:

  - ``mov reg, imm``            -> constant integer value (``zero`` if 0)
  - ``mov reg1, reg2``          -> register-to-register propagation
  - ``lea reg, [rip + disp]``   -> RIP-relative static address
  - ``xor reg, reg`` (same reg) -> zero
  - ``mov [rsp+disp], src``     -> stack-argument write (Go ABI0, pre-1.17)

Any other instruction that writes a tracked register invalidates that
register's tracked value - a value derived from an unrecognized
instruction is never reported (CLAUDE.md section 40: "reject ambiguous
register states").

Strict analysis boundaries (approved plan Step 10):

  - never walks before the function's entry PC (the disassembled
    instruction list itself never contains anything earlier)
  - never walks past (before) an earlier CALL instruction within the same
    function - Go's calling convention clobbers the argument registers on
    every call, so nothing before the previous call is valid evidence for
    this one
  - a hard cap on the number of instructions inspected per call site
    (``MAX_WINDOW_INSTRUCTIONS`` - a safety/performance bound, not a Go
    semantic)
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import count

import capstone
from capstone import x86

from gomemforensics.common.memory import MemoryReader
from gomemforensics.common.models import ArtifactProvenance, Confidence
from gomemforensics.go_runtime.models import (
    ArgumentArtifact,
    ArgumentLocation,
    ArgumentRecoveryStatus,
    CallSiteArtifact,
)
from gomemforensics.go_runtime.scanning import read_partial

#: Safety bounds (not Go runtime invariants - see module docstring).
MAX_WINDOW_INSTRUCTIONS = 32
MAX_FUNCTION_DISASSEMBLY_BYTES = 8192
RIP_CLASSIFICATION_READ_BYTES = 64
#: A copy chain longer than this many hops is downgraded to EXPERIMENTAL -
#: an engineering trust threshold, not a decoded fact.
MAX_TRUSTED_COPY_HOPS = 2

_PRINTABLE_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_MIN_PRINTABLE_RATIO_FOR_STRING_GUESS = 0.85

#: 64-bit-canonical register name for every alias Capstone may report for
#: the 16 general-purpose x86-64 registers, across operand widths - Go
#: argument leaves are one machine word (8 bytes), so a 32/16/8-bit write
#: to a register is tracked under its 64-bit canonical name (verified: a
#: 32-bit write implicitly zero-extends/clobbers the full 64-bit register
#: on x86-64, so this is a correctness requirement, not a convenience).
_CANONICAL_REGISTER: dict[str, str] = {}
for _canon, _aliases in {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
    "r10": ("r10", "r10d", "r10w", "r10b"),
    "r11": ("r11", "r11d", "r11w", "r11b"),
    "r12": ("r12", "r12d", "r12w", "r12b"),
    "r13": ("r13", "r13d", "r13w", "r13b"),
    "r14": ("r14", "r14d", "r14w", "r14b"),
    "r15": ("r15", "r15d", "r15w", "r15b"),
}.items():
    for _alias in _aliases:
        _CANONICAL_REGISTER[_alias] = _canon


def _canonical(register_name: str) -> str | None:
    return _CANONICAL_REGISTER.get(register_name)


@dataclass(frozen=True)
class _RegVal:
    """One resolved register/stack-slot value at a point in the simulation."""

    kind: str  # "immediate" | "zero" | "rip_relative"
    immediate: int | None = None
    rip_target: int | None = None
    hops: int = 0  # number of register-to-register copies to reach this value


def _new_capstone_engine() -> capstone.Cs:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def disassemble_function(
    reader: MemoryReader,
    entry_pc: int,
    end_pc: int | None = None,
    max_bytes: int = MAX_FUNCTION_DISASSEMBLY_BYTES,
) -> list:
    """Disassemble a bounded window of a function's code, starting at ``entry_pc``.

    ``end_pc`` (typically the next function's entry address, when known -
    Go's function table lists entries in address order, though this is
    used only as a scan boundary, never treated as a hard layout
    guarantee) caps how far disassembly proceeds; ``max_bytes`` is an
    independent absolute cap. Reads use :func:`gomemforensics.go_runtime.scanning.read_partial`
    so a function near the end of a mapped region still yields whatever
    prefix is actually backed rather than raising.
    """
    if end_pc is not None and end_pc > entry_pc:
        window = min(max_bytes, end_pc - entry_pc)
    else:
        window = max_bytes

    code = read_partial(reader, entry_pc, window)
    if not code:
        return []

    md = _new_capstone_engine()
    return list(md.disasm(code, entry_pc))


def find_call_site_indices(instructions: list) -> list[int]:
    """Indices of every ``CALL`` instruction in a disassembled instruction list."""
    return [i for i, insn in enumerate(instructions) if insn.mnemonic == "call"]


def _window_start_index(instructions: list, call_index: int) -> int:
    """Backward window boundary for a call site (approved plan Step 10)."""
    idx = call_index - 1
    steps = 0
    while idx >= 0 and steps < MAX_WINDOW_INSTRUCTIONS:
        if instructions[idx].mnemonic == "call":
            return idx + 1
        idx -= 1
        steps += 1
    return idx + 1


def _classify_rip_target(reader: MemoryReader, target_address: int, known_string_data_addresses: dict[int, str]) -> tuple[str, str, Confidence, ArgumentRecoveryStatus, bool]:
    """Classify a RIP-relative reference's target.

    Returns ``(type_hint, value, confidence, status, is_pointer)``. Never
    fabricates string content - a match against an independently recovered
    :class:`~gomemforensics.go_runtime.models.StringArtifact`'s
    ``data_address`` is the only case reported as ``"string"``; otherwise
    the address itself is the reported evidence.
    """
    if target_address in known_string_data_addresses:
        return (
            "string",
            f"string_ref:{known_string_data_addresses[target_address]}",
            Confidence.MEDIUM,
            ArgumentRecoveryStatus.SUPPORTED,
            True,
        )

    raw = read_partial(reader, target_address, RIP_CLASSIFICATION_READ_BYTES)
    if not raw:
        return (
            "address",
            f"0x{target_address:x}",
            Confidence.LOW,
            ArgumentRecoveryStatus.EXPERIMENTAL,
            True,
        )

    printable = sum(1 for b in raw if b in _PRINTABLE_BYTES)
    if len(raw) and printable / len(raw) >= _MIN_PRINTABLE_RATIO_FOR_STRING_GUESS:
        # Readable and text-shaped, but not linked to a validated
        # StringArtifact - reported as a possibility, not a certainty.
        return (
            "possible_static_data",
            f"0x{target_address:x}",
            Confidence.LOW,
            ArgumentRecoveryStatus.EXPERIMENTAL,
            True,
        )

    return (
        "static_address",
        f"0x{target_address:x}",
        Confidence.MEDIUM,
        ArgumentRecoveryStatus.SUPPORTED,
        True,
    )


def _apply_instruction(insn, register_state: dict[str, _RegVal], stack_state: dict[int, _RegVal]) -> None:
    ops = insn.operands

    if insn.mnemonic == "mov" and len(ops) == 2:
        dst, src = ops[0], ops[1]

        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_IMM:
            reg = _canonical(insn.reg_name(dst.reg))
            if reg is not None:
                value = src.imm
                register_state[reg] = (
                    _RegVal(kind="zero", immediate=0) if value == 0 else _RegVal(kind="immediate", immediate=value)
                )
            return

        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_REG:
            dst_reg = _canonical(insn.reg_name(dst.reg))
            src_reg = _canonical(insn.reg_name(src.reg))
            if dst_reg is None:
                return
            source_value = register_state.get(src_reg) if src_reg is not None else None
            if source_value is None:
                register_state.pop(dst_reg, None)  # source unresolved -> ambiguous, not reported
            else:
                register_state[dst_reg] = _RegVal(
                    kind=source_value.kind,
                    immediate=source_value.immediate,
                    rip_target=source_value.rip_target,
                    hops=source_value.hops + 1,
                )
            return

        if dst.type == x86.X86_OP_MEM and dst.mem.base == x86.X86_REG_RSP and src.type in (x86.X86_OP_REG, x86.X86_OP_IMM):
            offset = dst.mem.disp
            if src.type == x86.X86_OP_IMM:
                stack_state[offset] = (
                    _RegVal(kind="zero", immediate=0) if src.imm == 0 else _RegVal(kind="immediate", immediate=src.imm)
                )
            else:
                src_reg = _canonical(insn.reg_name(src.reg))
                source_value = register_state.get(src_reg) if src_reg is not None else None
                if source_value is not None:
                    stack_state[offset] = source_value
                else:
                    stack_state.pop(offset, None)
            return

    if insn.mnemonic == "lea" and len(ops) == 2:
        dst, src = ops[0], ops[1]
        if dst.type == x86.X86_OP_REG and src.type == x86.X86_OP_MEM and src.mem.base == x86.X86_REG_RIP:
            reg = _canonical(insn.reg_name(dst.reg))
            if reg is not None:
                target = insn.address + insn.size + src.mem.disp
                register_state[reg] = _RegVal(kind="rip_relative", rip_target=target)
            return

    if insn.mnemonic == "xor" and len(ops) == 2:
        a, b = ops[0], ops[1]
        if a.type == x86.X86_OP_REG and b.type == x86.X86_OP_REG and a.reg == b.reg:
            reg = _canonical(insn.reg_name(a.reg))
            if reg is not None:
                register_state[reg] = _RegVal(kind="zero", immediate=0)
            return

    # Unrecognized instruction: any register it writes becomes ambiguous
    # and is no longer trusted (approved plan Step 10).
    try:
        _, regs_write = insn.regs_access()
    except capstone.CsError:
        regs_write = ()
    for reg_id in regs_write:
        canon = _canonical(insn.reg_name(reg_id))
        if canon is not None:
            register_state.pop(canon, None)


def _build_argument_artifact(
    location: ArgumentLocation,
    value: _RegVal,
    reader: MemoryReader,
    known_string_data_addresses: dict[int, str],
) -> ArgumentArtifact:
    """Build the final "value known" evidence for one callee-declared
    :class:`ArgumentLocation`, given the resolved register/stack value
    found at exactly that location.

    The location's own mapping confidence (HIGH for a clean ArgInfo leaf,
    MEDIUM for one derived from a truncated ArgInfo argument - see
    :func:`gomemforensics.go_runtime.functab._resolve_argument_locations`)
    is folded in: a value read from a less-certain mapping is never
    reported as more certain than the shape that told us where to look.
    """
    if value.kind == "immediate":
        type_hint, val, is_pointer = "integer", str(value.immediate), False
        confidence = Confidence.HIGH if value.hops == 0 else Confidence.MEDIUM
        status = ArgumentRecoveryStatus.SUPPORTED if value.hops <= MAX_TRUSTED_COPY_HOPS else ArgumentRecoveryStatus.EXPERIMENTAL
    elif value.kind == "zero":
        type_hint, val, is_pointer = "zero", "0", None
        confidence = Confidence.HIGH if value.hops == 0 else Confidence.MEDIUM
        status = ArgumentRecoveryStatus.SUPPORTED if value.hops <= MAX_TRUSTED_COPY_HOPS else ArgumentRecoveryStatus.EXPERIMENTAL
    else:  # rip_relative
        type_hint, val, confidence, status, is_pointer = _classify_rip_target(
            reader, value.rip_target, known_string_data_addresses
        )
        if value.hops > MAX_TRUSTED_COPY_HOPS:
            status = ArgumentRecoveryStatus.EXPERIMENTAL
            confidence = Confidence.LOW

    if location.confidence != Confidence.HIGH:
        status = ArgumentRecoveryStatus.EXPERIMENTAL
        if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[location.confidence]:
            confidence = location.confidence

    return ArgumentArtifact(
        index=location.argument_index,
        leaf_index=location.leaf_index,
        type_hint=type_hint,
        value=val,
        location=location.abi_location,
        confidence=confidence,
        extraction_method="capstone_backward_analysis",
        status=status,
        is_pointer=is_pointer,
    )


_CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1, Confidence.UNKNOWN: 0}


def analyze_call_site(
    reader: MemoryReader,
    pid: int,
    call_id: str,
    instructions: list,
    call_index: int,
    caller_function: str | None,
    known_function_addresses: dict[int, str] | None = None,
    known_function_argument_locations: dict[int, list[ArgumentLocation]] | None = None,
    known_string_data_addresses: dict[int, str] | None = None,
) -> CallSiteArtifact:
    """Analyze one ``CALL`` instruction within an already-disassembled function.

    ``known_function_argument_locations`` (Phase 4.1) maps a resolved
    callee's entry address to its ArgInfo-derived, ABI-mapped
    :class:`ArgumentLocation` list (see
    :mod:`gomemforensics.go_runtime.functab`). Register/stack state is
    always simulated across the whole backward window regardless (that is
    pure evidence-gathering), but a value is only ever *reported* - as a
    specific "argument N, leaf M" - for a location the callee's own shape
    actually declares:

    - target resolved AND its shape is known (even if legitimately
      empty, for a zero-argument function): only those declared locations
      are examined; ``argument_analysis_status = SUPPORTED``.
    - target unresolved (indirect call), or resolved but its shape is
      unavailable/ambiguous (no ArgInfo, ``ArgsPointerMaps``-only, or a
      non-register ABI era): no per-argument artifacts are produced at
      all - ``recovered_arguments`` stays empty and
      ``argument_analysis_status = UNSUPPORTED``. A live register or
      stack value observed in this case is never reported as an argument
      merely because it exists (CLAUDE.md section 40).
    """
    known_function_addresses = known_function_addresses or {}
    known_function_argument_locations = known_function_argument_locations or {}
    known_string_data_addresses = known_string_data_addresses or {}

    call_insn = instructions[call_index]
    target_op = call_insn.operands[0] if call_insn.operands else None
    target_address = target_op.imm if target_op is not None and target_op.type == x86.X86_OP_IMM else None
    target_function = known_function_addresses.get(target_address) if target_address is not None else None

    window_start = _window_start_index(instructions, call_index)
    register_state: dict[str, _RegVal] = {}
    stack_state: dict[int, _RegVal] = {}
    for insn in instructions[window_start:call_index]:
        _apply_instruction(insn, register_state, stack_state)

    callee_locations = (
        known_function_argument_locations.get(target_address) if target_address is not None else None
    )

    arguments: list[ArgumentArtifact] = []
    if callee_locations is not None:
        argument_analysis_status = ArgumentRecoveryStatus.SUPPORTED
        for loc in callee_locations:
            value = register_state.get(loc.register) if loc.location_kind == "register" else stack_state.get(loc.stack_offset)
            if value is not None:
                arguments.append(_build_argument_artifact(loc, value, reader, known_string_data_addresses))
    else:
        argument_analysis_status = ArgumentRecoveryStatus.UNSUPPORTED

    overall_confidence = Confidence.UNKNOWN
    if arguments:
        overall_confidence = min((a.confidence for a in arguments), key=lambda c: _CONFIDENCE_RANK[c])

    provenance = ArtifactProvenance(
        artifact_id=call_id,
        artifact_type="go_call_site",
        analyzer="go_runtime.backward_analysis.analyze_call_site",
        extraction_method="capstone_backward_analysis",
        confidence=overall_confidence,
        pid=pid,
        virtual_address=f"0x{call_insn.address:x}",
    )

    return CallSiteArtifact(
        id=call_id,
        pid=pid,
        caller_function=caller_function,
        call_address=call_insn.address,
        target_address=target_address,
        target_function=target_function,
        recovered_arguments=arguments,
        argument_analysis_status=argument_analysis_status,
        confidence=overall_confidence,
        extraction_method="capstone_backward_analysis",
        provenance=provenance,
    )


def analyze_function_call_sites(
    reader: MemoryReader,
    pid: int,
    entry_pc: int,
    caller_function: str | None,
    end_pc: int | None = None,
    known_function_addresses: dict[int, str] | None = None,
    known_function_argument_locations: dict[int, list[ArgumentLocation]] | None = None,
    known_string_data_addresses: dict[int, str] | None = None,
    id_counter: count | None = None,
) -> list[CallSiteArtifact]:
    """Disassemble one function and analyze every ``CALL`` site within it.

    Never raises on a malformed/undecodable instruction stream - Capstone
    simply stops disassembling at the point it cannot decode further, and
    whatever call sites were found up to that point are still analyzed
    (CLAUDE.md section 24).
    """
    instructions = disassemble_function(reader, entry_pc, end_pc)
    if not instructions:
        return []

    counter = id_counter or count(1)
    results = []
    for call_index in find_call_site_indices(instructions):
        call_id = f"CALL-{pid}-{entry_pc:x}-{next(counter)}"
        results.append(
            analyze_call_site(
                reader,
                pid,
                call_id,
                instructions,
                call_index,
                caller_function,
                known_function_addresses,
                known_function_argument_locations,
                known_string_data_addresses,
            )
        )
    return results
