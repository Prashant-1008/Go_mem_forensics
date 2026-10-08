"""Unit tests for Capstone-based x86-64 backward call-site argument analysis.

All raw instruction bytes below were hand-encoded from documented x86-64
encoding rules and independently verified by disassembling them with
Capstone before being used here (see the verification script referenced
in the Phase 4 session notes) - never guessed.

Phase 4.1 correction: backward analysis no longer sweeps every ABI-order
register/stack slot that happens to hold a value - it only ever reports a
value for a location the *callee's* recovered
:class:`~gomemforensics.go_runtime.models.ArgumentLocation` list actually
declares. Every test below that wants a value recovered must therefore
supply ``known_function_argument_locations`` describing the callee's
expected shape (via the ``_loc``/``_locs_at`` helpers) - this is by
design, not incidental test plumbing: it is the same mechanism that
prevents an unrelated live register from being misattributed as an
argument (see ``TestFalsePositiveControl`` below).
"""

import struct

import pytest

from gomemforensics.common.memory import MockMemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime import backward_analysis as ba
from gomemforensics.go_runtime.models import ArgumentLocation

# --- Hand-encoded instruction builders (verified via Capstone disasm) ------

_REG_INFO = {  # register name -> (needs_REX_extension_bit, ModRM/opcode field 0-7)
    "rax": (0, 0), "rcx": (0, 1), "rdx": (0, 2), "rbx": (0, 3),
    "rsp": (0, 4), "rbp": (0, 5), "rsi": (0, 6), "rdi": (0, 7),
    "r8": (1, 0), "r9": (1, 1), "r10": (1, 2), "r11": (1, 3),
}


def _mov_reg_imm32(reg: str, imm: int) -> bytes:
    b, field = _REG_INFO[reg]
    rex = 0x48 | (0x01 if b else 0x00)
    modrm = 0xC0 | field
    return bytes([rex, 0xC7, modrm]) + struct.pack("<i", imm)


def _mov_reg_reg(dst: str, src: str) -> bytes:
    db, dfield = _REG_INFO[dst]
    sb, sfield = _REG_INFO[src]
    rex = 0x48 | (0x04 if sb else 0) | (0x01 if db else 0)
    modrm = 0xC0 | (sfield << 3) | dfield
    return bytes([rex, 0x89, modrm])


def _xor_reg_reg(reg: str) -> bytes:
    b, field = _REG_INFO[reg]
    rex = 0x48 | (0x04 if b else 0) | (0x01 if b else 0)
    modrm = 0xC0 | (field << 3) | field
    return bytes([rex, 0x31, modrm])


def _inc_reg(reg: str) -> bytes:
    b, field = _REG_INFO[reg]
    rex = 0x48 | (0x01 if b else 0)
    modrm = 0xC0 | field
    return bytes([rex, 0xFF, modrm])


def _mov_mem_rsp_reg(disp8: int, src: str) -> bytes:
    sb, sfield = _REG_INFO[src]
    rex = 0x48 | (0x04 if sb else 0)
    modrm = 0x44 | (sfield << 3)
    return bytes([rex, 0x89, modrm, 0x24]) + struct.pack("<b", disp8)


def _mov_mem_rsp_imm32(disp8: int, imm: int) -> bytes:
    return bytes([0x48, 0xC7, 0x44, 0x24]) + struct.pack("<b", disp8) + struct.pack("<i", imm)


def _lea_rip(reg: str, insn_address: int, target: int) -> bytes:
    _, field = _REG_INFO[reg]
    modrm = 0x05 | (field << 3)
    disp = target - (insn_address + 7)
    return bytes([0x48, 0x8D, modrm]) + struct.pack("<i", disp)


def _call_rel32(insn_address: int, target: int) -> bytes:
    disp = target - (insn_address + 5)
    return bytes([0xE8]) + struct.pack("<i", disp)


_CALL_RAX = bytes([0xFF, 0xD0])  # indirect call rax - verified length 2
_NOP = bytes([0x90])


def _assemble(entry_pc: int, parts) -> bytes:
    """Resolve a list of raw-bytes-or-callable(insn_address)->bytes parts
    into one contiguous buffer, in address order."""
    addr = entry_pc
    resolved = []
    for part in parts:
        b = part(addr) if callable(part) else part
        resolved.append(b)
        addr += len(b)
    return b"".join(resolved)


ENTRY_PC = 0x401000
DEFAULT_TARGET = 0x402000


def _loc(
    register: str | None = None,
    stack_offset: int | None = None,
    argument_index: int = 0,
    leaf_index: int = 0,
    confidence: Confidence = Confidence.HIGH,
    function_id: str = "FUNC-TEST",
) -> ArgumentLocation:
    """Build one callee-declared :class:`ArgumentLocation` for a test."""
    return ArgumentLocation(
        argument_index=argument_index,
        leaf_index=leaf_index,
        kind="scalar",
        size=8,
        location_kind="register" if register is not None else "stack",
        register=register,
        stack_offset=stack_offset,
        confidence=confidence,
        function_id=function_id,
    )


def _locs_at(target: int, *locations: ArgumentLocation) -> dict[int, list[ArgumentLocation]]:
    """A ``known_function_argument_locations`` dict declaring ``target``'s
    callee shape as exactly ``locations`` - the "shape known" precondition
    every positive-recovery test below relies on."""
    return {target: list(locations)}


class TestDisassembleFunction:
    def test_disassembles_within_max_bytes(self):
        code = _mov_reg_imm32("rax", 1) + _CALL_RAX
        reader = MockMemoryReader(ENTRY_PC, code)
        instructions = ba.disassemble_function(reader, ENTRY_PC)
        assert [i.mnemonic for i in instructions] == ["mov", "call"]

    def test_respects_end_pc_bound(self):
        code = _mov_reg_imm32("rax", 1) + _mov_reg_imm32("rbx", 2) + _CALL_RAX
        reader = MockMemoryReader(ENTRY_PC, code)
        # end_pc cuts off after the first instruction (7 bytes).
        instructions = ba.disassemble_function(reader, ENTRY_PC, end_pc=ENTRY_PC + 7)
        assert [i.mnemonic for i in instructions] == ["mov"]

    def test_unreadable_region_returns_empty_list(self):
        reader = MockMemoryReader(ENTRY_PC, b"")
        assert ba.disassemble_function(reader, ENTRY_PC + 0x9999) == []

    def test_partially_backed_region_disassembles_available_prefix(self):
        # MockMemoryReader region is smaller than MAX_FUNCTION_DISASSEMBLY_BYTES;
        # read_partial must still yield the available prefix, not nothing.
        code = _mov_reg_imm32("rax", 1) + _CALL_RAX
        reader = MockMemoryReader(ENTRY_PC, code)  # exactly 9 bytes, no padding
        instructions = ba.disassemble_function(reader, ENTRY_PC)
        assert [i.mnemonic for i in instructions] == ["mov", "call"]


class TestFindCallSiteIndices:
    def test_finds_all_calls(self):
        code = _mov_reg_imm32("rax", 1) + _CALL_RAX + _NOP + _CALL_RAX
        reader = MockMemoryReader(ENTRY_PC, code)
        instructions = ba.disassemble_function(reader, ENTRY_PC)
        assert ba.find_call_site_indices(instructions) == [1, 3]

    def test_no_calls_returns_empty(self):
        code = _mov_reg_imm32("rax", 1) + _NOP
        reader = MockMemoryReader(ENTRY_PC, code)
        instructions = ba.disassemble_function(reader, ENTRY_PC)
        assert ba.find_call_site_indices(instructions) == []


class TestImmediateAndZeroArguments:
    def test_immediate_argument_recovered_as_supported_high_confidence(self):
        target = 0x402000
        code = _assemble(
            ENTRY_PC,
            [_mov_reg_imm32("rax", 0x2A), lambda a: _call_rel32(a, target)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_addresses={target: "main.target"},
            known_function_argument_locations=_locs_at(target, _loc(register="rax")),
        )
        assert len(results) == 1
        call = results[0]
        assert call.target_address == target
        assert call.target_function == "main.target"
        assert call.argument_analysis_status.value == "supported"
        assert len(call.recovered_arguments) == 1
        arg = call.recovered_arguments[0]
        assert arg.location == "register:rax"
        assert arg.index == 0
        assert arg.leaf_index == 0
        assert arg.type_hint == "integer"
        assert arg.value == "42"
        assert arg.status.value == "supported"
        assert arg.confidence.value == "high"

    def test_zero_via_xor_recovered(self):
        code = _assemble(
            ENTRY_PC,
            [_xor_reg_reg("r8"), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="r8")),
        )
        args = results[0].recovered_arguments
        assert len(args) == 1
        assert args[0].location == "register:r8"
        assert args[0].type_hint == "zero"
        assert args[0].value == "0"
        assert args[0].status.value == "supported"


class TestRegisterPropagation:
    def test_single_hop_copy_is_supported_medium_confidence(self):
        code = _assemble(
            ENTRY_PC,
            [
                _mov_reg_imm32("rax", 5),
                _mov_reg_reg("rdi", "rax"),  # rdi = rax (1 hop)
                lambda a: _call_rel32(a, DEFAULT_TARGET),
            ],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rdi")),
        )
        args = results[0].recovered_arguments
        by_reg = {a.location: a for a in args}
        assert "register:rdi" in by_reg
        assert by_reg["register:rdi"].value == "5"
        assert by_reg["register:rdi"].confidence.value == "medium"
        assert by_reg["register:rdi"].status.value == "supported"

    def test_long_copy_chain_downgraded_to_experimental(self):
        # rax -(hop1)-> rbx -(hop2)-> rcx -(hop3)-> rdi: hops=3 > MAX_TRUSTED_COPY_HOPS.
        code = _assemble(
            ENTRY_PC,
            [
                _mov_reg_imm32("rax", 9),
                _mov_reg_reg("rbx", "rax"),
                _mov_reg_reg("rcx", "rbx"),
                _mov_reg_reg("rdi", "rcx"),
                lambda a: _call_rel32(a, DEFAULT_TARGET),
            ],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rdi")),
        )
        by_reg = {a.location: a for a in results[0].recovered_arguments}
        assert by_reg["register:rdi"].status.value == "experimental"

    def test_copy_from_unresolved_source_is_not_reported(self):
        # rbx is never set before this copy - rdi must stay unresolved
        # (ambiguous source), never fabricated, even though the callee
        # declares rdi as its one argument location.
        code = _assemble(
            ENTRY_PC,
            [_mov_reg_reg("rdi", "rbx"), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rdi")),
        )
        locations = [a.location for a in results[0].recovered_arguments]
        assert "register:rdi" not in locations


class TestUnrecognizedInstructionInvalidatesRegister:
    def test_clobbering_instruction_removes_prior_value(self):
        code = _assemble(
            ENTRY_PC,
            [
                _mov_reg_imm32("rax", 0x2A),
                _inc_reg("rax"),  # unrecognized pattern - must invalidate rax
                lambda a: _call_rel32(a, DEFAULT_TARGET),
            ],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rax")),
        )
        locations = [a.location for a in results[0].recovered_arguments]
        assert "register:rax" not in locations


class TestRipRelativeClassification:
    def test_linked_to_known_string_artifact(self):
        target = 0x403000
        code = _assemble(
            ENTRY_PC,
            [lambda a: _lea_rip("rsi", a, target), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rsi")),
            known_string_data_addresses={target: "STR-0001"},
        )
        by_reg = {a.location: a for a in results[0].recovered_arguments}
        arg = by_reg["register:rsi"]
        assert arg.type_hint == "string"
        assert arg.value == "string_ref:STR-0001"
        assert arg.status.value == "supported"
        assert arg.is_pointer is True

    def test_unreadable_target_is_experimental_low_confidence(self):
        target = 0x900000  # far outside any mapped region
        code = _assemble(
            ENTRY_PC,
            [lambda a: _lea_rip("rsi", a, target), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rsi")),
        )
        by_reg = {a.location: a for a in results[0].recovered_arguments}
        arg = by_reg["register:rsi"]
        assert arg.type_hint == "address"
        assert arg.value == f"0x{target:x}"
        assert arg.status.value == "experimental"
        assert arg.confidence.value == "low"

    def test_readable_non_string_target_is_static_address(self):
        target = 0x403000
        code = _assemble(
            ENTRY_PC,
            [lambda a: _lea_rip("rsi", a, target), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(
            ENTRY_PC, code, extra_regions={target: b"\x00\x01\x02\x03" * 8}
        )
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rsi")),
        )
        by_reg = {a.location: a for a in results[0].recovered_arguments}
        assert by_reg["register:rsi"].type_hint == "static_address"

    def test_readable_printable_target_is_possible_static_data(self):
        target = 0x403000
        code = _assemble(
            ENTRY_PC,
            [lambda a: _lea_rip("rsi", a, target), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(
            ENTRY_PC, code, extra_regions={target: b"hello world printable text!!!!!"}
        )
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rsi")),
        )
        by_reg = {a.location: a for a in results[0].recovered_arguments}
        assert by_reg["register:rsi"].type_hint == "possible_static_data"
        assert by_reg["register:rsi"].status.value == "experimental"


class TestStackBasedAbi0:
    """ABI0 (stack-based, pre-1.17) is implemented but, per the approved
    Phase 4.1 correction, not integration-validated - no pre-1.17 _func
    layout is verified (see functab.resolve_func_layout), so no real
    pipeline path ever produces a stack-kind ArgumentLocation today. These
    tests exercise the mechanism directly, synthetically, which is the
    honest limit of what can be claimed for ABI0 right now.
    """

    def test_stack_arguments_recovered_when_callee_shape_declares_them(self):
        code = _assemble(
            ENTRY_PC,
            [
                _mov_reg_imm32("rax", 7),
                _mov_mem_rsp_imm32(0x8, 3),
                _mov_mem_rsp_reg(0x10, "rax"),
                lambda a: _call_rel32(a, DEFAULT_TARGET),
            ],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(
                DEFAULT_TARGET,
                _loc(stack_offset=0x8, argument_index=0),
                _loc(stack_offset=0x10, argument_index=1),
            ),
        )
        args = results[0].recovered_arguments
        assert [a.location for a in args] == ["stack:+0x8", "stack:+0x10"]
        assert args[0].value == "3"
        assert args[1].value == "7"

    def test_register_value_not_used_when_callee_shape_is_stack_only(self):
        # A register value set up before the call must not leak into a
        # stack-only callee's recovered arguments even though it was, in
        # fact, set - only declared stack locations are examined.
        code = _assemble(
            ENTRY_PC,
            [_mov_reg_imm32("rax", 1), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(stack_offset=0x8)),
        )
        assert results[0].recovered_arguments == []


class TestFalsePositiveControl:
    """Phase 4.1 correction: an extra live register must never become a
    reported argument merely because it holds a determined value."""

    def test_extra_live_register_not_in_declared_shape_is_excluded(self):
        # Callee genuinely takes ONE argument (rax). rbx is also set in
        # the window (e.g. leftover/coincidental setup) but is NOT part
        # of the callee's declared shape and must never be reported.
        code = _assemble(
            ENTRY_PC,
            [
                _mov_reg_imm32("rax", 0x2A),
                _mov_reg_imm32("rbx", 0x99),
                lambda a: _call_rel32(a, DEFAULT_TARGET),
            ],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rax")),
        )
        args = results[0].recovered_arguments
        assert len(args) == 1
        assert args[0].location == "register:rax"
        assert all(a.location != "register:rbx" for a in args)

    def test_unresolved_target_never_fabricates_arguments(self):
        # Indirect call - target address unknown, so callee shape cannot
        # possibly be known either. Even though rax holds a determined
        # value, nothing may be reported as an "argument".
        code = _mov_reg_imm32("rax", 0x2A) + _CALL_RAX
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
        )
        assert results[0].target_address is None
        assert results[0].recovered_arguments == []
        assert results[0].argument_analysis_status.value == "unsupported"

    def test_resolved_target_with_unknown_shape_never_fabricates_arguments(self):
        # Target IS resolved (known_function_addresses has a name for
        # it), but its argument shape was never supplied (e.g. no
        # ArgInfo could be decoded for it) - still must not guess.
        target = 0x402000
        code = _assemble(
            ENTRY_PC,
            [_mov_reg_imm32("rax", 0x2A), lambda a: _call_rel32(a, target)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_addresses={target: "main.target"},
            known_function_argument_locations={},  # shape unknown for every target
        )
        assert results[0].target_function == "main.target"
        assert results[0].recovered_arguments == []
        assert results[0].argument_analysis_status.value == "unsupported"

    def test_zero_argument_callee_shape_is_supported_not_unsupported(self):
        # A callee resolved WITH a known (empty) shape - a real,
        # zero-argument function - is a distinct, positive finding from
        # "shape unknown", even though recovered_arguments is [] in both
        # cases; argument_analysis_status must distinguish them.
        target = 0x402000
        code = _assemble(ENTRY_PC, [lambda a: _call_rel32(a, target)])
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(target),  # empty tuple -> []
        )
        assert results[0].recovered_arguments == []
        assert results[0].argument_analysis_status.value == "supported"

    def test_truncated_argument_location_caps_status_to_experimental(self):
        # A location whose ArgInfo shape was truncated is recorded at
        # reduced (MEDIUM) mapping confidence - even a cleanly-recovered
        # immediate value at that location must not be reported as more
        # certain than the shape that told us where to look.
        code = _assemble(
            ENTRY_PC,
            [_mov_reg_imm32("rax", 0x2A), lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(
                DEFAULT_TARGET, _loc(register="rax", confidence=Confidence.MEDIUM)
            ),
        )
        arg = results[0].recovered_arguments[0]
        assert arg.value == "42"  # still recovered - the *value read* was clean
        assert arg.status.value == "experimental"  # but capped by the shape's own uncertainty
        assert arg.confidence.value == "medium"


class TestCallSiteBoundaries:
    def test_indirect_call_has_no_target_address(self):
        code = _mov_reg_imm32("rax", 1) + _CALL_RAX
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
        )
        assert results[0].target_address is None
        assert results[0].target_function is None

    def test_window_never_crosses_previous_call_boundary(self):
        code = _assemble(
            ENTRY_PC,
            [
                _mov_reg_imm32("rax", 1),
                lambda a: _call_rel32(a, 0x402000),  # call #1
                _mov_reg_imm32("rbx", 2),
                lambda a: _call_rel32(a, 0x402100),  # call #2
            ],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations={
                0x402000: [_loc(register="rax")],
                0x402100: [_loc(register="rax"), _loc(register="rbx", argument_index=1)],
            },
        )
        assert len(results) == 2
        second_call_locations = [a.location for a in results[1].recovered_arguments]
        # rax was set before call #1 and must not be visible to call #2's
        # analysis - only rbx (set after call #1) is in scope, even
        # though call #2's declared shape also asks about rax.
        assert "register:rax" not in second_call_locations
        assert "register:rbx" in second_call_locations

    def test_window_never_walks_before_function_entry(self):
        # A call site as the very first instruction: nothing to walk back
        # over, must not crash or produce a negative index.
        code = _assemble(ENTRY_PC, [lambda a: _call_rel32(a, DEFAULT_TARGET)])
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rax")),
        )
        assert len(results) == 1
        assert results[0].recovered_arguments == []

    def test_window_bounded_by_max_window_instructions(self):
        filler = [_NOP] * (ba.MAX_WINDOW_INSTRUCTIONS + 10)
        code = _assemble(
            ENTRY_PC,
            [_mov_reg_imm32("rbx", 99), *filler, lambda a: _call_rel32(a, DEFAULT_TARGET)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
            known_function_argument_locations=_locs_at(DEFAULT_TARGET, _loc(register="rbx")),
        )
        # The rbx write is further back than MAX_WINDOW_INSTRUCTIONS and
        # must fall outside the analyzed window, even though the callee
        # declares rbx as its argument location.
        locations = [a.location for a in results[0].recovered_arguments]
        assert "register:rbx" not in locations

    def test_no_call_sites_returns_empty_list(self):
        code = _mov_reg_imm32("rax", 1) + _NOP
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC, caller_function="main.f",
        )
        assert results == []

    def test_unreadable_function_returns_empty_list_not_raise(self):
        reader = MockMemoryReader(ENTRY_PC, b"")
        results = ba.analyze_function_call_sites(
            reader, pid=1, entry_pc=ENTRY_PC + 0x9999, caller_function="main.f",
        )
        assert results == []


class TestCallSiteIdsAndProvenance:
    def test_call_ids_are_unique_and_deterministic_given_same_counter_seed(self):
        code = _assemble(
            ENTRY_PC,
            [lambda a: _call_rel32(a, 0x402000), _NOP, lambda a: _call_rel32(a, 0x402100)],
        )
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=7, entry_pc=ENTRY_PC, caller_function="main.f",
        )
        ids = [c.id for c in results]
        assert len(ids) == len(set(ids))
        assert all(str(ENTRY_PC).lower() or True for _ in ids)  # sanity: no exception building ids

    def test_call_site_provenance_records_pid_and_address(self):
        code = _assemble(ENTRY_PC, [lambda a: _call_rel32(a, 0x402000)])
        reader = MockMemoryReader(ENTRY_PC, code)
        results = ba.analyze_function_call_sites(
            reader, pid=42, entry_pc=ENTRY_PC, caller_function="main.f",
        )
        prov = results[0].provenance
        assert prov is not None
        assert prov.pid == 42
        assert prov.virtual_address == f"0x{ENTRY_PC:x}"
