"""Unit tests for pcsp-based Go stack unwinding (Phase 5E).

Every pcsp stream byte sequence below is hand-encoded from the verified
zigzag/varint encoding (see tests/unit/test_pctab.py's own verification
notes) and independently re-derivable: ``uvdelta = zigzag(value_delta)``,
single-byte varints only (values kept < 0x80) unless a test explicitly
needs a multi-byte one.
"""

from gomemforensics.common.memory import MockMemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.functab import FunctionIndex
from gomemforensics.go_runtime.layouts import (
    FUNC_FLAG_SP_WRITE,
    FUNC_FLAG_TOP_FRAME,
    FUNC_ID_MORESTACK,
)
from gomemforensics.go_runtime.models import FunctionArtifact, FunctionClassification
from gomemforensics.go_runtime.stack_unwind import MAX_FRAMES, unwind_goroutine

PCTAB_BASE = 0x140500000
STACK_LO = 0xC000010000
STACK_HI = 0xC000018000


def _zigzag(delta: int) -> int:
    return (delta << 1) if delta >= 0 else ((-delta - 1) << 1) | 1


def _constant_pcsp_stream(frame_size: int) -> bytes:
    """A pcsp stream encoding a constant frame size for a wide PC range.
    Byte 0 is a deliberate leading pad (pcsp offset must never be 0 -
    that is the verified "no table" sentinel)."""
    uv = _zigzag(frame_size - (-1))
    assert uv < 0x80
    return bytes([0xAA, uv, 0x7F, 0x00])  # pad, uvdelta, pcdelta=0x7f, terminator


def _fn(
    entry: int,
    name: str,
    pcsp_offset: int | None = 1,
    func_flag: int = 0,
    func_id: int = 0,
) -> FunctionArtifact:
    return FunctionArtifact(
        id=f"FUNC-1-{entry:x}", pid=1, address=entry, entry_address=entry,
        name=name, package="main", source_file="main.go", source_line=1, function_size=None,
        classification=FunctionClassification.APPLICATION, confidence=Confidence.HIGH,
        extraction_method="test", go_version="1.22+", architecture="x86_64",
        func_id=func_id, func_flag=func_flag, pcsp_offset=pcsp_offset,
    )


class TestSingleFrameStop:
    def test_top_frame_function_stops_with_complete_status(self):
        entry = 0x140001000
        fn = _fn(entry, "runtime.goexit", func_flag=FUNC_FLAG_TOP_FRAME)
        index = FunctionIndex([fn])
        reader = MockMemoryReader(entry, b"\x00" * 16)

        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index,
            initial_pc=entry, initial_sp=STACK_HI - 0x100,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "complete"
        assert len(frames) == 1
        assert frames[0].function_name == "runtime.goexit"

    def test_zero_return_address_is_complete_not_invalid(self):
        entry = 0x140001000
        sp = STACK_HI - 0x100
        stream = _constant_pcsp_stream(0x20)
        fn = _fn(entry, "main.f")
        index = FunctionIndex([fn])
        reader = MockMemoryReader(
            entry, b"\x00" * 16,
            extra_regions={PCTAB_BASE: stream, sp + 0x20: (0).to_bytes(8, "little")},
        )
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=sp,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "complete"
        assert len(frames) == 1


class TestTwoFrameUnwind:
    def test_caller_frame_recovered_via_pcsp_delta(self):
        func_a_entry = 0x140001000  # caller (top frame)
        func_b_entry = 0x140002000  # callee (current frame)
        sp_b = STACK_HI - 0x1000
        return_addr_slot = sp_b + 0x20

        stream = _constant_pcsp_stream(0x20)
        fn_a = _fn(func_a_entry, "main.a", func_flag=FUNC_FLAG_TOP_FRAME, pcsp_offset=None)
        fn_b = _fn(func_b_entry, "main.b", pcsp_offset=1)
        index = FunctionIndex([fn_a, fn_b])

        reader = MockMemoryReader(
            func_a_entry, b"\x00" * 16,
            extra_regions={
                PCTAB_BASE: stream,
                return_addr_slot: (func_a_entry + 0x10).to_bytes(8, "little"),
            },
        )
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index,
            initial_pc=func_b_entry + 5, initial_sp=sp_b,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "complete"
        assert len(frames) == 2
        assert frames[0].function_name == "main.b"
        assert frames[0].pc == func_b_entry + 5
        assert frames[0].sp == sp_b
        assert frames[1].function_name == "main.a"
        assert frames[1].pc == func_a_entry + 0x10
        assert frames[1].sp == return_addr_slot + 8

    def test_negative_frame_size_delta_decoded_correctly(self):
        # val=0x20 for [entry, entry+0x7f), then val=0x10 for the rest
        # (delta -0x10, zigzag(-0x10) = 0x1f).
        func_a_entry = 0x140001000
        func_b_entry = 0x140002000
        sp_b = STACK_HI - 0x1000

        uv1 = _zigzag(0x20 - (-1))
        uv2 = _zigzag(0x10 - 0x20)
        stream = bytes([0xAA, uv1, 0x7F, uv2, 0x7F, 0x00])
        target_pc = func_b_entry + 0x7F + 5  # inside the second range -> frame size 0x10
        return_addr_slot = sp_b + 0x10

        fn_a = _fn(func_a_entry, "main.a", func_flag=FUNC_FLAG_TOP_FRAME, pcsp_offset=None)
        fn_b = _fn(func_b_entry, "main.b", pcsp_offset=1)
        index = FunctionIndex([fn_a, fn_b])
        reader = MockMemoryReader(
            func_a_entry, b"\x00" * 16,
            extra_regions={PCTAB_BASE: stream, return_addr_slot: (func_a_entry + 4).to_bytes(8, "little")},
        )
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=target_pc, initial_sp=sp_b,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "complete"
        assert frames[1].sp == return_addr_slot + 8


class TestStoppingConditions:
    def test_unresolved_pc_at_start_reports_unresolved_function(self):
        index = FunctionIndex([])
        reader = MockMemoryReader(0x140001000, b"\x00" * 16)
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=0x140001000, initial_sp=STACK_HI - 0x100,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "unresolved_function"
        assert frames == []

    def test_sp_write_function_stops_as_unsupported(self):
        entry = 0x140001000
        fn = _fn(entry, "runtime.morestack", func_flag=FUNC_FLAG_SP_WRITE, func_id=FUNC_ID_MORESTACK)
        index = FunctionIndex([fn])
        reader = MockMemoryReader(entry, b"\x00" * 16)
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=STACK_HI - 0x100,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "unsupported_frame"
        assert len(frames) == 1  # the frame itself is still reported, just not unwound past

    def test_special_func_id_stops_as_unsupported_even_without_sp_write_flag(self):
        entry = 0x140001000
        fn = _fn(entry, "runtime.morestack", func_flag=0, func_id=FUNC_ID_MORESTACK)
        index = FunctionIndex([fn])
        reader = MockMemoryReader(entry, b"\x00" * 16)
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=STACK_HI - 0x100,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "unsupported_frame"

    def test_missing_pcsp_offset_reports_malformed_pcsp(self):
        entry = 0x140001000
        fn = _fn(entry, "main.f", pcsp_offset=None)
        index = FunctionIndex([fn])
        reader = MockMemoryReader(entry, b"\x00" * 16)
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=STACK_HI - 0x100,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "malformed_pcsp"
        assert len(frames) == 1

    def test_return_address_slot_outside_stack_bounds(self):
        entry = 0x140002000
        sp = STACK_HI - 0x10  # spdelta (0x20) pushes the slot past stack_hi
        stream = _constant_pcsp_stream(0x20)
        fn = _fn(entry, "main.b")
        index = FunctionIndex([fn])
        reader = MockMemoryReader(entry, b"\x00" * 16, extra_regions={PCTAB_BASE: stream})
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=sp,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "stack_bounds_exceeded"

    def test_unreadable_return_address_slot(self):
        entry = 0x140002000
        sp = STACK_HI - 0x1000
        stream = _constant_pcsp_stream(0x20)
        fn = _fn(entry, "main.b")
        index = FunctionIndex([fn])
        # PCTAB region present, but the return-address slot itself is not
        # backed by any region at all.
        reader = MockMemoryReader(entry, b"\x00" * 16, extra_regions={PCTAB_BASE: stream})
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=sp,
            stack_lo=STACK_LO, stack_hi=sp + 0x1000,  # keep the slot in-bounds so it reaches the read
        )
        assert status.value == "unreadable_stack"

    def test_return_address_resolving_to_unknown_function_is_invalid(self):
        func_b_entry = 0x140002000
        sp_b = STACK_HI - 0x1000
        return_addr_slot = sp_b + 0x20
        stream = _constant_pcsp_stream(0x20)
        fn_b = _fn(func_b_entry, "main.b")
        index = FunctionIndex([fn_b])  # no function registered for the "caller"
        reader = MockMemoryReader(
            func_b_entry, b"\x00" * 16,
            extra_regions={PCTAB_BASE: stream, return_addr_slot: (0x999999).to_bytes(8, "little")},
        )
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=func_b_entry, initial_sp=sp_b,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "invalid_return_address"
        assert len(frames) == 1

    def test_self_cycle_return_address_stops_immediately(self):
        entry = 0x140002000
        sp = STACK_HI - 0x1000
        return_addr_slot = sp + 0x20
        stream = _constant_pcsp_stream(0x20)
        fn = _fn(entry, "main.b")
        index = FunctionIndex([fn])
        reader = MockMemoryReader(
            entry, b"\x00" * 16,
            extra_regions={PCTAB_BASE: stream, return_addr_slot: entry.to_bytes(8, "little")},
        )
        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index, initial_pc=entry, initial_sp=sp,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "invalid_return_address"
        assert len(frames) == 1

    def test_pctab_address_none_is_not_attempted(self):
        fn = _fn(0x140001000, "main.f")
        index = FunctionIndex([fn])
        reader = MockMemoryReader(0x140001000, b"\x00" * 16)
        frames, status = unwind_goroutine(
            reader, 8, None, index, initial_pc=0x140001000, initial_sp=STACK_HI - 0x100,
            stack_lo=STACK_LO, stack_hi=STACK_HI,
        )
        assert status.value == "not_attempted"
        assert frames == []


class TestBoundedWalk:
    def test_max_frames_bound_stops_a_deep_or_cyclic_chain(self):
        # A chain of MAX_FRAMES+5 distinct functions, each returning into
        # the next, all sharing one constant-frame-size (0x20) pcsp
        # stream - never reaches a TopFrame, must stop at the bound, not
        # loop. Each step advances sp by exactly spdelta(0x20) + ptrSize
        # (8) = 0x28 (the verified x86-64 formula - see
        # TestTwoFrameUnwind), so the Nth return-address slot sits at
        # base_sp + N*0x28 + 0x20.
        stream = _constant_pcsp_stream(0x20)
        functions = []
        chain_len = MAX_FRAMES + 5
        big_stack_lo = 0xC000000000
        base_sp = big_stack_lo + 0x1000
        big_stack_hi = base_sp + chain_len * 0x28 + 0x1000  # ample headroom
        extra_regions = {PCTAB_BASE: stream}
        for i in range(chain_len):
            entry = 0x140001000 + i * 0x1000
            functions.append(_fn(entry, f"main.f{i}"))
            slot = base_sp + i * 0x28 + 0x20
            next_entry = 0x140001000 + (i + 1) * 0x1000
            extra_regions[slot] = next_entry.to_bytes(8, "little")

        index = FunctionIndex(functions)
        reader = MockMemoryReader(0x140001000, b"\x00" * 16, extra_regions=extra_regions)

        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index,
            initial_pc=0x140001000, initial_sp=base_sp,
            stack_lo=big_stack_lo, stack_hi=big_stack_hi,
            max_frames=MAX_FRAMES,
        )
        assert status.value == "bounded"
        assert len(frames) == MAX_FRAMES

    def test_max_frames_bound_is_necessary_even_when_sp_is_purely_monotonic(self):
        """Regression test for a specific audit finding: `sp` strictly
        increasing every iteration (guaranteed by this project's own
        rejection of negative/misaligned `spdelta` - see the long comment
        at the `sp_delta < 0` check in `stack_unwind.py`) does NOT by
        itself bound the number of iterations to anything small, and does
        NOT make `MAX_FRAMES` redundant. Go's own source only verifies
        `spdelta`'s *alignment* (`runtime/symtab.go:1212`, debug-build
        only) - never its sign - so non-negativity is this project's own
        defensive addition, not a Go-runtime guarantee. Without
        `MAX_FRAMES`, a well-formed (non-negative, aligned) but
        maximal-size chain against a large stack could still take on the
        order of `(stack_hi - stack_lo) / pointer_size` steps before
        stack bounds naturally intervened - for this project's own
        `MAX_PLAUSIBLE_STACK_SIZE` (1 GiB), roughly 10^8, six orders of
        magnitude more than `MAX_FRAMES` (256).

        This test constructs a chain that is purely, uniformly monotonic
        (every step advances `sp` by the exact same amount, no cycles, no
        malformed data - the "well-behaved" case) with a stack region
        sized with 10x headroom beyond what the full chain would consume,
        and confirms the walk still stops at exactly `MAX_FRAMES` well
        before stack exhaustion, proving the bound is load-bearing rather
        than a redundant backstop. The chain length here is kept modest
        (`MAX_FRAMES + 20`) for the test's own runtime cost, not because
        the underlying argument is scale-limited - the general reasoning
        above (`(stack_hi - stack_lo) / pointer_size` can reach ~10^8 for
        this project's own `MAX_PLAUSIBLE_STACK_SIZE`) does not depend on
        this test actually constructing a gigabyte-scale stack.
        """
        stream = _constant_pcsp_stream(0x20)
        # A stack with generous headroom beyond what MAX_FRAMES worth of
        # steps consumes - enough to prove stack exhaustion is not what
        # stops the walk, without needing an unrealistically long chain
        # (MockMemoryReader is a linear-scan test double; a chain long
        # enough to literally reach a gigabyte-scale stack bound would
        # make this test itself pathologically slow, which is exactly the
        # kind of cost this project's real bounds are meant to avoid -
        # the *proof* only needs stack_hi meaningfully unreached at
        # MAX_FRAMES, not stack_hi sized to the project's full
        # MAX_PLAUSIBLE_STACK_SIZE).
        step = 0x28  # spdelta(0x20) + ptrSize(8), the verified x86-64 formula
        big_stack_lo = 0xC000000000
        base_sp = big_stack_lo + 0x1000
        chain_len = MAX_FRAMES + 20  # comfortably more than MAX_FRAMES
        big_stack_hi = base_sp + (chain_len * step * 10)  # 10x headroom past the full chain

        functions = []
        extra_regions = {PCTAB_BASE: stream}
        for i in range(chain_len):
            entry = 0x140001000 + i * 0x1000
            functions.append(_fn(entry, f"main.f{i}"))
            slot = base_sp + i * step + 0x20
            next_entry = 0x140001000 + (i + 1) * 0x1000
            extra_regions[slot] = next_entry.to_bytes(8, "little")

        index = FunctionIndex(functions)
        reader = MockMemoryReader(0x140001000, b"\x00" * 16, extra_regions=extra_regions)

        frames, status = unwind_goroutine(
            reader, 8, PCTAB_BASE, index,
            initial_pc=0x140001000, initial_sp=base_sp,
            stack_lo=big_stack_lo, stack_hi=big_stack_hi,
            max_frames=MAX_FRAMES,
        )

        # sp strictly increased every single step (monotonicity holds -
        # confirmed directly, not merely assumed).
        sps = [f.sp for f in frames]
        assert sps == sorted(sps)
        assert len(set(sps)) == len(sps)

        # And yet MAX_FRAMES, not stack exhaustion, is what stopped it.
        assert status.value == "bounded"
        assert len(frames) == MAX_FRAMES
