"""pcsp-based Go stack unwinding (paper Section 3.4, "Stack Unwinding").

x86-64 only. Verified line-by-line against the real unwinder
(``runtime/traceback.go``, ``gentraceback``, the ``!usesLR`` / x86 branch
- ``usesLR`` is an ARM64/architectures-with-a-link-register concept this
project does not implement or claim support for) and
``runtime/symtab.go``'s ``funcspdelta``:

    funcspdelta(f, pc) == pcvalue(f, f.pcsp, pc, true)   -- verified,
        symtab.go:1210-1216 - the *exact* decoder already implemented in
        gomemforensics.go_runtime.pctab, reused here, never
        reimplemented.

    fp = sp + funcspdelta(f, pc)                         -- traceback.go:327
    if !usesLR: fp += ptrSize                             -- traceback.go:330
        ("On x86, call instruction pushes return PC before
        entering new function.")

    lrPtr = fp - ptrSize   (== sp + funcspdelta(f, pc))    -- traceback.go:378
    lr = *(*uintptr)(lrPtr)                                -- traceback.go:379
        (the return address VALUE, read from that address)

    argp = fp + sys.MinFrameSize                           -- traceback.go:411
        MinFrameSize == 0 for amd64 (verified:
        internal/goarch/goarch_amd64.go), so argp == fp for this
        project's only supported architecture - the paper's own
        simplified "sp + sp_delta + ptrSize" description is exactly
        correct for x86-64, confirmed independently rather than merely
        trusted.

    frame.pc = frame.lr; frame.sp = frame.fp                -- traceback.go:495,497
        (advance to the caller's frame)

Stopping conditions, all source-verified rather than invented
(``internal/abi/symtab.go``'s ``FuncFlag``/``FuncID`` doc comments):

  - the current function has ``FuncFlagTopFrame`` set (e.g. ``goexit``,
    ``mstart``) -> the real unwinder itself stops here and considers the
    traceback *successfully complete* -> :attr:`UnwindStatus.COMPLETE`.
  - the current function has ``FuncFlagSPWrite`` set, or its ``FuncID``
    is one of the small set of real, named special cases the real
    unwinder handles specially (morestack, systemstack, async
    preemption, sigpanic, cgocallback, ...) -> this project does not
    attempt to replicate that special-casing (approved plan: "do not
    implement special handling unless source-verified") ->
    :attr:`UnwindStatus.UNSUPPORTED_FRAME`.
  - the decoded return address does not resolve to any recovered
    function, the computed addresses fall outside the goroutine's own
    stack bounds, the return-address slot is unreadable, or the pcsp
    stream fails to decode -> the corresponding explicit
    :class:`UnwindStatus` value, never silently treated as success.
  - a hard cap on frame count / a cycle in the frame chain (a bounded
    walk, never an infinite loop - CLAUDE.md section 44).
"""

from __future__ import annotations

import struct

from gomemforensics.common.memory import MemoryAccessError, MemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.functab import FunctionIndex
from gomemforensics.go_runtime.layouts import FUNC_FLAG_SP_WRITE, FUNC_FLAG_TOP_FRAME, FUNC_IDS_REQUIRING_SPECIAL_UNWIND_HANDLING
from gomemforensics.go_runtime.models import GoroutineFrame, UnwindStatus
from gomemforensics.go_runtime.pctab import MalformedPctabError, read_pc_value_from_reader

#: Safety bounds (not Go runtime invariants).
MAX_FRAMES = 256
#: Bounded pcsp-stream read window per frame lookup (same default as
#: pctab.DEFAULT_PC_VALUE_READ_WINDOW, named explicitly here for clarity).
PCSP_READ_WINDOW = 4096


def unwind_goroutine(
    reader: MemoryReader,
    pointer_size: int,
    pctab_address: int | None,
    function_index: FunctionIndex,
    initial_pc: int,
    initial_sp: int,
    stack_lo: int,
    stack_hi: int,
    max_frames: int = MAX_FRAMES,
) -> tuple[list[GoroutineFrame], UnwindStatus]:
    """Unwind a goroutine's call stack starting from ``(initial_pc, initial_sp)``.

    ``initial_pc``/``initial_sp`` should already reflect the verified
    syscall-state substitution (``g.syscallpc``/``g.syscallsp`` when
    ``g.syscallsp != 0``, else ``g.sched.pc``/``g.sched.sp`` - see
    :mod:`gomemforensics.go_runtime.goroutines`) - this function itself
    has no g-specific knowledge, only PC/SP/stack-bounds/a function index,
    so it never becomes a second place that has to know about ``g``
    layout.
    """
    frames: list[GoroutineFrame] = []

    if pctab_address is None:
        return frames, UnwindStatus.NOT_ATTEMPTED

    pc = initial_pc
    sp = initial_sp
    unwind_method = "g.sched (or g.syscall, per verified substitution rule)"

    for frame_index in range(max_frames):
        fn = function_index.resolve(pc)
        if fn is None:
            return frames, UnwindStatus.UNRESOLVED_FUNCTION if frame_index == 0 else UnwindStatus.INVALID_RETURN_ADDRESS

        frames.append(
            GoroutineFrame(
                frame_index=frame_index,
                pc=pc,
                sp=sp,
                function_id=fn.id,
                function_name=fn.name,
                source_file=fn.source_file,
                source_line=fn.source_line,
                confidence=Confidence.HIGH,
                unwind_method=unwind_method,
            )
        )

        if fn.func_flag is not None and fn.func_flag & FUNC_FLAG_TOP_FRAME:
            return frames, UnwindStatus.COMPLETE

        if fn.func_flag is not None and fn.func_flag & FUNC_FLAG_SP_WRITE:
            return frames, UnwindStatus.UNSUPPORTED_FRAME
        if fn.func_id is not None and fn.func_id in FUNC_IDS_REQUIRING_SPECIAL_UNWIND_HANDLING:
            return frames, UnwindStatus.UNSUPPORTED_FRAME

        if fn.pcsp_offset is None:
            return frames, UnwindStatus.MALFORMED_PCSP

        try:
            sp_delta = read_pc_value_from_reader(
                reader, pctab_address, fn.pcsp_offset, fn.entry_address, pc, PCSP_READ_WINDOW
            )
        except MalformedPctabError:
            return frames, UnwindStatus.MALFORMED_PCSP
        if sp_delta is None or sp_delta < 0 or sp_delta % pointer_size != 0:
            # Two distinct checks, only one of which Go's own source
            # verifies - do not conflate them:
            #
            # - Alignment (`sp_delta % pointer_size != 0`): a Go-verified
            #   invariant. `funcspdelta` (runtime/symtab.go:1210-1216)
            #   asserts exactly this (`x & (goarch.PtrSize-1) != 0`) at
            #   line 1212 - but only when `debugPcln` is set, i.e. this
            #   check does not even run in a production Go build; the
            #   real runtime otherwise trusts the value unconditionally.
            # - Non-negativity (`sp_delta < 0`): NOT a Go-verified
            #   invariant. `funcspdelta` returns a signed `int32`
            #   (symtab.go:1210), and the real runtime never checks its
            #   sign at all - it is cast straight to `uintptr` at the one
            #   call site that matters (`traceback.go:327`,
            #   `frame.sp + uintptr(funcspdelta(...))`), so a
            #   hypothetically negative value would silently wrap around
            #   to a huge unsigned delta in the real runtime, with no
            #   defensive handling whatsoever. Real, correctly-compiled
            #   frame sizes are never negative by construction (a stack
            #   frame cannot have negative size), but that is a property
            #   of trusted compiler output, not something Go's own source
            #   independently verifies at decode time. This project adds
            #   the `< 0` check itself - a deliberate engineering
            #   addition, stricter than the real runtime, appropriate
            #   here because this tool reads potentially corrupted or
            #   adversarial memory rather than trusted linker output.
            #
            # Consequence for loop safety: given this rejection, `new_sp`
            # below is arithmetically guaranteed to exceed `sp` by at
            # least `pointer_size` every iteration (a property of this
            # code's own arithmetic, not a Go-runtime guarantee) - but
            # this does NOT make `MAX_FRAMES` redundant. A corrupted-but-
            # internally-consistent stream (non-negative, aligned,
            # otherwise nonsensical) driving a very large stack could
            # still take up to `(stack_hi - stack_lo) / pointer_size`
            # steps - for this project's own `MAX_PLAUSIBLE_STACK_SIZE`
            # (1 GiB), on the order of 10^8 - before naturally hitting
            # `STACK_BOUNDS_EXCEEDED`. `MAX_FRAMES` (256) is the primary,
            # necessary bound that keeps the walk within a forensically
            # reasonable cost regardless (CLAUDE.md section 44); the
            # monotonicity property only rules out the walk revisiting an
            # exact prior `(pc, sp)` state, it does not by itself bound
            # the iteration count to anything small.
            return frames, UnwindStatus.MALFORMED_PCSP

        # Verified x86-64 formula (see module docstring): return-address
        # slot = sp + spdelta; new sp (argp, MinFrameSize==0 on amd64) =
        # sp + spdelta + ptrSize.
        return_addr_slot = sp + sp_delta
        new_sp = return_addr_slot + pointer_size

        if not (stack_lo <= return_addr_slot < stack_hi):
            return frames, UnwindStatus.STACK_BOUNDS_EXCEEDED

        try:
            raw = reader.read(return_addr_slot, pointer_size)
        except MemoryAccessError:
            return frames, UnwindStatus.UNREADABLE_STACK

        word_fmt = "<Q" if pointer_size == 8 else "<I"
        return_pc = struct.unpack(word_fmt, raw)[0]

        if return_pc == 0:
            # A zero return address is never a valid caller - the real
            # unwinder treats frame.lr == 0 as "no further caller"
            # (verified: traceback.go's own frame.lr==0 checks) rather
            # than as a decode failure; distinguished from a genuinely
            # unresolved nonzero PC below.
            return frames, UnwindStatus.COMPLETE

        if return_pc == pc:
            # A direct self-cycle (return address equal to the current
            # pc) cannot be a legitimate caller - stop rather than loop.
            return frames, UnwindStatus.INVALID_RETURN_ADDRESS

        pc = return_pc
        sp = new_sp
        unwind_method = "pcsp_frame_delta"

    return frames, UnwindStatus.BOUNDED
