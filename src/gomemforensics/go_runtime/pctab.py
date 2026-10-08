"""Go pctab (PC-value table) decoder.

A faithful transcription of the real Go runtime's decoding algorithm -
this is not a heuristic or approximation, it is the exact encoding the
compiler/linker emit and the runtime itself decodes, verified against
local go1.26.2 source:

- ``readvarint`` <- ``runtime/symtab.go``, ``func readvarint(p []byte) (read uint32, val uint32)``
- ``step`` <- ``runtime/symtab.go``, ``func step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool)``
- ``pc_value`` <- ``runtime/symtab.go``, ``func pcvalue(f funcInfo, off uint32, targetpc uintptr, strict bool) (int32, uintptr)``
  (the caching layer is omitted - irrelevant to a one-shot forensic
  lookup - but the decode loop itself is transcribed verbatim, including
  the ``first := pc == f.entry()`` condition being recomputed on every
  loop iteration rather than treated as a one-time flag - see
  ``pc_value``'s inline comment and ``TestPcValueFirstStepSemantics`` in
  ``tests/unit/test_pctab.py`` for the concrete edge case this matters
  for)
- ``PCQuantum`` (1 for amd64/386) <- ``internal/goarch/goarch_amd64.go``, ``_PCQuantum = 1``

The same decoder services ``pcsp``, ``pcfile``, and ``pcln`` - they are
three streams using the identical encoding, verified: ``runtime/symtab.go``
``funcline1`` calls ``pcvalue(f, f.pcfile, ...)`` and
``pcvalue(f, f.pcln, ...)`` using the same function as ``pcsp`` lookups.
"""

from __future__ import annotations

from dataclasses import dataclass

from gomemforensics.go_runtime.scanning import read_partial

#: Minimal unit for a program counter on x86/x86-64 (verified:
#: internal/goarch/goarch_amd64.go, ``_PCQuantum = 1``). PC tables record
#: deltas pre-divided by this quantum - ARM/ARM64/MIPS use 4, but this
#: project targets x86-64 only (see docs/architecture/go-runtime.md), so
#: only the amd64 value is defined here.
PC_QUANTUM_AMD64 = 1

#: Safety bound (not a Go runtime invariant): caps how many (pc, value)
#: steps a single decode walks before giving up, guarding against a
#: corrupted/adversarial stream whose continuation bits never terminate
#: within the read buffer.
MAX_PCTAB_STEPS = 100_000


class MalformedPctabError(Exception):
    """Raised when a pctab stream is truncated or otherwise malformed.

    Callers must catch this and record a recoverable AnalysisError
    (CLAUDE.md section 24) - a single malformed function's pctab stream
    must never abort analysis of the rest.
    """


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode one unsigned LEB128-style varint starting at ``offset``.

    Verified transcription of ``runtime/symtab.go``'s ``readvarint``:
    7 bits per byte, low-to-high, continuation via the 0x80 bit.

    Returns ``(bytes_consumed, value)``. Raises :class:`MalformedPctabError`
    if the stream ends before a terminating byte (high bit clear) is found.
    """
    value = 0
    shift = 0
    consumed = 0
    pos = offset
    while True:
        if pos >= len(data):
            raise MalformedPctabError(
                f"truncated varint at offset {offset} (ran off the end of a "
                f"{len(data)}-byte buffer after {consumed} bytes)"
            )
        b = data[pos]
        pos += 1
        consumed += 1
        value |= (b & 0x7F) << shift
        if b & 0x80 == 0:
            break
        shift += 7
        if consumed > 10:  # a valid varint for a 32-bit value never needs more than 5 bytes
            raise MalformedPctabError(f"varint at offset {offset} did not terminate within 10 bytes")
    return consumed, value


def _zigzag_decode(uvdelta: int) -> int:
    """Verified transcription of ``step``'s value-delta decode:
    ``-(uvdelta & 1) ^ (uvdelta >> 1)``."""
    return -(uvdelta & 1) ^ (uvdelta >> 1)


@dataclass(frozen=True)
class PctabStep:
    """One decoded (pc, value) step, valid for the half-open range
    ``[start_pc, end_pc)`` once the *next* step's ``pc`` is known."""

    pc: int
    val: int
    consumed: int  # bytes consumed from the stream by this step


def step(data: bytes, offset: int, pc: int, val: int, first: bool) -> PctabStep | None:
    """Decode one (pc-delta, value-delta) step. Verified transcription of
    ``runtime/symtab.go``'s ``step`` function.

    Returns ``None`` when the stream signals end-of-data (a zero
    value-delta byte on a non-first step - verified: ``if uvdelta == 0 &&
    !first { return nil, false }``), matching the real runtime's own
    terminator convention exactly - this is not a truncation error.
    """
    if offset >= len(data):
        raise MalformedPctabError(f"step() called past the end of a {len(data)}-byte buffer at offset {offset}")

    pos = offset
    uvdelta = data[pos]
    if uvdelta == 0 and not first:
        return None
    n = 1
    if uvdelta & 0x80:
        n, uvdelta = read_varint(data, pos)
    pos += n
    val += _zigzag_decode(uvdelta)

    if pos >= len(data):
        raise MalformedPctabError(f"truncated pc-delta at offset {pos}")
    pcdelta = data[pos]
    n2 = 1
    if pcdelta & 0x80:
        n2, pcdelta = read_varint(data, pos)
    pos += n2
    pc += pcdelta * PC_QUANTUM_AMD64

    return PctabStep(pc=pc, val=val, consumed=pos - offset)


def pc_value(pctab: bytes, table_offset: int, entry_pc: int, target_pc: int) -> int | None:
    """Look up the value active at ``target_pc``, decoding from ``pctab[table_offset:]``.

    Faithful transcription of ``runtime/symtab.go``'s ``pcvalue`` decode
    loop (the recursion/caching layer is irrelevant here - this is a
    one-shot, non-cached lookup). ``table_offset == 0`` means "no table"
    (verified: ``if off == 0 { return -1, 0 }``), returning ``None``.

    Args:
        pctab: the full ``moduledata.pctab`` bytes (or a sufficient slice
            starting at absolute offset 0 of that table).
        table_offset: ``_func.pcsp``/``pcfile``/``pcln`` (an offset into
            ``pctab``).
        entry_pc: the function's entry PC (``moduledata.text + entryoff``).
        target_pc: the PC to resolve a value for.

    Raises:
        MalformedPctabError: if the stream is truncated/corrupt before a
            legitimate end-of-data or answer is reached.
    """
    if table_offset == 0:
        return None
    if target_pc < entry_pc:
        raise ValueError(f"target_pc 0x{target_pc:x} is before entry_pc 0x{entry_pc:x}")

    offset = table_offset
    pc = entry_pc
    val = -1
    steps = 0

    while True:
        steps += 1
        if steps > MAX_PCTAB_STEPS:
            raise MalformedPctabError(f"pctab decode exceeded {MAX_PCTAB_STEPS} steps without terminating")

        # Verified: runtime/symtab.go's pcvalue calls step() with
        # `first = (pc == f.entry())`, recomputed fresh on *every*
        # iteration - not a one-time flag consumed after the first call.
        # This matters for the (rare, but real per the algorithm) case of
        # a step whose pc-delta is 0: pc stays at entry_pc, so the *next*
        # step is still "first" too, and a following zero value-delta
        # byte must NOT be misread as the stream terminator. An
        # iteration-count-based approximation gets exactly this case
        # wrong (see TestPcValueFirstStepSemantics in test_pctab.py).
        first = pc == entry_pc

        result = step(pctab, offset, pc, val, first)
        if result is None:
            break
        # step() computes the value active starting at the *previous* pc
        # (now held in `pc`, about to be overwritten) through result.pc -
        # the real runtime mutates `val` in place via a pointer, so the
        # value it returns once `targetpc < pc` is this step's NEW value
        # (result.val), not the value from before this step.
        if target_pc < result.pc:
            return result.val
        offset += result.consumed
        pc = result.pc
        val = result.val

    return None


#: Bounded read window for a single pctab stream lookup from a
#: MemoryReader - not a Go runtime invariant, a safety/performance bound.
#: Shared by every caller of :func:`read_pc_value_from_reader` (Phase 4's
#: `pcfile`/`pcln` source-line resolution and Phase 5's `pcsp`-based
#: stack unwinding) so there is exactly one windowing strategy, not one
#: per call site.
DEFAULT_PC_VALUE_READ_WINDOW = 4096


def read_pc_value_from_reader(
    reader,
    pctab_address: int,
    stream_offset: int,
    entry_pc: int,
    target_pc: int,
    window_size: int = DEFAULT_PC_VALUE_READ_WINDOW,
) -> int | None:
    """Read a bounded window of ``moduledata.pctab`` starting at
    ``stream_offset`` and decode the value active at ``target_pc``.

    This is the shared, memory-backed counterpart to :func:`pc_value`
    (which only ever operates on an in-hand byte buffer): it reads a
    small window starting *at* (one byte before, to preserve the
    ``table_offset == 0`` "no table" sentinel convention) the stream's
    own declared offset rather than from the pctab blob's start -
    scaling with the actual evidence instead of a fixed guess, and
    avoiding re-reading a large shared prefix for every call (this
    fixes the same class of real-fixture-surfaced bug documented in
    ``functab.py``'s history, now centralized here instead of
    reimplemented per call site).
    """
    if stream_offset == 0:
        return None
    window = read_partial(reader, pctab_address + stream_offset - 1, window_size + 1)
    if len(window) < 2:
        return None
    return pc_value(window, 1, entry_pc, target_pc)
