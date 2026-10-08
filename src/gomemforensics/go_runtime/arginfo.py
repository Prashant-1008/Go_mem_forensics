"""ArgInfo and ArgsPointerMaps funcdata decoding (paper Section 3.3.3).

Verified against local go1.26.2 source:

- Opcode constants and bytecode format doc comment: ``internal/abi/type.go``
  (``TraceArgsEndSeq = 0xff``, ``TraceArgsStartAgg = 0xfe``,
  ``TraceArgsEndAgg = 0xfd``, ``TraceArgsDotdotdot = 0xfc``,
  ``TraceArgsOffsetTooLarge = 0xfb``, ``TraceArgsSpecial = 0xf0``).
- Real bytecode *encoder*: ``cmd/compile/internal/ssagen/ssa.go``,
  ``EmitArgInfo`` - confirms exactly which Go types are wrapped in
  ``StartAgg``/``EndAgg`` (``string``, ``slice``, ``interface``, ``array``,
  ``complex``, non-SIMD ``struct``) versus emitted as a plain leaf
  (everything else, one leaf per machine word).
- Real bytecode *consumer*: ``runtime/traceback.go``, ``printArgs`` -
  confirms each ordinary byte pair is ``(offset_from_FP, size)``.
- ``stackmap`` struct (ArgsPointerMaps, pre-1.17): ``runtime/symtab.go``,
  ``type stackmap struct { n int32; nbit int32; bytedata [1]byte }``.

Critical semantic point (verified: ``cmd/compile/internal/abi/abiutils.go``,
``ABIParamAssignment.FrameOffset`` doc comment): the "offset from FP" in
ArgInfo is a *unified* frame-pointer-relative offset - for a
register-assigned argument, it is the offset of that argument's **spill
slot**, which is left *uninitialized at the time of a call*. ArgInfo alone
never tells you whether a given leaf is actually in a register or on the
stack at a given call site - that requires independently running the ABI
register-assignment algorithm (see
:mod:`gomemforensics.architecture.x86_64`), using ArgInfo only for each
argument's *shape* (leaf count/sizes, aggregate grouping).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gomemforensics.common.memory import MemoryAccessError, MemoryReader

#: Verified opcode constants (internal/abi/type.go).
TRACE_ARGS_END_SEQ = 0xFF
TRACE_ARGS_START_AGG = 0xFE
TRACE_ARGS_END_AGG = 0xFD
TRACE_ARGS_DOTDOTDOT = 0xFC
TRACE_ARGS_OFFSET_TOO_LARGE = 0xFB
TRACE_ARGS_SPECIAL = 0xF0  # bytes >= this are operators, not offsets

#: Verified: internal/abi/type.go, TraceArgsMaxLen = (5*3+2)*10+1 = 171.
TRACE_ARGS_MAX_LEN = 171

#: Safety bound (not a Go runtime invariant) on how many bytes of an
#: ArgInfo stream are read, independent of TRACE_ARGS_MAX_LEN, guarding
#: against a corrupted stream that never emits TraceArgsEndSeq.
MAX_ARGINFO_SCAN_BYTES = 4096


class MalformedArgInfoError(Exception):
    """Raised for a truncated/malformed ArgInfo stream. Callers must catch
    this and record a recoverable AnalysisError - never abort the run."""


@dataclass(frozen=True)
class ArgInfoLeaf:
    """One non-aggregate leaf: a single machine-word-or-smaller slot."""

    offset: int  # byte offset from FP (unified register-spill/stack view - see module docstring)
    size: int


@dataclass
class ArgInfoArgument:
    """One top-level argument, reconstructed from ArgInfo's flat bytecode.

    ``leaves`` holds every non-aggregate slot belonging to this argument,
    in declaration order - a single leaf for a scalar/pointer-like type,
    or multiple for an aggregate (e.g. 2 for a string: ptr, len - verified
    via the real encoder, ``EmitArgInfo``).
    """

    leaves: list[ArgInfoLeaf] = field(default_factory=list)
    is_aggregate: bool = False
    truncated: bool = False  # hit TraceArgsDotdotdot or TraceArgsOffsetTooLarge


def decode_arg_info(data: bytes) -> list[ArgInfoArgument]:
    """Decode an ArgInfo byte stream into a list of top-level arguments.

    Faithful transcription of the real consumer's opcode handling
    (``runtime/traceback.go``, ``printArgs``), restructured to group
    leaves by top-level argument (bounded by the *first* ``StartAgg``/
    plain-leaf at depth 0) rather than just printing them - which is what
    Phase 4's ABI-aware register/stack assignment needs.

    Never raises: an unrecognized/truncated stream returns whatever
    arguments were successfully parsed before the point of truncation, and
    that last argument is marked ``truncated`` - matching the paper's
    "explicitly distinguish known type / unknown type / unavailable
    metadata" requirement rather than raising and losing everything.
    """
    arguments: list[ArgInfoArgument] = []
    pos = 0
    depth = 0
    current: ArgInfoArgument | None = None

    def ensure_current() -> ArgInfoArgument:
        nonlocal current
        if current is None:
            current = ArgInfoArgument()
        return current

    limit = min(len(data), MAX_ARGINFO_SCAN_BYTES)
    while pos < limit:
        opcode = data[pos]
        pos += 1

        if opcode == TRACE_ARGS_END_SEQ:
            if current is not None:
                arguments.append(current)
                current = None
            break

        if opcode == TRACE_ARGS_START_AGG:
            arg = ensure_current()
            arg.is_aggregate = True
            depth += 1
            continue

        if opcode == TRACE_ARGS_END_AGG:
            depth = max(0, depth - 1)
            if depth == 0 and current is not None:
                arguments.append(current)
                current = None
            continue

        if opcode == TRACE_ARGS_DOTDOTDOT:
            arg = ensure_current()
            arg.truncated = True
            if depth == 0:
                arguments.append(current)  # type: ignore[arg-type]
                current = None
            continue

        if opcode == TRACE_ARGS_OFFSET_TOO_LARGE:
            arg = ensure_current()
            arg.truncated = True
            continue

        if opcode >= TRACE_ARGS_SPECIAL:
            # An unrecognized operator byte in the reserved range - treat
            # the stream as ended here rather than misinterpreting it.
            break

        # Ordinary leaf: (offset, size) pair.
        if pos >= limit:
            if current is not None:
                current.truncated = True
                arguments.append(current)
            break
        size = data[pos]
        pos += 1
        arg = ensure_current()
        arg.leaves.append(ArgInfoLeaf(offset=opcode, size=size))
        if depth == 0:
            arguments.append(arg)
            current = None

    if current is not None:
        arguments.append(current)

    return arguments


@dataclass(frozen=True)
class StackmapInfo:
    """Decoded ``stackmap`` header (ArgsPointerMaps, pre-1.17 stack ABI).

    Structural parsing only (n/nbit header, and the raw bitmap bytes) -
    per the paper's own acknowledgment ("we infer boundaries using Go's
    type layout conventions"), inferring individual *argument boundaries*
    from the raw pointer/non-pointer bitmap alone requires additional type
    layout knowledge this phase does not implement. This is recorded as an
    explicit limitation (approved plan Section 11: EXPERIMENTAL), not
    silently guessed.
    """

    num_bitmaps: int
    bits_per_map: int
    bitmap_bytes: bytes  # raw bytes of the *first* bitmap only (args, not locals)


def read_stackmap(reader: MemoryReader, address: int, pointer_size: int) -> StackmapInfo | None:
    """Read a ``stackmap`` header and its first bitmap.

    Returns ``None`` (not an exception) if the header or bitmap cannot be
    read, or if the declared counts are implausible - callers treat this
    as "ArgsPointerMaps unavailable", not a fatal error.
    """
    from gomemforensics.go_runtime.layouts import STACKMAP_GO1_26

    try:
        header = reader.read(address, STACKMAP_GO1_26.size(pointer_size))
    except MemoryAccessError:
        return None

    import struct

    offsets = STACKMAP_GO1_26.offsets(pointer_size)
    n = struct.unpack_from("<i", header, offsets["n"])[0]
    nbit = struct.unpack_from("<i", header, offsets["nbit"])[0]

    if n <= 0 or nbit <= 0 or n > 10_000 or nbit > 100_000:
        return None  # plausibility bound, not a language invariant

    bytes_per_map = (nbit + 7) // 8
    bytedata_address = address + STACKMAP_GO1_26.size(pointer_size)
    try:
        first_bitmap = reader.read(bytedata_address, bytes_per_map)
    except MemoryAccessError:
        return None

    return StackmapInfo(num_bitmaps=n, bits_per_map=nbit, bitmap_bytes=first_bitmap)
