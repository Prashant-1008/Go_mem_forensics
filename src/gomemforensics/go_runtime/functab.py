"""Go function table recovery (paper Section 3.3.1, Figure 3).

    moduledata -> ftab -> _func -> function entry PC -> funcnametab
    offset -> function name -> source/file metadata -> function
    metadata artifact

Every structure is verified against the local go1.26.2 install (see
``gomemforensics.go_runtime.layouts`` for citations); only that one Go
version era is supported (explicit scope decision - same as mspan/_type
in Phase 3). Works without any OS/ELF/PE symbol table - the whole point of
this recovery path (paper: "the central design goal is that Go function
recovery works even when normal OS symbol information is unavailable").
"""

from __future__ import annotations

import struct
from bisect import bisect_right
from dataclasses import dataclass
from itertools import count

from gomemforensics.architecture.x86_64 import (
    GO_ABI_INTERNAL_AMD64_INT_REGISTERS,
    assign_integer_argument_locations,
    is_register_based_abi,
)
from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence, FailureReason
from gomemforensics.go_runtime.arginfo import ArgInfoArgument, decode_arg_info, read_stackmap
from gomemforensics.go_runtime.classification import classify_function_path
from gomemforensics.go_runtime.layouts import (
    FUNC_LAYOUTS_BY_GO_VERSION_RANGE,
    FUNCDATA_ARG_INFO,
    FUNCDATA_ARGS_POINTER_MAPS,
    FUNCTAB_LAYOUTS_BY_GO_VERSION_RANGE,
)
from gomemforensics.go_runtime.models import (
    ArgumentArtifact,
    ArgumentLocation,
    ArgumentRecoveryStatus,
    FunctionArtifact,
    GoRuntime,
)
from gomemforensics.go_runtime.pctab import MalformedPctabError, read_pc_value_from_reader
from gomemforensics.go_runtime.scanning import iter_readable_chunks, read_partial

logger = get_logger("go_runtime.functab")

ANALYZER_VERSION = "go_runtime.functab/1"

#: Safety bounds (not Go runtime invariants).
MAX_FUNCTIONS_PARSED = 200_000
MAX_NAME_LENGTH = 4096
MAX_FILE_PATH_LENGTH = 4096
_CSTRING_CHUNK = 256
#: Bounded read window for a single function's pctab stream lookup (see
#: FunctionTableParser._pc_value_for_stream) - not a Go runtime invariant,
#: a safety/performance bound. Large enough that a realistic function's
#: pcfile/pcln stream (bounded independently by MAX_PCTAB_STEPS) always
#: terminates within it.
_PCTAB_STREAM_WINDOW = 4096

#: No-entry sentinels, verified: runtime/runtime2.go doc comments
#: ("An offset of 0 indicates that there is no table" for pcdata; "An
#: offset of ^uint32(0) indicates that there is no entry" for funcdata;
#: runtime/symtab.go funcfile: "fileoff != ^uint32(0)").
_NO_PCDATA = 0
_NO_FUNCDATA = 0xFFFFFFFF
_NO_CUTAB_ENTRY = 0xFFFFFFFF


def resolve_func_layout(go_version_range: str | None):
    """Look up the verified ``_func``/``functab`` layout pair for a Go version range.

    Returns ``(func_layout, functab_layout)`` or ``(None, None)`` if
    unsupported - callers must report UNSUPPORTED_RUNTIME_LAYOUT rather
    than guessing (approved plan Step 3).
    """
    if go_version_range is None:
        return None, None
    func_layout = FUNC_LAYOUTS_BY_GO_VERSION_RANGE.get(go_version_range)
    functab_layout = FUNCTAB_LAYOUTS_BY_GO_VERSION_RANGE.get(go_version_range)
    if func_layout is None or functab_layout is None:
        return None, None
    return func_layout, functab_layout


def _read_cstring(reader: MemoryReader, address: int, max_length: int) -> str | None:
    """Read a null-terminated string, bounded and resiliently chunked.

    Reuses :func:`gomemforensics.go_runtime.scanning.iter_readable_chunks`
    (the same resilient reader used by pclntab/moduledata/mspan/string
    scanning) rather than a raw fixed-size read: a name/path string near
    the end of a mapped region should still be recovered even if a full
    ``_CSTRING_CHUNK``-sized read past it would fail (CLAUDE.md section 24
    - handle partially inaccessible memory rather than giving up).
    """
    collected = bytearray()
    for _offset, chunk in iter_readable_chunks(reader, address, address + max_length, _CSTRING_CHUNK, 0):
        nul = chunk.find(b"\x00")
        if nul != -1:
            collected.extend(chunk[:nul])
            return bytes(collected).decode("utf-8", errors="replace")
        collected.extend(chunk)
        if len(collected) >= max_length:
            break
    return None  # no NUL terminator found within max_length (or nothing was readable at all)


@dataclass(frozen=True)
class _RawFunc:
    entry_off: int
    name_off: int
    args: int
    pcsp: int
    pcfile: int
    pcln: int
    npcdata: int
    cu_offset: int
    start_line: int
    func_id: int
    flag: int
    nfuncdata: int


def _decode_func(raw: bytes, layout, pointer_size: int) -> _RawFunc:
    offsets = layout.offsets(pointer_size)

    def u32(name: str) -> int:
        return struct.unpack_from("<I", raw, offsets[name])[0]

    return _RawFunc(
        entry_off=u32("entryOff"),
        name_off=u32("nameOff"),
        args=u32("args"),
        pcsp=u32("pcsp"),
        pcfile=u32("pcfile"),
        pcln=u32("pcln"),
        npcdata=u32("npcdata"),
        cu_offset=u32("cuOffset"),
        start_line=u32("startLine"),
        func_id=raw[offsets["funcID"]],
        flag=raw[offsets["flag"]],
        nfuncdata=raw[offsets["nfuncdata"]],
    )


class FunctionTableParser:
    """Parses ``moduledata.ftab`` into :class:`FunctionArtifact` records."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size
        self._id_counter = count(1)

    def parse(self, runtime: GoRuntime) -> tuple[list[FunctionArtifact], list[AnalysisError]]:
        """Parse every function table entry for ``runtime``.

        One malformed ``_func`` record never aborts the rest (approved
        plan Section 4/Step 17.15) - a recoverable AnalysisError is
        recorded per malformed entry and parsing continues.
        """
        artifacts: list[FunctionArtifact] = []
        errors: list[AnalysisError] = []
        pid = runtime.pid

        func_layout, functab_layout = resolve_func_layout(runtime.go_version)
        if func_layout is None:
            errors.append(
                AnalysisError(
                    component="go_runtime.functab",
                    message=(
                        f"UNSUPPORTED_RUNTIME_LAYOUT: no verified _func/functab layout for "
                        f"go_version={runtime.go_version!r}; function recovery skipped"
                    ),
                    pid=pid,
                    reason=FailureReason.UNSUPPORTED_GO_VERSION,
                )
            )
            return artifacts, errors

        if (
            runtime.ftab_address is None
            or runtime.ftab_length is None
            or runtime.pclntable_address is None
            or runtime.text_start is None
            or runtime.funcnametab_address is None
        ):
            errors.append(
                AnalysisError(
                    component="go_runtime.functab",
                    message="moduledata function tables not recovered (ftab/pclntable/text/funcnametab missing); function recovery skipped",
                    pid=pid,
                    reason=FailureReason.MODULEDATA_INVALID,
                )
            )
            return artifacts, errors

        functab_entry_size = functab_layout.size(self._pointer_size)
        func_min_size = func_layout.size(self._pointer_size)
        seen_entry_addresses: set[int] = set()

        entry_count = min(runtime.ftab_length, MAX_FUNCTIONS_PARSED)
        for i in range(entry_count):
            functab_addr = runtime.ftab_address + i * functab_entry_size
            try:
                raw_functab = self._reader.read(functab_addr, functab_entry_size)
            except MemoryAccessError as exc:
                errors.append(
                    AnalysisError(
                        component="go_runtime.functab",
                        message=f"functab entry {i} unreadable at 0x{functab_addr:x}: {exc}",
                        pid=pid,
                        reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                    )
                )
                continue

            offsets = functab_layout.offsets(self._pointer_size)
            entryoff = struct.unpack_from("<I", raw_functab, offsets["entryoff"])[0]
            funcoff = struct.unpack_from("<I", raw_functab, offsets["funcoff"])[0]
            entry_pc = runtime.text_start + entryoff
            func_addr = runtime.pclntable_address + funcoff

            if entry_pc in seen_entry_addresses:
                continue  # deterministic dedup
            seen_entry_addresses.add(entry_pc)

            try:
                artifact = self._parse_one_function(
                    runtime, func_layout, func_addr, entry_pc, func_min_size, errors
                )
            except Exception as exc:  # a single malformed function must not abort the table walk
                errors.append(
                    AnalysisError(
                        component="go_runtime.functab",
                        message=f"Malformed _func at 0x{func_addr:x} (entry 0x{entry_pc:x}) skipped: {exc}",
                        pid=pid,
                        reason=FailureReason.INSUFFICIENT_EVIDENCE,
                    )
                )
                continue

            if artifact is not None:
                artifacts.append(artifact)

        return artifacts, errors

    def _parse_one_function(
        self, runtime: GoRuntime, func_layout, func_addr: int, entry_pc: int, func_min_size: int, errors: list[AnalysisError]
    ) -> FunctionArtifact | None:
        pid = runtime.pid
        try:
            raw = self._reader.read(func_addr, func_min_size)
        except MemoryAccessError as exc:
            errors.append(
                AnalysisError(
                    component="go_runtime.functab",
                    message=f"_func at 0x{func_addr:x} unreadable: {exc}",
                    pid=pid,
                    reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                )
            )
            return None

        f = _decode_func(raw, func_layout, self._pointer_size)

        name = None
        if f.name_off != 0:
            name = _read_cstring(self._reader, runtime.funcnametab_address + f.name_off, MAX_NAME_LENGTH)

        source_file, source_line = self._resolve_file_line(runtime, f, entry_pc)

        classification = classify_function_path(source_file)

        artifact_id = f"FUNC-{pid}-{entry_pc:x}"
        argument_metadata, argument_locations = self._resolve_argument_metadata(
            runtime, func_addr, func_min_size, f, artifact_id
        )
        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type="go_function",
            analyzer="go_runtime.functab.FunctionTableParser",
            extraction_method="ftab_func_walk",
            confidence=Confidence.HIGH,  # structurally-located via verified moduledata.ftab, not a guess
            pid=pid,
            virtual_address=f"0x{entry_pc:x}",
            related_artifacts=[runtime.runtime_id] if runtime.runtime_id else [],
        )

        return FunctionArtifact(
            id=artifact_id,
            pid=pid,
            address=entry_pc,
            entry_address=entry_pc,
            name=name,
            package=_package_from_path(source_file),
            source_file=source_file,
            source_line=source_line,
            function_size=None,  # not directly stored in _func; not safely derivable without walking to the next entry
            classification=classification,
            confidence=Confidence.HIGH,
            extraction_method="ftab_func_walk",
            go_version=runtime.go_version,
            architecture=runtime.architecture,
            argument_metadata=argument_metadata,
            argument_locations=argument_locations,
            func_id=f.func_id,
            func_flag=f.flag,
            pcsp_offset=f.pcsp,
            provenance=provenance,
        )

    def _resolve_file_line(self, runtime: GoRuntime, f: _RawFunc, entry_pc: int) -> tuple[str | None, int | None]:
        if runtime.pctab_address is None or runtime.cutab_address is None or runtime.filetab_address is None:
            return None, None

        try:
            fileno = self._pc_value_for_stream(runtime, f.pcfile, entry_pc)
            line = self._pc_value_for_stream(runtime, f.pcln, entry_pc)
        except MalformedPctabError:
            return None, None

        if fileno is None or fileno < 0:
            return None, None

        cutab_index_addr = runtime.cutab_address + (f.cu_offset + fileno) * 4
        try:
            fileoff_bytes = self._reader.read(cutab_index_addr, 4)
        except MemoryAccessError:
            return None, None
        fileoff = struct.unpack("<I", fileoff_bytes)[0]
        if fileoff == _NO_CUTAB_ENTRY:
            return None, line if line is not None and line >= 0 else None

        source_file = _read_cstring(self._reader, runtime.filetab_address + fileoff, MAX_FILE_PATH_LENGTH)
        return source_file, (line if line is not None and line >= 0 else None)

    def _pc_value_for_stream(self, runtime: GoRuntime, stream_offset: int, entry_pc: int) -> int | None:
        """Look up one pctab stream's value at ``entry_pc``.

        ``stream_offset`` (``f.pcfile``/``f.pcln``) is an offset from the
        *start* of the whole pctab blob - which can be hundreds of KB to
        several MB into a real binary's pctab section (verified against
        the real fixture binary: a naive fixed-size read from
        ``pctab_address`` was too small for functions whose streams sit
        far into the table, silently truncating ``pc_value``'s walk for
        every function compiled after the first few hundred - a real bug
        this real-fixture validation surfaced, not a hypothetical one).

        Reads a small, bounded window starting just *before*
        ``stream_offset`` instead of from the blob's start - ``pc_value``
        only ever walks forward from its ``table_offset`` argument, so
        nothing earlier in the blob is needed. One leading pad byte keeps
        the local ``table_offset`` passed to :func:`~gomemforensics.go_runtime.pctab.pc_value`
        at ``1``, never ``0`` - ``0`` is the verified "no table" sentinel
        (:data:`_NO_PCDATA`), and re-using it as a real local offset would
        misclassify a valid, non-empty window as absent.
        """
        if stream_offset == _NO_PCDATA:
            return None
        return read_pc_value_from_reader(
            self._reader, runtime.pctab_address, stream_offset, entry_pc, entry_pc, _PCTAB_STREAM_WINDOW
        )

    def _resolve_argument_metadata(
        self, runtime: GoRuntime, func_addr: int, func_min_size: int, f: _RawFunc, function_id: str
    ) -> tuple[list[ArgumentArtifact], list[ArgumentLocation] | None]:
        """Resolve argument *shape* (``ArgumentArtifact``, unchanged from
        Phase 4) and, where the ABI era permits, ABI-mapped physical
        *locations* (``ArgumentLocation``, Phase 4.1). The two are
        distinct return values, never merged.
        """
        if f.nfuncdata == 0 or runtime.gofunc_address is None:
            return [], None

        funcdata_array_addr = func_addr + func_min_size + f.npcdata * 4
        try:
            funcdata_raw = self._reader.read(funcdata_array_addr, f.nfuncdata * 4)
        except MemoryAccessError:
            return [], None

        def funcdata_offset(idx: int) -> int | None:
            if idx >= f.nfuncdata:
                return None
            value = struct.unpack_from("<I", funcdata_raw, idx * 4)[0]
            return None if value == _NO_FUNCDATA else value

        arginfo_off = funcdata_offset(FUNCDATA_ARG_INFO)
        if arginfo_off is not None:
            return self._parse_arginfo(runtime, arginfo_off, function_id)

        argptrmaps_off = funcdata_offset(FUNCDATA_ARGS_POINTER_MAPS)
        if argptrmaps_off is not None:
            # ArgsPointerMaps (pre-1.17) never yields per-leaf boundaries
            # (see _parse_args_pointer_maps) - no ArgumentLocation is
            # derivable from it, so argument_locations stays None ("not
            # determined"), never an empty-but-attempted [] (approved
            # Phase 4.1 correction: the two must never be conflated).
            return self._parse_args_pointer_maps(runtime, argptrmaps_off), None

        return [], None

    def _parse_arginfo(
        self, runtime: GoRuntime, arginfo_off: int, function_id: str
    ) -> tuple[list[ArgumentArtifact], list[ArgumentLocation] | None]:
        from gomemforensics.go_runtime.arginfo import MAX_ARGINFO_SCAN_BYTES

        address = runtime.gofunc_address + arginfo_off
        raw = read_partial(self._reader, address, MAX_ARGINFO_SCAN_BYTES)
        if not raw:
            return [], None

        arguments = decode_arg_info(raw)
        results: list[ArgumentArtifact] = []
        for idx, arg in enumerate(arguments):
            type_hint = "aggregate" if arg.is_aggregate else "scalar"
            status = ArgumentRecoveryStatus.EXPERIMENTAL if arg.truncated else ArgumentRecoveryStatus.SUPPORTED
            results.append(
                ArgumentArtifact(
                    index=idx,
                    type_hint=type_hint,
                    value=None,  # ArgInfo gives shape/boundaries only, never a value - see backward_analysis.py
                    location=f"fp_offsets:{[l.offset for l in arg.leaves]}",
                    confidence=Confidence.MEDIUM,  # structurally decoded, but shape only, not a value
                    extraction_method="arginfo_funcdata",
                    status=status,
                )
            )

        locations = _resolve_argument_locations(runtime, function_id, arguments)
        return results, locations

    def _parse_args_pointer_maps(self, runtime: GoRuntime, argptrmaps_off: int) -> list[ArgumentArtifact]:
        address = runtime.gofunc_address + argptrmaps_off
        info = read_stackmap(self._reader, address, self._pointer_size)
        if info is None:
            return []
        # Per the paper's own acknowledgment (Section 3.3.3): inferring
        # individual argument boundaries from the raw pointer/non-pointer
        # bitmap requires additional Go type-layout knowledge not
        # implemented in this phase - reported as a single EXPERIMENTAL
        # summary artifact rather than fabricated per-argument boundaries.
        return [
            ArgumentArtifact(
                index=0,
                type_hint="pointer_bitmap",
                value=None,
                location=f"stackmap:{info.num_bitmaps}x{info.bits_per_map}bits",
                confidence=Confidence.LOW,
                extraction_method="args_pointer_maps_funcdata",
                status=ArgumentRecoveryStatus.EXPERIMENTAL,
            )
        ]


def _resolve_argument_locations(
    runtime: GoRuntime, function_id: str, arguments: list[ArgInfoArgument]
) -> list[ArgumentLocation] | None:
    """ABI-map ArgInfo's decoded leaf shape to physical register/stack
    locations (Phase 4.1 correction).

    Returns ``None`` ("not determined") rather than ``[]`` when the ABI
    era is not confidently register-based for this architecture/version -
    the same conservative boundary
    :func:`gomemforensics.architecture.x86_64.is_register_based_abi`
    already enforces everywhere else in this project, applied here too
    rather than assuming register-ABI just because an ``ArgInfo``
    funcdata entry happened to be present (``ArgInfo`` itself is only
    ever emitted for Go >=1.17, so in practice this only returns ``None``
    for the ``"1.16-1.17"`` straddling range, which is unreachable today
    since ``resolve_func_layout`` only supports ``"1.22+"`` - this check
    exists so the logic stays correct if that layout support is ever
    extended, not to broaden it now).

    Returns ``[]`` (not ``None``) for a function whose ArgInfo shape
    decoded successfully but has genuinely zero leaves - a real, distinct
    fact ("this function takes no mappable arguments"), never conflated
    with "not determined".
    """
    if runtime.architecture != "x86_64":
        return None
    if is_register_based_abi(runtime.go_version) is not True:
        return None

    leaf_lists = [[(leaf.offset, leaf.size) for leaf in arg.leaves] for arg in arguments]
    assigned = assign_integer_argument_locations(leaf_lists, len(GO_ABI_INTERNAL_AMD64_INT_REGISTERS))

    locations: list[ArgumentLocation] = []
    for arg_idx, (arg, leaf_locations) in enumerate(zip(arguments, assigned)):
        # A truncated ArgInfo argument ("..."/OffsetTooLarge) has
        # incomplete leaf data - the mapping itself is still mechanically
        # correct for whatever leaves ARE present, but is less certain
        # overall, so it is recorded at reduced confidence rather than
        # silently presented as equally trustworthy (approved Phase 4.1
        # correction: never let a downstream consumer treat this as more
        # certain than the shape it was derived from).
        mapping_confidence = Confidence.MEDIUM if arg.truncated else Confidence.HIGH
        kind = "aggregate_leaf" if len(leaf_locations) > 1 else "scalar"
        for leaf_idx, loc in enumerate(leaf_locations):
            locations.append(
                ArgumentLocation(
                    argument_index=arg_idx,
                    leaf_index=leaf_idx,
                    kind=kind,
                    size=loc.size,
                    location_kind=loc.kind,
                    register=loc.register,
                    stack_offset=loc.fp_offset if loc.kind == "stack" else None,
                    confidence=mapping_confidence,
                    function_id=function_id,
                )
            )
    return locations


def _package_from_path(source_file: str | None) -> str | None:
    """Best-effort package path derivation: the source file's directory
    component, which for Go source is the conventional package import path
    prefix. ``None`` if the source file itself is unknown."""
    if not source_file:
        return None
    normalized = source_file.replace("\\", "/")
    if "/" not in normalized:
        return None
    return normalized.rsplit("/", 1)[0]


class FunctionIndex:
    """A recovered function set, sorted and indexed once for repeated
    O(log n) "which function is PC in" lookups.

    Shared by Phase 5 (goroutine current-function resolution, stack
    unwinding, which may look this up once per unwound frame across many
    goroutines) so there is exactly one "resolve function by PC"
    implementation in the project - never a second, independent function
    parser (approved Phase 5 plan) - and so repeated lookups don't
    re-sort/re-scan the function list each time (CLAUDE.md section 44).

    A function's real upper PC bound is not stored anywhere this project
    recovers (``FunctionArtifact.function_size`` is always ``None`` - see
    ``docs/architecture/go-runtime.md``), so - matching the same
    documented approximation Phase 4's backward-analysis disassembly
    bound already uses - "covers pc" here means "pc falls in
    [this function's entry, the next function's entry)", the next
    recovered entry acting as a scan/lookup boundary, never treated as a
    verified function-size fact.
    """

    def __init__(self, functions: list[FunctionArtifact]) -> None:
        self._sorted = sorted(functions, key=lambda f: f.entry_address)
        self._entries = [f.entry_address for f in self._sorted]

    def resolve(self, pc: int) -> FunctionArtifact | None:
        if not self._sorted or pc < self._entries[0]:
            return None
        idx = bisect_right(self._entries, pc) - 1
        if idx < 0:
            return None
        return self._sorted[idx]
