"""Data models for recovered/candidate Go runtime structures.

Every recovered artifact carries an :class:`~gomemforensics.common.models.ArtifactProvenance`
record (CLAUDE.md section 13). Only fields that were actually recovered and
validated are populated; everything else stays ``None`` rather than guessed
(CLAUDE.md section 40).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

from gomemforensics.common.models import ArtifactProvenance, Confidence
from gomemforensics.common.utils import format_address


def _addr(value: int | None) -> str | None:
    return format_address(value) if value is not None else None


class PclntabDetectionStatus(str, Enum):
    """Taxonomy requested by the approved Phase 2 plan (Section 6)."""

    MAGIC_DETECTED = "magic_detected"
    MAGIC_NOT_DETECTED_STRUCTURAL_CANDIDATE = "magic_not_detected_structural_candidate"
    UNKNOWN = "unknown"


@dataclass
class PcHeaderFields:
    """Raw fields decoded from a candidate pcHeader (internal/debug use)."""

    magic: int
    pad1: int
    pad2: int
    min_lc: int
    ptr_size: int
    nfunc: int
    nfiles: int
    funcname_offset: int
    cu_offset: int
    filetab_offset: int
    pctab_offset: int
    pcln_offset: int


@dataclass
class PclntabCandidate:
    """One pclntab/pcHeader candidate found during scanning - validated or not.

    Rejected candidates are kept (not discarded) so the detector never
    silently picks "the first match" (approved plan Section 11); they are
    only surfaced in debug/diagnostic output, not treated as evidence.
    """

    candidate_id: str
    pid: int
    address: int
    detection_status: PclntabDetectionStatus
    magic: int | None
    layout_id: str | None
    header_fields: PcHeaderFields | None
    validation_errors: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    rejected: bool = False
    rejection_reason: str | None = None
    region_source: str | None = None

    @property
    def address_hex(self) -> str:
        return format_address(self.address)

    def to_json_dict(self) -> dict:
        from gomemforensics.go_runtime.version import MAGIC_TO_ERA

        version_hint = MAGIC_TO_ERA.get(self.magic, (None, None))[0] if self.magic is not None else None
        return {
            "candidate_id": self.candidate_id,
            "pid": self.pid,
            "address": self.address_hex,
            "detection_status": self.detection_status.value,
            "magic": f"0x{self.magic:x}" if self.magic is not None else None,
            "version_hint": version_hint,
            "layout_id": self.layout_id,
            "validation_errors": list(self.validation_errors),
            "confidence": self.confidence.value,
            "rejected": self.rejected,
            "rejection_reason": self.rejection_reason,
            "region_source": self.region_source,
        }


@dataclass
class ModuledataFields:
    """Raw fields decoded from a validated moduledata candidate."""

    pc_header_pointer: int
    text: int
    etext: int
    data: int
    edata: int
    bss: int
    ebss: int
    types: int
    etypes: int
    rodata: int | None
    typelinks_ptr: int
    typelinks_len: int
    itablinks_ptr: int
    itablinks_len: int
    #: Phase 4 additions - function table resolution (paper Section 3.3.1).
    #: ``gofunc`` is absent in the go1.16-1.17 era (see layouts.py) and
    #: stays ``None`` there.
    gofunc: int | None = None
    funcnametab_ptr: int = 0
    cutab_ptr: int = 0
    filetab_ptr: int = 0
    pctab_ptr: int = 0
    pclntable_ptr: int = 0
    ftab_ptr: int = 0
    ftab_len: int = 0


@dataclass
class ModuledataCandidate:
    """One moduledata candidate found by anchoring on a recovered pcHeader address."""

    candidate_id: str
    pid: int
    address: int
    anchor_pc_header_address: int
    layout_id: str | None
    fields: ModuledataFields | None
    validation_errors: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    rejected: bool = False
    rejection_reason: str | None = None

    @property
    def address_hex(self) -> str:
        return format_address(self.address)


@dataclass
class GoRuntime:
    """A validated, best-available reconstruction of one process's Go runtime.

    Field set matches the approved Phase 2 plan exactly. Every address
    field is an ``int`` (virtual address) or ``None`` if not recovered;
    JSON serialization renders addresses as hex strings.
    """

    pid: int
    architecture: str
    go_version: str | None
    go_version_confidence: Confidence

    pclntab_address: int | None = None
    pclntab_size: int | None = None
    pc_header_address: int | None = None
    moduledata_address: int | None = None

    text_start: int | None = None
    text_end: int | None = None
    rodata_start: int | None = None
    rodata_end: int | None = None
    data_start: int | None = None
    data_end: int | None = None
    bss_start: int | None = None
    bss_end: int | None = None
    types_start: int | None = None
    types_end: int | None = None
    typelinks_start: int | None = None
    typelinks_end: int | None = None
    itablinks_start: int | None = None
    itablinks_end: int | None = None

    #: Phase 4 additions - function table resolution (paper Section 3.3.1).
    #: All absolute addresses, taken directly from moduledata (the paper's
    #: preferred primary-recovery-path source, since moduledata uses
    #: absolute addresses resolved at process init, unlike pcHeader's
    #: relative offsets - see docs/architecture/go-runtime.md).
    ftab_address: int | None = None
    ftab_length: int | None = None
    funcnametab_address: int | None = None
    cutab_address: int | None = None
    filetab_address: int | None = None
    pctab_address: int | None = None
    pclntable_address: int | None = None
    gofunc_address: int | None = None

    confidence: Confidence = Confidence.UNKNOWN
    validation_errors: list[str] = field(default_factory=list)
    provenance: list[ArtifactProvenance] = field(default_factory=list)

    #: Internal identifier so ProcessInfo.go_runtime_id can reference this
    #: object without embedding the whole GoRuntime into ProcessInfo
    #: (approved plan Section 13: "Do not overload ProcessInfo").
    runtime_id: str = ""

    def to_json_dict(self) -> dict:
        return {
            "runtime_id": self.runtime_id,
            "pid": self.pid,
            "architecture": self.architecture,
            "go_version": self.go_version,
            "go_version_confidence": self.go_version_confidence.value,
            "pclntab_address": _addr(self.pclntab_address),
            "pclntab_size": self.pclntab_size,
            "pc_header_address": _addr(self.pc_header_address),
            "moduledata_address": _addr(self.moduledata_address),
            "text_start": _addr(self.text_start),
            "text_end": _addr(self.text_end),
            "rodata_start": _addr(self.rodata_start),
            "rodata_end": _addr(self.rodata_end),
            "data_start": _addr(self.data_start),
            "data_end": _addr(self.data_end),
            "bss_start": _addr(self.bss_start),
            "bss_end": _addr(self.bss_end),
            "types_start": _addr(self.types_start),
            "types_end": _addr(self.types_end),
            "typelinks_start": _addr(self.typelinks_start),
            "typelinks_end": _addr(self.typelinks_end),
            "itablinks_start": _addr(self.itablinks_start),
            "itablinks_end": _addr(self.itablinks_end),
            "ftab_address": _addr(self.ftab_address),
            "ftab_length": self.ftab_length,
            "funcnametab_address": _addr(self.funcnametab_address),
            "cutab_address": _addr(self.cutab_address),
            "filetab_address": _addr(self.filetab_address),
            "pctab_address": _addr(self.pctab_address),
            "pclntable_address": _addr(self.pclntable_address),
            "gofunc_address": _addr(self.gofunc_address),
            "confidence": self.confidence.value,
            "validation_errors": list(self.validation_errors),
            "provenance": [asdict(p) for p in self.provenance],
        }


@dataclass
class StringArtifact:
    """A recovered Go string, forensically evidenced - never classified as malicious.

    Produced by :class:`gomemforensics.go_runtime.strings.StringRecoveryEngine`.
    Field set matches the approved Phase 3 plan. ``value`` is preserved
    exactly as decoded - never modified, redacted, or interpreted here.

    Deduplication note (approved plan Section J): ``string_address`` is
    always unique per artifact - each header is itself distinct evidence
    (a distinct place in memory referencing a string). Artifacts sharing
    the same ``data_address`` reference the *same backing bytes* (a common,
    legitimate case - e.g. a string copy) and are never merged into one
    record on that basis; grouping by ``data_address`` downstream is the
    deterministic dedup/grouping key, never the recovered ``value`` alone.
    """

    id: str
    pid: int
    string_address: int
    data_address: int
    length: int
    value: str
    region: str  # "heap" | "static"
    extraction_method: str
    confidence: Confidence
    is_utf8: bool
    printable_ratio: float
    type_candidates: list[str] = field(default_factory=list)
    #: Never set to a malicious/suspicious label in this phase - IOC
    #: extraction and any classification heuristics are later-phase work.
    classification: str = "unknown"
    provenance: ArtifactProvenance | None = None

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "string_address": _addr(self.string_address),
            "data_address": _addr(self.data_address),
            "length": self.length,
            "value": self.value,
            "region": self.region,
            "classification": self.classification,
            "confidence": self.confidence.value,
            "extraction_method": self.extraction_method,
            "is_utf8": self.is_utf8,
            "printable_ratio": round(self.printable_ratio, 3),
            "type_candidates": list(self.type_candidates),
            "provenance": asdict(self.provenance) if self.provenance else None,
        }


# ---------------------------------------------------------------------------
# Phase 4 - Go function recovery
# ---------------------------------------------------------------------------


class FunctionClassification(str, Enum):
    """Paper-derived classification (Section 3.3.2) - an analytical
    categorization by recovered source path, never a maliciousness verdict."""

    RUNTIME = "runtime"
    RUNTIME_INTERNAL = "runtime_internal"
    STDLIB = "stdlib"
    THIRD_PARTY = "third_party"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class ArgumentRecoveryStatus(str, Enum):
    """Explicit boundary for argument-*value* recovery (approved plan Section 11).

    Distinct from :class:`~gomemforensics.common.models.Confidence`: this
    says how much the *analysis technique itself* is trusted for the
    situation encountered, not how much the *result* is trusted.
    """

    SUPPORTED = "supported"  # simple, verified instruction patterns
    EXPERIMENTAL = "experimental"  # optimized/complex code, plausible but unverified patterns
    UNSUPPORTED = "unsupported"  # architecture/version/ABI/memory does not allow analysis at all


@dataclass
class ArgumentArtifact:
    """One recovered (or attempted) call-site argument.

    ``value`` and ``is_pointer`` stay ``None`` whenever not actually
    determined - never guessed (approved plan Section 8: "explicitly
    distinguish known type / unknown type / ... / unavailable metadata").

    ``leaf_index`` (Phase 4.1) distinguishes which leaf of a multi-leaf
    aggregate argument (e.g. a string's ptr/len) this artifact is - ``0``
    for a scalar argument's single leaf. ``index`` is always the
    *top-level* argument index (matching :class:`ArgumentLocation` and
    the shape-only :func:`~gomemforensics.go_runtime.arginfo.decode_arg_info`
    output), never a raw "Nth register examined" count - Phase 4.1
    corrected backward analysis to only ever populate these from a
    specific, ArgInfo-derived :class:`ArgumentLocation`, never from an
    arbitrary live register merely because it held a value (CLAUDE.md
    section 40: never invent an argument's existence).
    """

    index: int
    type_hint: str | None  # e.g. "string", "pointer", "integer", "zero", "unknown"
    value: str | None
    location: str  # e.g. "register:rax", "stack:+0x10", "unknown"
    confidence: Confidence
    extraction_method: str
    status: ArgumentRecoveryStatus
    is_pointer: bool | None = None
    leaf_index: int | None = None

    def to_json_dict(self) -> dict:
        return {
            "index": self.index,
            "leaf_index": self.leaf_index,
            "type_hint": self.type_hint,
            "value": self.value,
            "location": self.location,
            "confidence": self.confidence.value,
            "extraction_method": self.extraction_method,
            "status": self.status.value,
            "is_pointer": self.is_pointer,
        }


@dataclass(frozen=True)
class ArgumentLocation:
    """Phase 4.1: the bridge between ArgInfo's argument *shape* and a
    backward-analysis-recovered argument *value* - a specific physical
    (register or stack) location, resolved via the verified x86-64 ABI
    register-assignment algorithm
    (:func:`gomemforensics.architecture.x86_64.assign_integer_argument_locations`).

    Producing this does **not** recover any value by itself - it only
    says *where* a value would be found if this function's call sites can
    be recovered. This is a deliberately distinct pipeline stage from
    both "argument shape known"
    (:class:`~gomemforensics.go_runtime.arginfo.ArgInfoArgument`/
    ``ArgInfoLeaf`` - offsets only, no physical location) and "argument
    value known" (:class:`ArgumentArtifact` - an actual recovered value
    at one specific call site). These three states are never collapsed
    into one (approved Phase 4.1 correction).
    """

    argument_index: int
    leaf_index: int
    kind: str  # "scalar" | "aggregate_leaf"
    size: int
    location_kind: str  # "register" | "stack"
    register: str | None
    stack_offset: int | None
    #: Confidence in this *mapping* itself (HIGH for a cleanly-decoded
    #: ArgInfo leaf; MEDIUM when the source ArgInfo argument was marked
    #: truncated - see :attr:`~gomemforensics.go_runtime.arginfo.ArgInfoArgument.truncated`)
    #: - independent of whether a *value* is ever recovered at this location.
    confidence: Confidence
    #: The :class:`FunctionArtifact` id this mapping was derived from -
    #: the "related ArgInfo artifact" provenance reference.
    function_id: str

    @property
    def abi_location(self) -> str:
        if self.location_kind == "register":
            return f"register:{self.register}"
        return f"stack:+0x{self.stack_offset:x}"

    def to_json_dict(self) -> dict:
        return {
            "argument_index": self.argument_index,
            "leaf_index": self.leaf_index,
            "kind": self.kind,
            "size": self.size,
            "location_kind": self.location_kind,
            "abi_location": self.abi_location,
            "confidence": self.confidence.value,
            "function_id": self.function_id,
        }


@dataclass
class CallSiteArtifact:
    """One recovered ``CALL`` site within a caller function, with any
    arguments the backward analyzer could resolve.

    ``argument_analysis_status`` (Phase 4.1) records whether argument
    recovery was even *attempted* with a known callee shape - distinct
    from whether any individual argument's *value* was recovered.
    ``SUPPORTED`` means the callee's ArgInfo-derived
    :class:`ArgumentLocation` list was known (possibly legitimately
    empty, for a zero-argument function); ``UNSUPPORTED`` means the
    target was unresolved or its argument shape unavailable - in that
    case ``recovered_arguments`` is always empty, by design, never a
    guess assembled from whichever live registers happened to hold a
    value (approved Phase 4.1 correction).
    """

    id: str
    pid: int
    caller_function: str | None
    call_address: int
    target_address: int | None
    target_function: str | None
    recovered_arguments: list[ArgumentArtifact] = field(default_factory=list)
    argument_analysis_status: ArgumentRecoveryStatus = ArgumentRecoveryStatus.UNSUPPORTED
    confidence: Confidence = Confidence.UNKNOWN
    extraction_method: str = "capstone_backward_analysis"
    provenance: ArtifactProvenance | None = None

    @property
    def call_address_hex(self) -> str:
        return format_address(self.call_address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "caller_function": self.caller_function,
            "call_address": _addr(self.call_address),
            "target_address": _addr(self.target_address),
            "target_function": self.target_function,
            "recovered_arguments": [a.to_json_dict() for a in self.recovered_arguments],
            "argument_analysis_status": self.argument_analysis_status.value,
            "confidence": self.confidence.value,
            "extraction_method": self.extraction_method,
            "provenance": asdict(self.provenance) if self.provenance else None,
        }


@dataclass
class FunctionArtifact:
    """A recovered Go function, resolved without relying on OS/ELF/PE symbols.

    Every field is best-effort: unresolved fields stay ``None`` rather
    than guessed. ``address``/``entry_address`` are always equal (both
    kept per the approved plan's explicit field list - ``address`` is the
    generic "where is this artifact" field other artifact models also use;
    ``entry_address`` is the Go-runtime-specific name for the same value).
    """

    id: str
    pid: int
    address: int
    entry_address: int
    name: str | None
    package: str | None
    source_file: str | None
    source_line: int | None
    function_size: int | None
    classification: FunctionClassification
    confidence: Confidence
    extraction_method: str
    go_version: str | None
    architecture: str
    argument_metadata: list[ArgumentArtifact] = field(default_factory=list)
    #: Phase 4.1: ArgInfo shape, ABI-mapped to physical locations - only
    #: ever populated for the register-based ABI era on x86-64 with a
    #: successfully-decoded ArgInfo funcdata entry. ``None`` means "not
    #: determined" (unresolved shape, non-x86-64, ABI0/ambiguous era, or
    #: no ArgInfo funcdata at all - only ``ArgsPointerMaps``, which does
    #: not yield per-leaf boundaries); an empty list means "determined,
    #: and this function genuinely takes zero mappable arguments" - the
    #: two are never conflated (approved Phase 4.1 correction).
    argument_locations: list[ArgumentLocation] | None = None
    recovered_call_sites: list[CallSiteArtifact] = field(default_factory=list)
    #: Phase 5A: `_func.funcID`/`_func.flag` (`internal/abi/symtab.go`
    #: `FuncID`/`FuncFlag`), decoded alongside every other `_func` field.
    #: Consumed by goroutine stack unwinding (`stack_unwind.py`) to detect
    #: the real runtime's own documented unwind-boundary cases
    #: (`FuncFlagTopFrame`, `FuncFlagSPWrite`) rather than a second,
    #: independent function parser re-reading `_func` bytes.
    func_id: int | None = None
    func_flag: int | None = None
    #: Phase 5E: `_func.pcsp` (an offset into `moduledata.pctab` for this
    #: function's own frame-size PC-value stream), decoded alongside
    #: `func_id`/`func_flag`. Consumed by `stack_unwind.py` via the same
    #: `gomemforensics.go_runtime.pctab.pc_value` decoder Phase 4 already
    #: uses for `pcfile`/`pcln` - `funcspdelta` in the real runtime
    #: (`runtime/symtab.go`) is verified to be nothing more than
    #: `pcvalue(f, f.pcsp, targetpc, true)`, the exact same function.
    pcsp_offset: int | None = None
    errors: list[str] = field(default_factory=list)
    provenance: ArtifactProvenance | None = None

    @property
    def address_hex(self) -> str:
        return format_address(self.address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "address": _addr(self.address),
            "entry_address": _addr(self.entry_address),
            "name": self.name,
            "package": self.package,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "function_size": self.function_size,
            "classification": self.classification.value,
            "confidence": self.confidence.value,
            "extraction_method": self.extraction_method,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "argument_metadata": [a.to_json_dict() for a in self.argument_metadata],
            "argument_locations": (
                [loc.to_json_dict() for loc in self.argument_locations]
                if self.argument_locations is not None
                else None
            ),
            "recovered_call_sites": [c.to_json_dict() for c in self.recovered_call_sites],
            "func_id": self.func_id,
            "func_flag": self.func_flag,
            "pcsp_offset": self.pcsp_offset,
            "errors": list(self.errors),
            "provenance": asdict(self.provenance) if self.provenance else None,
        }


# ---------------------------------------------------------------------------
# Phase 5 - Go goroutine recovery (paper Section 3.4)
# ---------------------------------------------------------------------------


class UnwindStatus(str, Enum):
    """How far/successfully stack unwinding proceeded for one goroutine.

    Distinct from :class:`~gomemforensics.common.models.Confidence`
    (which grades trust in the *recovered* frames), matching the same
    two-axis pattern Phase 4's :class:`ArgumentRecoveryStatus` already
    established for backward analysis.
    """

    COMPLETE = "complete"  # reached a real FuncFlagTopFrame function (verified stack-top)
    BOUNDED = "bounded"  # stopped cleanly at a safety bound (max frames/bytes), not an error
    UNSUPPORTED_FRAME = "unsupported_frame"  # hit a FuncFlagSPWrite function or a special FuncID (approved plan: never guess past these)
    INVALID_RETURN_ADDRESS = "invalid_return_address"  # decoded return address does not resolve to any known function
    STACK_BOUNDS_EXCEEDED = "stack_bounds_exceeded"  # computed sp/return-address address fell outside [stack.lo, stack.hi)
    UNREADABLE_STACK = "unreadable_stack"  # the return-address slot itself could not be read
    UNRESOLVED_FUNCTION = "unresolved_function"  # current pc does not resolve to any recovered function
    MALFORMED_PCSP = "malformed_pcsp"  # pcsp stream decode failed (MalformedPctabError)
    NOT_ATTEMPTED = "not_attempted"  # unwinding never started (e.g. sched.pc itself unresolved)


@dataclass
class GoroutineFrame:
    """One unwound stack frame, reproducible from the fields alone.

    ``unwind_method`` documents exactly how this frame's pc/sp were
    derived from the previous frame (or from ``g.sched``/``g.syscallpc``
    for frame 0), so a frame never has to be trusted without knowing its
    provenance.
    """

    frame_index: int
    pc: int
    sp: int
    function_id: str | None
    function_name: str | None
    source_file: str | None
    source_line: int | None
    confidence: Confidence
    unwind_method: str

    def to_json_dict(self) -> dict:
        return {
            "frame_index": self.frame_index,
            "pc": _addr(self.pc),
            "sp": _addr(self.sp),
            "function_id": self.function_id,
            "function_name": self.function_name,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "confidence": self.confidence.value,
            "unwind_method": self.unwind_method,
        }


@dataclass
class GoroutineArtifact:
    """A recovered, structurally-validated goroutine (paper Section 3.4).

    Field set matches the approved Phase 5 plan. ``sched_pc``/``sched_sp``
    are the *saved scheduler* PC/SP (``g.sched.pc``/``g.sched.sp``, or -
    when ``g.syscallsp != 0`` - ``g.syscallpc``/``g.syscallsp``, per the
    verified real-unwinder substitution rule in
    ``runtime/traceback.go:gentraceback`` - see ``stack_unwind.py``).
    ``start_pc``/``go_pc`` are ``g.startpc``/``g.gopc`` - the goroutine's
    entry function and the PC of the ``go`` statement that created it,
    respectively - and are never conflated with ``sched_pc`` (the
    *currently executing* location, when meaningful at all): CLAUDE.md
    section 40 / approved plan: "Never label g.gopc or g.startpc as
    current execution PC."
    """

    id: str
    pid: int
    goroutine_address: int
    goid: int | None
    status: int | None
    status_name: str | None
    is_scanning: bool
    wait_reason: int | None
    wait_reason_name: str | None
    m_address: int | None
    start_pc: int | None
    start_function_name: str | None
    go_pc: int | None
    go_pc_function_name: str | None
    sched_pc: int | None
    sched_sp: int | None
    used_syscall_state: bool
    stack_lo: int | None
    stack_hi: int | None
    stack_size: int | None
    current_function_id: str | None
    current_function_name: str | None
    current_source_file: str | None
    current_source_line: int | None
    frames: list[GoroutineFrame] = field(default_factory=list)
    unwind_status: UnwindStatus = UnwindStatus.NOT_ATTEMPTED
    allgs_index: int | None = None
    discovery_method: str = "allgs_slice_scan"
    confidence: Confidence = Confidence.UNKNOWN
    extraction_method: str = "goroutine_recovery"
    validation_errors: list[str] = field(default_factory=list)
    provenance: ArtifactProvenance | None = None

    @property
    def goroutine_address_hex(self) -> str:
        return format_address(self.goroutine_address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "goroutine_address": _addr(self.goroutine_address),
            "goid": self.goid,
            "status": self.status,
            "status_name": self.status_name,
            "is_scanning": self.is_scanning,
            "wait_reason": self.wait_reason,
            "wait_reason_name": self.wait_reason_name,
            "m_address": _addr(self.m_address),
            "start_pc": _addr(self.start_pc),
            "start_function_name": self.start_function_name,
            "go_pc": _addr(self.go_pc),
            "go_pc_function_name": self.go_pc_function_name,
            "sched_pc": _addr(self.sched_pc),
            "sched_sp": _addr(self.sched_sp),
            "used_syscall_state": self.used_syscall_state,
            "stack_lo": _addr(self.stack_lo),
            "stack_hi": _addr(self.stack_hi),
            "stack_size": self.stack_size,
            "current_function_id": self.current_function_id,
            "current_function_name": self.current_function_name,
            "current_source_file": self.current_source_file,
            "current_source_line": self.current_source_line,
            "frames": [f.to_json_dict() for f in self.frames],
            "unwind_status": self.unwind_status.value,
            "allgs_index": self.allgs_index,
            "discovery_method": self.discovery_method,
            "confidence": self.confidence.value,
            "extraction_method": self.extraction_method,
            "validation_errors": list(self.validation_errors),
            "provenance": asdict(self.provenance) if self.provenance else None,
        }


@dataclass(frozen=True)
class GoroutineRecoveryStats:
    """Explicit per-process goroutine-recovery counters (approved plan:
    "Statistics must distinguish: goroutines discovered, candidates
    scanned, valid goroutines, invalid candidates, frames recovered,
    unwind failures, unsupported cases")."""

    candidates_scanned: int = 0
    valid_goroutines: int = 0
    invalid_candidates: int = 0
    frames_recovered: int = 0
    unwind_failures: int = 0
    unwind_complete: int = 0
    unwind_unsupported: int = 0


@dataclass
class AllgsCandidate:
    """One candidate ``runtime.allgs`` slice header found during scanning -
    validated or not. Rejected candidates are kept (never discarded), the
    same pattern as :class:`PclntabCandidate`/`AllspansParser`'s
    candidates - a scan never silently picks "the first match"."""

    candidate_id: str
    pid: int
    address: int
    ptr: int
    length: int
    capacity: int
    sample_size: int
    valid_sample_count: int
    confidence: Confidence = Confidence.UNKNOWN
    rejected: bool = False
    rejection_reason: str | None = None
    validation_errors: list[str] = field(default_factory=list)

    @property
    def address_hex(self) -> str:
        return format_address(self.address)

    def to_json_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "pid": self.pid,
            "address": _addr(self.address),
            "ptr": _addr(self.ptr),
            "length": self.length,
            "capacity": self.capacity,
            "sample_size": self.sample_size,
            "valid_sample_count": self.valid_sample_count,
            "confidence": self.confidence.value,
            "rejected": self.rejected,
            "rejection_reason": self.rejection_reason,
            "validation_errors": list(self.validation_errors),
        }
