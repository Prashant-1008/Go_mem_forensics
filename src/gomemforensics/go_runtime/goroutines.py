"""Go goroutine discovery and validation (paper Section 3.4).

    runtime.allgs (writable-region slice-header scan)
        -> candidate *g pointers
        -> per-g structural validation
        -> GoroutineArtifact (status/PC/SP/stack bounds, no unwind yet)

``g``/``gobuf``/``stack`` layouts are verified against the local go1.26.2
install only (see ``gomemforensics.go_runtime.layouts.G_GO1_26`` for the
verification method, including a real-compiler cross-check) - the same
explicit single-era scope decision as ``mspan``/``_func`` in Phases 3-4.
A Go version outside ``"1.22+"`` reports UNSUPPORTED_RUNTIME_LAYOUT.

``runtime.allgs`` is a genuine Go slice (``var allgs []*g``,
``runtime/proc.go``) living at a fixed package-level location, but -
unlike ``pclntab``/``moduledata`` - has no equivalent anchor evidence:
it is not part of moduledata, and there is no other runtime structure
whose validated address gives an indirect way to find it. Per the paper
("stripped binaries lack this symbol... we scan writable memory regions
for candidate slice headers"), discovery here is therefore a genuine
structural scan (deliberately analogous to Phase 3's ``AllspansParser``
for ``allspans``, which faces the identical problem for the same reason)
- never a fabricated scan signature, but also never as strong an anchor
as pclntab's magic bytes or moduledata's pointer-equality anchor.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from itertools import count

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence, FailureReason
from gomemforensics.go_runtime.functab import FunctionIndex
from gomemforensics.go_runtime.layouts import (
    G_GO1_26,
    G_LAYOUTS_BY_GO_VERSION_RANGE,
    G_SCAN_BIT,
    G_STATUS_DEAD,
    G_STATUS_NAMES,
    G_WAIT_REASON_NAMES,
)
from gomemforensics.go_runtime.models import (
    AllgsCandidate,
    FunctionArtifact,
    GoroutineArtifact,
    GoroutineRecoveryStats,
    GoRuntime,
)
from gomemforensics.go_runtime.scanning import iter_readable_chunks

logger = get_logger("go_runtime.goroutines")

ANALYZER_VERSION = "go_runtime.goroutines/1"

# --- Safety bounds (explicitly not Go runtime invariants) ------------------
#: Plausibility bound on an allgs slice's declared length.
MAX_ALLGS_LEN = 1_000_000
#: How many g pointers are sampled to validate an allgs candidate.
MAX_ALLGS_SAMPLE = 64
#: Fraction of sampled g pointers that must structurally validate for the
#: allgs candidate itself to be accepted - same threshold Phase 3's
#: AllspansParser uses, for the same reason (a real slice may legitimately
#: contain some entries this project can't fully validate, e.g. very
#: unusual states, without the whole candidate being bogus).
MIN_VALID_G_SAMPLE_RATIO = 0.5
#: Hard cap on total goroutines actually recovered (post-validation) for
#: one process.
MAX_GOROUTINES_RECOVERED = 200_000
#: Plausibility bound on a single goroutine's stack size - Go's default
#: starting stack is a few KB and stacks can grow, but an implausibly
#: huge span is far more likely a corrupted/misaligned candidate than a
#: real stack (not a language invariant - a safety bound).
MAX_PLAUSIBLE_STACK_SIZE = 1 * 1024 * 1024 * 1024  # 1 GiB
#: Plausibility bound on goid - real goids are small monotonically
#: increasing integers; this is generous headroom, not a language limit.
MAX_PLAUSIBLE_GOID = 100_000_000
_SCAN_CHUNK_SIZE = 1024 * 1024


def resolve_g_layout(go_version_range: str | None):
    """Look up the verified ``g`` layout for a Go version range.

    Returns the layout or ``None`` if unsupported - callers must report
    UNSUPPORTED_RUNTIME_LAYOUT rather than guessing.
    """
    if go_version_range is None:
        return None
    return G_LAYOUTS_BY_GO_VERSION_RANGE.get(go_version_range)


@dataclass(frozen=True)
class _RawG:
    """Fields decoded from one ``g`` structure, verbatim field names from
    ``runtime/runtime2.go`` (see ``layouts.G_GO1_26``)."""

    address: int
    stack_lo: int
    stack_hi: int
    m: int
    sched_sp: int
    sched_pc: int
    sched_bp: int
    syscallsp: int
    syscallpc: int
    atomicstatus: int
    goid: int
    waitreason: int
    gopc: int
    startpc: int


def _decode_g(address: int, raw: bytes, pointer_size: int) -> _RawG:
    offsets = G_GO1_26.offsets(pointer_size)
    word_fmt = "<Q" if pointer_size == 8 else "<I"

    def word(name: str) -> int:
        return struct.unpack_from(word_fmt, raw, offsets[name])[0]

    return _RawG(
        address=address,
        stack_lo=word("stack_lo"),
        stack_hi=word("stack_hi"),
        m=word("m"),
        sched_sp=word("sched_sp"),
        sched_pc=word("sched_pc"),
        sched_bp=word("sched_bp"),
        syscallsp=word("syscallsp"),
        syscallpc=word("syscallpc"),
        atomicstatus=struct.unpack_from("<I", raw, offsets["atomicstatus"])[0],
        goid=word("goid"),
        waitreason=raw[offsets["waitreason"]],
        gopc=word("gopc"),
        startpc=word("startpc"),
    )


@dataclass(frozen=True)
class GValidationResult:
    valid: bool
    base_status: int | None
    is_scanning: bool
    reasons: list[str]  # rejection reasons if invalid; supporting notes if valid


def validate_g(raw: _RawG, pointer_size: int) -> GValidationResult:
    """Structural plausibility checks for a decoded ``g`` - paper Section 3.4:
    "A candidate g is considered valid if its stack bounds are properly
    aligned and ordered, its status field encodes a correct runtime state,
    and its goroutine identifier falls within reasonable bounds."

    Rejects: unordered/misaligned stack bounds, an implausible stack size,
    an unrecognized status value, and an out-of-bound goid. Does NOT
    require ``sched.sp`` to fall within ``[stack.lo, stack.hi)`` here -
    that invariant only holds for goroutines whose stack is actually
    "owned" by them at this instant (verified: ``runtime/runtime2.go``'s
    own status-constant doc comments - e.g. `_Gwaiting`'s "the stack is
    not owned *except*..."), which is not true for every valid status
    (e.g. `_Gdead`), so it is checked separately, per-status, by the
    caller rather than baked in here as an unconditional rejection rule
    (approved plan: "do not over-reject legitimate parked/dead/system
    goroutines").
    """
    reasons: list[str] = []

    if raw.stack_lo % pointer_size != 0 or raw.stack_hi % pointer_size != 0:
        reasons.append(f"stack bounds not pointer-aligned: lo=0x{raw.stack_lo:x} hi=0x{raw.stack_hi:x}")
    if raw.stack_lo >= raw.stack_hi:
        reasons.append(f"stack.lo (0x{raw.stack_lo:x}) >= stack.hi (0x{raw.stack_hi:x})")
    else:
        stack_size = raw.stack_hi - raw.stack_lo
        if stack_size > MAX_PLAUSIBLE_STACK_SIZE:
            reasons.append(f"stack size implausible: {stack_size} bytes")

    base_status = raw.atomicstatus & ~G_SCAN_BIT
    is_scanning = bool(raw.atomicstatus & G_SCAN_BIT)
    if base_status not in G_STATUS_NAMES:
        reasons.append(f"unrecognized status value: 0x{raw.atomicstatus:x} (base 0x{base_status:x})")

    if raw.goid > MAX_PLAUSIBLE_GOID:
        reasons.append(f"goid exceeds plausibility bound: {raw.goid}")

    if raw.waitreason >= len(G_WAIT_REASON_NAMES):
        reasons.append(f"unrecognized waitreason value: {raw.waitreason}")

    return GValidationResult(
        valid=not reasons,
        base_status=base_status if base_status in G_STATUS_NAMES else None,
        is_scanning=is_scanning,
        reasons=reasons,
    )


class AllgsParser:
    """Locates and structurally validates candidate ``runtime.allgs`` slices."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size

    def find_candidates(self, regions: list[MemoryRegion], pid: int) -> list[AllgsCandidate]:
        """Scan writable regions for a structurally valid allgs slice header.

        Unlike ``allspans`` (which Phase 3 can narrow to the recovered
        module's own data/bss bounds via moduledata), ``allgs`` has no
        such module-relative anchor - it is scanned across every
        readable+writable region, matching the paper's own description
        ("we scan writable memory regions for candidate slice headers").
        """
        candidates: list[AllgsCandidate] = []
        writable_regions = [r for r in regions if r.readable and r.writable]

        for region in writable_regions:
            for offset, chunk in iter_readable_chunks(
                self._reader, region.start, region.end, _SCAN_CHUNK_SIZE, 3 * self._pointer_size - 1
            ):
                candidates.extend(self._scan_chunk(chunk, offset, pid, len(candidates)))
                if len(candidates) >= MAX_ALLGS_LEN:
                    return candidates

        return candidates

    def _scan_chunk(self, chunk: bytes, base_offset: int, pid: int, existing_count: int) -> list[AllgsCandidate]:
        found: list[AllgsCandidate] = []
        header_size = 3 * self._pointer_size
        word_fmt = "<Q" if self._pointer_size == 8 else "<I"
        step = self._pointer_size

        # Align the first candidate position to the *absolute* address,
        # not the chunk-relative index (same fix as Phase 3's scanners).
        i = (-base_offset) % self._pointer_size
        while i + header_size <= len(chunk):
            ptr = struct.unpack_from(word_fmt, chunk, i)[0]
            length = struct.unpack_from(word_fmt, chunk, i + step)[0]
            cap_ = struct.unpack_from(word_fmt, chunk, i + 2 * step)[0]

            if ptr != 0 and ptr % self._pointer_size == 0 and 0 < length <= cap_ <= MAX_ALLGS_LEN:
                candidate = self._build_candidate(base_offset + i, ptr, length, cap_, pid, existing_count + len(found))
                if candidate is not None:
                    found.append(candidate)

            i += step

        return found

    def _build_candidate(
        self, address: int, ptr: int, length: int, cap_: int, pid: int, index: int
    ) -> AllgsCandidate | None:
        candidate_id = f"ALLGS-{pid}-{index:04d}"
        sample_size = min(length, MAX_ALLGS_SAMPLE)

        try:
            raw_ptrs = self._reader.read(ptr, sample_size * self._pointer_size)
        except MemoryAccessError as exc:
            return AllgsCandidate(
                candidate_id=candidate_id, pid=pid, address=address, ptr=ptr, length=length, capacity=cap_,
                sample_size=0, valid_sample_count=0,
                validation_errors=[f"Could not read g pointer array: {exc}"],
                rejected=True, rejection_reason="unreadable",
            )

        word_fmt = "<Q" if self._pointer_size == 8 else "<I"
        valid_count = 0
        for i in range(sample_size):
            g_ptr = struct.unpack_from(word_fmt, raw_ptrs, i * self._pointer_size)[0]
            if g_ptr == 0 or g_ptr % self._pointer_size != 0:
                continue
            raw_g = self._try_read_g(g_ptr)
            if raw_g is not None and validate_g(raw_g, self._pointer_size).valid:
                valid_count += 1

        ratio = (valid_count / sample_size) if sample_size else 0.0
        if ratio < MIN_VALID_G_SAMPLE_RATIO:
            return AllgsCandidate(
                candidate_id=candidate_id, pid=pid, address=address, ptr=ptr, length=length, capacity=cap_,
                sample_size=sample_size, valid_sample_count=valid_count,
                validation_errors=[
                    f"Only {valid_count}/{sample_size} sampled g pointers were structurally plausible "
                    f"(need >= {MIN_VALID_G_SAMPLE_RATIO:.0%})"
                ],
                rejected=True, rejection_reason="insufficient_valid_g_sample",
            )

        confidence = Confidence.HIGH if ratio >= 0.9 else Confidence.MEDIUM
        return AllgsCandidate(
            candidate_id=candidate_id, pid=pid, address=address, ptr=ptr, length=length, capacity=cap_,
            sample_size=sample_size, valid_sample_count=valid_count,
            confidence=confidence, rejected=False,
        )

    def _try_read_g(self, address: int) -> _RawG | None:
        try:
            raw = self._reader.read(address, G_GO1_26.size(self._pointer_size))
        except MemoryAccessError:
            return None
        try:
            return _decode_g(address, raw, self._pointer_size)
        except struct.error:
            return None


def select_best_allgs_candidate(candidates: list[AllgsCandidate]) -> AllgsCandidate | None:
    """Prefer the highest-confidence, most-validated candidate; never "first found" blindly."""
    accepted = [c for c in candidates if not c.rejected]
    if not accepted:
        return None
    return max(accepted, key=lambda c: (c.confidence == Confidence.HIGH, c.valid_sample_count))


class GoroutineRecoveryEngine:
    """Recovers :class:`GoroutineArtifact` records from a validated
    ``allgs`` candidate - discovery and validation are deliberately
    separate stages (:class:`AllgsParser`/:func:`validate_g`) from this
    orchestration step, per the approved Phase 5 plan ("do not combine
    discovery and validation into one opaque function").
    """

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size
        self._id_counter = count(1)

    def recover_goroutines(
        self,
        runtime: GoRuntime,
        regions: list[MemoryRegion],
        functions: list[FunctionArtifact],
    ) -> tuple[list[GoroutineArtifact], list[AnalysisError], GoroutineRecoveryStats]:
        """Discover, validate, and build goroutine artifacts for one process.

        ``functions`` should be the same list already recovered by
        :class:`~gomemforensics.go_runtime.functab.FunctionTableParser`
        for this runtime - reused (via :class:`FunctionIndex`) for
        current-function/creation-function resolution, never re-parsed.
        Gracefully skips (records a recoverable ``AnalysisError``, never
        raises) when: the Go version's ``g`` layout is unsupported, no
        valid ``allgs`` candidate is found, or an individual ``g``
        pointer fails to decode/validate (that specific entry is simply
        omitted, the rest of the walk continues).
        """
        pid = runtime.pid
        errors: list[AnalysisError] = []

        layout = resolve_g_layout(runtime.go_version)
        if layout is None:
            errors.append(
                AnalysisError(
                    component="go_runtime.goroutines",
                    message=(
                        f"UNSUPPORTED_RUNTIME_LAYOUT: no verified g layout for "
                        f"go_version={runtime.go_version!r}; goroutine recovery skipped"
                    ),
                    pid=pid,
                    reason=FailureReason.UNSUPPORTED_GO_VERSION,
                )
            )
            return [], errors, GoroutineRecoveryStats()

        allgs_parser = AllgsParser(self._reader, self._pointer_size)
        candidates = allgs_parser.find_candidates(regions, pid)
        best = select_best_allgs_candidate(candidates)
        if best is None:
            errors.append(
                AnalysisError(
                    component="go_runtime.goroutines",
                    message="no structurally valid runtime.allgs candidate found; goroutine recovery skipped",
                    pid=pid,
                    reason=FailureReason.ALLGS_NOT_FOUND,
                )
            )
            return [], errors, GoroutineRecoveryStats()

        entry_count = min(best.length, MAX_GOROUTINES_RECOVERED)
        try:
            raw_ptrs = self._reader.read(best.ptr, entry_count * self._pointer_size)
        except MemoryAccessError as exc:
            errors.append(
                AnalysisError(
                    component="go_runtime.goroutines",
                    message=f"allgs pointer array at 0x{best.ptr:x} unreadable: {exc}",
                    pid=pid,
                    reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                )
            )
            return [], errors, GoroutineRecoveryStats(candidates_scanned=entry_count, invalid_candidates=entry_count)

        function_index = FunctionIndex(functions)
        word_fmt = "<Q" if self._pointer_size == 8 else "<I"
        artifacts: list[GoroutineArtifact] = []

        for i in range(entry_count):
            g_ptr = struct.unpack_from(word_fmt, raw_ptrs, i * self._pointer_size)[0]
            if g_ptr == 0:
                continue
            try:
                artifact = self._build_goroutine(runtime, g_ptr, i, function_index, errors)
            except Exception as exc:  # one malformed g must not abort the rest of allgs
                errors.append(
                    AnalysisError(
                        component="go_runtime.goroutines",
                        message=f"Malformed g at 0x{g_ptr:x} (allgs index {i}) skipped: {exc}",
                        pid=pid,
                        reason=FailureReason.INSUFFICIENT_EVIDENCE,
                    )
                )
                continue
            if artifact is not None:
                artifacts.append(artifact)

        stats = GoroutineRecoveryStats(
            candidates_scanned=entry_count,
            valid_goroutines=len(artifacts),
            invalid_candidates=entry_count - len(artifacts),
        )
        return artifacts, errors, stats

    def _build_goroutine(
        self,
        runtime: GoRuntime,
        g_addr: int,
        allgs_index: int,
        function_index: FunctionIndex,
        errors: list[AnalysisError],
    ) -> GoroutineArtifact | None:
        pid = runtime.pid
        try:
            raw = self._reader.read(g_addr, G_GO1_26.size(self._pointer_size))
        except MemoryAccessError as exc:
            errors.append(
                AnalysisError(
                    component="go_runtime.goroutines",
                    message=f"g at 0x{g_addr:x} (allgs index {allgs_index}) unreadable: {exc}",
                    pid=pid,
                    reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                )
            )
            return None

        raw_g = _decode_g(g_addr, raw, self._pointer_size)
        result = validate_g(raw_g, self._pointer_size)
        if not result.valid:
            errors.append(
                AnalysisError(
                    component="go_runtime.goroutines",
                    message=f"g at 0x{g_addr:x} (allgs index {allgs_index}) failed validation: {'; '.join(result.reasons)}",
                    pid=pid,
                    reason=FailureReason.G_VALIDATION_FAILED,
                )
            )
            return None

        # Verified substitution rule (runtime/traceback.go, gentraceback):
        # `if gp.syscallsp != 0 { pc0 = gp.syscallpc; sp0 = gp.syscallsp }`
        # - the saved-syscall PC/SP are the meaningful "current" values
        # whenever syscallsp is nonzero, not only when status==_Gsyscall.
        used_syscall_state = raw_g.syscallsp != 0
        effective_pc = raw_g.syscallpc if used_syscall_state else raw_g.sched_pc
        effective_sp = raw_g.syscallsp if used_syscall_state else raw_g.sched_sp

        # sched/syscall sp is only meaningful ("owned") for statuses where
        # the goroutine's own stack is actually live - not, e.g., _Gdead
        # (approved plan: don't over-reject on a stale/zeroed sp for a
        # dead goroutine's sp-in-bounds check; the g itself is still a
        # valid, reportable artifact).
        stack_owned_statuses_checked = result.base_status != G_STATUS_DEAD
        sp_in_bounds = raw_g.stack_lo <= effective_sp < raw_g.stack_hi
        confidence = Confidence.HIGH
        if stack_owned_statuses_checked and effective_sp != 0 and not sp_in_bounds:
            confidence = Confidence.MEDIUM
            errors.append(
                AnalysisError(
                    component="go_runtime.goroutines",
                    message=(
                        f"g at 0x{g_addr:x}: effective sp 0x{effective_sp:x} outside stack bounds "
                        f"[0x{raw_g.stack_lo:x}, 0x{raw_g.stack_hi:x}) for status "
                        f"{G_STATUS_NAMES.get(result.base_status)!r} - confidence reduced, not rejected"
                    ),
                    pid=pid,
                    recoverable=True,
                    reason=FailureReason.STACK_UNAVAILABLE,
                )
            )

        current_fn = function_index.resolve(effective_pc) if effective_pc else None
        start_fn = function_index.resolve(raw_g.startpc) if raw_g.startpc else None
        go_pc_fn = function_index.resolve(raw_g.gopc) if raw_g.gopc else None

        artifact_id = f"GOROUTINE-{pid}-{g_addr:x}"
        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type="go_goroutine",
            analyzer="go_runtime.goroutines.GoroutineRecoveryEngine",
            extraction_method="allgs_slice_scan",
            confidence=confidence,
            pid=pid,
            virtual_address=f"0x{g_addr:x}",
            related_artifacts=[runtime.runtime_id] if runtime.runtime_id else [],
        )

        return GoroutineArtifact(
            id=artifact_id,
            pid=pid,
            goroutine_address=g_addr,
            goid=raw_g.goid,
            status=result.base_status,
            status_name=G_STATUS_NAMES.get(result.base_status),
            is_scanning=result.is_scanning,
            wait_reason=raw_g.waitreason,
            wait_reason_name=(
                G_WAIT_REASON_NAMES[raw_g.waitreason] if raw_g.waitreason < len(G_WAIT_REASON_NAMES) else None
            ),
            m_address=raw_g.m or None,
            start_pc=raw_g.startpc or None,
            start_function_name=start_fn.name if start_fn else None,
            go_pc=raw_g.gopc or None,
            go_pc_function_name=go_pc_fn.name if go_pc_fn else None,
            sched_pc=effective_pc or None,
            sched_sp=effective_sp or None,
            used_syscall_state=used_syscall_state,
            stack_lo=raw_g.stack_lo,
            stack_hi=raw_g.stack_hi,
            stack_size=raw_g.stack_hi - raw_g.stack_lo,
            current_function_id=current_fn.id if current_fn else None,
            current_function_name=current_fn.name if current_fn else None,
            current_source_file=current_fn.source_file if current_fn else None,
            current_source_line=current_fn.source_line if current_fn else None,
            allgs_index=allgs_index,
            confidence=confidence,
            validation_errors=list(result.reasons),
            provenance=provenance,
        )
