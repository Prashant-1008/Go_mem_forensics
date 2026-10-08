"""Go string recovery (Phase 3): heap-based and static-section extraction.

Implements the paper's string recovery methodology (Section 3.2):

- **Heap-based** (3.2.1): via allspans -> mspan -> allocation bitmap ->
  heap objects -> size-to-type candidate mapping -> two-word (ptr, len)
  string header validation, with itab-pointer-based interface
  disambiguation.
- **Static-section** (3.2.2): pattern scan for ptr+len-shaped Go string
  headers in readable static regions, validated the same way.

These two paths are implemented as separate methods
(:meth:`StringRecoveryEngine.recover_heap_strings` /
:meth:`recover_static_strings`) and never merged into one indistinguishable
method.

Scope, documented explicitly (see docs/architecture/go-runtime.md): only
heap objects whose size is exactly two machine words (a direct string
header candidate - the paper's own primary disambiguation case) are
interpreted as string candidates. Recursive field-walking into larger
composite types (arrays/slices of strings, structs with string fields,
maps) is **not implemented** in this phase - that requires the fuller Go
type system (uncommonType, struct field metadata) explicitly out of scope
("do not build the entire Go type system in this phase").
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from itertools import count

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence, FailureReason
from gomemforensics.go_runtime.layouts import ITAB_GO1_26, TYPE_HEADER_GO1_26, TYPE_KIND_MASK, TYPE_KIND_STRING
from gomemforensics.go_runtime.models import GoRuntime, StringArtifact
from gomemforensics.go_runtime.mspan import (
    AllspansParser,
    MspanWalker,
    resolve_mspan_layout,
    select_best_allspans_candidate,
)
from gomemforensics.go_runtime.scanning import iter_readable_chunks
from gomemforensics.go_runtime.types import TypeDescriptor, TypeIndex, build_type_index

logger = get_logger("go_runtime.strings")

ANALYZER_VERSION = "go_runtime.strings/1"

# --- Safety / plausibility bounds (explicitly not Go runtime invariants) --
#: A Go string longer than this is treated as implausible for recovery
#: purposes - guards against interpreting garbage as an enormous length.
MAX_STRING_LENGTH = 1 * 1024 * 1024  # 1 MiB
#: Fraction of bytes that must be printable ASCII/whitespace for a
#: non-UTF-8-decodable candidate to still be accepted, at LOW confidence.
MIN_PRINTABLE_RATIO = 0.85
#: Hard cap on how many static header candidates are scanned per process,
#: to keep worst-case work bounded.
MAX_STATIC_CANDIDATES = 200_000
_SCAN_CHUNK_SIZE = 1024 * 1024

_PRINTABLE_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


@dataclass(frozen=True)
class StringValidationResult:
    valid: bool
    value: str | None
    is_utf8: bool
    printable_ratio: float
    reasons: list[str]  # rejection reasons if invalid; supporting notes if valid


def validate_string_header(
    reader: MemoryReader, data_ptr: int, length: int
) -> StringValidationResult:
    """Validate and decode a candidate Go string header's backing bytes.

    UTF-8 validity is used as a *signal*, not an absolute requirement
    (approved plan Section F): a candidate that fails strict UTF-8
    decoding but is still predominantly printable is accepted at lower
    confidence rather than discarded outright, since Go strings are only
    guaranteed to be byte sequences - not every real Go string a malware
    sample constructs is valid UTF-8 (e.g. a deliberately obfuscated
    buffer). An empty string (``length == 0``) is a legitimate, valid Go
    string, not a rejection.
    """
    if length < 0:
        return StringValidationResult(False, None, False, 0.0, [f"negative length: {length}"])
    if length > MAX_STRING_LENGTH:
        return StringValidationResult(False, None, False, 0.0, [f"length {length} exceeds safety bound {MAX_STRING_LENGTH}"])
    if length == 0:
        return StringValidationResult(True, "", True, 1.0, ["empty string (length 0) - always valid"])
    if data_ptr == 0:
        return StringValidationResult(False, None, False, 0.0, ["null data pointer"])
    if not reader.is_valid(data_ptr):
        return StringValidationResult(False, None, False, 0.0, [f"data pointer 0x{data_ptr:x} not mapped"])

    try:
        raw = reader.read(data_ptr, length)
    except MemoryAccessError as exc:
        return StringValidationResult(False, None, False, 0.0, [f"backing bytes unreadable: {exc}"])

    printable_count = sum(1 for b in raw if b in _PRINTABLE_BYTES)
    printable_ratio = printable_count / len(raw) if raw else 1.0

    try:
        text = raw.decode("utf-8")
        is_utf8 = True
    except UnicodeDecodeError:
        is_utf8 = False
        text = raw.decode("utf-8", errors="replace")

    if not is_utf8 and printable_ratio < MIN_PRINTABLE_RATIO:
        return StringValidationResult(
            False, None, False, printable_ratio,
            [f"not valid UTF-8 and only {printable_ratio:.0%} printable (< {MIN_PRINTABLE_RATIO:.0%})"],
        )

    reasons = ["valid UTF-8"] if is_utf8 else [f"not valid UTF-8, but {printable_ratio:.0%} printable"]
    return StringValidationResult(True, text, is_utf8, printable_ratio, reasons)


def _looks_like_itab(reader: MemoryReader, pointer_size: int, candidate_ptr: int) -> bool:
    """Heuristic itab-pointer plausibility check (paper Section 3.2.1/3.1.5).

    Evidence, not proof (approved plan Section G): reads the candidate as
    an ``ITab`` header and checks its embedded ``Type`` pointer is itself
    readable and looks like a plausible ``_type`` header. False negatives
    are expected and acceptable - this only ever *excludes* a two-word
    object from string candidacy, it never asserts "this is definitely an
    interface".
    """
    if candidate_ptr == 0 or not reader.is_valid(candidate_ptr):
        return False
    try:
        raw = reader.read(candidate_ptr, ITAB_GO1_26.size(pointer_size))
    except MemoryAccessError:
        return False
    offsets = ITAB_GO1_26.offsets(pointer_size)
    word_fmt = "<Q" if pointer_size == 8 else "<I"
    type_ptr = struct.unpack_from(word_fmt, raw, offsets["type"])[0]
    if type_ptr == 0 or not reader.is_valid(type_ptr):
        return False
    try:
        type_raw = reader.read(type_ptr, TYPE_HEADER_GO1_26.size(pointer_size))
    except MemoryAccessError:
        return False
    kind_offset = TYPE_HEADER_GO1_26.offsets(pointer_size)["kind"]
    kind = type_raw[kind_offset] & TYPE_KIND_MASK
    return kind <= 26


def _heap_confidence(is_utf8: bool, type_candidates: list[TypeDescriptor]) -> Confidence:
    if not is_utf8:
        return Confidence.LOW
    if any(t.kind == TYPE_KIND_STRING for t in type_candidates):
        return Confidence.HIGH
    return Confidence.MEDIUM


def _static_confidence(is_utf8: bool) -> Confidence:
    return Confidence.MEDIUM if is_utf8 else Confidence.LOW


class StringRecoveryEngine:
    """Recovers Go string artifacts from a process's heap and static regions.

    Input: a validated :class:`GoRuntime`, a :class:`MemoryReader`, and the
    process's normalized :class:`MemoryRegion` list. Output:
    ``list[StringArtifact]`` plus recoverable :class:`AnalysisError`
    entries - never raises for corrupted/incomplete memory (approved plan
    Section Q).
    """

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size
        self._id_counter = count(1)

    def _next_id(self, pid: int) -> str:
        return f"STR-{pid}-{next(self._id_counter):04d}"

    # -- Heap -----------------------------------------------------------

    def recover_heap_strings(
        self, runtime: GoRuntime, regions: list[MemoryRegion]
    ) -> tuple[list[StringArtifact], list[AnalysisError]]:
        """Heap-based string recovery (paper Section 3.2.1).

        Returns an empty list (not an exception) whenever a prerequisite
        is missing or unsupported (no verified mspan layout for this Go
        version, no allspans candidate validates, etc.) - static recovery
        must still proceed regardless (approved plan Section B/Q).
        """
        artifacts: list[StringArtifact] = []
        errors: list[AnalysisError] = []
        pid = runtime.pid

        layout, layout_id = resolve_mspan_layout(runtime.go_version)
        if layout is None:
            errors.append(
                AnalysisError(
                    component="go_runtime.strings.heap",
                    message=(
                        f"UNSUPPORTED_RUNTIME_LAYOUT: no verified mspan layout for "
                        f"go_version={runtime.go_version!r}; heap string recovery skipped"
                    ),
                    pid=pid,
                    reason=FailureReason.UNSUPPORTED_GO_VERSION,
                )
            )
            return artifacts, errors

        type_index, type_errors = build_type_index(runtime, self._reader, self._pointer_size)
        errors.extend(type_errors)

        scan_bounds = None
        if runtime.data_start is not None and runtime.bss_end is not None:
            scan_bounds = (min(runtime.data_start, runtime.bss_end), max(runtime.data_start, runtime.bss_end))
        elif runtime.data_start is not None and runtime.data_end is not None:
            scan_bounds = (runtime.data_start, runtime.data_end)

        allspans_parser = AllspansParser(self._reader, self._pointer_size)
        candidates = allspans_parser.find_candidates(regions, pid, scan_bounds=scan_bounds)
        best = select_best_allspans_candidate(candidates)

        if best is None:
            errors.append(
                AnalysisError(
                    component="go_runtime.strings.heap",
                    message="No structurally valid allspans candidate found; heap string recovery skipped",
                    pid=pid,
                    reason=FailureReason.INSUFFICIENT_EVIDENCE,
                )
            )
            return artifacts, errors

        walker = MspanWalker(self._reader, self._pointer_size)
        heap_objects, walk_errors = walker.enumerate_heap_objects(best.span_pointers, pid)
        errors.extend(walk_errors)

        two_word_size = 2 * self._pointer_size
        for obj in heap_objects:
            if obj.size != two_word_size:
                continue  # scope limitation - see module docstring
            artifact = self._interpret_two_word_object(
                pid, obj.address, "heap", "mspan_allocation_bitmap", type_index, runtime
            )
            if artifact is not None:
                artifacts.append(artifact)

        return artifacts, errors

    def _interpret_two_word_object(
        self,
        pid: int,
        address: int,
        region: str,
        extraction_method: str,
        type_index: TypeIndex,
        runtime: GoRuntime,
    ) -> StringArtifact | None:
        try:
            raw = self._reader.read(address, 2 * self._pointer_size)
        except MemoryAccessError as exc:
            logger.debug("pid=%s: object at 0x%x unreadable, skipping: %s", pid, address, exc)
            return None

        word_fmt = "<Q" if self._pointer_size == 8 else "<I"
        word0 = struct.unpack_from(word_fmt, raw, 0)[0]
        word1 = struct.unpack_from(word_fmt, raw, self._pointer_size)[0]

        if region == "heap" and _looks_like_itab(self._reader, self._pointer_size, word0):
            logger.debug(
                "pid=%s: object at 0x%x looks like an interface value (itab-plausible), "
                "excluded from string candidacy - recursive interface payload processing "
                "is not implemented in Phase 3",
                pid,
                address,
            )
            return None

        result = validate_string_header(self._reader, word0, word1)
        if not result.valid:
            logger.debug("pid=%s: candidate at 0x%x rejected: %s", pid, address, "; ".join(result.reasons))
            return None

        type_candidates = type_index.candidates_for_size(2 * self._pointer_size) if region == "heap" else []
        confidence = (
            _heap_confidence(result.is_utf8, type_candidates)
            if region == "heap"
            else _static_confidence(result.is_utf8)
        )

        artifact_id = self._next_id(pid)
        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type="go_string",
            analyzer="go_runtime.strings.StringRecoveryEngine",
            extraction_method=extraction_method,
            confidence=confidence,
            pid=pid,
            virtual_address=f"0x{address:x}",
            memory_region=region,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=[runtime.runtime_id] if runtime.runtime_id else [],
        )
        return StringArtifact(
            id=artifact_id,
            pid=pid,
            string_address=address,
            data_address=word0,
            length=word1,
            value=result.value or "",
            region=region,
            extraction_method=extraction_method,
            confidence=confidence,
            is_utf8=result.is_utf8,
            printable_ratio=result.printable_ratio,
            type_candidates=[t.kind_name for t in type_candidates],
            provenance=provenance,
        )

    # -- Static -----------------------------------------------------------

    def recover_static_strings(
        self, runtime: GoRuntime, regions: list[MemoryRegion]
    ) -> tuple[list[StringArtifact], list[AnalysisError]]:
        """Static-section string-header pattern recovery (paper Section 3.2.2).

        Scans readable regions (never .text-only executable regions, to
        avoid confusing instruction bytes with header patterns) for
        aligned ``(ptr, len)`` pairs, validated with the same content
        checks as the heap path but always capped at MEDIUM confidence
        (paper: static headers are pattern-derived, not
        allocator-validated) - never HIGH.
        """
        artifacts: list[StringArtifact] = []
        errors: list[AnalysisError] = []
        pid = runtime.pid
        seen_addresses: set[int] = set()

        candidate_regions = [r for r in regions if r.readable and not (r.executable and not r.writable)]
        # The above keeps read-only-data and read-write regions, and drops
        # pure read-execute (.text-like) regions; a region that is both
        # writable and executable (unusual, but observed on some targets)
        # is still scanned, erring toward not missing evidence.

        header_size = 2 * self._pointer_size
        word_fmt = "<Q" if self._pointer_size == 8 else "<I"

        for region in candidate_regions:
            for offset, chunk in iter_readable_chunks(
                self._reader, region.start, region.end, _SCAN_CHUNK_SIZE, header_size - 1
            ):
                # offset (from the resilient chunk reader) is not
                # guaranteed pointer-aligned - align the first candidate
                # position to the absolute address, not the chunk-relative
                # index (see AllspansParser._scan_chunk for the same fix).
                i = (-offset) % self._pointer_size
                while i + header_size <= len(chunk):
                    address = offset + i
                    if address in seen_addresses:
                        i += self._pointer_size
                        continue

                    ptr = struct.unpack_from(word_fmt, chunk, i)[0]
                    length = struct.unpack_from(word_fmt, chunk, i + self._pointer_size)[0]

                    if 0 < length <= MAX_STRING_LENGTH and ptr != 0:
                        seen_addresses.add(address)
                        artifact = self._interpret_two_word_object(
                            pid, address, "static", "static_string_header_scan",
                            TypeIndex(), runtime,
                        )
                        if artifact is not None:
                            artifacts.append(artifact)
                            if len(artifacts) + len(seen_addresses) > MAX_STATIC_CANDIDATES:
                                return artifacts, errors

                    i += self._pointer_size

        return artifacts, errors
