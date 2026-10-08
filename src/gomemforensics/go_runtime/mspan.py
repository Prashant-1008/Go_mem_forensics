"""allspans discovery and mspan parsing for heap object enumeration.

Implements the paper's heap structure parsing (Section 3.2.1, Figure 2):
locate ``allspans`` in writable memory, validate it structurally (aligned
pointer, ``len <= cap``, and a sample of its entries pointing to
plausible ``mspan`` structures - "valid mspan ptrs" per Figure 2), then
decode each in-use ``mspan``'s allocation bitmap to enumerate live heap
object addresses: ``object_addr = startAddr + (bit_index * elemsize)``.

``mspan`` layout is verified against the local go1.26.2 install only (see
``gomemforensics.go_runtime.layouts.MSPAN_GO1_26``) - an explicit,
documented scope decision (docs/architecture/go-runtime.md). A Go version
outside that verified layout is reported as ``UNSUPPORTED_RUNTIME_LAYOUT``
rather than guessed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisError, Confidence, FailureReason
from gomemforensics.go_runtime.layouts import MSPAN_GO1_26, MSPAN_LAYOUTS_BY_GO_VERSION_RANGE, MSPAN_STATE_IN_USE
from gomemforensics.go_runtime.scanning import iter_readable_chunks, read_partial

logger = get_logger("go_runtime.mspan")

# --- Safety limits (explicitly not Go runtime invariants) -----------------
#: Plausibility bound on an allspans slice's declared length.
MAX_ALLSPANS_LEN = 2_000_000
#: How many span pointers are sampled to validate an allspans candidate.
MAX_SPAN_SAMPLE = 64
#: Fraction of sampled span pointers that must structurally validate for
#: the allspans candidate itself to be accepted.
MIN_VALID_SAMPLE_RATIO = 0.5
#: Hard cap on total spans walked for heap object enumeration, across the
#: whole allspans slice.
MAX_SPANS_PROCESSED = 200_000
#: Plausibility bound on a single mspan's object count.
MAX_OBJECTS_PER_SPAN = 100_000
#: Plausibility bound on a single mspan's element (object) size.
MAX_PLAUSIBLE_ELEMSIZE = 1 * 1024 * 1024 * 1024  # 1 GiB
#: Hard cap on total heap objects enumerated across all spans for one process.
MAX_HEAP_OBJECTS = 2_000_000
_SCAN_CHUNK_SIZE = 1024 * 1024


class MspanRejectionReason(str, Enum):
    UNREADABLE = "unreadable"
    NULL_START_ADDR = "null_start_addr"
    IMPLAUSIBLE_ELEMSIZE = "implausible_elemsize"
    IMPLAUSIBLE_NELEMS = "implausible_nelems"
    ALLOC_COUNT_EXCEEDS_NELEMS = "alloc_count_exceeds_nelems"
    UNKNOWN_STATE = "unknown_state"


@dataclass(frozen=True)
class MspanInfo:
    """Decoded, structurally-plausible subset of one ``mspan``."""

    address: int
    start_addr: int
    nelems: int
    elemsize: int
    alloc_count: int
    alloc_bits_ptr: int
    state: int

    @property
    def is_in_use(self) -> bool:
        return self.state == MSPAN_STATE_IN_USE


def _decode_mspan(address: int, raw: bytes, pointer_size: int) -> MspanInfo:
    offsets = MSPAN_GO1_26.offsets(pointer_size)
    word_fmt = "<Q" if pointer_size == 8 else "<I"

    def word(name: str) -> int:
        return struct.unpack_from(word_fmt, raw, offsets[name])[0]

    def u16(name: str) -> int:
        return struct.unpack_from("<H", raw, offsets[name])[0]

    return MspanInfo(
        address=address,
        start_addr=word("startAddr"),
        nelems=u16("nelems"),
        elemsize=word("elemsize"),
        alloc_count=u16("allocCount"),
        alloc_bits_ptr=word("allocBits"),
        state=raw[offsets["state"]],
    )




def validate_mspan(info: MspanInfo) -> list[str]:
    """Structural plausibility checks for a decoded mspan. Empty list = plausible."""
    errors: list[str] = []
    if info.start_addr == 0:
        errors.append("startAddr is null")
    if info.elemsize == 0 or info.elemsize > MAX_PLAUSIBLE_ELEMSIZE:
        errors.append(f"elemsize implausible: {info.elemsize}")
    if info.nelems > MAX_OBJECTS_PER_SPAN:
        errors.append(f"nelems exceeds plausibility bound: {info.nelems}")
    if info.alloc_count > info.nelems:
        errors.append(f"allocCount ({info.alloc_count}) > nelems ({info.nelems})")
    if info.state not in (0, 1, 2):  # mSpanDead, mSpanInUse, mSpanManual
        errors.append(f"unrecognized span state: {info.state}")
    return errors


def resolve_mspan_layout(go_version_range: str | None) -> tuple[object, str] | tuple[None, None]:
    """Look up the verified mspan layout for a detected Go version range.

    Returns ``(layout, layout_id)`` or ``(None, None)`` if the detected
    version falls outside every verified layout - callers must report
    ``UNSUPPORTED_RUNTIME_LAYOUT`` rather than guessing (approved plan
    Section C).
    """
    if go_version_range is None:
        return None, None
    layout = MSPAN_LAYOUTS_BY_GO_VERSION_RANGE.get(go_version_range)
    if layout is None:
        return None, None
    return layout, layout.layout_id


@dataclass
class AllspansCandidate:
    """One candidate ``allspans`` slice location - accepted or rejected.

    Preserved regardless of outcome (approved plan Section B: "Preserve
    multiple candidates if multiple structurally valid candidates exist").
    """

    candidate_id: str
    pid: int
    address: int
    declared_len: int | None = None
    declared_cap: int | None = None
    sampled_count: int = 0
    valid_sample_count: int = 0
    span_pointers: list[int] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    rejected: bool = False
    rejection_reason: str | None = None


class AllspansParser:
    """Locates and structurally validates the runtime's ``allspans`` slice."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size

    def find_candidates(
        self, regions: list[MemoryRegion], pid: int, scan_bounds: tuple[int, int] | None = None
    ) -> list[AllspansCandidate]:
        """Scan writable regions for a structurally valid allspans slice header.

        ``scan_bounds``, when given (typically the recovered module's own
        data/bss range from :class:`~gomemforensics.go_runtime.models.GoRuntime`),
        narrows the scan per the paper (Section 3.2.1: "locate the
        allspans slice header within the .data or .bss sections") rather
        than scanning every writable region in the process.
        """
        candidates: list[AllspansCandidate] = []
        writable_regions = [r for r in regions if r.readable and r.writable]

        for region in writable_regions:
            start, end = region.start, region.end
            if scan_bounds is not None:
                bound_start, bound_end = scan_bounds
                start, end = max(start, bound_start), min(end, bound_end)
                if start >= end:
                    continue

            for offset, chunk in iter_readable_chunks(
                self._reader, start, end, _SCAN_CHUNK_SIZE, 3 * self._pointer_size - 1
            ):
                candidates.extend(self._scan_chunk(chunk, offset, pid, len(candidates)))
                if len(candidates) >= MAX_ALLSPANS_LEN:
                    break

        return candidates

    def _scan_chunk(self, chunk: bytes, base_offset: int, pid: int, existing_count: int) -> list[AllspansCandidate]:
        found: list[AllspansCandidate] = []
        header_size = 3 * self._pointer_size
        word_fmt = "<Q" if self._pointer_size == 8 else "<I"
        step = self._pointer_size

        # base_offset (from the resilient chunk reader) is not guaranteed
        # pointer-aligned even though region.start usually is - align the
        # first candidate position to the *absolute* address, not to the
        # chunk-relative index, so alignment filtering below is meaningful.
        i = (-base_offset) % self._pointer_size
        while i + header_size <= len(chunk):
            ptr = struct.unpack_from(word_fmt, chunk, i)[0]
            length = struct.unpack_from(word_fmt, chunk, i + step)[0]
            cap_ = struct.unpack_from(word_fmt, chunk, i + 2 * step)[0]

            if ptr != 0 and ptr % self._pointer_size == 0 and 0 < length <= cap_ <= MAX_ALLSPANS_LEN:
                candidate = self._build_candidate(base_offset + i, ptr, length, cap_, pid, existing_count + len(found))
                if candidate is not None:
                    found.append(candidate)

            i += step

        return found

    def _build_candidate(
        self, address: int, ptr: int, length: int, cap_: int, pid: int, index: int
    ) -> AllspansCandidate | None:
        candidate_id = f"ALLSPANS-{pid}-{index:04d}"
        sample_size = min(length, MAX_SPAN_SAMPLE)

        try:
            raw_ptrs = self._reader.read(ptr, sample_size * self._pointer_size)
        except MemoryAccessError as exc:
            return AllspansCandidate(
                candidate_id=candidate_id,
                pid=pid,
                address=address,
                declared_len=length,
                declared_cap=cap_,
                validation_errors=[f"Could not read span pointer array: {exc}"],
                rejected=True,
                rejection_reason="unreadable",
            )

        word_fmt = "<Q" if self._pointer_size == 8 else "<I"
        span_pointers: list[int] = []
        valid_count = 0
        for i in range(sample_size):
            span_ptr = struct.unpack_from(word_fmt, raw_ptrs, i * self._pointer_size)[0]
            if span_ptr == 0:
                continue
            info = self._try_read_mspan(span_ptr)
            if info is not None and not validate_mspan(info):
                valid_count += 1
                span_pointers.append(span_ptr)

        ratio = (valid_count / sample_size) if sample_size else 0.0
        if ratio < MIN_VALID_SAMPLE_RATIO:
            return AllspansCandidate(
                candidate_id=candidate_id,
                pid=pid,
                address=address,
                declared_len=length,
                declared_cap=cap_,
                sampled_count=sample_size,
                valid_sample_count=valid_count,
                validation_errors=[
                    f"Only {valid_count}/{sample_size} sampled span pointers were structurally plausible "
                    f"(need >= {MIN_VALID_SAMPLE_RATIO:.0%})"
                ],
                rejected=True,
                rejection_reason="insufficient_valid_span_sample",
            )

        confidence = Confidence.HIGH if ratio >= 0.9 else Confidence.MEDIUM
        return AllspansCandidate(
            candidate_id=candidate_id,
            pid=pid,
            address=address,
            declared_len=length,
            declared_cap=cap_,
            sampled_count=sample_size,
            valid_sample_count=valid_count,
            span_pointers=span_pointers,
            confidence=confidence,
            rejected=False,
        )

    def _try_read_mspan(self, address: int) -> MspanInfo | None:
        try:
            raw = self._reader.read(address, MSPAN_GO1_26.size(self._pointer_size))
        except MemoryAccessError:
            return None
        try:
            return _decode_mspan(address, raw, self._pointer_size)
        except struct.error:
            return None


def select_best_allspans_candidate(candidates: list[AllspansCandidate]) -> AllspansCandidate | None:
    """Prefer the highest-confidence, most-validated candidate; never "first found" blindly."""
    accepted = [c for c in candidates if not c.rejected]
    if not accepted:
        return None
    return max(accepted, key=lambda c: (c.confidence == Confidence.HIGH, c.valid_sample_count))


@dataclass
class HeapObjectCandidate:
    """One live (allocated) heap object slot, per the allocation bitmap."""

    address: int
    size: int
    span_address: int
    bit_index: int


class MspanWalker:
    """Walks a validated allspans candidate's spans and enumerates live heap objects."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size

    def enumerate_heap_objects(
        self, span_pointers: list[int], pid: int
    ) -> tuple[list[HeapObjectCandidate], list[AnalysisError]]:
        """Return live heap object addresses/sizes from every in-use span.

        One malformed span never aborts the walk of the rest (approved
        plan Section D); a recoverable AnalysisError is recorded per
        malformed span instead.
        """
        objects: list[HeapObjectCandidate] = []
        errors: list[AnalysisError] = []

        for span_address in span_pointers[:MAX_SPANS_PROCESSED]:
            if len(objects) >= MAX_HEAP_OBJECTS:
                break
            try:
                objects.extend(self._enumerate_span(span_address))
            except MemoryAccessError as exc:
                errors.append(
                    AnalysisError(
                        component="go_runtime.mspan.enumerate_heap_objects",
                        message=f"Span at 0x{span_address:x} became unreadable during traversal: {exc}",
                        pid=pid,
                        reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                    )
                )
            except Exception as exc:  # a single malformed span must not abort the whole walk
                errors.append(
                    AnalysisError(
                        component="go_runtime.mspan.enumerate_heap_objects",
                        message=f"Malformed span at 0x{span_address:x} skipped: {exc}",
                        pid=pid,
                        reason=FailureReason.INSUFFICIENT_EVIDENCE,
                    )
                )

        return objects[:MAX_HEAP_OBJECTS], errors

    def _enumerate_span(self, span_address: int) -> list[HeapObjectCandidate]:
        raw = self._reader.read(span_address, MSPAN_GO1_26.size(self._pointer_size))
        info = _decode_mspan(span_address, raw, self._pointer_size)

        errors = validate_mspan(info)
        if errors:
            return []
        if not info.is_in_use:
            return []
        if info.alloc_count == 0 or info.alloc_bits_ptr == 0:
            return []

        bitmap_bytes_needed = (info.nelems + 7) // 8
        bitmap = read_partial(self._reader, info.alloc_bits_ptr, bitmap_bytes_needed)
        if not bitmap:
            return []
        # A truncated bitmap (e.g. the span straddles an unreadable page)
        # still yields the bits that ARE available, rather than discarding
        # every object in the span because the tail was inaccessible.

        objects: list[HeapObjectCandidate] = []
        max_objects = min(info.nelems, MAX_OBJECTS_PER_SPAN)
        for bit_index in range(max_objects):
            byte_index = bit_index // 8
            bit_offset = bit_index % 8
            if byte_index >= len(bitmap):
                break
            allocated = bool(bitmap[byte_index] & (1 << bit_offset))
            if not allocated:
                continue
            object_addr = info.start_addr + bit_index * info.elemsize
            objects.append(
                HeapObjectCandidate(
                    address=object_addr, size=info.elemsize, span_address=span_address, bit_index=bit_index
                )
            )
            if len(objects) >= MAX_OBJECTS_PER_SPAN:
                break

        return objects
