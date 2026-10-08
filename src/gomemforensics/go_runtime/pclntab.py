"""pclntab / pcHeader discovery and validation.

Implements the paper's documented approach (Section 3.1.1):

1. Scan read-only/executable regions for the version-specific magic bytes.
2. For every magic match, validate pcHeader invariants (zeroed padding,
   ``minLC in {1,2,4}``, ``ptrSize in {4,8}``, plausible ``nfunc``/``nfiles``).
3. Reject candidates that fail validation; never treat a bare magic match
   as proof.
4. When no magic-validated candidate exists, fall back to structural
   scanning (same invariants, without requiring a recognized magic value).

A single false-positive magic match against real compiler output is not
hypothetical here: scanning the actual compiled fixture binary
(tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe) for the
4-byte sequence matching the Go 1.20+ magic finds it 7 times; only 1 of
those 7 satisfies the pcHeader invariants below (see
tests/integration/test_go_runtime_real_fixture.py). This is the concrete,
non-hypothetical justification for never skipping validation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.layouts import (
    PCHEADER_1_18_PLUS,
    PCHEADER_PRE_1_18,
    StructLayout,
)
from gomemforensics.go_runtime.models import PcHeaderFields, PclntabCandidate, PclntabDetectionStatus
from gomemforensics.go_runtime.scanning import iter_readable_chunks
from gomemforensics.go_runtime.version import GO_1_16_MAGIC, GO_1_18_MAGIC, GO_1_20_MAGIC, magic_bytes_le

logger = get_logger("go_runtime.pclntab")

#: Magic values with a known modern (post-1.16) pcHeader shape. The
#: pre-1.16 magic (Go 1.2-1.15, 0xfffffffb) is intentionally excluded: that
#: era predates the pcHeader/offset-table redesign entirely and uses a
#: structurally different format this parser does not implement (see
#: docs/architecture/go-runtime.md "Known limitations").
_SUPPORTED_MAGICS: dict[int, StructLayout] = {
    GO_1_16_MAGIC: PCHEADER_PRE_1_18,
    GO_1_18_MAGIC: PCHEADER_1_18_PLUS,
    GO_1_20_MAGIC: PCHEADER_1_18_PLUS,
}

#: Safety limit, not a Go runtime invariant: caps how many bytes of a single
#: region are scanned for magic bytes, so a pathologically large mapped
#: region (some Windows/Linux processes have multi-GB reservations) cannot
#: turn a single-process scan into an unbounded, multi-gigabyte read. Real
#: pclntab data lives near the start of the module's read-only/text
#: mapping, well within this bound in every case observed.
MAX_SCAN_BYTES_PER_REGION = 64 * 1024 * 1024

#: Safety limit: caps how many magic-byte matches are investigated per
#: region, independent of how many bytes were scanned, to bound worst-case
#: work against a region containing pathological/repeating data.
MAX_MAGIC_MATCHES_PER_REGION = 64

#: Safety limit: caps how many validated + rejected candidates are kept in
#: total for one process, so a process with many false-positive matches
#: cannot cause unbounded memory growth in the result set.
MAX_CANDIDATES_PER_PROCESS = 128

#: Read chunk size used while scanning a region for magic bytes - keeps any
#: single MemoryReader.read() call bounded rather than reading a whole
#: (potentially huge) region into RAM at once.
_SCAN_CHUNK_SIZE = 1024 * 1024
_OVERLAP = 3  # magic is 4 bytes; overlap by 3 so a match spanning a chunk boundary is not missed

#: Plausibility bounds for pcHeader.nfunc/nfiles. Not a Go runtime
#: invariant (the real runtime has no such cap) - a safety/plausibility
#: bound to reject obviously-wrong candidates (e.g. interpreting random
#: data as a huge function count) without claiming it defeats obfuscation.
_MAX_PLAUSIBLE_COUNT = 5_000_000


@dataclass(frozen=True)
class _RawPcHeader:
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


def _decode_pc_header(raw: bytes, layout: StructLayout, pointer_size: int) -> _RawPcHeader:
    offsets = layout.offsets(pointer_size)
    word_fmt = "<q" if pointer_size == 8 else "<i"
    uword_fmt = "<Q" if pointer_size == 8 else "<I"

    def word(name: str) -> int:
        off = offsets[name]
        return struct.unpack_from(word_fmt, raw, off)[0]

    def uword(name: str) -> int:
        off = offsets[name]
        return struct.unpack_from(uword_fmt, raw, off)[0]

    magic = struct.unpack_from("<I", raw, offsets["magic"])[0]
    return _RawPcHeader(
        magic=magic,
        pad1=raw[offsets["pad1"]],
        pad2=raw[offsets["pad2"]],
        min_lc=raw[offsets["minLC"]],
        ptr_size=raw[offsets["ptrSize"]],
        nfunc=word("nfunc"),
        nfiles=uword("nfiles"),
        funcname_offset=uword("funcnameOffset"),
        cu_offset=uword("cuOffset"),
        filetab_offset=uword("filetabOffset"),
        pctab_offset=uword("pctabOffset"),
        pcln_offset=uword("pclnOffset"),
    )


def validate_pc_header(raw: _RawPcHeader, expected_pointer_size: int | None) -> list[str]:
    """Check pcHeader invariants per the paper (Section 3.1.1). Returns error strings; empty = valid."""
    errors: list[str] = []
    if raw.pad1 != 0:
        errors.append(f"pad1 must be 0, got {raw.pad1}")
    if raw.pad2 != 0:
        errors.append(f"pad2 must be 0, got {raw.pad2}")
    if raw.min_lc not in (1, 2, 4):
        errors.append(f"minLC must be in {{1,2,4}}, got {raw.min_lc}")
    if raw.ptr_size not in (4, 8):
        errors.append(f"ptrSize must be in {{4,8}}, got {raw.ptr_size}")
    elif expected_pointer_size is not None and raw.ptr_size != expected_pointer_size:
        errors.append(
            f"ptrSize {raw.ptr_size} does not match the process architecture's "
            f"pointer size {expected_pointer_size}"
        )
    if not (0 <= raw.nfunc < _MAX_PLAUSIBLE_COUNT):
        errors.append(f"nfunc out of plausible range [0, {_MAX_PLAUSIBLE_COUNT}): {raw.nfunc}")
    if not (0 <= raw.nfiles < _MAX_PLAUSIBLE_COUNT):
        errors.append(f"nfiles out of plausible range [0, {_MAX_PLAUSIBLE_COUNT}): {raw.nfiles}")
    return errors


def _select_pclntab_regions(regions: list[MemoryRegion]) -> list[MemoryRegion]:
    """Regions plausible for pclntab: readable, and read-only or executable.

    Per the paper (Section 3.1.1), pclntab lives in read-only segments.
    Executable regions are included too since the OS/linker can present the
    module's read-only data as R-X rather than strictly R--; regions that
    are writable and not executable (typical heap/stack/writable-data) are
    excluded, since pclntab is never linker-emitted there.
    """
    return [r for r in regions if r.readable and (not r.writable or r.executable)]


class PclntabParser:
    """Scans process memory regions for pclntab/pcHeader candidates."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size
        self._pc_header_size = max(layout.size(pointer_size) for layout in _SUPPORTED_MAGICS.values())

    def scan_regions(self, regions: list[MemoryRegion], pid: int) -> list[PclntabCandidate]:
        """Magic-byte scan across the given regions, then a structural fallback if nothing validated.

        Per the approved plan (Section 4): "Use memory-region boundaries
        where available" - only regions plausible for pclntab (readable,
        not required to be writable; pclntab lives in read-only/executable
        mapped data) are scanned, never the full virtual address space.
        """
        candidates: list[PclntabCandidate] = []
        scan_regions = _select_pclntab_regions(regions)

        for region in scan_regions:
            if len(candidates) >= MAX_CANDIDATES_PER_PROCESS:
                break
            candidates.extend(self._scan_region_for_magic(region, pid, len(candidates)))

        if not any(c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED and not c.rejected for c in candidates):
            logger.debug("pid=%s: no validated magic-byte pclntab candidate; attempting structural fallback", pid)
            for region in scan_regions:
                if len(candidates) >= MAX_CANDIDATES_PER_PROCESS:
                    break
                candidates.extend(self._scan_region_structurally(region, pid, len(candidates)))

        return candidates

    def _scan_region_for_magic(self, region: MemoryRegion, pid: int, existing_count: int) -> list[PclntabCandidate]:
        found: list[PclntabCandidate] = []
        scan_end = min(region.end, region.start + MAX_SCAN_BYTES_PER_REGION)
        magic_needles = {magic_bytes_le(m): m for m in _SUPPORTED_MAGICS}

        matches_in_region = 0
        for offset, chunk in iter_readable_chunks(self._reader, region.start, scan_end, _SCAN_CHUNK_SIZE, _OVERLAP):
            if matches_in_region >= MAX_MAGIC_MATCHES_PER_REGION:
                break
            for needle, magic in magic_needles.items():
                search_from = 0
                while True:
                    idx = chunk.find(needle, search_from)
                    if idx == -1:
                        break
                    candidate_address = offset + idx
                    candidate = self._build_candidate(
                        candidate_address,
                        magic,
                        pid,
                        region,
                        existing_count + len(found),
                    )
                    found.append(candidate)
                    matches_in_region += 1
                    search_from = idx + 1
                    if matches_in_region >= MAX_MAGIC_MATCHES_PER_REGION or existing_count + len(found) >= MAX_CANDIDATES_PER_PROCESS:
                        break
                if matches_in_region >= MAX_MAGIC_MATCHES_PER_REGION or existing_count + len(found) >= MAX_CANDIDATES_PER_PROCESS:
                    break

        return found

    def _build_candidate(
        self, address: int, magic: int, pid: int, region: MemoryRegion, index: int
    ) -> PclntabCandidate:
        layout = _SUPPORTED_MAGICS[magic]
        candidate_id = f"PCLNTAB-{pid}-{index:04d}"
        try:
            raw_bytes = self._reader.read(address, layout.size(self._pointer_size))
        except MemoryAccessError as exc:
            return PclntabCandidate(
                candidate_id=candidate_id,
                pid=pid,
                address=address,
                detection_status=PclntabDetectionStatus.MAGIC_DETECTED,
                magic=magic,
                layout_id=layout.layout_id,
                header_fields=None,
                validation_errors=[f"Could not read candidate pcHeader: {exc}"],
                confidence=Confidence.UNKNOWN,
                rejected=True,
                rejection_reason="unreadable",
                region_source=region.source,
            )

        raw = _decode_pc_header(raw_bytes, layout, self._pointer_size)
        errors = validate_pc_header(raw, self._pointer_size)

        if errors:
            return PclntabCandidate(
                candidate_id=candidate_id,
                pid=pid,
                address=address,
                detection_status=PclntabDetectionStatus.MAGIC_DETECTED,
                magic=magic,
                layout_id=layout.layout_id,
                header_fields=None,
                validation_errors=errors,
                confidence=Confidence.UNKNOWN,
                rejected=True,
                rejection_reason="pcHeader invariant violation",
                region_source=region.source,
            )

        header_fields = PcHeaderFields(
            magic=raw.magic,
            pad1=raw.pad1,
            pad2=raw.pad2,
            min_lc=raw.min_lc,
            ptr_size=raw.ptr_size,
            nfunc=raw.nfunc,
            nfiles=raw.nfiles,
            funcname_offset=raw.funcname_offset,
            cu_offset=raw.cu_offset,
            filetab_offset=raw.filetab_offset,
            pctab_offset=raw.pctab_offset,
            pcln_offset=raw.pcln_offset,
        )
        return PclntabCandidate(
            candidate_id=candidate_id,
            pid=pid,
            address=address,
            detection_status=PclntabDetectionStatus.MAGIC_DETECTED,
            magic=magic,
            layout_id=layout.layout_id,
            header_fields=header_fields,
            validation_errors=[],
            confidence=Confidence.HIGH,
            rejected=False,
            rejection_reason=None,
            region_source=region.source,
        )

    def _scan_region_structurally(self, region: MemoryRegion, pid: int, existing_count: int) -> list[PclntabCandidate]:
        """Aligned-address structural sweep, used only when magic-byte detection found nothing.

        Per the approved plan (Section 6), this must use pcHeader
        invariants, not printable-string heuristics, and must never claim
        to defeat all obfuscation. Every candidate here is reported with
        MAGIC_NOT_DETECTED_STRUCTURAL_CANDIDATE and at most LOW confidence.
        """
        found: list[PclntabCandidate] = []
        scan_end = min(region.end, region.start + MAX_SCAN_BYTES_PER_REGION)
        # Any of the modern layouts' sizes works as a probe shape; try the
        # 1.18+ shape first (covers the widest, most current version range).
        layout = PCHEADER_1_18_PLUS
        header_size = layout.size(self._pointer_size)
        alignment = self._pointer_size

        address = region.start - (region.start % alignment)
        if address < region.start:
            address += alignment

        matches_in_region = 0
        while address + header_size <= scan_end and matches_in_region < MAX_MAGIC_MATCHES_PER_REGION:
            try:
                raw_bytes = self._reader.read(address, header_size)
            except MemoryAccessError:
                address += alignment
                continue

            raw = _decode_pc_header(raw_bytes, layout, self._pointer_size)
            # A structural candidate must additionally NOT match a known
            # magic (otherwise the magic-byte scan above would already have
            # found and validated/rejected it) - this path is specifically
            # for corrupted/obfuscated magics.
            if raw.magic not in _SUPPORTED_MAGICS:
                errors = validate_pc_header(raw, self._pointer_size)
                if not errors:
                    candidate_id = f"PCLNTAB-{pid}-{existing_count + len(found):04d}"
                    header_fields = PcHeaderFields(
                        magic=raw.magic,
                        pad1=raw.pad1,
                        pad2=raw.pad2,
                        min_lc=raw.min_lc,
                        ptr_size=raw.ptr_size,
                        nfunc=raw.nfunc,
                        nfiles=raw.nfiles,
                        funcname_offset=raw.funcname_offset,
                        cu_offset=raw.cu_offset,
                        filetab_offset=raw.filetab_offset,
                        pctab_offset=raw.pctab_offset,
                        pcln_offset=raw.pcln_offset,
                    )
                    found.append(
                        PclntabCandidate(
                            candidate_id=candidate_id,
                            pid=pid,
                            address=address,
                            detection_status=PclntabDetectionStatus.MAGIC_NOT_DETECTED_STRUCTURAL_CANDIDATE,
                            magic=raw.magic,
                            layout_id=layout.layout_id,
                            header_fields=header_fields,
                            validation_errors=[],
                            confidence=Confidence.LOW,
                            rejected=False,
                            rejection_reason=None,
                            region_source=region.source,
                        )
                    )
                    matches_in_region += 1
            address += alignment

        return found
