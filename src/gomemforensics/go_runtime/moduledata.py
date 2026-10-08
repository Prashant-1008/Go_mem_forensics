"""moduledata discovery and validation.

Implements the paper's documented approach (Section 3.1.1): locate
moduledata by scanning writable segments for a pointer equal to the
already-recovered pcHeader address (the first field of moduledata is
literally ``*pcHeader`` in every verified layout - see
:mod:`gomemforensics.go_runtime.layouts`), then validate the candidate via
ordered region bounds (``data < edata`` etc.) and well-formed slice headers
(``len <= cap``). A single pointer match is never accepted as proof.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.layouts import (
    MODULEDATA_1_16_17,
    MODULEDATA_1_18_19,
    MODULEDATA_GO120_FAMILY_CANDIDATES,
    StructLayout,
)
from gomemforensics.go_runtime.models import ModuledataCandidate, ModuledataFields
from gomemforensics.go_runtime.scanning import iter_readable_chunks
from gomemforensics.go_runtime.version import GO_1_16_MAGIC, GO_1_18_MAGIC, GO_1_20_MAGIC

logger = get_logger("go_runtime.moduledata")

#: Which moduledata layout(s) are plausible for a given pcHeader magic.
#: The Go 1.20+ magic maps to *multiple* candidate layouts because the
#: moduledata shape changed within that single magic family (see
#: layouts.MODULEDATA_GO120_FAMILY_CANDIDATES) - each is tried in turn and
#: the first to pass full structural validation is accepted.
_LAYOUT_CANDIDATES_BY_MAGIC: dict[int, tuple[StructLayout, ...]] = {
    GO_1_16_MAGIC: (MODULEDATA_1_16_17,),
    GO_1_18_MAGIC: (MODULEDATA_1_18_19,),
    GO_1_20_MAGIC: MODULEDATA_GO120_FAMILY_CANDIDATES,
}

#: Safety limits (not Go runtime invariants) - see pclntab.py's identical
#: rationale. moduledata is linker-emitted once per module, so in practice
#: at most a handful of true positives ever exist; these bounds only guard
#: against pathological/adversarial memory content.
MAX_SCAN_BYTES_PER_REGION = 64 * 1024 * 1024
MAX_POINTER_MATCHES_PER_REGION = 64
MAX_CANDIDATES_PER_PROCESS = 64
_SCAN_CHUNK_SIZE = 1024 * 1024

#: Plausibility bound for a region's byte span (text/data/bss/types), not a
#: Go runtime invariant - real modules are far smaller than this; it exists
#: only to reject candidates whose "end" pointer is obvious garbage.
_MAX_PLAUSIBLE_REGION_SPAN = 4 * 1024 * 1024 * 1024  # 4 GiB


def _select_moduledata_regions(regions: list[MemoryRegion]) -> list[MemoryRegion]:
    """Regions plausible for moduledata: writable (it is runtime-initialized,
    linker-emitted non-pointer *writable* static data per the paper)."""
    return [r for r in regions if r.readable and r.writable]


@dataclass(frozen=True)
class _RawModuledata:
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
    gofunc: int | None
    typelinks_ptr: int
    typelinks_len: int
    typelinks_cap: int
    itablinks_ptr: int
    itablinks_len: int
    itablinks_cap: int
    # Phase 4 additions - function table resolution (paper Section 3.3.1).
    funcnametab_ptr: int
    cutab_ptr: int
    filetab_ptr: int
    pctab_ptr: int
    pclntable_ptr: int
    ftab_ptr: int
    ftab_len: int
    ftab_cap: int


def _decode_moduledata(raw: bytes, layout: StructLayout, pointer_size: int) -> _RawModuledata:
    offsets = layout.offsets(pointer_size)
    uword_fmt = "<Q" if pointer_size == 8 else "<I"

    def uword(name: str) -> int:
        return struct.unpack_from(uword_fmt, raw, offsets[name])[0]

    def slice_header(name: str) -> tuple[int, int, int]:
        base = offsets[name]
        ptr = struct.unpack_from(uword_fmt, raw, base)[0]
        length = struct.unpack_from(uword_fmt, raw, base + pointer_size)[0]
        cap = struct.unpack_from(uword_fmt, raw, base + 2 * pointer_size)[0]
        return ptr, length, cap

    typelinks_ptr, typelinks_len, typelinks_cap = slice_header("typelinks")
    itablinks_ptr, itablinks_len, itablinks_cap = slice_header("itablinks")
    ftab_ptr, ftab_len, ftab_cap = slice_header("ftab")
    funcnametab_ptr, _, _ = slice_header("funcnametab")
    cutab_ptr, _, _ = slice_header("cutab")
    filetab_ptr, _, _ = slice_header("filetab")
    pctab_ptr, _, _ = slice_header("pctab")
    pclntable_ptr, _, _ = slice_header("pclntable")

    return _RawModuledata(
        pc_header_pointer=uword("pcHeader"),
        text=uword("text"),
        etext=uword("etext"),
        data=uword("data"),
        edata=uword("edata"),
        bss=uword("bss"),
        ebss=uword("ebss"),
        types=uword("types"),
        etypes=uword("etypes"),
        rodata=uword("rodata") if "rodata" in offsets else None,
        gofunc=uword("gofunc") if "gofunc" in offsets else None,
        typelinks_ptr=typelinks_ptr,
        typelinks_len=typelinks_len,
        typelinks_cap=typelinks_cap,
        itablinks_ptr=itablinks_ptr,
        itablinks_len=itablinks_len,
        itablinks_cap=itablinks_cap,
        funcnametab_ptr=funcnametab_ptr,
        cutab_ptr=cutab_ptr,
        filetab_ptr=filetab_ptr,
        pctab_ptr=pctab_ptr,
        pclntable_ptr=pclntable_ptr,
        ftab_ptr=ftab_ptr,
        ftab_len=ftab_len,
        ftab_cap=ftab_cap,
    )


class ModuledataValidator:
    """Structural validation for a decoded moduledata candidate."""

    def validate(self, raw: _RawModuledata, anchor_pc_header_address: int) -> list[str]:
        errors: list[str] = []

        if raw.pc_header_pointer != anchor_pc_header_address:
            errors.append(
                f"pcHeader pointer 0x{raw.pc_header_pointer:x} does not match the "
                f"anchor address 0x{anchor_pc_header_address:x}"
            )

        errors.extend(self._check_ordered_range("text", raw.text, "etext", raw.etext))
        errors.extend(self._check_ordered_range("data", raw.data, "edata", raw.edata))
        errors.extend(self._check_ordered_range("bss", raw.bss, "ebss", raw.ebss))
        errors.extend(self._check_ordered_range("types", raw.types, "etypes", raw.etypes))

        if raw.typelinks_len > raw.typelinks_cap:
            errors.append(f"typelinks len ({raw.typelinks_len}) > cap ({raw.typelinks_cap})")
        if raw.itablinks_len > raw.itablinks_cap:
            errors.append(f"itablinks len ({raw.itablinks_len}) > cap ({raw.itablinks_cap})")

        if raw.text == 0:
            errors.append("text pointer is null")
        if raw.data == 0:
            errors.append("data pointer is null")

        return errors

    @staticmethod
    def _check_ordered_range(start_name: str, start: int, end_name: str, end: int) -> list[str]:
        if end < start:
            return [f"{start_name} (0x{start:x}) > {end_name} (0x{end:x}); expected {start_name} <= {end_name}"]
        if end - start > _MAX_PLAUSIBLE_REGION_SPAN:
            return [
                f"{end_name} - {start_name} = {end - start} bytes exceeds the plausibility bound "
                f"({_MAX_PLAUSIBLE_REGION_SPAN} bytes) - likely a false-positive candidate"
            ]
        return []


class ModuledataParser:
    """Anchors on a recovered pcHeader address to find and validate moduledata."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size
        self._validator = ModuledataValidator()

    def find_candidates(
        self,
        regions: list[MemoryRegion],
        pid: int,
        pc_header_address: int,
        pc_header_magic: int,
    ) -> list[ModuledataCandidate]:
        layouts = _LAYOUT_CANDIDATES_BY_MAGIC.get(pc_header_magic)
        if not layouts:
            logger.debug(
                "pid=%s: no moduledata layout known for pcHeader magic 0x%x", pid, pc_header_magic
            )
            return []

        candidates: list[ModuledataCandidate] = []
        needle = pc_header_address.to_bytes(self._pointer_size, byteorder="little")

        for region in _select_moduledata_regions(regions):
            if len(candidates) >= MAX_CANDIDATES_PER_PROCESS:
                break
            for match_address in self._scan_region_for_pointer(region, needle):
                if len(candidates) >= MAX_CANDIDATES_PER_PROCESS:
                    break
                candidates.append(
                    self._build_candidate(
                        match_address, pid, pc_header_address, layouts, len(candidates)
                    )
                )

        return candidates

    def _scan_region_for_pointer(self, region: MemoryRegion, needle: bytes):
        scan_end = min(region.end, region.start + MAX_SCAN_BYTES_PER_REGION)
        overlap = self._pointer_size - 1
        matches = 0

        for offset, chunk in iter_readable_chunks(self._reader, region.start, scan_end, _SCAN_CHUNK_SIZE, overlap):
            if matches >= MAX_POINTER_MATCHES_PER_REGION:
                break
            search_from = 0
            while True:
                idx = chunk.find(needle, search_from)
                if idx == -1:
                    break
                # moduledata's pcHeader field is pointer-aligned in every
                # verified layout; reject misaligned coincidental matches.
                candidate_address = offset + idx
                if candidate_address % self._pointer_size == 0:
                    yield candidate_address
                    matches += 1
                    if matches >= MAX_POINTER_MATCHES_PER_REGION:
                        break
                search_from = idx + 1

    def _build_candidate(
        self,
        address: int,
        pid: int,
        pc_header_address: int,
        layouts: tuple[StructLayout, ...],
        index: int,
    ) -> ModuledataCandidate:
        candidate_id = f"MODULEDATA-{pid}-{index:04d}"
        last_errors: list[str] = []
        last_layout_id: str | None = None

        for layout in layouts:
            size = layout.size(self._pointer_size)
            try:
                raw_bytes = self._reader.read(address, size)
            except MemoryAccessError as exc:
                last_errors = [f"Could not read candidate moduledata ({layout.layout_id}): {exc}"]
                last_layout_id = layout.layout_id
                continue

            raw = _decode_moduledata(raw_bytes, layout, self._pointer_size)
            errors = self._validator.validate(raw, pc_header_address)
            last_errors, last_layout_id = errors, layout.layout_id

            if not errors:
                fields = ModuledataFields(
                    pc_header_pointer=raw.pc_header_pointer,
                    text=raw.text,
                    etext=raw.etext,
                    data=raw.data,
                    edata=raw.edata,
                    bss=raw.bss,
                    ebss=raw.ebss,
                    types=raw.types,
                    etypes=raw.etypes,
                    rodata=raw.rodata,
                    typelinks_ptr=raw.typelinks_ptr,
                    typelinks_len=raw.typelinks_len,
                    itablinks_ptr=raw.itablinks_ptr,
                    itablinks_len=raw.itablinks_len,
                    gofunc=raw.gofunc,
                    funcnametab_ptr=raw.funcnametab_ptr,
                    cutab_ptr=raw.cutab_ptr,
                    filetab_ptr=raw.filetab_ptr,
                    pctab_ptr=raw.pctab_ptr,
                    pclntable_ptr=raw.pclntable_ptr,
                    ftab_ptr=raw.ftab_ptr,
                    ftab_len=raw.ftab_len,
                )
                return ModuledataCandidate(
                    candidate_id=candidate_id,
                    pid=pid,
                    address=address,
                    anchor_pc_header_address=pc_header_address,
                    layout_id=layout.layout_id,
                    fields=fields,
                    validation_errors=[],
                    confidence=Confidence.HIGH,
                    rejected=False,
                    rejection_reason=None,
                )

        return ModuledataCandidate(
            candidate_id=candidate_id,
            pid=pid,
            address=address,
            anchor_pc_header_address=pc_header_address,
            layout_id=last_layout_id,
            fields=None,
            validation_errors=last_errors,
            confidence=Confidence.UNKNOWN,
            rejected=True,
            rejection_reason="moduledata invariant violation (tried every known layout for this magic family)",
        )
