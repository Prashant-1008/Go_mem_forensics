"""Validates PclntabParser against real Go 1.26.2 compiler output.

This reads the actual compiled benign fixture binary's file bytes directly
(tests/fixtures/go/bin/, built by scripts/fixtures/build_fixture.ps1) and
treats them as a flat address space - it does NOT involve Volatility or a
captured memory image. This is real, non-fabricated validation of the
byte-level pcHeader parsing/validation logic against genuine compiler
output, but it is explicitly NOT a substitute for full memory-image
validation (see docs/validation/validation-plan.md, which tracks that
separately and honestly as still pending).

Ground truth was independently established (once, manually, outside this
test) by scanning the compiled binary for the Go 1.20+ magic
(0xfffffff1) alone: it occurs 7 times, of which exactly 1 satisfies every
pcHeader invariant - a concrete, real demonstration of why a bare
magic-byte match is never accepted as proof. This test scans for all
three supported magic families at once (as the real parser always does),
which naturally surfaces additional coincidental matches from the other
two magic values scattered through the binary's data/debug sections; the
invariant that actually matters - exactly one validated candidate overall,
with the expected recovered field values - is asserted below.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.go_runtime.models import PclntabDetectionStatus
from gomemforensics.go_runtime.pclntab import PclntabParser

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"


class _FileBackedReader(MemoryReader):
    """Treats a file's raw bytes as a flat address space starting at 0.

    Test-only: real analysis always goes through a Volatility-backed
    MemoryReader over actual process virtual memory. File offsets are not
    equivalent to runtime virtual addresses in a PE - this reader exists
    solely to validate pcHeader parsing/validation against real compiled
    bytes, not to model address translation.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def pointer_size(self) -> int:
        return 8

    def is_valid(self, address: int) -> bool:
        return 0 <= address < len(self._data)

    def read(self, address: int, length: int) -> bytes:
        if address < 0 or address + length > len(self._data):
            raise MemoryAccessError(f"out of bounds: [{address}, {address + length}) vs len={len(self._data)}")
        return self._data[address : address + length]


@pytest.mark.skipif(
    not _WINDOWS_FIXTURE.exists(),
    reason="Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.",
)
def test_pclntab_parser_finds_exactly_one_valid_candidate_in_real_binary():
    data = _WINDOWS_FIXTURE.read_bytes()
    reader = _FileBackedReader(data)
    region = MemoryRegion(start=0, end=len(data), readable=True, writable=False, executable=True)

    candidates = PclntabParser(reader, pointer_size=8).scan_regions([region], pid=1)

    magic_candidates = [c for c in candidates if c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED]
    # At least the 7 known Go120-magic occurrences, plus whatever
    # incidental matches the other two supported magic values produce
    # elsewhere in the binary's data/debug sections.
    assert len(magic_candidates) >= 7

    accepted = [c for c in magic_candidates if not c.rejected]
    assert len(accepted) == 1, "exactly one magic match across all families should satisfy every pcHeader invariant"

    valid = accepted[0]
    assert valid.header_fields is not None
    assert valid.header_fields.nfunc == 2192
    assert valid.header_fields.nfiles == 252
    assert valid.header_fields.min_lc == 1
    assert valid.header_fields.ptr_size == 8

    rejected = [c for c in magic_candidates if c.rejected]
    assert all(c.validation_errors for c in rejected)
