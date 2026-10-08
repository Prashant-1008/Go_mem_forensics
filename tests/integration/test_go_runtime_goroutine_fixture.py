"""Validates Phase 5's *static* prerequisites against real Go 1.26.2 compiler
output: pcsp decoding, and the mechanics of pcsp-based stack unwinding
given real function/pctab metadata.

CRITICAL SCOPE NOTE, stronger than Phase 4's equivalent caveat: a compiled
Go executable file has **no runtime goroutine state at all**.
``runtime.allgs`` does not exist as populated data in a static binary -
it is a `var allgs []*g` slice that the runtime only populates *after* a
process starts and creates goroutines. There is therefore no way to
validate allgs discovery, g structural validation, or a *live* stack
unwind against this (or any other) compiled binary - only against a real
captured memory image, which remains genuinely UNVALIDATED (see
docs/validation/validation-plan.md).

What this module *can* and does validate for real, against real compiled
bytes: that `_func.pcsp` decodes to real, sane frame-size values for real
functions via the exact same decoder
(`gomemforensics.go_runtime.pctab.read_pc_value_from_reader`) production
code uses, and that `stack_unwind.unwind_goroutine`, given a real
function's real entry PC/pcsp stream and a synthetic (non-runtime) stack
buffer under this test's own control, walks frames using genuine pcsp
data rather than only ever having been run against hand-crafted synthetic
streams (tests/unit/test_stack_unwind.py). This is real static-metadata
validation - it is not, and must never be represented as, goroutine
runtime-state validation.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from gomemforensics.common.memory import MemoryAccessError, MemoryReader
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.functab import FunctionIndex, FunctionTableParser
from gomemforensics.go_runtime.layouts import FUNC_FLAG_TOP_FRAME
from gomemforensics.go_runtime.pctab import read_pc_value_from_reader
from gomemforensics.go_runtime.stack_unwind import unwind_goroutine

from tests.integration.test_go_runtime_function_fixture import _build_regions, _PEMappedReader

pefile = pytest.importorskip("pefile", reason="pefile not available - PE-mapped goroutine-fixture test skipped")

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"


class _WritableOverlayReader(MemoryReader):
    """Wraps a real (read-only) PE-mapped reader and adds a small
    synthetic, writable overlay region - used here to plant a fabricated
    "stack" (return-address slots) at addresses that don't collide with
    the real image, so the unwinder's return-address reads land in
    controlled, test-owned memory rather than real (and therefore
    unpredictable) stack/heap content that doesn't exist in a static file
    anyway. This does NOT simulate a real stack in any runtime sense - it
    is scaffolding to exercise the unwind mechanics against a real
    function's real pcsp-decoded frame size.
    """

    def __init__(self, base: MemoryReader, overlay: dict[int, bytes]) -> None:
        self._base = base
        self._overlay = overlay

    @property
    def pointer_size(self) -> int:
        return self._base.pointer_size

    def is_valid(self, address: int) -> bool:
        for start, data in self._overlay.items():
            if start <= address < start + len(data):
                return True
        return self._base.is_valid(address)

    def read(self, address: int, length: int) -> bytes:
        for start, data in self._overlay.items():
            if start <= address and address + length <= start + len(data):
                return data[address - start : address - start + length]
        return self._base.read(address, length)


@pytest.fixture(scope="module")
def _real_functions():
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")

    pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
    reader = _PEMappedReader(pe)
    regions = _build_regions(pe)
    result = GoProcessDetector().detect(pid=1, architecture="x86_64", pointer_size=8, reader=reader, regions=regions)
    assert result.runtime is not None
    functions, errors = FunctionTableParser(reader, pointer_size=8).parse(result.runtime)
    return reader, result.runtime, functions


def test_pcsp_decodes_to_a_plausible_frame_size_for_a_real_function(_real_functions):
    reader, runtime, functions = _real_functions
    by_name = {f.name: f for f in functions if f.name}
    fn = by_name["main.fixtureGoroutineCPUWork"]
    assert fn.pcsp_offset is not None

    frame_size = read_pc_value_from_reader(
        reader, runtime.pctab_address, fn.pcsp_offset, fn.entry_address, fn.entry_address
    )
    # A real function's frame size at entry is 0 (before the prologue's
    # `sub rsp, N`) per the verified pcsp semantics - not asserting a
    # specific nonzero value (which would be a guess), only that the
    # decode succeeds and produces a plausible, pointer-aligned result.
    assert frame_size is not None
    assert frame_size >= 0
    assert frame_size % 8 == 0


def test_pcsp_frame_size_is_stable_and_pointer_aligned_across_many_real_functions(_real_functions):
    reader, runtime, functions = _real_functions
    checked = 0
    for fn in functions:
        if fn.pcsp_offset is None or fn.name is None:
            continue
        frame_size = read_pc_value_from_reader(
            reader, runtime.pctab_address, fn.pcsp_offset, fn.entry_address, fn.entry_address
        )
        if frame_size is None:
            continue
        assert frame_size >= 0, fn.name
        assert frame_size % 8 == 0, fn.name
        checked += 1
        if checked >= 200:
            break
    assert checked > 50  # confirms this actually exercised real data, not zero functions


def test_unwind_mechanics_against_a_real_functions_real_pcsp_stream(_real_functions):
    """Exercises unwind_goroutine's frame-delta arithmetic using a REAL
    function's REAL entry PC and REAL pcsp-decoded frame size, with a
    synthetic (test-controlled) return-address slot - this validates the
    *mechanics* against real static metadata, never a live goroutine
    stack (which cannot exist in this file at all - see module docstring).
    """
    reader, runtime, functions = _real_functions
    by_name = {f.name: f for f in functions if f.name}
    callee = by_name["main.fixtureGoroutineCPUWork"]
    assert callee.pcsp_offset is not None

    # A real, plausible mid-function PC (entry + a small offset) - the
    # frame size decoded there is real pcsp data, not fabricated.
    target_pc = callee.entry_address + 4
    frame_size = read_pc_value_from_reader(
        reader, runtime.pctab_address, callee.pcsp_offset, callee.entry_address, target_pc
    )
    assert frame_size is not None and frame_size % 8 == 0

    # A synthetic caller with FuncFlagTopFrame so the walk completes in
    # exactly 2 frames - the caller itself is fabricated (there is no
    # real "caller frame" to point at without a live call stack), but the
    # callee's own pcsp-derived spdelta is real.
    fake_caller_entry = 0x9000000000
    synthetic_stack_base = 0x9100000000
    return_addr_slot = synthetic_stack_base + frame_size
    overlay = {return_addr_slot: fake_caller_entry.to_bytes(8, "little")}
    overlay_reader = _WritableOverlayReader(reader, overlay)

    from gomemforensics.go_runtime.models import FunctionArtifact, FunctionClassification
    from gomemforensics.common.models import Confidence

    fake_caller = FunctionArtifact(
        id="FUNC-1-fake", pid=1, address=fake_caller_entry, entry_address=fake_caller_entry,
        name="test.fakeCaller", package="test", source_file=None, source_line=None, function_size=None,
        classification=FunctionClassification.APPLICATION, confidence=Confidence.HIGH,
        extraction_method="test", go_version=runtime.go_version, architecture="x86_64",
        func_id=0, func_flag=FUNC_FLAG_TOP_FRAME, pcsp_offset=None,
    )
    index = FunctionIndex([*functions, fake_caller])

    frames, status = unwind_goroutine(
        overlay_reader, 8, runtime.pctab_address, index,
        initial_pc=target_pc, initial_sp=synthetic_stack_base,
        stack_lo=synthetic_stack_base - 0x1000, stack_hi=synthetic_stack_base + 0x10000,
    )
    assert status.value == "complete"
    assert len(frames) == 2
    assert frames[0].function_name == "main.fixtureGoroutineCPUWork"
    assert frames[0].pc == target_pc
    assert frames[1].function_name == "test.fakeCaller"
    assert frames[1].sp == return_addr_slot + 8
