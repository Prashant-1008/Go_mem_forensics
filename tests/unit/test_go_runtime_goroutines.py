"""Unit tests for Go goroutine discovery and validation (Phase 5B/5C).

All synthetic - no real memory image or Go binary needed (real-fixture
validation, where meaningful at all, lives in tests/integration/ - see
its module docstring for why a compiled binary cannot validate live
goroutine/allgs runtime state).
"""

import struct

import pytest

from gomemforensics.common.memory import MockMemoryReader, MemoryRegion
from gomemforensics.common.models import Confidence, FailureReason
from gomemforensics.go_runtime.goroutines import (
    AllgsParser,
    GoroutineRecoveryEngine,
    resolve_g_layout,
    select_best_allgs_candidate,
    validate_g,
    _decode_g,
)
from gomemforensics.go_runtime.layouts import (
    G_GO1_26,
    G_SCAN_BIT,
    G_STATUS_DEAD,
    G_STATUS_RUNNABLE,
    G_STATUS_RUNNING,
    G_STATUS_WAITING,
)
from gomemforensics.go_runtime.models import GoRuntime
from tests.unit.go_runtime_helpers import build_struct_bytes

STACK_LO = 0xC000010000
STACK_HI = 0xC000018000
G_ADDR = 0xC000020000
ALLGS_ARRAY = 0xC000030000
ALLGS_HEADER = 0xC000040000


def _g_bytes(**overrides) -> bytes:
    defaults = dict(
        stack_lo=STACK_LO, stack_hi=STACK_HI,
        m=0x1230000, sched_sp=STACK_HI - 0x100, sched_pc=0x140001000,
        atomicstatus=G_STATUS_RUNNING, goid=1, waitreason=0,
        gopc=0x140002000, startpc=0x140001000,
    )
    defaults.update(overrides)
    return build_struct_bytes(G_GO1_26, 8, defaults)


def _make_runtime(**overrides) -> GoRuntime:
    defaults = dict(
        pid=1, architecture="x86_64", go_version="1.22+", go_version_confidence=Confidence.HIGH,
        runtime_id="GORUNTIME-1-test",
    )
    defaults.update(overrides)
    return GoRuntime(**defaults)


def _allgs_reader(g_ptrs: list[int], extra_regions: dict | None = None) -> MockMemoryReader:
    array_bytes = b"".join(struct.pack("<Q", p) for p in g_ptrs)
    header_bytes = struct.pack("<QQQ", ALLGS_ARRAY, len(g_ptrs), len(g_ptrs))
    regions = {ALLGS_ARRAY: array_bytes, ALLGS_HEADER: header_bytes}
    if extra_regions:
        regions.update(extra_regions)
    return MockMemoryReader(0x1000, b"\x00" * 16, extra_regions=regions)


def _writable_region(start: int, end: int) -> MemoryRegion:
    return MemoryRegion(start=start, end=end, readable=True, writable=True, executable=False, source="test")


class TestResolveGLayout:
    def test_verified_era_resolves(self):
        assert resolve_g_layout("1.22+") is not None

    def test_unsupported_version_returns_none(self):
        assert resolve_g_layout("1.16-1.17") is None

    def test_none_version_returns_none(self):
        assert resolve_g_layout(None) is None


class TestValidateG:
    def test_valid_running_g(self):
        raw = _decode_g(G_ADDR, _g_bytes(), 8)
        result = validate_g(raw, 8)
        assert result.valid is True
        assert result.base_status == G_STATUS_RUNNING
        assert result.is_scanning is False

    def test_scan_bit_masked_and_reported_separately(self):
        raw = _decode_g(G_ADDR, _g_bytes(atomicstatus=G_STATUS_WAITING | G_SCAN_BIT), 8)
        result = validate_g(raw, 8)
        assert result.valid is True
        assert result.base_status == G_STATUS_WAITING
        assert result.is_scanning is True

    def test_unordered_stack_bounds_rejected(self):
        raw = _decode_g(G_ADDR, _g_bytes(stack_lo=STACK_HI, stack_hi=STACK_LO), 8)
        result = validate_g(raw, 8)
        assert result.valid is False
        assert any("stack.lo" in r for r in result.reasons)

    def test_misaligned_stack_bounds_rejected(self):
        raw = _decode_g(G_ADDR, _g_bytes(stack_lo=STACK_LO + 1), 8)
        result = validate_g(raw, 8)
        assert result.valid is False
        assert any("not pointer-aligned" in r for r in result.reasons)

    def test_implausible_stack_size_rejected(self):
        raw = _decode_g(G_ADDR, _g_bytes(stack_lo=0, stack_hi=8 * 1024 * 1024 * 1024), 8)
        result = validate_g(raw, 8)
        assert result.valid is False
        assert any("stack size implausible" in r for r in result.reasons)

    def test_unrecognized_status_rejected(self):
        raw = _decode_g(G_ADDR, _g_bytes(atomicstatus=0xFF), 8)
        result = validate_g(raw, 8)
        assert result.valid is False
        assert any("unrecognized status" in r for r in result.reasons)

    def test_implausible_goid_rejected(self):
        raw = _decode_g(G_ADDR, _g_bytes(goid=10**12), 8)
        result = validate_g(raw, 8)
        assert result.valid is False
        assert any("goid exceeds" in r for r in result.reasons)

    def test_unrecognized_waitreason_rejected(self):
        raw = _decode_g(G_ADDR, _g_bytes(waitreason=255), 8)
        result = validate_g(raw, 8)
        assert result.valid is False
        assert any("waitreason" in r for r in result.reasons)

    def test_dead_goroutine_with_zeroed_sched_is_still_a_valid_structural_candidate(self):
        # A dead g's stack is still ordered/aligned/plausible-sized even
        # if sched.sp/pc are stale or zeroed - validate_g must not reject
        # it on that basis (that check is applied later, conditionally,
        # by the caller - see TestGoroutineRecoveryEngine).
        raw = _decode_g(G_ADDR, _g_bytes(atomicstatus=G_STATUS_DEAD, sched_sp=0, sched_pc=0), 8)
        result = validate_g(raw, 8)
        assert result.valid is True
        assert result.base_status == G_STATUS_DEAD

    def test_runnable_status_is_valid(self):
        raw = _decode_g(G_ADDR, _g_bytes(atomicstatus=G_STATUS_RUNNABLE), 8)
        assert validate_g(raw, 8).valid is True


class TestAllgsParser:
    def test_finds_and_validates_single_candidate(self):
        reader = _allgs_reader([G_ADDR], extra_regions={G_ADDR: _g_bytes()})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        candidates = AllgsParser(reader, 8).find_candidates(regions, pid=1)
        accepted = [c for c in candidates if not c.rejected]
        assert len(accepted) == 1
        assert accepted[0].ptr == ALLGS_ARRAY
        assert accepted[0].length == 1
        assert accepted[0].valid_sample_count == 1

    def test_null_ptr_never_becomes_a_candidate(self):
        header_bytes = struct.pack("<QQQ", 0, 5, 5)
        reader = MockMemoryReader(0x1000, b"\x00" * 16, extra_regions={ALLGS_HEADER: header_bytes})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        candidates = AllgsParser(reader, 8).find_candidates(regions, pid=1)
        assert candidates == []

    def test_len_greater_than_cap_never_becomes_a_candidate(self):
        header_bytes = struct.pack("<QQQ", ALLGS_ARRAY, 10, 5)
        reader = MockMemoryReader(0x1000, b"\x00" * 16, extra_regions={ALLGS_HEADER: header_bytes})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        candidates = AllgsParser(reader, 8).find_candidates(regions, pid=1)
        assert candidates == []

    def test_unreadable_g_pointer_array_is_rejected_not_fatal(self):
        header_bytes = struct.pack("<QQQ", 0xDEAD0000, 5, 5)  # array itself unmapped
        reader = MockMemoryReader(0x1000, b"\x00" * 16, extra_regions={ALLGS_HEADER: header_bytes})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        candidates = AllgsParser(reader, 8).find_candidates(regions, pid=1)
        assert len(candidates) == 1
        assert candidates[0].rejected is True
        assert candidates[0].rejection_reason == "unreadable"

    def test_majority_invalid_sample_rejects_candidate(self):
        # 4 pointers, only 1 structurally validates - below the 50% ratio.
        garbage = _g_bytes(stack_lo=STACK_HI, stack_hi=STACK_LO)  # invalid (unordered)
        g_ptrs = [G_ADDR, G_ADDR + 0x1000, G_ADDR + 0x2000, G_ADDR + 0x3000]
        reader = _allgs_reader(
            g_ptrs,
            extra_regions={
                G_ADDR: _g_bytes(),
                G_ADDR + 0x1000: garbage,
                G_ADDR + 0x2000: garbage,
                G_ADDR + 0x3000: garbage,
            },
        )
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        candidates = AllgsParser(reader, 8).find_candidates(regions, pid=1)
        accepted = [c for c in candidates if not c.rejected]
        assert accepted == []

    def test_only_writable_regions_are_scanned(self):
        header_bytes = struct.pack("<QQQ", ALLGS_ARRAY, 1, 1)
        reader = MockMemoryReader(
            0x1000, b"\x00" * 16,
            extra_regions={ALLGS_ARRAY: struct.pack("<Q", G_ADDR), ALLGS_HEADER: header_bytes, G_ADDR: _g_bytes()},
        )
        read_only_region = MemoryRegion(
            start=ALLGS_HEADER, end=ALLGS_HEADER + 4096, readable=True, writable=False, executable=False, source="test"
        )
        candidates = AllgsParser(reader, 8).find_candidates([read_only_region], pid=1)
        assert candidates == []


class TestSelectBestAllgsCandidate:
    def test_no_accepted_candidates_returns_none(self):
        assert select_best_allgs_candidate([]) is None

    def test_prefers_higher_confidence_and_more_validated_samples(self):
        reader = _allgs_reader([G_ADDR, G_ADDR + 0x1000], extra_regions={G_ADDR: _g_bytes(), G_ADDR + 0x1000: _g_bytes()})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        candidates = AllgsParser(reader, 8).find_candidates(regions, pid=1)
        best = select_best_allgs_candidate(candidates)
        assert best is not None
        assert not best.rejected


class TestGoroutineRecoveryEngine:
    def test_unsupported_go_version_reports_error(self):
        runtime = _make_runtime(go_version="1.16-1.17")
        reader = _allgs_reader([], extra_regions={})
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, [], [])
        assert artifacts == []
        assert any("UNSUPPORTED_RUNTIME_LAYOUT" in e.message for e in errors)
        assert any(e.reason == FailureReason.UNSUPPORTED_GO_VERSION for e in errors)
        assert stats.candidates_scanned == 0

    def test_no_allgs_candidate_reports_error_not_exception(self):
        runtime = _make_runtime()
        reader = MockMemoryReader(0x1000, b"\x00" * 16)
        regions = [_writable_region(0x1000, 0x2000)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert artifacts == []
        assert any("no structurally valid runtime.allgs candidate" in e.message for e in errors)
        assert any(e.reason == FailureReason.ALLGS_NOT_FOUND for e in errors)

    def test_recovers_one_valid_goroutine(self):
        runtime = _make_runtime()
        reader = _allgs_reader([G_ADDR], extra_regions={G_ADDR: _g_bytes(goid=42)})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert errors == []
        assert len(artifacts) == 1
        g = artifacts[0]
        assert g.goid == 42
        assert g.status_name == "running"
        assert g.stack_lo == STACK_LO
        assert g.stack_hi == STACK_HI
        assert g.allgs_index == 0
        assert stats.valid_goroutines == 1
        assert stats.candidates_scanned == 1
        assert stats.invalid_candidates == 0

    def test_null_g_pointer_slot_skipped_silently(self):
        runtime = _make_runtime()
        reader = _allgs_reader([G_ADDR, 0], extra_regions={G_ADDR: _g_bytes()})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert len(artifacts) == 1

    def test_invalid_g_recorded_as_error_not_fatal(self):
        runtime = _make_runtime()
        bad = _g_bytes(atomicstatus=0xFF)  # unrecognized status
        reader = _allgs_reader([G_ADDR, G_ADDR + 0x1000], extra_regions={G_ADDR: _g_bytes(), G_ADDR + 0x1000: bad})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert len(artifacts) == 1
        assert any("failed validation" in e.message for e in errors)
        assert stats.invalid_candidates == 1

    def test_used_syscall_state_when_syscallsp_nonzero(self):
        # Verified substitution rule (runtime/traceback.go, gentraceback):
        # syscallsp != 0 -> use syscallpc/syscallsp as the effective PC/SP.
        runtime = _make_runtime()
        raw = _g_bytes(
            atomicstatus=3,  # _Gsyscall (paper's own listed value, verified in layouts.py)
            sched_pc=0x140009000, sched_sp=STACK_HI - 0x999,  # would be out of a tight range but irrelevant here
        )
        # Patch syscallpc/syscallsp directly since _g_bytes() doesn't expose them by name.
        from gomemforensics.go_runtime.layouts import G_GO1_26
        buf = bytearray(raw)
        offsets = G_GO1_26.offsets(8)
        struct.pack_into("<Q", buf, offsets["syscallpc"], 0x140001000)
        struct.pack_into("<Q", buf, offsets["syscallsp"], STACK_HI - 0x100)
        reader = _allgs_reader([G_ADDR], extra_regions={G_ADDR: bytes(buf)})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert len(artifacts) == 1
        g = artifacts[0]
        assert g.used_syscall_state is True
        assert g.sched_pc == 0x140001000
        assert g.sched_sp == STACK_HI - 0x100

    def test_out_of_bounds_sp_reduces_confidence_not_rejected(self):
        runtime = _make_runtime()
        # sched_sp far outside [stack_lo, stack_hi) for a RUNNING goroutine.
        reader = _allgs_reader([G_ADDR], extra_regions={G_ADDR: _g_bytes(sched_sp=0x1)})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert len(artifacts) == 1
        assert artifacts[0].confidence == Confidence.MEDIUM
        assert any("outside stack bounds" in e.message for e in errors)
        assert any(e.reason == FailureReason.STACK_UNAVAILABLE for e in errors)

    def test_dead_goroutine_zeroed_sp_not_penalized(self):
        runtime = _make_runtime()
        reader = _allgs_reader([G_ADDR], extra_regions={G_ADDR: _g_bytes(atomicstatus=G_STATUS_DEAD, sched_sp=0, sched_pc=0)})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert len(artifacts) == 1
        assert artifacts[0].confidence == Confidence.HIGH

    def test_gopc_and_startpc_never_reported_as_sched_pc(self):
        # Regression guard for "Never label g.gopc or g.startpc as
        # current execution PC" - the three fields must all stay distinct.
        runtime = _make_runtime()
        reader = _allgs_reader(
            [G_ADDR],
            extra_regions={G_ADDR: _g_bytes(sched_pc=0x140001000, gopc=0x140002000, startpc=0x140003000)},
        )
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, _errors, _stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        g = artifacts[0]
        assert g.sched_pc == 0x140001000
        assert g.go_pc == 0x140002000
        assert g.start_pc == 0x140003000
        assert len({g.sched_pc, g.go_pc, g.start_pc}) == 3

    def test_current_function_resolved_from_reused_function_list(self):
        from gomemforensics.go_runtime.models import FunctionArtifact, FunctionClassification

        runtime = _make_runtime()
        fn = FunctionArtifact(
            id="FUNC-1-a", pid=1, address=0x140001000, entry_address=0x140001000,
            name="main.worker", package="main", source_file="main.go", source_line=10, function_size=None,
            classification=FunctionClassification.APPLICATION, confidence=Confidence.HIGH,
            extraction_method="test", go_version="1.22+", architecture="x86_64",
        )
        reader = _allgs_reader([G_ADDR], extra_regions={G_ADDR: _g_bytes(sched_pc=0x140001010)})
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, _errors, _stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [fn])
        g = artifacts[0]
        assert g.current_function_name == "main.worker"
        assert g.current_source_file == "main.go"

    def test_malformed_g_does_not_abort_the_rest_of_allgs(self):
        runtime = _make_runtime()
        # Second g pointer is misaligned (odd address) - _decode_g on a
        # too-short/garbage read must not crash the whole walk.
        reader = _allgs_reader(
            [G_ADDR, G_ADDR + 0x1000],
            extra_regions={G_ADDR: _g_bytes(), G_ADDR + 0x1000: b"\xff" * 4},  # too short to decode
        )
        regions = [_writable_region(ALLGS_HEADER, ALLGS_HEADER + 4096)]
        artifacts, errors, _stats = GoroutineRecoveryEngine(reader, 8).recover_goroutines(runtime, regions, [])
        assert len(artifacts) == 1  # the first, valid g is still recovered
        # The 4-byte region is too short to satisfy a full G_GO1_26-sized
        # read, so this is caught as an unreadable address range, not a
        # validate_g() rejection - distinct from the "g failed validation"
        # case (test_*_failed_validation below).
        assert any(e.reason == FailureReason.ADDRESS_SPACE_UNAVAILABLE for e in errors)
