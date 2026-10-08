"""Unit tests for allspans discovery and mspan parsing (mspan.py)."""

import struct

from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.go_runtime.layouts import MSPAN_GO1_26, MSPAN_STATE_IN_USE
from gomemforensics.go_runtime.mspan import (
    AllspansParser,
    MspanWalker,
    resolve_mspan_layout,
    select_best_allspans_candidate,
    validate_mspan,
    _decode_mspan,
)

from tests.unit.go_runtime_helpers import build_struct_bytes

ALLSPANS_ADDR = 0x180000000
SPAN_ARRAY_ADDR = 0x180001000
SPAN0_ADDR = 0x180002000
SPAN1_ADDR = 0x180002100
BITMAP0_ADDR = 0x180003000
HEAP_BASE = 0x1C0000000


def _mspan_bytes(**overrides) -> bytes:
    defaults = dict(startAddr=HEAP_BASE, nelems=8, elemsize=16, allocCount=2, allocBits=BITMAP0_ADDR, state=MSPAN_STATE_IN_USE)
    defaults.update(overrides)
    return build_struct_bytes(MSPAN_GO1_26, 8, defaults)


def _region(start=ALLSPANS_ADDR, end=None, writable=True):
    return MemoryRegion(start=start, end=end or (start + 64), readable=True, writable=writable, executable=False)


class TestValidateMspan:
    def test_plausible_span_has_no_errors(self):
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(), 8)
        assert validate_mspan(info) == []

    def test_null_start_addr_rejected(self):
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(startAddr=0), 8)
        assert any("startAddr" in e for e in validate_mspan(info))

    def test_zero_elemsize_rejected(self):
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(elemsize=0), 8)
        assert any("elemsize" in e for e in validate_mspan(info))

    def test_implausible_elemsize_rejected(self):
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(elemsize=2**40), 8)
        assert any("elemsize" in e for e in validate_mspan(info))

    def test_nelems_is_inherently_bounded_by_its_uint16_width(self):
        # mspan.nelems is a real uint16 field (verified: runtime/mheap.go),
        # so no legitimately-encoded span can ever exceed 65535 - the
        # MAX_OBJECTS_PER_SPAN safety bound (100_000) is unreachable via a
        # genuine field value and exists as defense-in-depth only. This
        # replaces an "impossible nelems" test that could not actually be
        # constructed from a real uint16 encoding.
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(nelems=65535), 8)
        assert info.nelems == 65535
        assert validate_mspan(info) == []

    def test_alloc_count_exceeding_nelems_rejected(self):
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(nelems=4, allocCount=10), 8)
        assert any("allocCount" in e for e in validate_mspan(info))

    def test_unrecognized_state_rejected(self):
        info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(state=99), 8)
        assert any("state" in e for e in validate_mspan(info))

    def test_dead_and_manual_states_are_structurally_valid(self):
        # state 0 (dead) / 2 (manual) are real, legitimate span states -
        # only currently-unrecognized values should be rejected.
        for state in (0, 2):
            info = _decode_mspan(SPAN0_ADDR, _mspan_bytes(state=state), 8)
            assert validate_mspan(info) == []


class TestResolveMspanLayout:
    def test_verified_era_resolves(self):
        layout, layout_id = resolve_mspan_layout("1.22+")
        assert layout is not None
        assert layout_id == "mspan@go1.26.2"

    def test_unsupported_version_range_returns_none(self):
        layout, layout_id = resolve_mspan_layout("1.16-1.17")
        assert layout is None
        assert layout_id is None

    def test_unknown_version_returns_none(self):
        layout, layout_id = resolve_mspan_layout(None)
        assert layout is None


class TestAllspansParser:
    def _build_reader(self, span_bytes_map: dict[int, bytes], allspans_len=1, allspans_cap=1, ptr=SPAN_ARRAY_ADDR):
        header = struct.pack("<QQQ", ptr, allspans_len, allspans_cap)
        span_array = b"".join(struct.pack("<Q", addr) for addr in span_bytes_map)
        regions = {SPAN_ARRAY_ADDR: span_array}
        regions.update(span_bytes_map)
        # bitmap always available for the default single-span case
        regions.setdefault(BITMAP0_ADDR, bytes([0b00000101]))
        return MockMemoryReader(ALLSPANS_ADDR, header, extra_regions=regions)

    def test_valid_allspans_with_valid_span_accepted(self):
        reader = self._build_reader({SPAN0_ADDR: _mspan_bytes()})
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)

        accepted = [c for c in candidates if not c.rejected]
        assert len(accepted) == 1
        assert accepted[0].span_pointers == [SPAN0_ADDR]

    def test_invalid_allspans_pointer_null_is_not_a_candidate(self):
        header = struct.pack("<QQQ", 0, 1, 1)  # null pointer
        reader = MockMemoryReader(ALLSPANS_ADDR, header)
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)
        assert candidates == []

    def test_len_greater_than_cap_is_not_a_candidate(self):
        header = struct.pack("<QQQ", SPAN_ARRAY_ADDR, 10, 2)  # len > cap
        reader = MockMemoryReader(ALLSPANS_ADDR, header, extra_regions={SPAN_ARRAY_ADDR: b"\x00" * 80})
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)
        assert candidates == []

    def test_inaccessible_span_lowers_valid_ratio_and_rejects(self):
        # span array points at an address with no backing data at all.
        header = struct.pack("<QQQ", SPAN_ARRAY_ADDR, 1, 1)
        span_array = struct.pack("<Q", 0x999999999999)  # unreadable
        reader = MockMemoryReader(ALLSPANS_ADDR, header, extra_regions={SPAN_ARRAY_ADDR: span_array})
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)

        assert len(candidates) == 1
        assert candidates[0].rejected is True
        assert candidates[0].rejection_reason == "insufficient_valid_span_sample"

    def test_malformed_mspan_excluded_from_sample(self):
        reader = self._build_reader({SPAN0_ADDR: _mspan_bytes(elemsize=0)})  # malformed
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)
        # The only sampled span is malformed -> ratio 0 -> rejected.
        assert len(candidates) == 1
        assert candidates[0].rejected is True

    def test_multiple_spans_mixed_validity(self):
        reader = self._build_reader(
            {SPAN0_ADDR: _mspan_bytes(), SPAN1_ADDR: _mspan_bytes(elemsize=0)},
            allspans_len=2, allspans_cap=2,
        )
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)
        accepted = [c for c in candidates if not c.rejected]
        # 1/2 valid == exactly the MIN_VALID_SAMPLE_RATIO threshold -> accepted.
        assert len(accepted) == 1
        assert accepted[0].span_pointers == [SPAN0_ADDR]

    def test_scan_bounds_restricts_search(self):
        reader = self._build_reader({SPAN0_ADDR: _mspan_bytes()})
        # Bounds that do not overlap the region at all -> nothing found.
        candidates = AllspansParser(reader, 8).find_candidates(
            [_region()], pid=1, scan_bounds=(0x999000000, 0x999001000)
        )
        assert candidates == []

    def test_select_best_prefers_high_confidence(self):
        reader = self._build_reader({SPAN0_ADDR: _mspan_bytes()})
        candidates = AllspansParser(reader, 8).find_candidates([_region()], pid=1)
        best = select_best_allspans_candidate(candidates)
        assert best is not None
        assert best.rejected is False

    def test_select_best_returns_none_when_all_rejected(self):
        candidates = AllspansParser(
            self._build_reader({SPAN0_ADDR: _mspan_bytes(elemsize=0)}), 8
        ).find_candidates([_region()], pid=1)
        assert select_best_allspans_candidate(candidates) is None


class TestMspanWalkerHeapObjectEnumeration:
    def test_enumerates_only_allocated_bits(self):
        # bitmap 0b00000101 -> bits 0 and 2 set -> two live objects.
        span_bytes = _mspan_bytes(startAddr=HEAP_BASE, nelems=8, elemsize=16, allocBits=BITMAP0_ADDR)
        reader = MockMemoryReader(
            SPAN0_ADDR, span_bytes, extra_regions={BITMAP0_ADDR: bytes([0b00000101])}
        )
        objects, errors = MspanWalker(reader, 8).enumerate_heap_objects([SPAN0_ADDR], pid=1)

        assert errors == []
        addresses = sorted(o.address for o in objects)
        assert addresses == [HEAP_BASE, HEAP_BASE + 2 * 16]
        assert all(o.size == 16 for o in objects)

    def test_dead_span_yields_no_objects(self):
        span_bytes = _mspan_bytes(state=0)  # mSpanDead
        reader = MockMemoryReader(SPAN0_ADDR, span_bytes, extra_regions={BITMAP0_ADDR: bytes([0xFF])})
        objects, errors = MspanWalker(reader, 8).enumerate_heap_objects([SPAN0_ADDR], pid=1)
        assert objects == []
        assert errors == []

    def test_malformed_span_recorded_as_recoverable_error_and_skipped(self):
        # Span address itself is entirely unreadable.
        reader = MockMemoryReader(0x1000, b"\x00" * 16)
        objects, errors = MspanWalker(reader, 8).enumerate_heap_objects([0x999999999999], pid=42)

        assert objects == []
        assert len(errors) == 1
        assert errors[0].pid == 42
        assert errors[0].recoverable is True
        assert "go_runtime.mspan" in errors[0].component

    def test_one_bad_span_does_not_prevent_processing_others(self):
        good_span = _mspan_bytes(startAddr=HEAP_BASE, nelems=8, elemsize=16, allocBits=BITMAP0_ADDR)
        reader = MockMemoryReader(
            SPAN0_ADDR, good_span, extra_regions={BITMAP0_ADDR: bytes([0b00000001])}
        )
        objects, errors = MspanWalker(reader, 8).enumerate_heap_objects(
            [0xBADBADBADBAD, SPAN0_ADDR], pid=1
        )
        assert len(objects) == 1
        assert objects[0].address == HEAP_BASE
        assert len(errors) == 1  # the bad span, recorded, not fatal

    def test_truncated_bitmap_does_not_crash(self):
        # nelems=64 implies an 8-byte bitmap, but only 1 byte is backed.
        span_bytes = _mspan_bytes(startAddr=HEAP_BASE, nelems=64, elemsize=16, allocBits=BITMAP0_ADDR)
        reader = MockMemoryReader(SPAN0_ADDR, span_bytes, extra_regions={BITMAP0_ADDR: bytes([0b00000001])})
        objects, errors = MspanWalker(reader, 8).enumerate_heap_objects([SPAN0_ADDR], pid=1)
        assert errors == []
        assert len(objects) == 1
        assert objects[0].address == HEAP_BASE
