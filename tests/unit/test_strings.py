"""Unit tests for heap-based Go string recovery (strings.py)."""

import struct

from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.layouts import ITAB_GO1_26, MSPAN_GO1_26, MSPAN_STATE_IN_USE, TYPE_HEADER_GO1_26, TYPE_KIND_STRING, TYPE_KIND_STRUCT
from gomemforensics.go_runtime.models import GoRuntime
from gomemforensics.go_runtime.strings import StringRecoveryEngine, _looks_like_itab, validate_string_header

from tests.unit.go_runtime_helpers import build_struct_bytes

ALLSPANS_ADDR = 0x180000000
SPAN_ARRAY_ADDR = 0x180001000
SPAN0_ADDR = 0x180002000
BITMAP0_ADDR = 0x180003000
HEAP_BASE = 0x1C0000000
STRING_DATA_ADDR = 0x1C0100000
TYPES_BASE = 0x150000000
TYPELINKS_ADDR = 0x150100000
ITAB_ADDR = 0x160000000


def _region():
    return MemoryRegion(start=ALLSPANS_ADDR, end=ALLSPANS_ADDR + 64, readable=True, writable=True, executable=False)


def _mspan_bytes(**overrides) -> bytes:
    defaults = dict(startAddr=HEAP_BASE, nelems=8, elemsize=16, allocCount=1, allocBits=BITMAP0_ADDR, state=MSPAN_STATE_IN_USE)
    defaults.update(overrides)
    return build_struct_bytes(MSPAN_GO1_26, 8, defaults)


def _build_heap_reader(string_ptr: int, string_len: int, extra: dict | None = None) -> MockMemoryReader:
    allspans_header = struct.pack("<QQQ", SPAN_ARRAY_ADDR, 1, 1)
    span_array = struct.pack("<Q", SPAN0_ADDR)
    span0 = _mspan_bytes()
    bitmap0 = bytes([0b00000001])  # bit 0 allocated
    heap_object = struct.pack("<QQ", string_ptr, string_len)

    regions = {
        SPAN_ARRAY_ADDR: span_array,
        SPAN0_ADDR: span0,
        BITMAP0_ADDR: bitmap0,
        HEAP_BASE: heap_object + b"\x00" * 48,
    }
    if extra:
        regions.update(extra)
    return MockMemoryReader(ALLSPANS_ADDR, allspans_header, extra_regions=regions)


def _runtime(**overrides) -> GoRuntime:
    defaults = dict(
        pid=1, architecture="x86_64", go_version="1.22+", go_version_confidence=Confidence.HIGH,
        data_start=ALLSPANS_ADDR, bss_end=ALLSPANS_ADDR + 64, runtime_id="GORUNTIME-1-test",
    )
    defaults.update(overrides)
    return GoRuntime(**defaults)


class TestValidateStringHeader:
    def test_valid_utf8_string(self):
        reader = MockMemoryReader(STRING_DATA_ADDR, b"hello world")
        result = validate_string_header(reader, STRING_DATA_ADDR, 11)
        assert result.valid is True
        assert result.value == "hello world"
        assert result.is_utf8 is True

    def test_empty_string_is_valid(self):
        reader = MockMemoryReader(STRING_DATA_ADDR, b"")
        result = validate_string_header(reader, 0, 0)
        assert result.valid is True
        assert result.value == ""

    def test_negative_length_rejected(self):
        reader = MockMemoryReader(STRING_DATA_ADDR, b"x")
        result = validate_string_header(reader, STRING_DATA_ADDR, -1)
        assert result.valid is False
        assert "negative" in result.reasons[0]

    def test_impossible_length_rejected(self):
        reader = MockMemoryReader(STRING_DATA_ADDR, b"x")
        result = validate_string_header(reader, STRING_DATA_ADDR, 10**9)
        assert result.valid is False

    def test_null_pointer_rejected(self):
        reader = MockMemoryReader(STRING_DATA_ADDR, b"x")
        result = validate_string_header(reader, 0, 4)
        assert result.valid is False
        assert "null" in result.reasons[0]

    def test_truncated_backing_data_rejected(self):
        reader = MockMemoryReader(STRING_DATA_ADDR, b"hi")  # only 2 bytes backed
        result = validate_string_header(reader, STRING_DATA_ADDR, 100)
        assert result.valid is False

    def test_non_utf8_but_mostly_printable_accepted_lower_signal(self):
        raw = b"password=abc" + bytes([0xFF])  # one non-UTF8 continuation byte
        reader = MockMemoryReader(STRING_DATA_ADDR, raw)
        result = validate_string_header(reader, STRING_DATA_ADDR, len(raw))
        assert result.valid is True
        assert result.is_utf8 is False

    def test_random_binary_data_rejected(self):
        raw = bytes(range(256))  # mostly non-printable, not valid UTF-8
        reader = MockMemoryReader(STRING_DATA_ADDR, raw)
        result = validate_string_header(reader, STRING_DATA_ADDR, len(raw))
        assert result.valid is False


class TestLooksLikeItab:
    def test_plausible_itab_detected(self):
        type_bytes = build_struct_bytes(TYPE_HEADER_GO1_26, 8, {"size": 8, "kind": TYPE_KIND_STRUCT})
        itab_bytes = build_struct_bytes(ITAB_GO1_26, 8, {"type": TYPES_BASE})
        reader = MockMemoryReader(ITAB_ADDR, itab_bytes, extra_regions={TYPES_BASE: type_bytes})
        assert _looks_like_itab(reader, 8, ITAB_ADDR) is True

    def test_null_pointer_is_not_itab(self):
        reader = MockMemoryReader(ITAB_ADDR, b"\x00" * 32)
        assert _looks_like_itab(reader, 8, 0) is False

    def test_plain_string_pointer_is_not_itab(self):
        # The itab's own "Type" field would need to point somewhere
        # readable and _type-shaped; a bare data pointer does not.
        reader = MockMemoryReader(STRING_DATA_ADDR, b"hello world")
        assert _looks_like_itab(reader, 8, STRING_DATA_ADDR) is False


class TestStringRecoveryEngineHeap:
    def test_confirmed_go_string_recovered_with_high_confidence(self):
        reader = _build_heap_reader(STRING_DATA_ADDR, 11, extra={STRING_DATA_ADDR: b"hello world"})
        runtime = _runtime()

        engine = StringRecoveryEngine(reader, 8)
        artifacts, errors = engine.recover_heap_strings(runtime, [_region()])

        assert errors == []
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.value == "hello world"
        assert artifact.region == "heap"
        assert artifact.extraction_method == "mspan_allocation_bitmap"
        assert artifact.string_address == HEAP_BASE
        assert artifact.data_address == STRING_DATA_ADDR
        assert artifact.length == 11
        assert artifact.classification == "unknown"
        assert artifact.confidence == Confidence.MEDIUM  # no type metadata available to corroborate

    def test_confidence_high_when_type_index_confirms_string_kind(self):
        type_bytes = build_struct_bytes(TYPE_HEADER_GO1_26, 8, {"size": 16, "kind": TYPE_KIND_STRING})
        typelinks_data = struct.pack("<i", 0)  # offset 0 from TYPES_BASE
        reader = _build_heap_reader(
            STRING_DATA_ADDR, 11,
            extra={STRING_DATA_ADDR: b"hello world", TYPES_BASE: type_bytes, TYPELINKS_ADDR: typelinks_data},
        )
        runtime = _runtime(types_start=TYPES_BASE, typelinks_start=TYPELINKS_ADDR, typelinks_end=TYPELINKS_ADDR + 4)

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_heap_strings(runtime, [_region()])

        assert errors == []
        assert len(artifacts) == 1
        assert artifacts[0].confidence == Confidence.HIGH
        assert "string" in artifacts[0].type_candidates

    def test_unsupported_runtime_layout_reports_error_and_no_strings(self):
        reader = _build_heap_reader(STRING_DATA_ADDR, 11, extra={STRING_DATA_ADDR: b"hello world"})
        runtime = _runtime(go_version="1.16-1.17")  # not a verified mspan era

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_heap_strings(runtime, [_region()])

        assert artifacts == []
        assert len(errors) == 1
        assert "UNSUPPORTED_RUNTIME_LAYOUT" in errors[0].message

    def test_no_go_version_reports_error_and_no_strings(self):
        reader = _build_heap_reader(STRING_DATA_ADDR, 11, extra={STRING_DATA_ADDR: b"hello world"})
        runtime = _runtime(go_version=None)

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_heap_strings(runtime, [_region()])
        assert artifacts == []
        assert len(errors) == 1

    def test_itab_like_object_excluded_from_string_candidacy(self):
        type_bytes = build_struct_bytes(TYPE_HEADER_GO1_26, 8, {"size": 8, "kind": TYPE_KIND_STRUCT})
        itab_bytes = build_struct_bytes(ITAB_GO1_26, 8, {"type": TYPES_BASE})
        reader = _build_heap_reader(
            ITAB_ADDR, 999,  # word0 will instead point at a plausible itab
            extra={TYPES_BASE: type_bytes, ITAB_ADDR: itab_bytes},
        )
        runtime = _runtime()

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_heap_strings(runtime, [_region()])
        assert artifacts == []  # excluded as a probable interface, not a rejected string

    def test_no_allspans_candidate_yields_no_strings_and_recoverable_error(self):
        reader = MockMemoryReader(ALLSPANS_ADDR, b"\x00" * 64)  # no valid slice header anywhere
        runtime = _runtime()

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_heap_strings(runtime, [_region()])
        assert artifacts == []
        assert len(errors) == 1
        assert errors[0].recoverable is True

    def test_ambiguous_type_size_mapping_yields_medium_confidence(self):
        # Two candidate types share the 2-word size, neither is exactly "string".
        type_a = build_struct_bytes(TYPE_HEADER_GO1_26, 8, {"size": 16, "kind": TYPE_KIND_STRUCT})
        typelinks_data = struct.pack("<i", 0)
        reader = _build_heap_reader(
            STRING_DATA_ADDR, 11,
            extra={STRING_DATA_ADDR: b"hello world", TYPES_BASE: type_a, TYPELINKS_ADDR: typelinks_data},
        )
        runtime = _runtime(types_start=TYPES_BASE, typelinks_start=TYPELINKS_ADDR, typelinks_end=TYPELINKS_ADDR + 4)

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_heap_strings(runtime, [_region()])
        assert len(artifacts) == 1
        assert artifacts[0].confidence == Confidence.MEDIUM
        assert artifacts[0].type_candidates == ["struct"]
