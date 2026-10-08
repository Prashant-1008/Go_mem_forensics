"""Unit tests for minimal Go `_type` metadata support (types.py)."""

from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.layouts import TYPE_HEADER_GO1_26, TYPE_KIND_SLICE, TYPE_KIND_STRING, TYPE_KIND_STRUCT
from gomemforensics.go_runtime.models import GoRuntime
from gomemforensics.go_runtime.types import MAX_TYPES_INDEXED, TypeIndex, TypeParser, build_type_index

from tests.unit.go_runtime_helpers import build_struct_bytes

TYPE_ADDR = 0x140060000


def _type_bytes(*, size: int, kind: int, ptr_bytes: int = 0) -> bytes:
    return build_struct_bytes(
        TYPE_HEADER_GO1_26, 8, {"size": size, "ptrBytes": ptr_bytes, "kind": kind}
    )


class TestTypeParser:
    def test_valid_string_type_header(self):
        reader = MockMemoryReader(TYPE_ADDR, _type_bytes(size=16, kind=TYPE_KIND_STRING, ptr_bytes=8))
        descriptor = TypeParser(reader, 8).parse(TYPE_ADDR)

        assert descriptor is not None
        assert descriptor.size == 16
        assert descriptor.kind == TYPE_KIND_STRING
        assert descriptor.kind_name == "string"
        assert descriptor.may_reference_strings is True

    def test_direct_iface_flag_bit_is_masked_off(self):
        # KindDirectIface = 1 << 5 (0x20) can be OR'd into the raw kind byte;
        # the true kind must still decode correctly.
        raw_kind = TYPE_KIND_STRING | 0x20
        reader = MockMemoryReader(TYPE_ADDR, _type_bytes(size=16, kind=raw_kind))
        descriptor = TypeParser(reader, 8).parse(TYPE_ADDR)

        assert descriptor is not None
        assert descriptor.kind == TYPE_KIND_STRING
        assert descriptor.raw_kind == raw_kind

    def test_invalid_kind_rejected(self):
        # 255 & TYPE_KIND_MASK(0x1F) == 31, which exceeds the highest real
        # Kind value (UnsafePointer=26) even after masking off the
        # KindDirectIface flag bit - genuinely invalid, not just an
        # unmasked flag combination.
        reader = MockMemoryReader(TYPE_ADDR, _type_bytes(size=16, kind=255))
        assert TypeParser(reader, 8).parse(TYPE_ADDR) is None

    def test_implausibly_large_size_rejected(self):
        reader = MockMemoryReader(TYPE_ADDR, _type_bytes(size=2**40, kind=TYPE_KIND_STRUCT))
        assert TypeParser(reader, 8).parse(TYPE_ADDR) is None

    def test_ptr_bytes_exceeding_size_rejected(self):
        reader = MockMemoryReader(TYPE_ADDR, _type_bytes(size=8, kind=TYPE_KIND_STRUCT, ptr_bytes=100))
        assert TypeParser(reader, 8).parse(TYPE_ADDR) is None

    def test_unreadable_address_returns_none_not_exception(self):
        reader = MockMemoryReader(TYPE_ADDR, b"\x00" * 4)  # far too short
        assert TypeParser(reader, 8).parse(TYPE_ADDR) is None


class TestTypeIndex:
    def test_multiple_candidates_same_size_all_retained(self):
        from gomemforensics.go_runtime.types import TypeDescriptor

        index = TypeIndex()
        index.add(TypeDescriptor(address=1, size=16, ptr_bytes=8, kind=TYPE_KIND_STRING, raw_kind=TYPE_KIND_STRING))
        index.add(TypeDescriptor(address=2, size=16, ptr_bytes=16, kind=TYPE_KIND_SLICE, raw_kind=TYPE_KIND_SLICE))
        index.add(TypeDescriptor(address=3, size=16, ptr_bytes=0, kind=TYPE_KIND_STRUCT, raw_kind=TYPE_KIND_STRUCT))

        candidates = index.candidates_for_size(16)
        assert len(candidates) == 3
        assert {c.kind for c in candidates} == {TYPE_KIND_STRING, TYPE_KIND_SLICE, TYPE_KIND_STRUCT}

    def test_no_candidates_for_unknown_size(self):
        assert TypeIndex().candidates_for_size(999) == []


class TestBuildTypeIndex:
    def test_missing_typelinks_yields_empty_index_no_error(self):
        runtime = GoRuntime(pid=1, architecture="x86_64", go_version="1.22+", go_version_confidence=Confidence.HIGH)
        reader = MockMemoryReader(0x1000, b"\x00" * 16)

        index, errors = build_type_index(runtime, reader, 8)

        assert len(index) == 0
        assert errors == []

    def test_indexes_types_referenced_by_typelinks(self):
        types_base = 0x150000000
        typelinks_addr = 0x150100000

        type_a = _type_bytes(size=16, kind=TYPE_KIND_STRING)
        type_b = _type_bytes(size=16, kind=TYPE_KIND_SLICE)
        # Two int32 offsets from types_base: 0 -> type_a, 0x100 -> type_b.
        typelinks_data = (0).to_bytes(4, "little", signed=True) + (0x100).to_bytes(4, "little", signed=True)

        reader = MockMemoryReader(
            types_base,
            type_a + b"\x00" * (0x100 - len(type_a)) + type_b,
            extra_regions={typelinks_addr: typelinks_data},
        )

        runtime = GoRuntime(
            pid=1, architecture="x86_64", go_version="1.22+", go_version_confidence=Confidence.HIGH,
            types_start=types_base, typelinks_start=typelinks_addr, typelinks_end=typelinks_addr + 8,
        )

        index, errors = build_type_index(runtime, reader, 8)

        assert errors == []
        assert len(index) == 2
        candidates = index.candidates_for_size(16)
        assert {c.kind for c in candidates} == {TYPE_KIND_STRING, TYPE_KIND_SLICE}

    def test_entry_count_bounded_by_max_types_indexed(self):
        # Just confirm the safety constant exists and is a sane positive bound.
        assert MAX_TYPES_INDEXED > 0
