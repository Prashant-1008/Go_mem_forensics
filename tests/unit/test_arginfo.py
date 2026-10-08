"""Unit tests for ArgInfo/ArgsPointerMaps funcdata decoding.

Byte streams below are hand-constructed to match the verified encoder
shape (cmd/compile/internal/ssagen/ssa.go, EmitArgInfo) and consumer
opcode handling (runtime/traceback.go, printArgs) documented in
gomemforensics.go_runtime.arginfo.
"""

import struct

from gomemforensics.common.memory import MockMemoryReader
from gomemforensics.go_runtime.arginfo import (
    TRACE_ARGS_DOTDOTDOT,
    TRACE_ARGS_END_AGG,
    TRACE_ARGS_END_SEQ,
    TRACE_ARGS_OFFSET_TOO_LARGE,
    TRACE_ARGS_START_AGG,
    ArgInfoLeaf,
    decode_arg_info,
    read_stackmap,
)
from gomemforensics.go_runtime.layouts import STACKMAP_GO1_26


class TestDecodeArgInfoScalars:
    def test_single_int_argument(self):
        # (offset=0, size=8) leaf, then EndSeq.
        stream = bytes([0x00, 0x08, TRACE_ARGS_END_SEQ])
        args = decode_arg_info(stream)
        assert len(args) == 1
        assert args[0].is_aggregate is False
        assert args[0].leaves == [ArgInfoLeaf(offset=0, size=8)]

    def test_multiple_scalar_arguments(self):
        # int at offset 0 (size 8), pointer at offset 8 (size 8).
        stream = bytes([0x00, 0x08, 0x08, 0x08, TRACE_ARGS_END_SEQ])
        args = decode_arg_info(stream)
        assert len(args) == 2
        assert [leaf.offset for arg in args for leaf in arg.leaves] == [0, 8]

    def test_zero_argument_function(self):
        stream = bytes([TRACE_ARGS_END_SEQ])
        assert decode_arg_info(stream) == []


class TestDecodeArgInfoAggregates:
    def test_string_argument_is_two_leaf_aggregate(self):
        # string = ptr (offset 0, size 8) + len (offset 8, size 8), wrapped
        # in StartAgg/EndAgg per the verified encoder.
        stream = bytes(
            [TRACE_ARGS_START_AGG, 0x00, 0x08, 0x08, 0x08, TRACE_ARGS_END_AGG, TRACE_ARGS_END_SEQ]
        )
        args = decode_arg_info(stream)
        assert len(args) == 1
        assert args[0].is_aggregate is True
        assert [leaf.offset for leaf in args[0].leaves] == [0, 8]

    def test_scalar_then_aggregate(self):
        # int (offset 0, size 8), then a 2-leaf aggregate at offsets 8/16.
        stream = bytes(
            [
                0x00, 0x08,
                TRACE_ARGS_START_AGG, 0x08, 0x08, 0x10, 0x08, TRACE_ARGS_END_AGG,
                TRACE_ARGS_END_SEQ,
            ]
        )
        args = decode_arg_info(stream)
        assert len(args) == 2
        assert args[0].is_aggregate is False
        assert args[1].is_aggregate is True
        assert len(args[1].leaves) == 2


class TestDecodeArgInfoTruncation:
    def test_dotdotdot_marks_truncated(self):
        # DOTDOTDOT at depth 0 starts its own trailing pseudo-argument
        # (the "..." omitted-args marker) rather than retroactively
        # marking the previous, already-closed argument.
        stream = bytes([0x00, 0x08, TRACE_ARGS_DOTDOTDOT, TRACE_ARGS_END_SEQ])
        args = decode_arg_info(stream)
        assert len(args) == 2
        assert args[0].truncated is False
        assert args[1].truncated is True

    def test_offset_too_large_marks_truncated(self):
        stream = bytes([TRACE_ARGS_OFFSET_TOO_LARGE, TRACE_ARGS_END_SEQ])
        args = decode_arg_info(stream)
        assert len(args) == 1
        assert args[0].truncated is True

    def test_missing_end_seq_terminator_does_not_raise(self):
        # A leaf's opcode byte present but its size byte missing - decoder
        # must stop cleanly, not raise or hang.
        stream = bytes([0x00])
        args = decode_arg_info(stream)
        assert args == [] or args[-1].truncated is True

    def test_empty_stream_returns_no_arguments(self):
        assert decode_arg_info(b"") == []

    def test_unrecognized_operator_byte_stops_decoding_safely(self):
        # 0xF5 is >= TRACE_ARGS_SPECIAL but not one of the named opcodes.
        stream = bytes([0x00, 0x08, 0xF5, 0x00, 0x08, TRACE_ARGS_END_SEQ])
        args = decode_arg_info(stream)
        # Only the first (valid) argument is recovered; nothing after the
        # unrecognized operator byte is fabricated.
        assert len(args) == 1


class TestReadStackmap:
    def test_valid_stackmap_header_and_bitmap(self):
        header = bytearray(STACKMAP_GO1_26.size(8))
        offsets = STACKMAP_GO1_26.offsets(8)
        struct.pack_into("<i", header, offsets["n"], 1)
        struct.pack_into("<i", header, offsets["nbit"], 16)
        bitmap = bytes([0b1010_1010, 0b0000_0001])  # 2 bytes for 16 bits
        reader = MockMemoryReader(0x1000, bytes(header) + bitmap)

        info = read_stackmap(reader, 0x1000, 8)
        assert info is not None
        assert info.num_bitmaps == 1
        assert info.bits_per_map == 16
        assert info.bitmap_bytes == bitmap

    def test_implausible_negative_n_returns_none(self):
        header = bytearray(STACKMAP_GO1_26.size(8))
        offsets = STACKMAP_GO1_26.offsets(8)
        struct.pack_into("<i", header, offsets["n"], -1)
        struct.pack_into("<i", header, offsets["nbit"], 8)
        reader = MockMemoryReader(0x1000, bytes(header) + b"\x00")

        assert read_stackmap(reader, 0x1000, 8) is None

    def test_implausibly_large_nbit_returns_none(self):
        header = bytearray(STACKMAP_GO1_26.size(8))
        offsets = STACKMAP_GO1_26.offsets(8)
        struct.pack_into("<i", header, offsets["n"], 1)
        struct.pack_into("<i", header, offsets["nbit"], 1_000_000)
        reader = MockMemoryReader(0x1000, bytes(header))

        assert read_stackmap(reader, 0x1000, 8) is None

    def test_unreadable_header_returns_none_not_raise(self):
        reader = MockMemoryReader(0x1000, b"")
        assert read_stackmap(reader, 0x1000, 8) is None

    def test_header_readable_but_bitmap_truncated_returns_none(self):
        header = bytearray(STACKMAP_GO1_26.size(8))
        offsets = STACKMAP_GO1_26.offsets(8)
        struct.pack_into("<i", header, offsets["n"], 1)
        struct.pack_into("<i", header, offsets["nbit"], 64)  # needs 8 bitmap bytes
        reader = MockMemoryReader(0x1000, bytes(header))  # no bitmap bytes appended

        assert read_stackmap(reader, 0x1000, 8) is None
