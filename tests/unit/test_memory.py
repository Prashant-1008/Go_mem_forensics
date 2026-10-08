"""Tests for the MemoryReader abstraction and MockMemoryReader."""

import pytest

from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MockMemoryReader


def test_mock_reader_reads_within_bounds():
    reader = MockMemoryReader(base_address=0x1000, data=b"ABCDEFGH", pointer_size=8)

    assert reader.read(0x1000, 4) == b"ABCD"
    assert reader.read(0x1004, 4) == b"EFGH"


def test_mock_reader_is_valid():
    reader = MockMemoryReader(base_address=0x1000, data=b"ABCDEFGH")

    assert reader.is_valid(0x1000) is True
    assert reader.is_valid(0x1007) is True
    assert reader.is_valid(0x1008) is False  # one past the end
    assert reader.is_valid(0x0FFF) is False  # one before the start


def test_mock_reader_read_out_of_bounds_raises():
    reader = MockMemoryReader(base_address=0x1000, data=b"ABCD")

    with pytest.raises(MemoryAccessError):
        reader.read(0x1000, 100)

    with pytest.raises(MemoryAccessError):
        reader.read(0x2000, 1)


def test_mock_reader_negative_length_raises():
    reader = MockMemoryReader(base_address=0x1000, data=b"ABCD")

    with pytest.raises(MemoryAccessError):
        reader.read(0x1000, -1)


def test_mock_reader_read_pointer_little_endian():
    # Pointer value 0x0102030405060708, stored little-endian.
    data = bytes.fromhex("0807060504030201")
    reader = MockMemoryReader(base_address=0x2000, data=data, pointer_size=8)

    assert reader.read_pointer(0x2000) == 0x0102030405060708


def test_mock_reader_read_string_replaces_invalid_utf8():
    reader = MockMemoryReader(base_address=0x3000, data=b"hello\xff\xfe")

    assert reader.read_string(0x3000, 5) == "hello"
    # Invalid bytes are replaced, not raised, since evidence bytes may
    # legitimately not be valid UTF-8.
    result = reader.read_string(0x3000, 7)
    assert result.startswith("hello")


def test_mock_reader_invalid_pointer_size_raises():
    with pytest.raises(ValueError):
        MockMemoryReader(base_address=0x1000, data=b"AAAA", pointer_size=3)


def test_memory_reader_is_abstract():
    with pytest.raises(TypeError):
        MemoryReader()  # type: ignore[abstract]


def test_mock_reader_has_no_write_method():
    reader = MockMemoryReader(base_address=0x1000, data=b"AAAA")
    assert not hasattr(reader, "write")
