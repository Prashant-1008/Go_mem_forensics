"""Tests for the resilient chunked-region scanning helper.

Covers the specific edge case found while building the pclntab tests: a
short final chunk (already below the retry floor) must be tried once and
either succeed or be skipped - not forced through a larger floor-sized
read that would spuriously fail.
"""

from gomemforensics.common.memory import MockMemoryReader
from gomemforensics.go_runtime.scanning import iter_readable_chunks


def test_single_chunk_within_bounds():
    reader = MockMemoryReader(0x1000, b"A" * 100)
    chunks = list(iter_readable_chunks(reader, 0x1000, 0x1000 + 100, chunk_size=1000, overlap=0))
    assert len(chunks) == 1
    assert chunks[0] == (0x1000, b"A" * 100)


def test_short_final_region_smaller_than_retry_floor_is_read_directly():
    # Region is only 64 bytes - well below the internal 4096-byte retry
    # floor. This must still be read successfully in one shot rather than
    # forced through a failing floor-sized attempt.
    reader = MockMemoryReader(0x2000, b"B" * 64)
    chunks = list(iter_readable_chunks(reader, 0x2000, 0x2000 + 64, chunk_size=1024 * 1024, overlap=3))
    assert len(chunks) == 1
    assert chunks[0] == (0x2000, b"B" * 64)


def test_declared_bounds_exceeding_backing_data_still_yield_the_readable_prefix():
    # Declared region is much larger than what the reader actually backs -
    # a single oversized chunk read must degrade rather than abort with
    # nothing yielded at all.
    reader = MockMemoryReader(0x3000, b"C" * 5000)
    chunks = list(
        iter_readable_chunks(reader, 0x3000, 0x3000 + 1024 * 1024, chunk_size=1024 * 1024, overlap=3)
    )
    assert chunks  # at least the readable prefix was yielded
    total_bytes = b"".join(c for _, c in chunks)
    assert b"C" in total_bytes


def test_completely_unreadable_region_yields_nothing():
    reader = MockMemoryReader(0x4000, b"")
    chunks = list(iter_readable_chunks(reader, 0x5000, 0x5000 + 4096, chunk_size=4096, overlap=0))
    assert chunks == []


def test_overlap_covers_boundary_spanning_needle():
    # A 4-byte needle placed exactly at a chunk boundary must still be
    # found thanks to the overlap.
    needle = b"MAGC"
    data = b"\x00" * 998 + needle + b"\x00" * 998
    reader = MockMemoryReader(0x6000, data)
    chunks = list(iter_readable_chunks(reader, 0x6000, 0x6000 + len(data), chunk_size=1000, overlap=3))
    joined_found = any(needle in chunk for _, chunk in chunks)
    assert joined_found
