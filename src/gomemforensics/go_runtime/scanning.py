"""Shared resilient chunked-region scanning helper.

A memory region's declared bounds (from a VAD/VMA) do not guarantee every
byte in that range is actually readable - Windows VADs in particular can
span committed and reserved-but-inaccessible sub-ranges. A single failed
chunk read must degrade the scan of that sub-range, not abort scanning of
the entire (possibly mostly-valid) region (CLAUDE.md section 24: "recover
-> record error -> continue").
"""

from __future__ import annotations

from typing import Iterator

from gomemforensics.common.memory import MemoryAccessError, MemoryReader

#: Chunk size below which :func:`iter_readable_chunks` gives up on a
#: sub-range and skips ahead, when a read fails entirely. 4 KiB matches
#: the common OS page size, a reasonable minimum granularity for "this
#: specific part is unreadable".
_MIN_CHUNK_SIZE = 4096

#: Size below which :func:`_read_resilient`'s retry switches from halving
#: to a linear byte-by-byte shrink, to find the exact readable prefix of a
#: small, partially-backed range. Deliberately much smaller than
#: ``_MIN_CHUNK_SIZE``: halving converges to this floor in O(log n) steps
#: from any starting size, keeping the (at most ``_LINEAR_SHRINK_FLOOR``)
#: linear attempts cheap even in the worst case.
_LINEAR_SHRINK_FLOOR = 64


def iter_readable_chunks(
    reader: MemoryReader,
    start: int,
    end: int,
    chunk_size: int,
    overlap: int,
) -> Iterator[tuple[int, bytes]]:
    """Yield ``(offset, bytes)`` chunks covering ``[start, end)``.

    Adjacent chunks overlap by ``overlap`` bytes so a needle spanning a
    chunk boundary is never missed. If a chunk fails to read, it is halved
    and retried down to a small floor; if even the floor is unreadable,
    that slice is skipped (not the rest of the region).
    """
    offset = start
    while offset < end:
        length = min(chunk_size, end - offset)
        chunk = _read_resilient(reader, offset, length)
        if chunk is None:
            offset += _MIN_CHUNK_SIZE
            continue

        yield offset, chunk

        if offset + len(chunk) >= end:
            break  # already covered the region end; no redundant overlap-only tail chunk

        advance = len(chunk) - overlap
        if advance <= 0:
            advance = len(chunk) or 1
        offset += advance


def read_partial(reader: MemoryReader, address: int, length: int) -> bytes:
    """Read as much of ``[address, address + length)`` as possible, never raising.

    Public wrapper around the same resilient shrink-and-retry strategy
    :func:`iter_readable_chunks` uses internally, for call sites that want
    a single bounded "best-effort" read rather than a chunk iterator (e.g.
    a heap span's allocation bitmap, or a bounded pctab lookup window) -
    CLAUDE.md section 24: a range that is only partially backed should
    still yield whatever prefix *is* readable, not nothing.
    """
    return _read_resilient(reader, address, length) or b""


def _read_resilient(reader: MemoryReader, offset: int, length: int) -> bytes | None:
    """Try ``length`` bytes; on failure, shrink and retry until something succeeds.

    Two phases: while the attempt size is above ``_LINEAR_SHRINK_FLOOR``,
    it halves (fast, O(log n) convergence from any starting size,
    including a small one - unlike a plateau-based floor, this never
    forces an oversized minimum attempt). Once at or below that floor, it
    falls back to a bounded linear shrink (at most
    ``_LINEAR_SHRINK_FLOOR`` further attempts) to find the exact readable
    prefix of a small, partially-backed range - e.g. a declared range a
    little larger than what is actually mapped - rather than giving up on
    the first failure just because the attempt started out small.
    """
    attempt = length
    while attempt > 0:
        try:
            return reader.read(offset, attempt)
        except MemoryAccessError:
            attempt = attempt - 1 if attempt <= _LINEAR_SHRINK_FLOOR else attempt // 2
    return None
