"""Read-only memory access abstraction.

Every future analyzer (Go runtime parsing, string/function/goroutine
recovery) must access target-process memory exclusively through a
:class:`MemoryReader`. This keeps analyzer logic testable with synthetic
buffers (:class:`MockMemoryReader`) and defers the real Volatility-backed
implementation to Phase 1 without analyzer code needing to change.

Forensic integrity note (CLAUDE.md section 12): this interface deliberately
has no ``write`` method. Evidence must never be modified.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class MemoryAccessError(Exception):
    """Raised when a requested memory region cannot be read."""


@dataclass(frozen=True)
class MemoryRegion:
    """A normalized, OS-independent description of one mapped memory range.

    Populated from Windows VAD or Linux VMA information (see
    :meth:`gomemforensics.volatility.integration.VolatilityIntegration.get_process_regions`)
    when the process layer exposes it. The Go runtime detection layer
    (Phase 2+) works against a ``list[MemoryRegion]`` plus a
    :class:`MemoryReader` and is never coupled to Volatility internals
    directly.
    """

    start: int
    end: int
    readable: bool
    writable: bool
    executable: bool
    #: Free-form provenance tag for debugging (e.g. ``"vad"``/``"vma"``);
    #: never used for validation logic itself.
    source: str | None = None

    @property
    def size(self) -> int:
        return max(0, self.end - self.start)

    def contains(self, address: int, length: int = 1) -> bool:
        """Whether ``[address, address + length)`` lies fully within this region."""
        return self.start <= address and address + length <= self.end


class MemoryReader(ABC):
    """Abstract, read-only accessor over a process's (or image's) memory.

    Concrete implementations back this onto a real memory image (via
    Volatility, in later phases) or, for tests, onto an in-memory buffer.
    """

    @property
    @abstractmethod
    def pointer_size(self) -> int:
        """Pointer size in bytes for the memory being read (4 or 8)."""

    @abstractmethod
    def read(self, address: int, length: int) -> bytes:
        """Read ``length`` bytes starting at ``address``.

        Raises:
            MemoryAccessError: if the region is unreadable or invalid.
        """

    @abstractmethod
    def is_valid(self, address: int) -> bool:
        """Return whether ``address`` is currently readable."""

    def read_pointer(self, address: int, byteorder: str = "little") -> int:
        """Read a single pointer-sized value at ``address``.

        Default implementation built on :meth:`read`; concrete readers may
        override for efficiency.
        """
        raw = self.read(address, self.pointer_size)
        return int.from_bytes(raw, byteorder=byteorder, signed=False)

    def read_string(self, address: int, length: int, encoding: str = "utf-8") -> str:
        """Read ``length`` raw bytes at ``address`` and decode as text.

        This performs no Go-runtime-aware string reconstruction - it is a
        raw fixed-length read. Go string header interpretation (pointer +
        length pairs, heap/static classification) is implemented by the
        string-recovery analyzer in a later phase, on top of this primitive.
        Decoding errors are replaced rather than raised, since evidence
        bytes may legitimately be non-UTF-8; callers that need strict
        validation should decode ``read()`` output themselves.
        """
        raw = self.read(address, length)
        return raw.decode(encoding, errors="replace")


class MockMemoryReader(MemoryReader):
    """In-memory :class:`MemoryReader` backed by one or more disjoint buffers.

    Intended for unit tests only. The primary region is
    ``[base_address, base_address + len(data))``; ``extra_regions`` (a
    mapping of base address -> bytes) can model additional, non-contiguous
    mapped ranges - e.g. a pclntab candidate in one region and a
    moduledata candidate in another, as Go runtime detection tests need.
    Any address outside every declared region is treated as unmapped.
    """

    def __init__(
        self,
        base_address: int,
        data: bytes,
        pointer_size: int = 8,
        extra_regions: dict[int, bytes] | None = None,
    ) -> None:
        if pointer_size not in (4, 8):
            raise ValueError(f"pointer_size must be 4 or 8, got {pointer_size}")
        self._pointer_size = pointer_size
        self._regions: dict[int, bytes] = {base_address: data}
        if extra_regions:
            self._regions.update(extra_regions)

    @property
    def pointer_size(self) -> int:
        return self._pointer_size

    def _find_region(self, address: int, length: int) -> bytes | None:
        for base, buf in self._regions.items():
            if base <= address and address + length <= base + len(buf):
                return buf[address - base : address - base + length]
        return None

    def is_valid(self, address: int) -> bool:
        return any(base <= address < base + len(buf) for base, buf in self._regions.items())

    def read(self, address: int, length: int) -> bytes:
        if length < 0:
            raise MemoryAccessError(f"Negative read length: {length}")
        result = self._find_region(address, length)
        if result is None:
            mapped = ", ".join(
                f"[0x{base:x}, 0x{base + len(buf):x})" for base, buf in self._regions.items()
            )
            raise MemoryAccessError(
                f"Address range [0x{address:x}, 0x{address + length:x}) is outside every "
                f"mapped region ({mapped or 'none'})"
            )
        return result
