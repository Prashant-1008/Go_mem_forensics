"""Minimal Go type metadata (`_type`) support for string recovery.

Implements only the subset the paper's size-to-type mapping (Section
3.2.1) needs - not a full Go type system (approved plan Section A: "Do
not build the entire Go type system in this phase").

Field layout verified against the local go1.26.2 install
(``internal/abi/type.go``, ``type Type struct``) - see
``gomemforensics.go_runtime.layouts.TYPE_HEADER_GO1_26``. This is the only
verified era (see docs/architecture/go-runtime.md); other Go versions are
not attempted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader
from gomemforensics.common.models import AnalysisError, FailureReason
from gomemforensics.go_runtime.layouts import (
    TYPE_HEADER_GO1_26,
    TYPE_KIND_ARRAY,
    TYPE_KIND_INTERFACE,
    TYPE_KIND_MAP,
    TYPE_KIND_MASK,
    TYPE_KIND_POINTER,
    TYPE_KIND_SLICE,
    TYPE_KIND_STRING,
    TYPE_KIND_STRUCT,
)
from gomemforensics.go_runtime.models import GoRuntime

logger = get_logger("go_runtime.types")

#: Highest valid Kind_ value (internal/abi/type.go: UnsafePointer = 26).
_MAX_VALID_KIND = 26

#: Safety bound (not a language invariant) rejecting obviously-garbage
#: type headers.
_MAX_PLAUSIBLE_TYPE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GiB

#: Safety bound on how many typelinks entries are indexed per process, to
#: keep type-index construction from becoming unbounded on a pathological
#: or corrupted moduledata.
MAX_TYPES_INDEXED = 50_000

_KIND_NAMES = {
    TYPE_KIND_STRING: "string",
    TYPE_KIND_SLICE: "slice",
    TYPE_KIND_ARRAY: "array",
    TYPE_KIND_STRUCT: "struct",
    TYPE_KIND_MAP: "map",
    TYPE_KIND_INTERFACE: "interface",
    TYPE_KIND_POINTER: "pointer",
}


@dataclass(frozen=True)
class TypeDescriptor:
    """A minimal, verified subset of a decoded ``_type`` header."""

    address: int
    size: int
    ptr_bytes: int
    kind: int  # masked (TYPE_KIND_MASK applied) - the true Kind_ value
    raw_kind: int  # unmasked, as stored (may include the KindDirectIface flag bit)

    @property
    def kind_name(self) -> str:
        return _KIND_NAMES.get(self.kind, f"kind_{self.kind}")

    @property
    def may_reference_strings(self) -> bool:
        """Whether this type's layout might directly contain or reference a string.

        Per the paper (Section 3.2.1): candidates are restricted to types
        "whose layout may directly contain or indirectly reference string
        values" - String itself, plus composite kinds that could. This is
        deliberately permissive (a plausibility filter): it never proves a
        heap object of this type actually holds a string - the per-object
        validation in ``StringRecoveryEngine`` does that.
        """
        return self.kind in (
            TYPE_KIND_STRING,
            TYPE_KIND_ARRAY,
            TYPE_KIND_SLICE,
            TYPE_KIND_STRUCT,
            TYPE_KIND_MAP,
            TYPE_KIND_INTERFACE,
            TYPE_KIND_POINTER,
        )


class TypeParser:
    """Reads a single ``_type`` header from memory."""

    def __init__(self, reader: MemoryReader, pointer_size: int) -> None:
        self._reader = reader
        self._pointer_size = pointer_size

    def parse(self, address: int) -> TypeDescriptor | None:
        """Decode and lightly validate a `_type` header at ``address``.

        Returns ``None`` (not an exception) for unreadable or
        implausible headers - callers treat this as "no usable type
        metadata here", not a fatal error.
        """
        try:
            raw = self._reader.read(address, TYPE_HEADER_GO1_26.size(self._pointer_size))
        except MemoryAccessError:
            return None

        offsets = TYPE_HEADER_GO1_26.offsets(self._pointer_size)
        word_fmt = "<Q" if self._pointer_size == 8 else "<I"

        size = struct.unpack_from(word_fmt, raw, offsets["size"])[0]
        ptr_bytes = struct.unpack_from(word_fmt, raw, offsets["ptrBytes"])[0]
        raw_kind = raw[offsets["kind"]]
        kind = raw_kind & TYPE_KIND_MASK

        if kind > _MAX_VALID_KIND:
            return None
        if size > _MAX_PLAUSIBLE_TYPE_SIZE:
            return None
        if ptr_bytes > size and size > 0:
            return None  # ptrBytes must not exceed the type's own size

        return TypeDescriptor(address=address, size=size, ptr_bytes=ptr_bytes, kind=kind, raw_kind=raw_kind)


class TypeIndex:
    """``size -> [TypeDescriptor, ...]`` index, preserving ambiguity.

    Per the approved plan (Section E): multiple Go types can share a size,
    so this is never collapsed to a single "the" type - every candidate at
    a given size is retained.
    """

    def __init__(self) -> None:
        self._by_size: dict[int, list[TypeDescriptor]] = {}

    def add(self, descriptor: TypeDescriptor) -> None:
        self._by_size.setdefault(descriptor.size, []).append(descriptor)

    def candidates_for_size(self, size: int) -> list[TypeDescriptor]:
        """Every known type descriptor with exactly this size (never a single "winner")."""
        return list(self._by_size.get(size, []))

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_size.values())


def build_type_index(
    runtime: GoRuntime, reader: MemoryReader, pointer_size: int
) -> tuple[TypeIndex, list[AnalysisError]]:
    """Build a :class:`TypeIndex` from a recovered runtime's ``typelinks``.

    ``typelinks`` entries are ``int32`` offsets *from* ``moduledata.types``
    (verified: ``runtime/symtab.go`` moduledata field comment,
    ``typelinks []int32 // offsets from types``). Requires
    ``runtime.types_start``/``typelinks_start``/``typelinks_end`` to have
    been recovered (Phase 2, HIGH-confidence moduledata only) - if not
    available, returns an empty index (not an error): type-based
    disambiguation is simply unavailable, and string recovery falls back
    to pointer/length/content validation alone.
    """
    index = TypeIndex()
    errors: list[AnalysisError] = []

    if runtime.types_start is None or runtime.typelinks_start is None or runtime.typelinks_end is None:
        logger.debug("pid=%s: no typelinks/types recovered; type index will be empty", runtime.pid)
        return index, errors

    element_size = 4  # int32
    typelinks_bytes = runtime.typelinks_end - runtime.typelinks_start
    entry_count = min(typelinks_bytes // element_size, MAX_TYPES_INDEXED)

    if entry_count <= 0:
        return index, errors

    try:
        raw = reader.read(runtime.typelinks_start, entry_count * element_size)
    except MemoryAccessError as exc:
        errors.append(
            AnalysisError(
                component="go_runtime.types.build_type_index",
                message=f"Could not read typelinks slice: {exc}",
                pid=runtime.pid,
                reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
            )
        )
        return index, errors

    parser = TypeParser(reader, pointer_size)
    for i in range(entry_count):
        offset = struct.unpack_from("<i", raw, i * element_size)[0]
        type_address = runtime.types_start + offset
        descriptor = parser.parse(type_address)
        if descriptor is not None:
            index.add(descriptor)

    return index, errors
