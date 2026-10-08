"""Shared byte-buffer builders for Go runtime unit tests.

Not a test module itself (no ``test_`` prefix, so pytest does not collect
it) - just synthetic pcHeader/moduledata/mspan/_type/itab construction
helpers used across tests/unit/test_go_runtime_*.py and
tests/unit/test_{types,mspan,strings,static_strings}.py, built directly
from the verified StructLayout field lists in
gomemforensics.go_runtime.layouts.
"""

from __future__ import annotations

import struct

from gomemforensics.go_runtime.layouts import FieldKind, StructLayout


def _uword_fmt(pointer_size: int) -> str:
    return "<Q" if pointer_size == 8 else "<I"


def _word_fmt(pointer_size: int) -> str:
    return "<q" if pointer_size == 8 else "<i"


def build_pc_header_bytes(
    layout: StructLayout,
    pointer_size: int,
    *,
    magic: int,
    min_lc: int = 1,
    ptr_size: int | None = None,
    nfunc: int = 10,
    nfiles: int = 2,
    pad1: int = 0,
    pad2: int = 0,
    funcname_offset: int = 0x100,
    cu_offset: int = 0x200,
    filetab_offset: int = 0x300,
    pctab_offset: int = 0x400,
    pcln_offset: int = 0x500,
) -> bytes:
    """Build a synthetic pcHeader buffer matching ``layout`` exactly."""
    ptr_size = pointer_size if ptr_size is None else ptr_size
    offsets = layout.offsets(pointer_size)
    buf = bytearray(layout.size(pointer_size))

    struct.pack_into("<I", buf, offsets["magic"], magic & 0xFFFFFFFF)
    buf[offsets["pad1"]] = pad1
    buf[offsets["pad2"]] = pad2
    buf[offsets["minLC"]] = min_lc
    buf[offsets["ptrSize"]] = ptr_size
    struct.pack_into(_word_fmt(pointer_size), buf, offsets["nfunc"], nfunc)
    struct.pack_into(_uword_fmt(pointer_size), buf, offsets["nfiles"], nfiles)
    if "textStartOrUnused" in offsets:
        struct.pack_into(_uword_fmt(pointer_size), buf, offsets["textStartOrUnused"], 0)
    struct.pack_into(_uword_fmt(pointer_size), buf, offsets["funcnameOffset"], funcname_offset)
    struct.pack_into(_uword_fmt(pointer_size), buf, offsets["cuOffset"], cu_offset)
    struct.pack_into(_uword_fmt(pointer_size), buf, offsets["filetabOffset"], filetab_offset)
    struct.pack_into(_uword_fmt(pointer_size), buf, offsets["pctabOffset"], pctab_offset)
    struct.pack_into(_uword_fmt(pointer_size), buf, offsets["pclnOffset"], pcln_offset)
    return bytes(buf)


def build_moduledata_bytes(
    layout: StructLayout,
    pointer_size: int,
    *,
    pc_header_pointer: int,
    text: int,
    etext: int,
    data: int,
    edata: int,
    bss: int,
    ebss: int,
    types: int,
    etypes: int,
    rodata: int | None = None,
    typelinks_ptr: int = 0,
    typelinks_len: int = 0,
    typelinks_cap: int = 0,
    itablinks_ptr: int = 0,
    itablinks_len: int = 0,
    itablinks_cap: int = 0,
) -> bytes:
    """Build a synthetic moduledata buffer matching ``layout`` exactly."""
    offsets = layout.offsets(pointer_size)
    buf = bytearray(layout.size(pointer_size))
    fmt = _uword_fmt(pointer_size)

    def put(name: str, value: int) -> None:
        struct.pack_into(fmt, buf, offsets[name], value & ((1 << (pointer_size * 8)) - 1))

    def put_slice(name: str, ptr: int, length: int, cap: int) -> None:
        base = offsets[name]
        struct.pack_into(fmt, buf, base, ptr)
        struct.pack_into(fmt, buf, base + pointer_size, length)
        struct.pack_into(fmt, buf, base + 2 * pointer_size, cap)

    put("pcHeader", pc_header_pointer)
    put("text", text)
    put("etext", etext)
    put("data", data)
    put("edata", edata)
    put("bss", bss)
    put("ebss", ebss)
    put("types", types)
    put("etypes", etypes)
    if rodata is not None and "rodata" in offsets:
        put("rodata", rodata)
    put_slice("typelinks", typelinks_ptr, typelinks_len, typelinks_cap)
    put_slice("itablinks", itablinks_ptr, itablinks_len, itablinks_cap)
    return bytes(buf)


def build_struct_bytes(layout: StructLayout, pointer_size: int, values: dict[str, int]) -> bytes:
    """Generic byte-buffer builder for any :class:`StructLayout`.

    Fields not present in ``values`` default to 0. For ``SLICE``/``STRING``
    fields, ``values["<name>"]`` sets the pointer; ``values["<name>_len"]``
    sets the length (default 0); a slice's capacity defaults to its length
    unless ``values["<name>_cap"]`` is given. Used for mspan/_type/itab
    (Phase 3), which - unlike pcHeader/moduledata - mix several field
    sizes (U8/U16/U32/WORD), so a single generic builder driven by the
    layout's own declared field kinds is less error-prone than one
    hand-written function per struct.
    """
    offsets = layout.offsets(pointer_size)
    buf = bytearray(layout.size(pointer_size))
    word_fmt = _uword_fmt(pointer_size)
    word_mask = (1 << (pointer_size * 8)) - 1

    for spec in layout.fields:
        off = offsets[spec.name]
        if spec.kind is FieldKind.MAGIC_U32 or spec.kind is FieldKind.U32:
            struct.pack_into("<I", buf, off, values.get(spec.name, 0) & 0xFFFFFFFF)
        elif spec.kind is FieldKind.U8:
            buf[off] = values.get(spec.name, 0) & 0xFF
        elif spec.kind is FieldKind.U16:
            struct.pack_into("<H", buf, off, values.get(spec.name, 0) & 0xFFFF)
        elif spec.kind is FieldKind.WORD:
            struct.pack_into(word_fmt, buf, off, values.get(spec.name, 0) & word_mask)
        elif spec.kind is FieldKind.SLICE:
            ptr = values.get(spec.name, 0)
            length = values.get(f"{spec.name}_len", 0)
            cap_ = values.get(f"{spec.name}_cap", length)
            struct.pack_into(word_fmt, buf, off, ptr & word_mask)
            struct.pack_into(word_fmt, buf, off + pointer_size, length & word_mask)
            struct.pack_into(word_fmt, buf, off + 2 * pointer_size, cap_ & word_mask)
        elif spec.kind is FieldKind.STRING:
            ptr = values.get(spec.name, 0)
            length = values.get(f"{spec.name}_len", 0)
            struct.pack_into(word_fmt, buf, off, ptr & word_mask)
            struct.pack_into(word_fmt, buf, off + pointer_size, length & word_mask)

    return bytes(buf)
