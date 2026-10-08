"""Version-and-architecture-aware Go runtime struct layouts.

Every layout below is a literal transcription of a real ``runtime/symtab.go``
field list (declaration order matters - Go does not reorder struct fields),
each with a citation to the exact source it was read from. Byte offsets are
never hand-typed as magic numbers: :class:`StructLayout` computes them
mechanically from the declared field order and a target pointer size,
because Go struct layout is fully determined by field order + pointer size
for the field kinds used here (no field in the prefix we care about needs
compiler-inserted alignment padding - see the "Why no padding" note below).

Sources consulted (all read in full before transcribing; see
docs/architecture/go-runtime.md for the narrative discussion):

- Local installed toolchain: ``go1.26.2`` at
  ``C:\\Program Files (x86)\\Go\\src\\runtime\\symtab.go`` and
  ``C:\\Program Files (x86)\\Go\\src\\internal\\abi\\symtab.go``
  (``go version`` verified: ``go1.26.2 windows/386``, host bitness does not
  affect the struct definitions themselves).
- ``https://raw.githubusercontent.com/golang/go/go1.17.13/src/runtime/symtab.go``
- ``https://raw.githubusercontent.com/golang/go/go1.19.13/src/runtime/symtab.go``
- ``https://raw.githubusercontent.com/golang/go/go1.20.14/src/runtime/symtab.go``
- ``https://raw.githubusercontent.com/golang/go/go1.21.13/src/runtime/symtab.go``

Why no inter-field padding: every field in the prefixes declared below is
either a fixed 4-byte magic, single 1-byte scalars grouped together (which
sum to a pointer-size-aligned block), or a pointer/uintptr/slice/string -
all of which are already aligned to their own natural alignment given the
preceding fields' sizes on both 32-bit and 64-bit targets. No field kind
used here ever needs the Go compiler to insert padding before it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FieldKind(Enum):
    """The handful of Go field shapes that appear in the structures we parse."""

    MAGIC_U32 = "magic_u32"  # always 4 bytes, regardless of pointer size
    U8 = "u8"  # always 1 byte (uint8, bool, and Go's other 1-byte kinds)
    U16 = "u16"  # always 2 bytes (uint16)
    U32 = "u32"  # always 4 bytes (uint32, int32)
    WORD = "word"  # int / uint / uintptr / pointer / func value: platform word size
    SLICE = "slice"  # {ptr, len, cap}: 3 words
    STRING = "string"  # {ptr, len}: 2 words


_FIXED_SIZES = {FieldKind.MAGIC_U32: 4, FieldKind.U8: 1, FieldKind.U16: 2, FieldKind.U32: 4}


def _field_size(kind: FieldKind, pointer_size: int) -> int:
    if kind in _FIXED_SIZES:
        return _FIXED_SIZES[kind]
    if kind is FieldKind.WORD:
        return pointer_size
    if kind is FieldKind.SLICE:
        return 3 * pointer_size
    if kind is FieldKind.STRING:
        return 2 * pointer_size
    raise AssertionError(f"unhandled FieldKind: {kind}")  # pragma: no cover


def _field_alignment(kind: FieldKind, pointer_size: int) -> int:
    """Go's struct-layout alignment for each field kind.

    Matches the real Go compiler's rule that a field aligns to its own
    size, capped at the platform word size (true for every scalar and
    pointer-shaped kind used here; Go never over-aligns beyond a
    pointer's width on the architectures this project targets).
    """
    return min(_field_size(kind, pointer_size), pointer_size)


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: FieldKind


@dataclass(frozen=True)
class StructLayout:
    """An ordered field list for one verified era of a Go runtime struct."""

    #: Short, unique identifier used in provenance/debug output (e.g.
    #: ``"pcHeader@go1.18+"``).
    layout_id: str
    #: Human-readable citation of exactly where this field order was read.
    source: str
    fields: tuple[FieldSpec, ...]

    def offsets(self, pointer_size: int) -> dict[str, int]:
        """Compute each field's byte offset for a given pointer size.

        Alignment-aware: a field is placed at the next offset that is a
        multiple of its own alignment (its size, capped at the pointer
        size), inserting padding exactly as the real Go compiler would.
        For the pcHeader/moduledata layouts (Phase 2) every field already
        happens to fall on an aligned boundary given the declared order,
        so this produces identical results to the original no-padding
        computation there; for mspan (Phase 3) real padding is required
        and computed here rather than hand-inserted.
        """
        offsets: dict[str, int] = {}
        cursor = 0
        for field in self.fields:
            align = _field_alignment(field.kind, pointer_size)
            if align and cursor % align:
                cursor += align - (cursor % align)
            offsets[field.name] = cursor
            cursor += _field_size(field.kind, pointer_size)
        return offsets

    def field_offset(self, name: str, pointer_size: int) -> int:
        return self.offsets(pointer_size)[name]

    def size(self, pointer_size: int) -> int:
        """Total byte span covering every declared field, including any
        alignment padding :meth:`offsets` inserted between them (a prefix
        of the real struct in the moduledata/mspan case - see module
        docstring)."""
        if not self.fields:
            return 0
        offsets = self.offsets(pointer_size)
        last_field = self.fields[-1]
        return offsets[last_field.name] + _field_size(last_field.kind, pointer_size)


# ---------------------------------------------------------------------------
# pcHeader layouts
# ---------------------------------------------------------------------------
# Verified identical in shape across go1.19.13, go1.20.14, go1.21.13, and the
# locally installed go1.26.2 (the field that starts as "textStart" in
# go1.18-go1.20 becomes an unused placeholder "_" from some later release
# onward per the local go1.26.2 source's own comment - a semantic change
# only, not a size/offset change, so one layout covers the whole go1.18+
# range observed).

PCHEADER_PRE_1_18 = StructLayout(
    layout_id="pcHeader@go1.16-1.17",
    source="https://raw.githubusercontent.com/golang/go/go1.17.13/src/runtime/symtab.go (lines 371-383)",
    fields=(
        FieldSpec("magic", FieldKind.MAGIC_U32),
        FieldSpec("pad1", FieldKind.U8),
        FieldSpec("pad2", FieldKind.U8),
        FieldSpec("minLC", FieldKind.U8),
        FieldSpec("ptrSize", FieldKind.U8),
        FieldSpec("nfunc", FieldKind.WORD),
        FieldSpec("nfiles", FieldKind.WORD),
        FieldSpec("funcnameOffset", FieldKind.WORD),
        FieldSpec("cuOffset", FieldKind.WORD),
        FieldSpec("filetabOffset", FieldKind.WORD),
        FieldSpec("pctabOffset", FieldKind.WORD),
        FieldSpec("pclnOffset", FieldKind.WORD),
    ),
)

PCHEADER_1_18_PLUS = StructLayout(
    layout_id="pcHeader@go1.18+",
    source=(
        "https://raw.githubusercontent.com/golang/go/go1.19.13/src/runtime/symtab.go (lines 395-408); "
        "confirmed identical shape in go1.20.14, go1.21.13, and local go1.26.2 "
        "(C:\\Program Files (x86)\\Go\\src\\runtime\\symtab.go lines 376-395)"
    ),
    fields=(
        FieldSpec("magic", FieldKind.MAGIC_U32),
        FieldSpec("pad1", FieldKind.U8),
        FieldSpec("pad2", FieldKind.U8),
        FieldSpec("minLC", FieldKind.U8),
        FieldSpec("ptrSize", FieldKind.U8),
        FieldSpec("nfunc", FieldKind.WORD),
        FieldSpec("nfiles", FieldKind.WORD),
        FieldSpec("textStartOrUnused", FieldKind.WORD),
        FieldSpec("funcnameOffset", FieldKind.WORD),
        FieldSpec("cuOffset", FieldKind.WORD),
        FieldSpec("filetabOffset", FieldKind.WORD),
        FieldSpec("pctabOffset", FieldKind.WORD),
        FieldSpec("pclnOffset", FieldKind.WORD),
    ),
)

# ---------------------------------------------------------------------------
# moduledata layouts (prefix only, through itablinks - the fields Phase 2's
# GoRuntime model needs; fields after itablinks are not parsed).
# ---------------------------------------------------------------------------
# A leading `sys.NotInHeap` marker (introduced go1.21) is a zero-sized type
# and contributes 0 bytes - deliberately omitted from every field list below
# since it has no offset effect.

_MODULEDATA_COMMON_PREFIX = (
    FieldSpec("pcHeader", FieldKind.WORD),
    FieldSpec("funcnametab", FieldKind.SLICE),
    FieldSpec("cutab", FieldKind.SLICE),
    FieldSpec("filetab", FieldKind.SLICE),
    FieldSpec("pctab", FieldKind.SLICE),
    FieldSpec("pclntable", FieldKind.SLICE),
    FieldSpec("ftab", FieldKind.SLICE),
    FieldSpec("findfunctab", FieldKind.WORD),
    FieldSpec("minpc", FieldKind.WORD),
    FieldSpec("maxpc", FieldKind.WORD),
    FieldSpec("text", FieldKind.WORD),
    FieldSpec("etext", FieldKind.WORD),
    FieldSpec("noptrdata", FieldKind.WORD),
    FieldSpec("enoptrdata", FieldKind.WORD),
    FieldSpec("data", FieldKind.WORD),
    FieldSpec("edata", FieldKind.WORD),
    FieldSpec("bss", FieldKind.WORD),
    FieldSpec("ebss", FieldKind.WORD),
    FieldSpec("noptrbss", FieldKind.WORD),
    FieldSpec("enoptrbss", FieldKind.WORD),
)

MODULEDATA_1_16_17 = StructLayout(
    layout_id="moduledata@go1.16-1.17",
    source="https://raw.githubusercontent.com/golang/go/go1.17.13/src/runtime/symtab.go (lines 390-411)",
    fields=_MODULEDATA_COMMON_PREFIX
    + (
        FieldSpec("end", FieldKind.WORD),
        FieldSpec("gcdata", FieldKind.WORD),
        FieldSpec("gcbss", FieldKind.WORD),
        FieldSpec("types", FieldKind.WORD),
        FieldSpec("etypes", FieldKind.WORD),
        FieldSpec("textsectmap", FieldKind.SLICE),
        FieldSpec("typelinks", FieldKind.SLICE),
        FieldSpec("itablinks", FieldKind.SLICE),
    ),
)

MODULEDATA_1_18_19 = StructLayout(
    layout_id="moduledata@go1.18-1.19",
    source="https://raw.githubusercontent.com/golang/go/go1.19.13/src/runtime/symtab.go (lines 415-438); rodata/gofunc fields introduced vs go1.17.13",
    fields=_MODULEDATA_COMMON_PREFIX
    + (
        FieldSpec("end", FieldKind.WORD),
        FieldSpec("gcdata", FieldKind.WORD),
        FieldSpec("gcbss", FieldKind.WORD),
        FieldSpec("types", FieldKind.WORD),
        FieldSpec("etypes", FieldKind.WORD),
        FieldSpec("rodata", FieldKind.WORD),
        FieldSpec("gofunc", FieldKind.WORD),
        FieldSpec("textsectmap", FieldKind.SLICE),
        FieldSpec("typelinks", FieldKind.SLICE),
        FieldSpec("itablinks", FieldKind.SLICE),
    ),
)

MODULEDATA_1_20_EARLY = StructLayout(
    layout_id="moduledata@go1.20-1.21",
    source=(
        "https://raw.githubusercontent.com/golang/go/go1.20.14/src/runtime/symtab.go (lines 434-458); "
        "confirmed still identical (no epclntab field) in go1.21.13"
    ),
    fields=_MODULEDATA_COMMON_PREFIX
    + (
        FieldSpec("covctrs", FieldKind.WORD),
        FieldSpec("ecovctrs", FieldKind.WORD),
        FieldSpec("end", FieldKind.WORD),
        FieldSpec("gcdata", FieldKind.WORD),
        FieldSpec("gcbss", FieldKind.WORD),
        FieldSpec("types", FieldKind.WORD),
        FieldSpec("etypes", FieldKind.WORD),
        FieldSpec("rodata", FieldKind.WORD),
        FieldSpec("gofunc", FieldKind.WORD),
        FieldSpec("textsectmap", FieldKind.SLICE),
        FieldSpec("typelinks", FieldKind.SLICE),
        FieldSpec("itablinks", FieldKind.SLICE),
    ),
)

MODULEDATA_1_22_PLUS = StructLayout(
    layout_id="moduledata@go1.22+",
    source=(
        "Local go1.26.2 install: C:\\Program Files (x86)\\Go\\src\\runtime\\symtab.go (lines 402-430). "
        "Adds an `epclntab` field vs go1.21.13 - exact introduction version between 1.22 and 1.26 not "
        "independently pinned down (see docs/architecture/go-runtime.md); this layout is only confirmed "
        "correct at the go1.26.2 endpoint."
    ),
    fields=_MODULEDATA_COMMON_PREFIX
    + (
        FieldSpec("covctrs", FieldKind.WORD),
        FieldSpec("ecovctrs", FieldKind.WORD),
        FieldSpec("end", FieldKind.WORD),
        FieldSpec("gcdata", FieldKind.WORD),
        FieldSpec("gcbss", FieldKind.WORD),
        FieldSpec("types", FieldKind.WORD),
        FieldSpec("etypes", FieldKind.WORD),
        FieldSpec("rodata", FieldKind.WORD),
        FieldSpec("gofunc", FieldKind.WORD),
        FieldSpec("epclntab", FieldKind.WORD),
        FieldSpec("textsectmap", FieldKind.SLICE),
        FieldSpec("typelinks", FieldKind.SLICE),
        FieldSpec("itablinks", FieldKind.SLICE),
    ),
)

#: All known moduledata layouts sharing the Go120PCLnTabMagic (0xfffffff1)
#: magic family, most-recent-first. Because this single magic value has
#: covered every release from Go 1.20 through the locally verified 1.26.2
#: (see gomemforensics.go_runtime.version), and the moduledata shape
#: changed *within* that window (the `epclntab` field), a magic match alone
#: cannot select the right moduledata layout - the parser must try each
#: candidate in turn and accept whichever one passes full structural
#: validation (docs/architecture/go-runtime.md "Moduledata era ambiguity").
MODULEDATA_GO120_FAMILY_CANDIDATES: tuple[StructLayout, ...] = (
    MODULEDATA_1_22_PLUS,
    MODULEDATA_1_20_EARLY,
)


# ---------------------------------------------------------------------------
# mspan layout (Phase 3 - Go string recovery)
# ---------------------------------------------------------------------------
# Verified against the local go1.26.2 install only
# (C:\Program Files (x86)\Go\src\runtime\mheap.go, `type mspan struct`).
# Unlike pcHeader/moduledata, mspan is a much larger, more volatile
# runtime-internal struct (GC bookkeeping fields change frequently across
# releases) and was NOT independently re-verified against older tagged
# releases in this phase - this is an explicit, documented scope decision
# (see docs/architecture/go-runtime.md "mspan: single verified era").
#
# Only the prefix through `elemsize` is declared - everything Phase 3's
# string recovery needs (startAddr, nelems, allocBits, allocCount,
# spanclass/state, elemsize); trailing fields (limit, speciallock,
# specials, userArenaChunkFree, largeType) are not parsed.
#
# Every intermediate field's exact size was independently confirmed from
# source before transcribing this list, including the non-obvious ones:
# gclinkptr = uintptr (runtime/mcache.go), spanClass = uint8
# (runtime/mheap.go), mSpanStateBox = struct{ s atomic.Uint8 } => 1 byte
# (runtime/mheap.go + internal/runtime/atomic/types.go: Uint8{noCopy,
# value uint8}, noCopy is zero-sized).
MSPAN_GO1_26 = StructLayout(
    layout_id="mspan@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\runtime\mheap.go (type mspan struct, `_ sys.NotInHeap` through `elemsize`)",
    fields=(
        # `_ sys.NotInHeap` is zero-sized - omitted, no offset effect.
        FieldSpec("next", FieldKind.WORD),
        FieldSpec("prev", FieldKind.WORD),
        FieldSpec("list", FieldKind.WORD),
        FieldSpec("startAddr", FieldKind.WORD),
        FieldSpec("npages", FieldKind.WORD),
        FieldSpec("manualFreeList", FieldKind.WORD),  # gclinkptr = uintptr
        FieldSpec("freeindex", FieldKind.U16),
        FieldSpec("nelems", FieldKind.U16),
        FieldSpec("freeIndexForScan", FieldKind.U16),
        FieldSpec("allocCache", FieldKind.WORD),  # uint64; WORD is correct on amd64 (8 bytes)
        FieldSpec("allocBits", FieldKind.WORD),  # *gcBits
        FieldSpec("gcmarkBits", FieldKind.WORD),  # *gcBits
        FieldSpec("pinnerBits", FieldKind.WORD),  # *gcBits
        FieldSpec("sweepgen", FieldKind.U32),
        FieldSpec("divMul", FieldKind.U32),
        FieldSpec("allocCount", FieldKind.U16),
        FieldSpec("spanclass", FieldKind.U8),
        FieldSpec("state", FieldKind.U8),  # mSpanStateBox -> atomic.Uint8 -> 1 byte
        FieldSpec("needzero", FieldKind.U8),
        FieldSpec("isUserArenaChunk", FieldKind.U8),  # bool
        FieldSpec("allocCountBeforeCache", FieldKind.U16),
        FieldSpec("elemsize", FieldKind.WORD),
    ),
)

#: mSpanInUse per runtime/mheap.go's `mSpanState` const block
#: (`mSpanDead=0, mSpanInUse=1, mSpanManual=2`) - matches the paper's own
#: Figure 2 caption ("state: 0 (dead/free), 1(in-use)").
MSPAN_STATE_IN_USE = 1

#: Only mspan layout currently verified. Keyed here (rather than by magic
#: family like pcHeader/moduledata) because mspan's shape is not governed
#: by the pclntab magic at all - it is purely a Go-version fact. Extend
#: this table (and MspanParser's lookup) if/when another era is verified
#: against real source; never guess an additional entry.
MSPAN_LAYOUTS_BY_GO_VERSION_RANGE: dict[str, StructLayout] = {
    "1.22+": MSPAN_GO1_26,
}


# ---------------------------------------------------------------------------
# _type (abi.Type) and itab (abi.ITab) headers (Phase 3)
# ---------------------------------------------------------------------------
# Verified against the local go1.26.2 install only
# (C:\Program Files (x86)\Go\src\internal\abi\type.go `type Type struct`,
# and internal\abi\iface.go `type ITab struct`).
TYPE_HEADER_GO1_26 = StructLayout(
    layout_id="_type@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\internal\abi\type.go (type Type struct)",
    fields=(
        FieldSpec("size", FieldKind.WORD),  # Size_
        FieldSpec("ptrBytes", FieldKind.WORD),  # PtrBytes
        FieldSpec("hash", FieldKind.U32),  # Hash
        FieldSpec("tflag", FieldKind.U8),  # TFlag
        FieldSpec("align", FieldKind.U8),  # Align_
        FieldSpec("fieldAlign", FieldKind.U8),  # FieldAlign_
        FieldSpec("kind", FieldKind.U8),  # Kind_
        FieldSpec("equal", FieldKind.WORD),  # Equal func value (pointer-sized)
        FieldSpec("gcdata", FieldKind.WORD),  # *byte
        FieldSpec("str", FieldKind.U32),  # NameOff = int32
        FieldSpec("ptrToThis", FieldKind.U32),  # TypeOff = int32
    ),
)

#: Kind_ can have bit 5 (0x20, `KindDirectIface`) set as a flag alongside
#: the real kind value; masking it off is required to read the true kind
#: (verified: internal/abi/type.go `KindDirectIface Kind = 1 << 5`, and
#: every real Kind constant is < 32, i.e. fits in the lower 5 bits).
TYPE_KIND_MASK = 0x1F

#: internal/abi/type.go Kind constants (0-indexed, iota).
TYPE_KIND_STRING = 24
TYPE_KIND_SLICE = 23
TYPE_KIND_ARRAY = 17
TYPE_KIND_STRUCT = 25
TYPE_KIND_MAP = 21
TYPE_KIND_INTERFACE = 20
TYPE_KIND_POINTER = 22

ITAB_GO1_26 = StructLayout(
    layout_id="itab@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\internal\abi\iface.go (type ITab struct)",
    fields=(
        FieldSpec("inter", FieldKind.WORD),  # *InterfaceType
        FieldSpec("type", FieldKind.WORD),  # *Type
        FieldSpec("hash", FieldKind.U32),  # copy of Type.Hash
        # `Fun [1]uintptr` follows (padded to WORD alignment) - not parsed;
        # Phase 3 only needs the header through `type` for disambiguation.
    ),
)


# ---------------------------------------------------------------------------
# _func and functab (Phase 4 - Go function recovery)
# ---------------------------------------------------------------------------
# Verified against the local go1.26.2 install only (same documented scope
# decision as mspan in Phase 3 - see docs/architecture/go-runtime.md).
# Source: C:\Program Files (x86)\Go\src\runtime\runtime2.go, `type _func struct`.
#
# Only the fixed-size header (through `nfuncdata`) is declared here. The
# struct is immediately followed by two variable-length arrays
# (`pcdata [npcdata]uint32` and `funcdata [nfuncdata]uint32`, per the
# struct's own trailing doc comment) which are NOT part of this
# StructLayout - FunctionTableParser reads them separately, at
# `FUNC_GO1_26.size(ptr_size)` and beyond, using the decoded `npcdata`/
# `nfuncdata` counts.
FUNC_GO1_26 = StructLayout(
    layout_id="_func@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\runtime\runtime2.go (type _func struct, entryOff through nfuncdata)",
    fields=(
        # `sys.NotInHeap` is zero-sized - omitted, no offset effect.
        FieldSpec("entryOff", FieldKind.U32),  # start pc, offset from moduledata.text
        FieldSpec("nameOff", FieldKind.U32),  # signed int32 in source; stored/read as raw 4 bytes
        FieldSpec("args", FieldKind.U32),  # in/out args size (int32 in source)
        FieldSpec("deferreturn", FieldKind.U32),
        FieldSpec("pcsp", FieldKind.U32),
        FieldSpec("pcfile", FieldKind.U32),
        FieldSpec("pcln", FieldKind.U32),
        FieldSpec("npcdata", FieldKind.U32),
        FieldSpec("cuOffset", FieldKind.U32),
        FieldSpec("startLine", FieldKind.U32),  # int32 in source
        FieldSpec("funcID", FieldKind.U8),  # abi.FuncID = uint8
        FieldSpec("flag", FieldKind.U8),  # abi.FuncFlag = uint8
        FieldSpec("pad", FieldKind.U8),  # explicit 1-byte pad in source
        FieldSpec("nfuncdata", FieldKind.U8),
    ),
)

#: FUNCDATA_* indices into `_func`'s trailing `funcdata [nfuncdata]uint32`
#: array. Verified: internal/abi/symtab.go.
FUNCDATA_ARGS_POINTER_MAPS = 0
FUNCDATA_ARG_INFO = 5

#: `functab` element of `moduledata.ftab` - verified: runtime/symtab.go,
#: `type functab struct`. `entryoff` is relative to `moduledata.text`;
#: `funcoff` is relative to `moduledata.pclntable` (verified:
#: runtime/symtab.go `funcInfo` construction, e.g.
#: `datap.pclntable[datap.ftab[i].funcoff]`).
FUNCTAB_GO1_26 = StructLayout(
    layout_id="functab@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\runtime\symtab.go (type functab struct)",
    fields=(
        FieldSpec("entryoff", FieldKind.U32),
        FieldSpec("funcoff", FieldKind.U32),
    ),
)

#: `stackmap` header - verified: runtime/symtab.go, `type stackmap struct`.
#: Used for ArgsPointerMaps (pre-1.17 stack ABI) funcdata; only the header
#: is declared - `bytedata` is a variable-length trailing bitmap array
#: read separately using the decoded `n`/`nbit` counts.
STACKMAP_GO1_26 = StructLayout(
    layout_id="stackmap@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\runtime\symtab.go (type stackmap struct)",
    fields=(
        FieldSpec("n", FieldKind.U32),  # number of bitmaps (int32 in source)
        FieldSpec("nbit", FieldKind.U32),  # number of bits per bitmap (int32 in source)
    ),
)

#: Only one verified era, same scope decision as mspan (Phase 3).
FUNC_LAYOUTS_BY_GO_VERSION_RANGE: dict[str, StructLayout] = {
    "1.22+": FUNC_GO1_26,
}
FUNCTAB_LAYOUTS_BY_GO_VERSION_RANGE: dict[str, StructLayout] = {
    "1.22+": FUNCTAB_GO1_26,
}


# ---------------------------------------------------------------------------
# Phase 5 - Go goroutine recovery (paper Section 3.4)
# ---------------------------------------------------------------------------
#
# `runtime.g` (`runtime/runtime2.go`, local go1.26.2 install) is a large,
# GC/scheduler-internal struct - the same explicit single-era scope
# decision as `mspan` (Phase 3) and `_func` (Phase 4): verified only
# against the local go1.26.2 install, not re-verified across historical
# tagged releases. A Go version outside `"1.22+"` reports
# UNSUPPORTED_RUNTIME_LAYOUT, never a guessed offset.
#
# Only the struct PREFIX through `startpc` is declared - everything this
# phase's stated objectives (candidate discovery, validation, current
# PC/SP, stack bounds, status, wait reason, m pointer, goroutine-creation
# PC) actually need. Trailing fields (`racectx`, `waiting`, `cgoCtxt`,
# `labels`, `timer`, `sleepWhen`, `selectDone`, `goroutineProfiled`, ...)
# are deliberately NOT declared - CLAUDE.md section 40 / approved plan:
# "do not assume every field is needed". Fields between `waitreason` and
# `startpc` that this project does not directly consume (`preempt`,
# `paniconfault`, `gcscandone`, `writebuf`, `sigcode0/1`, `sigpc`, ...)
# are still declared as placeholder FieldSpec entries, because later
# fields' offsets are cumulative - `gopc`/`startpc` cannot be located
# without correctly accounting for every byte before them.
#
# Every field name/type/order below is transcribed directly from
# `runtime/runtime2.go`'s `type g struct` (stack/stackguard0/stackguard1/
# _panic/_defer/m/sched/syscallsp/syscallpc/syscallbp/stktopsp/param/
# atomicstatus/stackLock/goid/schedlink/waitsince/waitreason/preempt/
# preemptStop/preemptShrink/asyncSafePoint/paniconfault/gcscandone/
# throwsplit/activeStackChans/parkingOnChan/inMarkAssist/coroexit/
# raceignore/nocgocallback/tracking/trackingSeq/trackingStamp/
# runnableTime/lockedm/fipsIndicator/fipsOnlyBypass/ditWanted/
# syncSafePoint/runningCleanups/sig/secret/writebuf/sigcode0/sigcode1/
# sigpc/parentGoid/gopc/ancestors/startpc), `type gobuf struct` (sp/pc/g/
# ctxt/lr/bp), and `type stack struct` (lo/hi).
#
# This declared field list's byte offsets were independently
# cross-checked - not merely computed by this project's own
# alignment-aware `StructLayout` engine - against the REAL go1.26.2
# compiler: a throwaway Go program declaring a structurally identical
# struct (same field sizes/order, using local stand-in type names since
# `runtime.g`'s real types are unexported/internal to package runtime and
# cannot be imported) was compiled and run with the local `go1.26.2`
# toolchain, and its `unsafe.Offsetof`/`unsafe.Sizeof` output was
# compared field-by-field against this layout's `StructLayout.offsets()`
# computation (see `tests/unit/test_go_runtime_layouts.py::TestGLayout`
# for the exact expected offsets asserted from that verification run).
# `atomic.Uint32`/`atomic.Bool` (`internal/runtime/atomic/types.go`) were
# separately confirmed to be 4/1 bytes respectively (the wrapped
# `noCopy` marker type is zero-sized: `type noCopy struct{}`).
G_GO1_26 = StructLayout(
    layout_id="g@go1.26.2",
    source=r"Local go1.26.2 install: C:\Program Files (x86)\Go\src\runtime\runtime2.go (type g struct, stack through startpc; type gobuf struct; type stack struct)",
    fields=(
        FieldSpec("stack_lo", FieldKind.WORD),
        FieldSpec("stack_hi", FieldKind.WORD),
        FieldSpec("stackguard0", FieldKind.WORD),
        FieldSpec("stackguard1", FieldKind.WORD),
        FieldSpec("_panic", FieldKind.WORD),
        FieldSpec("_defer", FieldKind.WORD),
        FieldSpec("m", FieldKind.WORD),
        FieldSpec("sched_sp", FieldKind.WORD),
        FieldSpec("sched_pc", FieldKind.WORD),
        FieldSpec("sched_g", FieldKind.WORD),
        FieldSpec("sched_ctxt", FieldKind.WORD),
        FieldSpec("sched_lr", FieldKind.WORD),
        FieldSpec("sched_bp", FieldKind.WORD),
        FieldSpec("syscallsp", FieldKind.WORD),
        FieldSpec("syscallpc", FieldKind.WORD),
        FieldSpec("syscallbp", FieldKind.WORD),
        FieldSpec("stktopsp", FieldKind.WORD),
        FieldSpec("param", FieldKind.WORD),
        FieldSpec("atomicstatus", FieldKind.U32),
        FieldSpec("stackLock", FieldKind.U32),
        FieldSpec("goid", FieldKind.WORD),
        FieldSpec("schedlink", FieldKind.WORD),
        FieldSpec("waitsince", FieldKind.WORD),
        FieldSpec("waitreason", FieldKind.U8),
        FieldSpec("preempt", FieldKind.U8),
        FieldSpec("preemptStop", FieldKind.U8),
        FieldSpec("preemptShrink", FieldKind.U8),
        FieldSpec("asyncSafePoint", FieldKind.U8),
        FieldSpec("paniconfault", FieldKind.U8),
        FieldSpec("gcscandone", FieldKind.U8),
        FieldSpec("throwsplit", FieldKind.U8),
        FieldSpec("activeStackChans", FieldKind.U8),
        FieldSpec("parkingOnChan", FieldKind.U8),
        FieldSpec("inMarkAssist", FieldKind.U8),
        FieldSpec("coroexit", FieldKind.U8),
        FieldSpec("raceignore", FieldKind.U8),
        FieldSpec("nocgocallback", FieldKind.U8),
        FieldSpec("tracking", FieldKind.U8),
        FieldSpec("trackingSeq", FieldKind.U8),
        FieldSpec("trackingStamp", FieldKind.WORD),
        FieldSpec("runnableTime", FieldKind.WORD),
        FieldSpec("lockedm", FieldKind.WORD),
        FieldSpec("fipsIndicator", FieldKind.U8),
        FieldSpec("fipsOnlyBypass", FieldKind.U8),
        FieldSpec("ditWanted", FieldKind.U8),
        FieldSpec("syncSafePoint", FieldKind.U8),
        FieldSpec("runningCleanups", FieldKind.U8),
        FieldSpec("sig", FieldKind.U32),
        FieldSpec("secret", FieldKind.U32),
        FieldSpec("writebuf_ptr", FieldKind.WORD),
        FieldSpec("writebuf_len", FieldKind.WORD),
        FieldSpec("writebuf_cap", FieldKind.WORD),
        FieldSpec("sigcode0", FieldKind.WORD),
        FieldSpec("sigcode1", FieldKind.WORD),
        FieldSpec("sigpc", FieldKind.WORD),
        FieldSpec("parentGoid", FieldKind.WORD),
        FieldSpec("gopc", FieldKind.WORD),
        FieldSpec("ancestors", FieldKind.WORD),
        FieldSpec("startpc", FieldKind.WORD),
    ),
)

#: Only one verified era, same scope decision as mspan/_func.
G_LAYOUTS_BY_GO_VERSION_RANGE: dict[str, StructLayout] = {
    "1.22+": G_GO1_26,
}

#: Goroutine status constants, verified verbatim against
#: `runtime/runtime2.go`'s untyped status-constant block (`_Gidle = iota`
#: through `_Gdeadextra`), plus the `_Gscan` bit and its four OR'd
#: variants actually used by real code (`_Gscanrunnable`, `_Gscanrunning`,
#: `_Gscansyscall`, and - not explicitly listed with the others in source
#: but following the same `_Gscan + <base>` pattern - `_Gscanwaiting`).
#: `_Gscan` is a status *bit*, not a standalone state: real code masks it
#: off (`atomicstatus &^ _Gscan`) to get the status the goroutine will
#: return to once a concurrent stack scan completes - this project does
#: the same (see `goroutines.py`), reporting `is_scanning` separately
#: rather than silently discarding the bit.
G_STATUS_IDLE = 0
G_STATUS_RUNNABLE = 1
G_STATUS_RUNNING = 2
G_STATUS_SYSCALL = 3
G_STATUS_WAITING = 4
G_STATUS_MORIBUND_UNUSED = 5
G_STATUS_DEAD = 6
G_STATUS_ENQUEUE_UNUSED = 7
G_STATUS_COPYSTACK = 8
G_STATUS_PREEMPTED = 9
G_STATUS_LEAKED = 10
G_STATUS_DEADEXTRA = 11
G_SCAN_BIT = 0x1000

#: Base (post-`_Gscan`-mask) status value -> human-readable name. Verified
#: against the exact doc comments in `runtime/runtime2.go` for each
#: constant. `moribund_unused`/`enqueue_unused` are real, source-verified
#: constants (explicitly documented as "currently unused, but hardcoded
#: in gdb scripts" / "currently unused") - kept for completeness, not
#: invented.
G_STATUS_NAMES: dict[int, str] = {
    G_STATUS_IDLE: "idle",
    G_STATUS_RUNNABLE: "runnable",
    G_STATUS_RUNNING: "running",
    G_STATUS_SYSCALL: "syscall",
    G_STATUS_WAITING: "waiting",
    G_STATUS_MORIBUND_UNUSED: "moribund_unused",
    G_STATUS_DEAD: "dead",
    G_STATUS_ENQUEUE_UNUSED: "enqueue_unused",
    G_STATUS_COPYSTACK: "copystack",
    G_STATUS_PREEMPTED: "preempted",
    G_STATUS_LEAKED: "leaked",
    G_STATUS_DEADEXTRA: "deadextra",
}

#: `waitReason` (`runtime/runtime2.go`, `type waitReason uint8` + its
#: const block) transcribed verbatim, index = enum value, value = the
#: exact string Go's own `waitReasonStrings` table uses (verified against
#: both the const block's inline comments and the `waitReasonStrings`
#: array literal - the two independently agree for every entry checked).
#: Index 0 (`waitReasonZero`) is `""` - a real, valid "no wait reason"
#: value (the goroutine is not in `_Gwaiting`), not a decode failure.
G_WAIT_REASON_NAMES: tuple[str, ...] = (
    "", "GC assist marking", "IO wait", "dumping heap",
    "garbage collection", "garbage collection scan", "panicwait",
    "GC assist wait", "GC sweep wait", "GC scavenge wait",
    "finalizer wait", "force gc (idle)", "GOMAXPROCS updater (idle)",
    "semacquire", "sleep", "chan receive (nil chan)",
    "chan send (nil chan)", "select (no cases)", "select", "chan receive",
    "chan send", "sync.Cond.Wait", "sync.Mutex.Lock",
    "sync.RWMutex.RLock", "sync.RWMutex.Lock", "sync.WaitGroup.Wait",
    "trace reader (blocked)", "wait for GC cycle", "GC worker (idle)",
    "GC worker (active)", "preempted", "debug call",
    "GC mark termination", "stopping the world", "flushing proc caches",
    "trace goroutine status", "trace proc status", "page trace flush",
    "coroutine", "GC weak to strong wait", "synctest.Run",
    "synctest.Wait", "chan receive (durable)", "chan send (durable)",
    "select (durable)", "sync.WaitGroup.Wait (durable)", "cleanup wait",
)

#: `FuncFlag` bits (`internal/abi/symtab.go`), verified verbatim.
#: `FuncFlagTopFrame`: the traceback routine stops here and considers the
#: unwind successfully complete (e.g. `goexit`, `mstart`).
#: `FuncFlagSPWrite`: the function writes an arbitrary (non-constant)
#: value to SP - `pcsp` cannot encode this, so unwinding past such a
#: function is NOT safe and is explicitly not attempted here, matching
#: the real runtime's own documented stance ("stopping at an SPWrite
#: function is considered to be an incomplete unwinding of the stack").
FUNC_FLAG_TOP_FRAME = 0x01
FUNC_FLAG_SP_WRITE = 0x02
FUNC_FLAG_ASM = 0x04

#: `FuncID` values (`internal/abi/symtab.go`), verified verbatim -
#: identifies functions the real unwinder (`runtime/traceback.go`,
#: `gentraceback`) treats specially (stack-transition trampolines,
#: signal/panic/preemption entry points, ...). This project's unwinder
#: does not attempt to replicate that special-casing (approved plan:
#: "Do NOT implement special handling unless source-verified... mark it
#: unsupported/partial") - encountering one of these mid-unwind stops the
#: walk and reports it explicitly rather than silently misinterpreting
#: pcsp/return-address data that the real runtime treats as a special case.
FUNC_ID_NORMAL = 0
FUNC_ID_ABORT = 1
FUNC_ID_ASMCGOCALL = 2
FUNC_ID_ASYNC_PREEMPT = 3
FUNC_ID_CGOCALLBACK = 4
FUNC_ID_COROSTART = 5
FUNC_ID_DEBUG_CALL_V2 = 6
FUNC_ID_GC_BG_MARK_WORKER = 7
FUNC_ID_GOEXIT = 8
FUNC_ID_GOGO = 9
FUNC_ID_GOPANIC = 10
FUNC_ID_HANDLE_ASYNC_EVENT = 11
FUNC_ID_MCALL = 12
FUNC_ID_MORESTACK = 13
FUNC_ID_MSTART = 14
FUNC_ID_PANICWRAP = 15
FUNC_ID_RT0_GO = 16
FUNC_ID_RUNTIME_MAIN = 17
FUNC_ID_RUN_FINALIZERS = 18
FUNC_ID_RUN_CLEANUPS = 19
FUNC_ID_SIGPANIC = 20
FUNC_ID_SYSTEMSTACK = 21
FUNC_ID_SYSTEMSTACK_SWITCH = 22
FUNC_ID_WRAPPER = 23

#: FuncIDs the unwinder treats as an explicit stop-with-reason boundary,
#: beyond the FuncFlag checks above - defense in depth, not a substitute
#: for them (approved plan Step: "do not implement special handling
#: unless source-verified" - each of these is a real, named
#: runtime/traceback.go special case, not an invented heuristic set).
FUNC_IDS_REQUIRING_SPECIAL_UNWIND_HANDLING = frozenset(
    {
        FUNC_ID_MORESTACK,
        FUNC_ID_SYSTEMSTACK,
        FUNC_ID_SYSTEMSTACK_SWITCH,
        FUNC_ID_ASYNC_PREEMPT,
        FUNC_ID_SIGPANIC,
        FUNC_ID_GOGO,
        FUNC_ID_MCALL,
        FUNC_ID_ASMCGOCALL,
        FUNC_ID_CGOCALLBACK,
        FUNC_ID_DEBUG_CALL_V2,
    }
)
