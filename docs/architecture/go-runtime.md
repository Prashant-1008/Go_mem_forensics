# Go Runtime Detection (Phases 2-4)

**Status: Phase 4 - Go Function Recovery.** Covers
`gomemforensics.go_runtime`: pclntab discovery, pcHeader validation, Go
version detection, moduledata discovery/validation (Phase 2), Go string
recovery - heap-based (allspans/mspan/allocation bitmap) and
static-section header scanning (Phase 3), and Go function recovery -
`ftab`/`_func` metadata, pctab PC-value decoding, source/package
classification, ArgInfo/ArgsPointerMaps argument *shape*, and (x86-64
only, ABI era permitting) Capstone-based backward call-site argument
*value* analysis (Phase 4). Goroutine recovery (allgs discovery, `g`
validation, and x86-64 pcsp-based stack unwinding) is a separate Phase 5
subsystem, built directly on top of this one's function-table metadata -
see `docs/architecture/go-goroutines.md`, not documented here.

Terminology is kept aligned with the reference paper ("Memory Forensics
Techniques for Automated Detection and Analysis of Go Malware") throughout
this document, per CLAUDE.md section 41.

## Source of truth for struct layouts

Every struct offset used by this subsystem is transcribed from real Go
runtime source, never invented (CLAUDE.md section 40). Two kinds of
sources were used, both recorded per-layout in
`gomemforensics.go_runtime.layouts`:

1. **The local installed toolchain** - `go1.26.2` at
   `C:\Program Files (x86)\Go\src\runtime\symtab.go` and
   `...\src\internal\abi\symtab.go` (verified via `go version` /
   `go env GOROOT`).
2. **Specific tagged releases fetched from
   `https://raw.githubusercontent.com/golang/go/<tag>/src/runtime/symtab.go`**
   - `go1.17.13`, `go1.19.13`, `go1.20.14`, `go1.21.13` - fetched and read
   in full to verify how `pcHeader`/`moduledata` actually differed across
   the magic-byte-family boundaries the paper documents, rather than
   assuming the current toolchain's shape applied unchanged to older
   versions.

This second step mattered: naively assuming the locally-installed
`go1.26.2` layout applied to all Go 1.20+ binaries would have been wrong.
Fetching `go1.20.14` and `go1.21.13` revealed that `moduledata` gained an
extra `epclntab` field *within* the single `Go120PCLnTabMagic` (`0xfffffff1`)
magic family, sometime after `go1.21.13` and at or before `go1.26.2` - a
real, source-confirmed drift that a fixed offset table would have gotten
silently wrong for a meaningful slice of real-world binaries.

## pclntab / pcHeader

Per the paper (Section 3.1): `pclntab` (program counter line table) begins
with a `pcHeader` structure containing version-identifying magic bytes,
`minLC` (minimum instruction size), `ptrSize`, `nfunc`/`nfiles` counts, and
offsets to `funcnametab`/`cutab`/`filetab`/`pctab`/`pclntable`.

**Two verified `pcHeader` eras** (`gomemforensics.go_runtime.layouts.PCHEADER_PRE_1_18`
/ `PCHEADER_1_18_PLUS`): Go 1.18 inserted one extra `uintptr` field
(originally `textStart`, later reduced to an unused placeholder - a
semantic change only, confirmed identical in size/position across
`go1.19.13`, `go1.20.14`, `go1.21.13`, and local `go1.26.2`). This exactly
matches the paper's own note that `textStart` was introduced in Go 1.18.

**Magic bytes** (`gomemforensics.go_runtime.version`), verified against
`internal/abi/symtab.go`:

| Magic (LE bytes) | Value | Go versions | Paper reference |
|---|---|---|---|
| `\xfb\xff\xff\xff` | `0xfffffffb` | 1.2-1.15 | Section 3.1.1 |
| `\xfa\xff\xff\xff` | `0xfffffffa` | 1.16-1.17 | Section 3.1.1 |
| `\xf0\xff\xff\xff` | `0xfffffff0` | 1.18-1.19 | Section 3.1.1 |
| `\xf1\xff\xff\xff` | `0xfffffff1` | 1.20+ (confirmed current as of local go1.26.2 - `CurrentPCLnTabMagic = Go120PCLnTabMagic`) | Section 3.1.1 |

**Discovery** (`PclntabParser`): scans read-only/executable process
regions (never the full virtual address space - regions come from
`VolatilityIntegration.get_process_regions`) for these magic byte
sequences. Every magic match is validated against `pcHeader` invariants
before being trusted - never accepted as proof on its own (paper Section
3.1.1). **This is not hypothetical**: scanning the project's own compiled
benign fixture binary (`tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe`,
built with the local go1.26.2 toolchain) for just the Go 1.20+ magic finds
it 7 times; only 1 of those 7 satisfies the invariants below - see
`tests/integration/test_go_runtime_real_fixture.py`.

**Validated invariants** (`validate_pc_header`, paper Section 3.1.1):

- `pad1 == 0`, `pad2 == 0`
- `minLC ∈ {1, 2, 4}`
- `ptrSize ∈ {4, 8}`, and must match the process's actual architecture
- `nfunc`, `nfiles` within a plausibility bound

The plausibility bound (`_MAX_PLAUSIBLE_COUNT = 5,000,000`) is explicitly
**not** a Go runtime invariant - the real runtime has no such cap - it is
a safety/plausibility bound to reject obviously-garbage candidates, and is
documented as such in the code rather than presented as a language fact.

**Structure-based fallback**: when no magic-validated candidate exists in
a process, an aligned-address sweep applies the same `pcHeader` invariants
without requiring a recognized magic value (paper Section 3.1.1,
"structure-based pclntab location"). Results are tagged
`magic_not_detected_structural_candidate` and capped at `LOW` confidence -
this is explicitly **not** claimed to defeat all obfuscation, only to
recover a structurally-plausible candidate when the magic itself has been
corrupted or stripped.

**Detection status taxonomy** (`PclntabDetectionStatus`): `magic_detected`,
`magic_not_detected_structural_candidate`, `unknown` - exactly the three
states requested by the approved plan.

## Go version detection

`GoVersionDetector` (paper Section 3.1.3): primary evidence is the
validated `pcHeader`'s magic value, mapped to the version range table
above. **No exact patch version is ever invented** - if the evidence
supports "Go 1.20+", the tool reports `"1.20+"`, never a fabricated
`"1.20.7"`.

**Moduledata-era refinement**: within the single `0xfffffff1` magic
family, `moduledata`'s shape itself differs (the `epclntab` field - see
above), so successfully matching one `moduledata` layout over another is
itself real structural evidence. `GoVersionDetector.refine_with_moduledata_layout`
narrows `"1.20+"` to `"1.20-1.21"` or `"1.22+"` accordingly - this is
matching-by-structure, not a guess, and only ever narrows an
already-evidence-backed range.

`GoRuntime.go_version` reports whichever is more precise: an exact
version if one is ever pinned down (not currently possible from
`pcHeader`/`moduledata` alone) or otherwise the version range string.

## moduledata

Per the paper (Section 3.1): located by scanning writable regions for a
pointer value equal to the already-recovered `pcHeader` address (the
first field of `moduledata` is literally `*pcHeader` in every verified
layout), then validated via ordered region bounds (`text <= etext`, etc.)
and well-formed slice headers (`len <= cap`).

**Four verified `moduledata` eras**
(`gomemforensics.go_runtime.layouts.MODULEDATA_1_16_17` /
`_1_18_19` / `_1_20_EARLY` / `_1_22_PLUS`):

| Era | Magic family | vs. previous era |
|---|---|---|
| 1.16-1.17 | `0xfffffffa` | baseline |
| 1.18-1.19 | `0xfffffff0` | `+rodata`, `+gofunc` |
| 1.20-~1.21 | `0xfffffff1` | `+covctrs`, `+ecovctrs` |
| ~1.22+ | `0xfffffff1` (same magic!) | `+epclntab` |

Because the last two eras share one magic value,
`ModuledataParser` tries `MODULEDATA_GO120_FAMILY_CANDIDATES` (most-recent
first) against every pointer match and accepts whichever one passes full
structural validation - never assumes the newer shape just because it is
more common. This is documented, not silent, magic-family ambiguity
handling.

**A single pointer match is never accepted as proof** - `ModuledataValidator`
checks:

- the located candidate's own `pcHeader` field equals the anchor address
- `text <= etext`, `data <= edata`, `bss <= ebss`, `types <= etypes`
- `typelinks.len <= typelinks.cap`, `itablinks.len <= itablinks.cap`
- `text`/`data` are non-null
- no span exceeds a 4 GiB plausibility bound (again, a safety bound, not a
  language invariant)

**Fields not recoverable from `moduledata` as a real struct fact, not a
gap in this implementation**: `moduledata` has exactly one `rodata`
field (a start address) with **no corresponding `erodata` field in any
verified era** - `GoRuntime.rodata_end` is therefore always `None`, by
design, reflecting the real struct shape rather than a missing feature.
`typelinks_end`/`itablinks_end` *are* computed (from the slice's
`ptr + len * element_size`, where `typelinks` elements are 4-byte
`int32` offsets and `itablinks` elements are pointer-sized), since that
is a real, derivable fact from the recovered slice header.

## Runtime layout system

`gomemforensics.go_runtime.layouts.StructLayout` computes byte offsets
mechanically from a declared field order and a target pointer size - no
offset is ever hand-typed as a magic number. `pcHeader`/`moduledata`'s
field kinds (`MAGIC_U32`, `WORD`, `SLICE`, `STRING`) happen to already be
naturally aligned given their preceding fields on both 32-bit and 64-bit
targets, so Phases 2-3 used a simple cumulative-offset computation.
**Phase 4 required making this alignment-aware** (each field is placed at
the next offset that is a multiple of `min(field_size, pointer_size)`,
matching real Go compiler struct layout rules) once `_func`'s mixed
`U32`/`U8` fields were declared - a naive cumulative sum would have
mis-placed every field after the first `uint8` run. The alignment-aware
version is a strict superset (produces identical offsets for every
already-aligned Phase 2-3 layout; the full regression suite is the
evidence for that, not an assumption).

Layouts are keyed by **Go version era x architecture**. At Phase 2, only
x86-64 (`pointer_size=8`) is exercised end-to-end; the same `StructLayout`
objects also compute correct 32-bit (`pointer_size=4`) offsets (tested in
`tests/unit/test_go_runtime_layouts.py`), but nothing in this phase
exercises that against a real 32-bit image.

## Memory region abstraction

`gomemforensics.common.memory.MemoryRegion` (start, end, readable,
writable, executable, source) is OS-independent. The Go runtime detection
layer depends only on `MemoryReader` + `list[MemoryRegion]` - never on
Volatility internals directly (approved plan Section 9). Region
enumeration itself is implemented in
`VolatilityIntegration.get_process_regions`, using:

- **Windows**: `EPROCESS.get_vad_root().traverse()`, `VAD.get_start()`/
  `get_end()`/`get_protection()` (via `VadInfo.protect_values` +
  `winnt_protections`, all verified against
  `volatility3/plugins/windows/vadinfo.py`).
- **Linux**: `mm_struct.get_vma_iter()`, `vma.vm_start`/`vm_end`/
  `get_protection()` (verified against
  `volatility3/framework/symbols/linux/extensions/__init__.py`).

`PclntabParser` scans regions that are readable and (read-only or
executable); `ModuledataParser` scans regions that are readable and
writable - matching the paper's own region-targeting strategy rather than
scanning full virtual address space.

## Scanning resilience

A region's declared bounds (from a VAD/VMA) do not guarantee every byte in
that range is actually readable - Windows VADs in particular can span
committed and reserved-but-inaccessible sub-ranges. `gomemforensics.go_runtime.scanning.iter_readable_chunks`
degrades a failed chunk read (retrying at a smaller size, down to a 4 KiB
floor) rather than aborting the scan of an otherwise-valid region -
discovered and regression-tested via a real edge case hit while building
the test suite (a chunk read spanning past the end of a small backing
region).

## Confidence model

`GoProcessDetector` (approved plan Section 10):

- **HIGH**: a magic-validated `pcHeader` AND a structurally-validated
  `moduledata` were both recovered.
- **MEDIUM**: a magic-validated `pcHeader` was recovered, but no
  `moduledata` candidate validated.
- **LOW**: only a structural (non-magic) `pcHeader` candidate validated.
- **UNKNOWN**: nothing validated.

`ProcessInfo.is_go_candidate` is only ever set `True` for HIGH/MEDIUM - a
structural-only (LOW) match never flips a process to "confirmed Go"
(CLAUDE.md: "a magic-byte match... must not automatically become a
confirmed Go process").

## Multiple candidates

Every `pclntab`/`moduledata` candidate (accepted or rejected) is kept, not
discarded, with `candidate_id`, `address`, `magic`/`version_hint`,
`validation_errors`, `confidence`, and `rejection_reason` (approved plan
Section 11). The "best" candidate is selected only by evidence-based
ranking (magic-validated over structural-only), never "first found" as a
default; ties resolve to encounter order only because no other evidence
distinguishes them, and the rejected candidates remain visible in
`go_candidates` in the JSON output.

## Go string recovery (Phase 3)

Implements the paper's `go_strings` methodology (Section 3.2, Figure 2).
Struct sources for this phase (all verified against the local `go1.26.2`
install only - see "mspan: single verified era" below):
`C:\Program Files (x86)\Go\src\runtime\mheap.go` (`type mspan struct`,
`type gcBits struct`, `type spanClass`, `type mSpanStateBox`),
`...\src\internal\abi\type.go` (`type Type struct`, the modern `_type`),
and `...\src\internal\abi\iface.go` (`type ITab struct`).

### Type metadata (minimal subset)

`gomemforensics.go_runtime.types.TypeParser`/`TypeIndex` implement only
what size-to-type mapping needs (paper Section 3.1.4): `_type.Size_`,
`PtrBytes`, and `Kind_` (masked with `TYPE_KIND_MASK = 0x1F` to strip the
`KindDirectIface` flag bit - verified: `internal/abi/type.go`,
`KindDirectIface Kind = 1 << 5`). No kind-specific metadata
(`uncommonType`, struct field descriptors, method sets) is parsed - "do
not build the entire Go type system in this phase."

`TypeIndex` is a `size -> [TypeDescriptor, ...]` map, never collapsed to
one type per size (paper: "multiple types may share the same size").
`build_type_index` populates it by walking `moduledata.typelinks`
(`[]int32` offsets from `moduledata.types` - verified field comment in
`runtime/symtab.go`), bounded by `MAX_TYPES_INDEXED`. If Phase 2 did not
recover `types_start`/`typelinks_start`/`typelinks_end` (moduledata not at
HIGH confidence), the index is simply empty - not an error; string
recovery still proceeds without type-based corroboration.

### allspans discovery

`gomemforensics.go_runtime.mspan.AllspansParser` scans writable memory
(the recovered module's own `data`/`bss` bounds when available, from
Phase 2's `GoRuntime` - narrower and paper-aligned: "locate the allspans
slice header within the .data or .bss sections"; falls back to any
writable region otherwise) for `(ptr, len, cap)`-shaped headers. A
candidate is validated by: pointer alignment and non-null, `len <= cap`
within a plausibility bound, and - critically - sampling up to
`MAX_SPAN_SAMPLE` of its entries and requiring at least
`MIN_VALID_SAMPLE_RATIO` (50%) to structurally decode as plausible
`mspan` values (paper Figure 2: "valid mspan ptrs"). A bare pointer match
is never accepted alone. Multiple candidates are preserved
(`AllspansCandidate`, accepted or rejected); `select_best_allspans_candidate`
picks the most-validated one by evidence, never "first found".

### mspan: single verified era

`gomemforensics.go_runtime.layouts.MSPAN_GO1_26` is the **only** verified
`mspan` layout, checked against the local `go1.26.2` install alone - an
explicit, documented scope decision, unlike `pcHeader`/`moduledata` which
have multiple verified eras. Reasons: `mspan` is a much larger, more
volatile, GC-internal struct (its shape changes far more often across Go
releases than the paper's own `pcHeader`/`moduledata` snapshot), and its
mixed field types (`uint16`, `uint32`, `uint8`, `bool`, wrapped atomics)
required independently confirming several non-obvious intermediate sizes
before the target field (`elemsize`) offset could be trusted (see the
layout's own field-by-field source comments). Extending to another
verified era is future work, not attempted here.
`resolve_mspan_layout(go_version_range)` returns `(None, None)` -
surfaced as an `UNSUPPORTED_RUNTIME_LAYOUT` error, never a guess - for any
Go version range outside `"1.22+"`.

Only the struct prefix through `elemsize` is declared (everything string
recovery needs: `startAddr`, `nelems`, `allocBits`, `allocCount`,
`spanclass`/`state`, `elemsize`); trailing GC/allocator-internal fields
are not parsed.

### Allocation bitmap traversal

`gomemforensics.go_runtime.mspan.MspanWalker` decodes each in-use
(`state == mSpanInUse == 1`, matching the paper's Figure 2 caption
exactly) span's allocation bitmap and computes live object addresses as
`object_addr = startAddr + (bit_index * elemsize)` (paper Figure 2,
verbatim formula), reading bit *n*'s allocation state per the verified
source comment in `runtime/mheap.go` (`allocBits[n/8] & (1<<(n%8))` != 0
=> allocated). A truncated bitmap read (e.g. a span straddling an
unreadable page) still yields whatever prefix of bits *is* readable
rather than discarding the whole span; one malformed span is recorded as
a recoverable `AnalysisError` and does not stop the rest of the walk
(CLAUDE.md section 24).

### Heap string interpretation - scope decision

Only heap objects whose size is **exactly two machine words** are
interpreted as string-header candidates - the paper's own primary
disambiguation case ("For objects whose size equals two machine words...").
**Recursive field-walking into larger composite types** (arrays/slices of
strings, structs with string fields, maps) that the paper also describes
is **not implemented** in this phase - it requires the fuller Go type
system (`uncommonType`, struct field metadata) explicitly out of scope.
Documented here as a scope limitation, not a silent gap.

For a two-word object, `gomemforensics.go_runtime.strings._looks_like_itab`
implements the paper's interface/string disambiguation (Section 3.1.5/3.2.1):
reads the first word as a candidate `itab` pointer and checks its `Type`
field is itself readable and `_type`-shaped. This is evidence, not proof
(approved plan Section G) - a false negative just means a real interface
value gets (harmlessly) excluded from string candidacy; there is no
recursive interface-payload unwrapping in this phase.

### String header validation

`gomemforensics.go_runtime.strings.validate_string_header` reads the
pointer size from the caller-supplied architecture pointer size (never
hardcoded to 8 - Section F of the approved plan), and validates: length
non-negative and within a plausibility bound (`MAX_STRING_LENGTH`), data
pointer non-null and mapped, and the full backing byte range readable.
**UTF-8 validity is a signal, not an absolute requirement**: a candidate
that fails strict UTF-8 decoding but is still >= `MIN_PRINTABLE_RATIO`
(85%) printable is still accepted, at lower confidence - documented
decision, since a Go string is only guaranteed to be a byte sequence, and
a malware sample's deliberately-obfuscated buffer is exactly the kind of
non-UTF-8-but-meaningful data this tool must not silently discard. An
empty string (`length == 0`) is always a legitimate, valid result, never a
rejection.

### Static-section recovery

`StringRecoveryEngine.recover_static_strings` is a structurally separate
method from the heap path (never merged): it scans readable, non-pure-executable
regions for aligned `(ptr, len)` pairs and validates them with the exact
same content checks as the heap path, but **never at HIGH confidence**
(paper: static headers are pattern-derived, not allocator-validated
evidence) - capped at MEDIUM (UTF-8) or LOW (printable-only fallback).

### Confidence model (strings)

- **HIGH** (heap only): validated live allocation, valid two-word object,
  content-validated (UTF-8), **and** the size-matched type index confirms
  a `String`-kind candidate at that size (strongest evidence).
- **MEDIUM**: content-validated (UTF-8) but without a confirmed
  `String`-kind type match (heap: ambiguous or no type metadata; static:
  always, when UTF-8).
- **LOW**: content passed only the printable-ratio fallback (not valid
  UTF-8).
- Rejected candidates are never emitted as artifacts; rejection reasons
  are logged at DEBUG level (approved plan Section F: "record why they
  were rejected if debug/verbose diagnostics are enabled"), not silently
  dropped.

### Deduplication / grouping

`string_address` (the header's own location) is always unique per
artifact - each header is distinct evidence. Artifacts that share a
`data_address` (the same backing bytes - e.g. a string copy, or two
static headers referencing one constant) are cross-linked via
`provenance.related_artifacts` in a deterministic post-pass
(`pipeline._link_shared_backing_strings`), keyed strictly on
`data_address` - never on the recovered `value` alone (two artifacts with
coincidentally-equal values but different backing addresses are
independent evidence and are not linked).

### Scanning resilience (extended)

The alignment bug class described below in "Scanning resilience" applies
identically to the allspans pointer scan and the static header scan - both
were fixed the same way (align the first candidate position to the
*absolute* address, not the chunk-relative index) while building this
phase's tests.

## Go function recovery (Phase 4)

Implements the paper's `go_functions` methodology (Section 3.3):
`moduledata.ftab` → `_func` → `funcnametab`/`filetab`/`cutab` (name and
source position, resolved **without any OS/ELF/PE symbol table** - the
central design goal, verified end-to-end against the real fixture binary
below) → pctab-decoded PC-value tables → source-path-based classification
→ (x86-64, ABI-permitting) `funcdata`-declared `ArgInfo`/`ArgsPointerMaps`
argument shape → Capstone backward-disassembly argument *value* evidence.

### `_func`/`functab`: single verified era, alignment-aware layouts

`gomemforensics.go_runtime.layouts.FUNC_GO1_26`/`FUNCTAB_GO1_26` are the
**only** verified layouts, checked against the local `go1.26.2` install's
`runtime/runtime2.go` (`type _func struct`) - the same explicit
single-era scope decision as Phase 3's `mspan` (see above), for the same
reason: `_func` mixes `uint32`/`uint8` fields, so unlike `pcHeader`/
`moduledata` (whose fields all happened to already be naturally aligned),
correctly computing `_func`'s real byte offsets required making
`StructLayout.offsets()`/`.size()` **alignment-aware** (each field placed
at the next offset that is a multiple of `min(field_size, pointer_size)`,
matching real compiler struct layout rules) - a genuine engine extension
made in this phase, not merely a new layout declaration.
`resolve_func_layout(go_version_range)` returns `(None, None)` -
surfaced as `UNSUPPORTED_RUNTIME_LAYOUT`, never guessed - outside
`"1.22+"`.

### Function table walk

`gomemforensics.go_runtime.functab.FunctionTableParser` walks
`moduledata.ftab` (bounded by `MAX_FUNCTIONS_PARSED`), decoding each
`_func` record and resolving its name via `funcnametab` and its source
file/line via the pctab `pcfile`/`pcln` streams and `cutab`/`filetab`. One
malformed `_func` record (truncated read, invalid name/file offset,
impossible PC delta) is recorded as a recoverable `AnalysisError` and
never aborts the rest of the walk (CLAUDE.md section 24); entries are
deterministically deduplicated by entry PC.

### pctab PC-value decoder

`gomemforensics.go_runtime.pctab` is a **faithful transcription** of the
real runtime's PC-value delta-stream format - unsigned-LEB128 varints,
zigzag-encoded value deltas, `PCQuantum=1` for amd64 - not a heuristic
approximation. `pc_value()` walks forward from a stream's declared
`table_offset` (verified sentinel: `0` means "no table"), bounded by
`MAX_PCTAB_STEPS` against a malformed/never-terminating stream. Verified
against 25 hand-calculated synthetic cases (`tests/unit/test_pctab.py`).

**Real-fixture bug found and fixed by this phase's own validation work**:
the first working version of `FunctionTableParser._resolve_file_line`
read a single *fixed* 64 KiB window starting at the pctab blob's base
address, then indexed into it using each function's raw `pcfile`/`pcln`
stream offset. This is correct only for functions whose streams happen to
sit within the first 64 KiB of a (potentially multi-hundred-KiB, real)
pctab blob. Validating against the real compiled fixture binary (not just
synthetic buffers) surfaced this directly: names resolved correctly for
every function, but `source_file`/`classification` silently came back
`None`/`UNKNOWN` for `main.*`, `strings.*`, and most `runtime.*`
functions (whose streams sit well past 64 KiB), while early-table
`internal/abi.*` functions resolved fine - exactly the kind of
sample-size-dependent bug CLAUDE.md section 26 warns about ("a parser
must not be considered reliable merely because it works on one sample").
**Fix**: `_pc_value_for_stream` now reads a small, bounded window starting
*at* (one byte before, to preserve the `table_offset==0` sentinel
convention) each stream's own declared offset - scales with the actual
evidence instead of guessing a fixed bound, and avoids re-reading a large
shared prefix for every function. See `tests/integration/test_go_runtime_function_fixture.py`.

**Phase 4.1 correction - `first` flag semantics.** A follow-up audit
directly compared `pc_value()`'s loop against the real
`runtime/symtab.go` `pcvalue` source and found a second, independent
divergence: the real implementation recomputes `first := pc ==
f.entry()` fresh on *every* loop iteration (a value-based check), while
this project's version treated `first` as a one-time flag (`True` only
for the literal first loop pass, `False` forever after) - an
iteration-based approximation. The two differ only when a step's PC-delta
is `0` (the function's `pc` stays at `entry_pc`, so the real algorithm's
*next* step is still "first" too); an iteration-based `first` then
misreads a legitimate zero value-delta byte in that next step as the
stream terminator, silently losing every subsequent answer. This edge
case was not observed in the project's real compiled fixture or any other
real Go output - it was found by direct source comparison, not by a
failing test, and is not claimed to occur in practice. **Fixed**:
`pc_value()` now recomputes `first = (pc == entry_pc)` on every
iteration, matching the real algorithm exactly; the constructed edge case
that would have diverged under the old logic is regression-tested in
`tests/unit/test_pctab.py::TestPcValueFirstStepSemantics`, which also
includes a local re-implementation of the old (incorrect) behavior to
demonstrate the concrete divergence rather than merely asserting the new
answer in isolation.

### Classification

`gomemforensics.go_runtime.classification.classify_function_path`
(paper Section 3.3.2) is a deterministic, path-prefix-only function of
the *recovered source path alone* - never the function's name
(CLAUDE.md section 7/20: never infer anything from a name alone).
Categories: `runtime`, `runtime_internal` (paper's two named examples,
`internal/abi`/`internal/cpu`, plus the small set of directly analogous
packages actually present in the local GOROOT's `src/internal/`),
`stdlib`, `third_party` (`vendor/` or a domain-shaped path segment),
`application`, `unknown`. The public stdlib package-name set is the
literal directory listing of the local `go1.26.2` install's `src/`, not
invented.

**Confirmed against real compiled output, not just synthetic paths**
(`tests/integration/test_go_runtime_function_fixture.py`): the fixture's
own `main.*` functions classify `APPLICATION`; `strings.ToUpper`
classifies `STDLIB`; genuinely `runtime`-sourced functions (`runtime.main`,
`runtime.gopanic`, `runtime.newobject`) classify `RUNTIME`. Notably,
several functions **named** `runtime.X` (e.g. `runtime.mapaccess1_fast32`,
`runtime.memequal`) classify `RUNTIME_INTERNAL` because their *real*
source lives in `internal/runtime/maps`/`internal/bytealg` (Go's
linkname-based ABI compatibility naming) - confirming the classifier is
genuinely evidence-based on path, not silently keying off the name.

### Argument shape: ArgInfo / ArgsPointerMaps

`gomemforensics.go_runtime.arginfo.decode_arg_info` decodes the
`FUNCDATA_ArgInfo` bytecode (Go ≥1.17) - verified against both the real
*consumer* (`runtime/traceback.go`, `printArgs`) and the real *encoder*
(`cmd/compile/internal/ssagen/ssa.go`, `EmitArgInfo`), which settles which
types are wrapped in `StartAgg`/`EndAgg` (string, slice, interface, array,
complex, non-SIMD struct) versus emitted as a single leaf. **Critical
semantic point** (verified: `cmd/compile/internal/abi/abiutils.go`,
`ABIParamAssignment.FrameOffset`): ArgInfo's per-leaf "offset from FP" is
a *unified* frame view - for a register-assigned argument it is an
**uninitialized spill-slot offset**, not a live value location. ArgInfo
therefore only ever gives argument *shape* (leaf count/sizes, aggregate
grouping) here, never a value - recovering an actual value requires the
separate backward-analysis path below. `read_stackmap` structurally parses
the pre-1.17 `ArgsPointerMaps` `stackmap` header/bitmap, but - per the
paper's own acknowledged limitation (Section 3.3.3) - does not attempt to
infer individual argument boundaries from the raw bitmap (that needs
additional Go type-layout knowledge out of scope here), so it is reported
as a single `EXPERIMENTAL` summary artifact, not fabricated per-argument
boundaries.

**Confirmed against the real fixture binary**: `main.fixtureArgMulti(a
int, b string, c bool)` decodes to exactly the expected shape - one
scalar leaf (`a`), one 2-leaf aggregate (`b`, the string's ptr+len), one
scalar leaf (`c`).

### x86-64 ABI abstraction

`gomemforensics.architecture.x86_64` owns every amd64-specific fact used
by argument recovery - register names, the verified 9-register
ABIInternal integer argument sequence (`RAX, RBX, RCX, RDI, RSI, R8, R9,
R10, R11`, from the local `go1.26.2` install's own
`cmd/compile/abi-internal.md`), and `assign_integer_argument_locations`,
a direct implementation of the verified register-assignment algorithm
(each argument assigned entirely to registers or entirely to the stack;
a spilled argument does **not** consume registers a later, smaller
argument could still use). `is_register_based_abi(go_version_range)`
selects Go's pre-1.17 stack ABI0 vs. ≥1.17 register-based ABIInternal as
two **architecturally distinct strategies**, never merged with swapped
constants (CLAUDE.md section 7/approved-plan Step 9) - and returns
`None` (never guesses) for the one version range this project cannot
confidently place on either side of the 1.17 boundary
(`"1.16-1.17"`, the widest magic-based range distinguishable at all).

**Phase 4.1 correction - actually integrated into the recovery
pipeline.** Through the end of Phase 4, `assign_integer_argument_locations`
was implemented and unit-tested but had zero production call sites: ArgInfo
shape decoding (`functab.py`) and Capstone value recovery
(`backward_analysis.py`) were two disconnected paths, and backward
analysis instead swept every one of the 9 ABI-sequence registers that
happened to hold a determined value, reporting each as "argument N"
regardless of whether the callee actually had that many arguments. A
follow-up audit found this by direct source review (not a failing test)
and it is now corrected: `functab.py`'s `_resolve_argument_locations`
calls `assign_integer_argument_locations` on every function's decoded
ArgInfo leaves and stores the result as
`FunctionArtifact.argument_locations` - a new
`gomemforensics.go_runtime.models.ArgumentLocation` list, one entry per
argument leaf, each carrying `argument_index`, `leaf_index`, and its
resolved `register`/`stack_offset`. This is a third, distinct pipeline
stage, never collapsed with the other two: "argument shape known"
(`ArgInfoArgument`/`ArgInfoLeaf` - offsets only) → **"ABI location known"
(`ArgumentLocation` - a specific register/stack slot, no value yet)** →
"argument value known" (`ArgumentArtifact` - an actual value at one call
site, or nothing at all).

`argument_locations` is `None` when the ABI-mapped shape was never
determined (non-x86-64, ABI0/ambiguous era, or a callee with no ArgInfo
funcdata - only `ArgsPointerMaps`, which has no per-leaf boundaries),
distinct from `[]`, which means "determined, and this function genuinely
takes zero mappable arguments" - the two are never conflated.

### Capstone backward call-site analysis

`gomemforensics.go_runtime.backward_analysis` (x86-64 only) locates every
`CALL` instruction within a function and simulates register/stack state
across the backward window using a small set of controlled instruction
patterns: `mov reg, imm` (constant/zero), `mov reg1, reg2` (register
propagation, confidence/status downgraded past `MAX_TRUSTED_COPY_HOPS`),
`lea reg, [rip+disp]` (RIP-relative static address - classified by
matching a recovered `StringArtifact`'s `data_address` when possible,
otherwise by reading and printable-ratio-scoring the backing bytes), `xor
reg, reg` (zero), and `mov [rsp+disp], src` (Go ABI0 stack-argument
writes). Any other instruction that writes a tracked register invalidates
it - a value derived from an unrecognized instruction is never reported.
The backward walk never crosses an earlier `CALL` (Go's convention
clobbers argument registers on every call) or the function's own entry
PC, and is capped at `MAX_WINDOW_INSTRUCTIONS`.

**Phase 4.1 correction - reporting is now driven by the callee's own
shape, not a blanket sweep.** State simulation itself is unchanged (pure
evidence-gathering), but a value is only ever *reported* - as a specific
"argument N, leaf M" - for a location the target function's own
`ArgumentLocation` list (see above) actually declares. When the call
target is unresolved (indirect call), or resolved but its argument shape
is unavailable, `CallSiteArtifact.recovered_arguments` is always empty
and `CallSiteArtifact.argument_analysis_status` is `UNSUPPORTED` - a live
register or stack value observed in that case is **never** reported as an
argument merely because it holds a value. `argument_analysis_status =
SUPPORTED` (even with zero recovered arguments, for a genuine
zero-argument callee) means the callee's shape *was* known and examined;
this is a call-site-level fact, distinct from whether any individual
argument's *value* was actually recovered.

Every recovered `ArgumentArtifact` carries an explicit
`ArgumentRecoveryStatus` (`SUPPORTED`/`EXPERIMENTAL`/`UNSUPPORTED`) -
independent of `Confidence` - so the two questions ("is this specific
result trustworthy" vs. "is this technique trustworthy for the situation
encountered") are never conflated. A location derived from a truncated
ArgInfo shape (`ArgumentLocation.confidence != HIGH`) caps the resulting
artifact's status to `EXPERIMENTAL` regardless of how cleanly the
instruction pattern itself matched - a value is never reported as more
certain than the shape that told the analyzer where to look.

**Confirmed against the real fixture binary, more thoroughly than
initially reported.** The original Phase 4 write-up highlighted only two
real call sites (`main.fixtureOuter`'s call to `main.fixtureInner`, and
the compiler-inserted `runtime.morestack_noctxt` prologue check), both of
which recover no argument value - correct, since `fixtureOuter(n int) int
{ return fixtureInner(n) }` passes its own incoming argument straight
through in RDI without any instruction rewriting it, so there is no
*write* for the backward analyzer's window to observe. Re-validated more
broadly (`tests/integration/test_go_runtime_function_fixture.py::test_backward_analysis_recovers_real_arguments_using_callee_arginfo_shape`),
the corrected, ABI-integrated pipeline recovers multiple real,
independently-verifiable values from `main.runFixtureFunctionCatalog`'s
real calls: `fixtureArgInt(41)` → `rax=41`; `fixtureArgConstant(1)` →
`rax=1`; `fixtureOuter(5)` → `rax=5`; `fixtureArgMulti(7, "seven",
true)` → `rax=7, rcx=5` (`len("seven")`), `rdi=1`; `fixtureStdlibCall`/
`fixtureHelperA`'s string-length leaves recovered as `14`/`7`
(`len("gomemforensics")`/`len("fixture")`) exactly. The same test also
confirms the false-positive control directly against real code:
`fixtureArgInt` takes exactly one argument, and exactly one is ever
reported for its real call site, regardless of what else was live in the
window.

## Known limitations

- Go 1.2-1.15 (`0xfffffffb` magic) predates the `pcHeader`/offset-table
  redesign entirely and uses a structurally different format. Magic-byte
  *recognition* exists (feeds a coarse version signal), but full
  `pcHeader`/`moduledata` struct parsing for that era is **not
  implemented** - explicitly out of scope, not a hidden gap.
- `pclntab_size` is always `None` - not safely computable from `pcHeader`
  fields alone without also parsing the referenced tables (a later-phase
  concern), so it is left unknown rather than estimated.
- `mspan` has only one verified layout era (local `go1.26.2`) - a Go
  version outside that is reported as `UNSUPPORTED_RUNTIME_LAYOUT`, never
  guessed. See "mspan: single verified era" above.
- Heap string recovery is scoped to exactly-two-word objects only; no
  recursive composite-type field walking (arrays/slices/structs/maps of
  strings) - see "Heap string interpretation - scope decision" above.
- `rodata_end` is always `None` - `moduledata` has no corresponding
  `erodata` field in any verified era (a real struct fact, not a gap).
- ARM64: Volatility 3 2.28.2 itself has no ARM/AArch64 translation layer
  (see `docs/architecture/volatility3-integration.md`), so Go runtime
  detection on ARM64 is unreachable in this phase regardless of this
  subsystem's own design; see `docs/supported-platforms/platforms.md`.
- No real captured memory image has been used to validate end-to-end
  detection or string/function recovery yet (see
  `docs/validation/validation-plan.md`) - only synthetic buffers and the
  real, on-disk compiled fixture binary's bytes, mapped through its real
  PE section table (not a memory image - heap/goroutine state does not
  exist on disk at all), have been used so far.
- `_func`/`functab` has only one verified layout era (local `go1.26.2`) -
  same scope decision, same reason, as `mspan` above.
- `function_size` is always `None` - not safely derivable from `_func`
  alone without walking to the next `ftab` entry across the same
  ambiguity `pclntab_size` already has (see above); left unknown rather
  than estimated.
- `ArgsPointerMaps` (pre-1.17 argument shape) is reported only as a single
  `EXPERIMENTAL` bitmap summary, never per-argument boundaries - the
  paper's own acknowledged limitation (Section 3.3.3): inferring
  boundaries from the raw bitmap needs additional Go type-layout
  knowledge out of scope here. Consequently it never produces an
  `ArgumentLocation`, so Capstone backward analysis has nothing to map
  ABI0-era calls onto today (see next bullet).
- Go ABI0 (stack-based, pre-1.17) backward analysis is implemented and
  unit-tested (`tests/unit/test_backward_analysis.py::TestStackBasedAbi0`),
  but **not integration-validated** - `_func`/`functab` is verified for
  only the `"1.22+"` era (register-based ABIInternal), so no real pipeline
  path exercises a stack-kind `ArgumentLocation` today. This is unchanged
  by the Phase 4.1 correction and remains an honest, disclosed limitation
  rather than a claim of broader validation.
- Capstone backward call-site **argument-value** analysis is x86-64 only,
  runs only for a call whose target resolves to a function with a known
  ArgInfo-derived `ArgumentLocation` shape (Phase 4.1: never a blanket
  sweep of live registers - see "Capstone backward call-site analysis"
  above), and recovers a value only for the small set of controlled
  instruction patterns listed above - real, optimized compiler output can
  still use patterns outside that set for any individual argument
  (confirmed directly against the real fixture binary: a pass-through
  argument that is never explicitly re-written before its call site
  recovers no value, the correct and expected outcome for that specific
  case - see `docs/validation/validation-plan.md` for the broader set of
  real values that ARE recovered elsewhere in the same binary). This
  remains the single highest-risk, most explicitly experimental component
  of Phase 4.
- ARM64 argument recovery is not implemented (not even as an unverified
  stub) - `backward_analysis`/`architecture.x86_64`'s ABI logic is never
  invoked for a non-x86-64 architecture; see CLAUDE.md section 51.
