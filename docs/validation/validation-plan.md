# Validation Plan

**Status: Phase 5 - Go Goroutine Recovery.** Phase 4.1 fixed two issues an
audit found in the completed Phase 4 work: a `pctab` decoder divergence
from the real algorithm's `first`-step semantics, and a production
integration gap where the verified x86-64 ABI register-assignment
algorithm was unit-tested but never actually called from the recovery
pipeline (backward analysis instead swept every ABI-sequence register
that held a value). Both are described in detail in
`docs/architecture/go-runtime.md`. Phase 5 adds `allgs` discovery, `g`
validation, and x86-64 pcsp-based stack unwinding - see
`docs/architecture/go-goroutines.md` and the Phase 5 sections below.

This document records what has actually been validated so far, and what
the plan is for validating each later phase. It must never claim a
validation result that was not actually produced (CLAUDE.md section 40).

## Phase 0 environment validation (performed)

Performed against the local development environment: Windows 10,
Python 3.14.3, no prior Volatility/Capstone installation.

| Check | Result |
|---|---|
| `python --version` | Python 3.14.3 |
| Other interpreters available via `py -0p` | Python 3.14 (`C:\Python314`), Python 2.7 (`C:\Python27`, unsuitable) |
| `pip download volatility3` metadata (`Requires-Python`) | `>=3.8.0` (no upper bound) |
| `volatility3==2.28.2` install + `import volatility3` | Succeeded, in an isolated throwaway virtual environment |
| `volatility3.framework.contexts`, `volatility3.framework.interfaces.plugins` import | Succeeded |
| `capstone` wheel availability for this platform | `capstone-5.0.9-py3-none-win_amd64.whl` (prebuilt, no compiler needed) |
| `capstone==5.0.9` install + `import capstone` | Succeeded (`capstone.__version__` reports `5.0.7`, the bundled native library version) |

**Conclusion:** Python 3.14.3 was found suitable for this project's
dependencies; no downgrade to an older Python version was necessary. This
project targets Python **>=3.11** (a conservative modern floor, not a
requirement to use exactly 3.14).

**Not yet validated:** any actual Volatility 3 layer, context, or plugin
API beyond the import checks above. Real image-opening behavior is Phase 1
work.

## Phase 0 functional validation (performed)

- `pytest` unit test suite (see `tests/unit/`) covering: package import,
  CLI `--help`/`version`/`info`/`validate`/`analyze`, evidence validation
  (success, empty file, nonexistent file, directory-instead-of-file,
  chunked-hash correctness against `hashlib`), `MockMemoryReader`
  (valid/invalid reads, pointer/string reads), `ArchitectureLayout`
  (`X86_64Layout` facts, `ARM64Layout` `NotImplementedError` behavior),
  OS profiles, configuration defaults, and logging level mapping.
- No test in this suite downloads, executes, or requires real malware, or
  requires a real memory image.

Exact pass/fail results for a given run belong in CI/commit history, not in
this document, to avoid this file going stale.

## Phase 1 Volatility API validation (performed)

Every Volatility 3 API this phase's code calls was first read directly
from the installed `volatility3==2.28.2` source (not from documentation or
general knowledge) before being used - full reference in
`docs/architecture/volatility3-integration.md`. This included reading
`volatility3/cli/__init__.py` in full (943 lines) as the canonical
end-to-end usage example, plus the complete bodies of
`windows/pslist.py`, `linux/pslist.py`, the Windows `EPROCESS` and Linux
`task_struct` extension classes, `framework/exceptions.py`, and
`framework/interfaces/layers.py`.

## Phase 1 functional validation (performed)

- Full `pytest` suite (unit + integration; see `tests/unit/` and
  `tests/integration/`), including the Phase 0 suite (updated where its
  premises changed - e.g. `analyze` now requires an image path argument).
- **Real Volatility construction attempted (not mocked) against a
  synthetic, deliberately-not-a-memory-image file** (64KB of random
  bytes): confirms `VolatilityRunner.construct_plugin`,
  `VolatilityIntegration.initialize`, and the CLI's `analyze` command all
  correctly detect an unsupported image, raise/record
  `VolatilityInitializationError`, and - for the CLI - still write a
  partial JSON report (evidence hash + the failure) and exit non-zero
  (`EXIT_ANALYSIS_ERROR = 3`). This is a real, non-mocked exercise of
  Volatility's Context/automagic/layer-stacking machinery, satisfying
  "actual Volatility context initialization if possible" without
  requiring a real memory image.
- `VolatilityMemoryReader` tested against a lightweight fake layer object
  that raises Volatility's real `InvalidAddressException`, confirming the
  reader correctly translates it into this project's own
  `MemoryAccessError` rather than crashing or silently padding.
- No test downloads, executes, or requires real malware.

**Not performed / explicitly pending - not fabricated:** end-to-end
`initialize()` -> `detect_os()` -> `detect_architecture()` ->
`enumerate_processes()` against a *real* captured Windows or Linux memory
image. No such image was available in the development environment (a
Windows 10 desktop with no memory-acquisition tooling installed, no VM
available in this session, and deliberately not acquiring a live dump of
the host machine's own RAM, which would capture real live secrets and is
outside the "controlled, benign Go program" testing approach CLAUDE.md
requires). Test infrastructure for this is fully built and ready:
`tests/integration/test_volatility_real.py::TestRealMemoryImage`, gated by
`@pytest.mark.memory_image` and the `real_memory_image_path` fixture in
`tests/conftest.py` (resolves `GOMEMFORENSICS_TEST_IMAGE` or the first
recognized file under `evidence/`). Running it currently reports
**SKIPPED**, not passed - this is the honest state, and
`docs/supported-platforms/platforms.md` reflects "implemented, not yet
validated against a real image" accordingly.

## Phase 2 Go runtime struct source verification (performed)

Every `pcHeader`/`moduledata` field order used by this phase was read
directly from real Go runtime source before being encoded as a
`StructLayout` - see `docs/architecture/go-runtime.md` for the full
narrative. Summary:

| Source | What it confirmed |
|---|---|
| Local `go1.26.2` install (`C:\Program Files (x86)\Go\src\runtime\symtab.go`, `...\src\internal\abi\symtab.go`) | Current `pcHeader`/`moduledata` shape; confirmed `CurrentPCLnTabMagic = Go120PCLnTabMagic` (the paper's "1.20+" magic is still current 6+ years later) |
| `github.com/golang/go` tag `go1.17.13` | `pcHeader` pre-1.18 shape (no `textStart` field); `moduledata` 1.16-1.17 shape (no `rodata`/`gofunc`/`covctrs`/`epclntab`) |
| `github.com/golang/go` tag `go1.19.13` | `pcHeader` 1.18+ shape confirmed; `moduledata` 1.18-1.19 shape (`+rodata`/`gofunc`, still no `covctrs`) |
| `github.com/golang/go` tag `go1.20.14` | `moduledata` 1.20 shape (`+covctrs`/`ecovctrs`, still no `epclntab`) |
| `github.com/golang/go` tag `go1.21.13` | Confirmed `moduledata` unchanged vs 1.20.14 (still no `epclntab`) despite the `sys.NotInHeap` marker appearing exactly here, as the paper documents |

**Gap, explicitly not resolved further**: the exact Go version where
`moduledata` gained the `epclntab` field (somewhere after `go1.21.13`, at
or before the locally-installed `go1.26.2`) was not pinned down further -
`ModuledataParser` handles this by trying both candidate layouts and
accepting whichever validates (documented in `go-runtime.md` as
"moduledata era ambiguity"), rather than guessing the boundary.

**Also verified against real (non-synthetic) compiled output**: the
project's own benign fixture, built with the local `go1.26.2` toolchain
(`tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe`), was
scanned directly (file bytes, not a memory image) by `PclntabParser`.
Ground truth established manually: the Go 1.20+ magic occurs 7 times in
the file; exactly 1 occurrence satisfies every `pcHeader` invariant (at
the time of Phase 2: `nfunc=2162`, `nfiles=249`, `minLC=1`, `ptrSize=8`),
the other 6 are coincidental 4-byte matches elsewhere in the binary. This
is regression-tested in `tests/integration/test_go_runtime_real_fixture.py`
and is real evidence for why a bare magic-byte match is never trusted -
not a hypothetical concern. (The fixture was extended in Phase 4 with 13
new functions plus a `strings` import for function-recovery testing;
`nfunc`/`nfiles` grew to `2184`/`252` accordingly - the test asserts the
current values, this narrative keeps the original Phase 2 numbers as the
historical record of what was actually observed at that time.)

## Phase 2 functional validation (performed)

- Full `pytest` suite (162 passed, 1 skipped as of Phase 2 completion),
  including new modules: `test_go_runtime_layouts.py`,
  `test_go_runtime_version.py`, `test_go_runtime_pclntab.py`,
  `test_go_runtime_moduledata.py`, `test_go_runtime_detector.py`,
  `test_go_runtime_scanning.py`, and the real-fixture-binary test above.
- Covers, per the approved plan's Section 18 checklist: valid magic for
  every supported family, invalid magic, valid/invalid `pcHeader`
  (`ptrSize`, `minLC`, impossible `nfunc`/`nfiles`, truncated buffer,
  corrupted padding), known version markers/ranges/unknown/conflicting
  indicators, valid/invalid `moduledata` (wrong `pcHeader` pointer,
  invalid slice `len`/`cap`, invalid region ordering, multiple
  candidates), confirmed Go candidate / non-Go process / magic-only false
  positive / structural candidate / inaccessible process, and memory
  boundary/invalid-address/partial-read behavior.
- A genuine robustness bug was found and fixed *during* this test-writing
  process (not hypothetical): a region's declared VAD/VMA bounds can
  exceed what is actually readable, and the original chunked scanner
  aborted the entire region on the first failed read. Fixed via
  `gomemforensics.go_runtime.scanning.iter_readable_chunks` (resilient,
  degrading retry down to a 4 KiB floor); regression-tested in
  `test_go_runtime_scanning.py`.
- No test downloads, executes, or requires real malware.

**Not performed / explicitly pending - not fabricated:** end-to-end Go
process detection against a *real* captured memory image containing the
benign fixture (`tests/fixtures/go/fixture.go`, built successfully for
both windows/amd64 and linux/amd64 via `scripts/fixtures/build_fixture.ps1`).
No memory-acquisition tooling (e.g. WinPmem, DumpIt, avml) is installed in
this development environment, and a live dump of the host machine's own
RAM was deliberately not taken (would capture real host secrets and is
outside the "controlled, benign Go program" approach CLAUDE.md requires).
This remains exactly as documented in the Phase 1 section above -
`tests/integration/test_volatility_real.py::TestRealMemoryImage` still
reports **SKIPPED**.

## Phase 2 paper validation table

| Paper technique | Implementation | Test | Real-image validation | Status | Known limitation |
|---|---|---|---|---|---|
| pclntab magic-byte detection (Section 3.1.1) | `PclntabParser` magic scan over read-only/executable regions | `test_go_runtime_pclntab.py` (synthetic) + `test_go_runtime_real_fixture.py` (real compiled binary bytes) | Not yet (no captured image) | REPRODUCED (parsing/validation logic); PARTIALLY REPRODUCED overall (real-image path pending) | Go 1.2-1.15 magic recognized but that era's different struct format is not parsed |
| pcHeader invariant validation (Section 3.1.1) | `validate_pc_header` | `TestValidatePcHeaderInvariants` (9 cases) + real fixture | Not yet | REPRODUCED (logic); real-image pending | Plausibility bounds (nfunc/nfiles cap) are an added safety bound, not a paper-specified exact threshold |
| Structure-based fallback on corrupted/obfuscated magic (Section 3.1.1) | `PclntabParser._scan_region_structurally` | `TestPclntabParserStructuralFallback` | Not yet | PARTIALLY REPRODUCED (same invariant-based approach; not tested against actual obfuscated/Garble-built binaries) | Never claimed to defeat all obfuscation, matching the paper's own scope |
| moduledata discovery via pcHeader-pointer anchor (Section 3.1.1) | `ModuledataParser.find_candidates` | `test_go_runtime_moduledata.py` (synthetic, all 3 verified layout eras) | Not yet | REPRODUCED (logic); real-image pending | Multi-layout ambiguity within the 1.20+ magic family resolved by trying both candidates, not by pinning the exact version boundary |
| moduledata structural validation (ordered bounds, slice len<=cap) (Section 3.1.1) | `ModuledataValidator` | `TestModuledataRejection` | Not yet | REPRODUCED (logic); real-image pending | Span-size plausibility bound (4 GiB) is an added safety bound |
| Go version identification via structural field changes across releases (Section 3.1.3) | `GoVersionDetector` + moduledata-era refinement | `test_go_runtime_version.py` | Not yet | REPRODUCED (logic); real-image pending | Exact patch version never reported - only the range the evidence supports, by design |
| Obfuscation-resistant, symbol-independent recovery (Section 3.1.3, general principle) | No reliance on `runtime.mheap`/`runtime.allgs`-style named symbols anywhere in Phase 2 | N/A (structural design property, not a single test) | Not yet | PARTIALLY REPRODUCED (design principle followed; not validated against an actual Garble-obfuscated sample) | No obfuscated/Garble sample available or downloaded in this environment |

## Phase 3 Go runtime struct source verification (performed)

Struct fields used by string recovery were read directly from the local
`go1.26.2` install before being encoded as `StructLayout` objects (see
`docs/architecture/go-runtime.md` for the full narrative):

| Struct | Source file | Fields verified |
|---|---|---|
| `mspan` | `runtime/mheap.go` | Full field-by-field walk from `next` through `elemsize`, including confirming the non-obvious intermediate types `gclinkptr` (uintptr), `spanClass` (uint8), `mSpanStateBox` (`atomic.Uint8` -> 1 byte, `noCopy` is zero-sized), `gcBits` (`{_ NotInHeap; x uint8}`, so `*gcBits` behaves as a byte-addressable bitmap pointer) |
| `_type` (`abi.Type`) | `internal/abi/type.go` | `Size_`, `PtrBytes`, `Hash`, `TFlag`, `Align_`, `FieldAlign_`, `Kind_`, plus the `KindDirectIface` flag-bit definition used to mask `Kind_` correctly |
| `itab` (`abi.ITab`) | `internal/abi/iface.go` | `Inter`, `Type`, `Hash` (header only - `Fun` array not parsed) |

**Explicit, documented scope decision**: unlike `pcHeader`/`moduledata`
(Phase 2, verified across 4 historical tagged releases), `mspan` was
**only** verified against the local `go1.26.2` install - it is a larger,
far more GC-internals-volatile struct, and independently re-verifying it
against multiple historical Go releases (the way Phase 2 did for
`pcHeader`/`moduledata`) was judged disproportionate effort for this
phase. A Go version outside the `"1.22+"` range this verification covers
is reported as `UNSUPPORTED_RUNTIME_LAYOUT`, never guessed - see
`gomemforensics.go_runtime.mspan.resolve_mspan_layout`.

A genuine implementation bug was found and fixed while building this
phase's tests, not hypothetical: the alignment-computation change needed
for `mspan` (which - unlike `pcHeader`/`moduledata` - has fields that
genuinely require compiler-inserted padding) required upgrading
`StructLayout.offsets()` from a naive cumulative-sum to a real
alignment-aware algorithm; a follow-on scanning-loop bug (chunk offsets
from the resilient reader are not guaranteed pointer-aligned) was also
found and fixed in both the new `AllspansParser` scan and the new static
string scan, plus a related performance regression in the resilient
reader itself (a linear retry fallback that could take up to 4096
attempts in the worst case, fixed to converge via halving first). All are
covered by regression tests (`tests/unit/test_go_runtime_scanning.py`,
`tests/unit/test_mspan.py`).

## Phase 3 functional validation (performed)

- Full `pytest` suite (227 passed, 1 skipped as of Phase 3 completion),
  including four new required test modules: `test_types.py`,
  `test_mspan.py`, `test_strings.py`, `test_static_strings.py`, plus a
  scanning regression module and two real-fixture-binary integration
  tests.
- Covers, per the approved plan's Section M checklist: invalid allspans
  pointer, `len > cap`, inaccessible span, malformed mspan, zero/invalid
  element size, impossible span bounds (documented as unreachable via a
  genuine `uint16` `nelems` field, tested accordingly rather than faked),
  allocation bitmap corruption/truncation, invalid string pointer,
  impossible string length, truncated backing data, non-printable/random
  candidate, ambiguous type-size mapping, unsupported Go runtime layout,
  partially inaccessible memory, and duplicate/shared backing strings.
- No test downloads, executes, or requires real malware.

**Real fixture *binary file* validation performed (explicitly NOT a
memory image)**: `tests/integration/test_go_runtime_string_fixture.py`
confirms the compiled benign fixture
(`tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe`,
rebuilt this phase with additional marker categories - short/long/repeated/
Unicode/empty static literals, a heap-created dynamic string, and a
string shared between two variables) contains the expected marker string
*bytes*. This is fixture-content sanity checking only - it does **not**
exercise `StringRecoveryEngine` or any header-scanning logic, because a
compiled executable has no heap state at all (allspans/mspan/live heap
objects are allocated by the Go runtime only after the process starts -
approved plan Section N, "A raw Go executable is NOT equivalent to a
process memory image").

**Not performed / explicitly pending - not fabricated**: end-to-end heap
or static string recovery against a *real* captured memory image. No such
image was available in this development environment (same constraint as
Phase 1/2 - see above). `tests/integration/test_volatility_real.py::TestRealMemoryImage`
remains the gate for this and still reports **SKIPPED**.

## Phase 3 paper validation table

| Paper technique | Implementation | Test | Real-image validation | Status | Known limitation |
|---|---|---|---|---|---|
| Type metadata extraction - `_type` header (Section 3.1.4) | `TypeParser`/`TypeIndex` | `test_types.py` | Not yet | REPRODUCED (minimal subset: size/kind/ptrBytes only, not full kind-specific metadata) | No `uncommonType`/method-set parsing - explicitly out of scope |
| allspans discovery + "valid mspan ptrs" validation (Section 3.2.1, Figure 2) | `AllspansParser` | `test_mspan.py` | Not yet | REPRODUCED (logic); real-image pending | Sample-ratio threshold (50%) is an added plausibility bound, not paper-specified |
| mspan parsing + allocation bitmap traversal (Section 3.2.1, Figure 2) | `MspanWalker`, `object_addr = startAddr + bit_index*elemsize` (paper's own formula) | `test_mspan.py` | Not yet | REPRODUCED (logic, single verified Go-version era); real-image pending | Only one verified `mspan` layout era (see above) |
| Size-to-type candidate mapping (Section 3.2.1) | `TypeIndex.candidates_for_size` | `test_types.py`, `test_strings.py` | Not yet | REPRODUCED (ambiguity preserved, never collapsed to one type) | No recursive candidate-type field validation |
| Interface/string two-word disambiguation via itab validity (Section 3.1.5/3.2.1) | `_looks_like_itab` | `test_strings.py::TestLooksLikeItab` | Not yet | PARTIALLY REPRODUCED (binary plausibility check; no recursive interface-payload processing) | Evidence, not proof - documented false-negative risk |
| Heap string validation: pointer/length/UTF-8/printability (Section 3.2.1) | `validate_string_header` | `test_strings.py` | Not yet | REPRODUCED (logic); real-image pending | UTF-8 treated as a signal, not an absolute requirement - documented decision |
| Static-section header pattern scan (Section 3.2.2) | `StringRecoveryEngine.recover_static_strings` | `test_static_strings.py` | Not yet | REPRODUCED (logic); real-image pending | Region model lacks precise `.rodata`/`.data`/`.bss` section labels - uses readable/writable/executable flags instead |
| Recursive field-walking into composite types (arrays/slices/structs/maps of strings) (Section 3.2.1) | Not implemented | N/A | N/A | **NOT REPRODUCED** - explicit scope decision | Requires the fuller Go type system (`uncommonType`, struct field metadata) - deferred |

## Phase 4 Go runtime struct source verification (performed)

Struct fields used by function recovery were read directly from the local
`go1.26.2` install before being encoded as `StructLayout` objects (see
`docs/architecture/go-runtime.md` for the full narrative):

| Struct | Source file | Fields verified |
|---|---|---|
| `_func` | `runtime/runtime2.go` (`type _func struct`) | Full field walk, `entryOff` through `nfuncdata` |
| `functab` | `runtime/symtab.go` | `entryoff`, `funcoff` |
| `stackmap` | `runtime/symtab.go` | `n`, `nbit`, `bytedata` header (`ArgsPointerMaps`) |
| ArgInfo bytecode opcodes | `internal/abi/type.go` | `TraceArgsEndSeq`/`StartAgg`/`EndAgg`/`Dotdotdot`/`OffsetTooLarge`/`Special`, `TraceArgsMaxLen` |
| ArgInfo bytecode *encoder* (which types get `StartAgg`/`EndAgg`) | `cmd/compile/internal/ssagen/ssa.go` (`EmitArgInfo`) | Confirms string/slice/interface/array/complex/struct wrap leaves; everything else is a single leaf |
| ArgInfo semantic meaning of "offset from FP" | `cmd/compile/internal/abi/abiutils.go` (`ABIParamAssignment.FrameOffset` doc comment) | Confirms it is a *unified*, spill-slot-inclusive view - a register-assigned argument's offset is not a live value location |
| amd64 ABIInternal register sequence + assignment algorithm | `cmd/compile/abi-internal.md` (local install) | 9-register integer sequence and the "spilled argument does not consume registers" rule |
| pctab PC-value delta-stream encoding | `runtime/symtab.go` (`pcvalue`/`step`/`readvarint`) | Unsigned-LEB128 varint, zigzag value-delta, `PCQuantum` |

**Same explicit single-era scope decision as Phase 3's `mspan`**: `_func`/
`functab` are verified only against the local `go1.26.2` install, not
re-verified against multiple historical tagged releases the way Phase 2
did for `pcHeader`/`moduledata`. A Go version outside `"1.22+"` is
reported as `UNSUPPORTED_RUNTIME_LAYOUT`, never guessed - see
`gomemforensics.go_runtime.functab.resolve_func_layout`.

**A genuine implementation bug was found and fixed by real-fixture
validation, not hypothetical**: the first working
`FunctionTableParser._resolve_file_line` read a fixed 64 KiB window from
the pctab blob's *base* address for every function, which silently
truncated `pc_value`'s walk (and therefore produced `None` source
file/classification, not a crash - it stayed hidden through every
synthetic unit test, whose hand-built pctab buffers are naturally small)
for any function whose `pcfile`/`pcln` stream sits further than 64 KiB
into a real, multi-hundred-KiB pctab table. Real-fixture validation
against the rebuilt benign fixture (`tests/fixtures/go/bin/
gomemforensics_fixture_windows_amd64.exe`) surfaced this directly: every
recovered function *name* was correct, but `main.*`/`strings.*`/most
`runtime.*` functions' classification silently came back `UNKNOWN`. Fixed
by reading a small, bounded window starting at (not before) each
function's own declared stream offset - see
`gomemforensics.go_runtime.functab.FunctionTableParser._pc_value_for_stream`
and `docs/architecture/go-runtime.md`. This is exactly the class of bug
CLAUDE.md section 26 warns a single working sample cannot rule out.

## Phase 4 functional validation (performed)

- Full `pytest` suite (348 passed, 1 skipped as of Phase 4 completion),
  including new modules: `test_pctab.py` (25 hand-calculated cases),
  `test_functab.py`, `test_classification.py`, `test_arginfo.py`,
  `test_backward_analysis.py` (26 cases against hand-encoded, individually
  Capstone-verified x86-64 instruction sequences), plus new
  `TestAssignIntegerArgumentLocations`/`TestIsRegisterBasedAbi` cases in
  `test_architecture.py` and `TestRecoverFunctions` in `test_pipeline.py`.
- Covers, per the approved plan's negative-test checklist: truncated
  `_func`, invalid ftab entry, invalid name/file offset, malformed pctab
  (truncated varint, runaway varint), impossible PC delta, inaccessible
  target memory, invalid RIP-relative address (unreadable and
  readable-but-non-string), unsupported Go version/runtime layout,
  ambiguous register state (unresolved copy source, clobbering
  instruction), and a call-site window that must not cross an earlier
  `CALL` or walk before function entry.
- No test downloads, executes, or requires real malware.

**Real fixture *binary file* validation performed** (via a PE-
section-aware `MemoryReader` built on `pefile`, mapping the fixture's
real virtual addresses to its file bytes through the actual PE section
table - not a raw-file-offset scan, since moduledata/ftab pointers are
real virtual addresses, unlike pclntab's own relative offsets):
`tests/integration/test_go_runtime_function_fixture.py` runs the full
`GoProcessDetector` → `FunctionTableParser` → classification pipeline
against the real compiled fixture (rebuilt this phase with 13 new
`//go:noinline` functions covering every fixture category from the
approved plan: integer/string/multi/pointer/zero/constant/global-address
arguments, nested calls, a stdlib call, an app-to-app call) and confirms:

- All 13 new fixture functions plus `main.main` recovered by name,
  correctly classified `APPLICATION`.
- `strings.ToUpper` classified `STDLIB`; `runtime.main`/`runtime.gopanic`/
  `runtime.newobject` (genuinely `runtime`-sourced) classified `RUNTIME`;
  `runtime.mapaccess1_fast32`/`runtime.memequal` (named `runtime.*` but
  actually sourced from `internal/runtime/maps`/`internal/bytealg`, Go's
  linkname-based ABI-compatibility naming) classified `RUNTIME_INTERNAL` -
  confirming classification is genuinely path-evidence-based, not
  name-based.
- `main.fixtureArgMulti(a int, b string, c bool)`'s ArgInfo shape decodes
  to exactly the expected leaves (1 scalar, 1 two-leaf aggregate, 1
  scalar).
- Capstone backward analysis correctly locates the real compiled `CALL`
  from `main.fixtureOuter` to `main.fixtureInner` (the nested-call
  category) and the compiler-inserted `runtime.morestack_noctxt` prologue
  check; neither recovers an argument value in the real, optimized
  codegen - the honest, expected result (see
  `docs/architecture/go-runtime.md`), not a gap papered over.
- Function recovery is deterministic across repeated runs against the
  same binary.

This is real, non-fabricated validation of the full static
recovery-and-classification path against genuine compiler output - but it
is explicitly **not** a substitute for real memory-image validation
(runtime-only state - goroutines, live register/stack values at capture
time - cannot exist in an on-disk file at all).

**Not performed / explicitly pending - not fabricated:** end-to-end
function recovery and call-site argument analysis against a *real*
captured memory image. Same constraint as every prior phase (no
memory-acquisition tooling available in this development environment) -
`tests/integration/test_volatility_real.py::TestRealMemoryImage` remains
the gate and still reports **SKIPPED**.

## Phase 4 paper validation table

| Paper technique | Implementation | Test | Real-image validation | Status | Known limitation |
|---|---|---|---|---|---|
| Function table walk: `ftab` → `_func` (Section 3.3.1) | `FunctionTableParser` | `test_functab.py` (synthetic) + real-fixture test (real compiled binary, VA-mapped) | Not yet | REPRODUCED (logic + real static metadata); real-image pending | Single verified `_func`/`functab` layout era (`"1.22+"`) |
| Name/source resolution without OS symbol tables (Section 3.3.1) | `funcnametab`/`filetab`/`cutab` resolution | Real-fixture test: every fixture + stdlib + runtime function name/source recovered correctly | Not yet | REPRODUCED, confirmed against real compiler output | None beyond the single verified layout era |
| pctab PC-value decoding (Section 3.3.1) | `gomemforensics.go_runtime.pctab` | 28 hand-calculated synthetic cases (Phase 4.1: +3, including `TestPcValueFirstStepSemantics`) + real-fixture test (indirectly, via source/line resolution) | Not yet | REPRODUCED - faithful, line-by-line transcription of the real algorithm (independently re-verified against `runtime/symtab.go` during a Phase 4.1 audit), not a heuristic | Two real bugs found and fixed: a fixed-size read window (Phase 4, via real-fixture validation) and the `first` flag being iteration-based rather than the real algorithm's per-step value-based recompute (Phase 4.1, found by direct source comparison, not by any failing test - see `docs/architecture/go-runtime.md`) |
| Function classification by source path (Section 3.3.2) | `classify_function_path` | `test_classification.py` (synthetic paths) + real-fixture test (real recovered paths) | Not yet | REPRODUCED, confirmed against real compiler output including a non-obvious linkname-naming edge case | Never infers anything from the function's name - path only |
| ArgInfo argument-shape decoding (Section 3.3.3) | `decode_arg_info` | `test_arginfo.py` + real-fixture test (`fixtureArgMulti`) | Not yet | REPRODUCED (shape only - see next row) | Never claims a *value*, only leaf count/sizes/aggregation - see module docstring's cited semantic source |
| ArgsPointerMaps (pre-1.17) argument shape (Section 3.3.3) | `read_stackmap` | `test_arginfo.py::TestReadStackmap` | Not yet | PARTIALLY REPRODUCED - header/bitmap parsed structurally, but per-argument boundary inference is explicitly not implemented, matching the paper's own acknowledged limitation | No pre-1.17 real binary built/tested (this project's Go toolchain is 1.26.2; an older cross-compiled Go toolchain was not available) |
| x86-64 ABI-aware argument-register assignment (Section 3.3.4, general principle) | `assign_integer_argument_locations`, `is_register_based_abi`, and (Phase 4.1) `functab._resolve_argument_locations` wiring it into production via `ArgumentLocation` | `TestAssignIntegerArgumentLocations`, `TestIsRegisterBasedAbi` (synthetic, algorithm-level) + real-fixture test (`main.fixtureArgMulti`'s 4-leaf shape correctly ABI-mapped to `rax/rbx/rcx/rdi`) | Not yet | REPRODUCED - as of Phase 4.1, actually called from production code (`FunctionTableParser`), not just unit-tested in isolation; cross-checked leaf-for-leaf against real optimized codegen via the backward-analysis row below | ABI0/ABIInternal era ambiguity (`"1.16-1.17"`) reported `None`/unsupported, never guessed; ABI0 (stack) mapping path itself remains unit-tested only, not integration-validated (see `docs/architecture/go-runtime.md`) |
| Capstone backward call-site argument recovery (Section 3.3.4) | `gomemforensics.go_runtime.backward_analysis`, driven by each callee's `ArgumentLocation` shape (Phase 4.1 - previously it independently swept every ABI-sequence register that held a value, a defect found and corrected; see below) | `test_backward_analysis.py` (31 cases, each pattern individually, hand-encoded and Capstone-verified, plus 5 explicit `TestFalsePositiveControl` cases) + real-fixture test (`test_backward_analysis_recovers_real_arguments_using_callee_arginfo_shape`) | Not yet | REPRODUCED for the SUPPORTED-status patterns, confirmed against real optimized compiler output at multiple real call sites (not just two): `fixtureArgInt(41)`→`rax=41`, `fixtureArgConstant(1)`→`rax=1`, `fixtureOuter(5)`→`rax=5`, `fixtureArgMulti(7,"seven",true)`→`rax=7,rcx=5,rdi=1`, plus string-length leaves for `fixtureStdlibCall`/`fixtureHelperA` recovered exactly (`14`/`7`). EXPERIMENTAL beyond that: real compiler output can still use unrecognized patterns for any individual argument (e.g. a pass-through argument never re-written before its call, as in `fixtureOuter`'s own call into `fixtureInner`) | Explicitly the highest-risk Phase 4 component (approved plan Step 11); real-world recovery rate against arbitrary optimized code beyond this project's own fixture is genuinely unknown |
| False-positive control: an extra live register must never be reported as a callee argument merely because it holds a value (Phase 4.1 correction, found by audit - approved plan's own "never invent an argument's existence" principle, CLAUDE.md section 40) | `backward_analysis.analyze_call_site`, gated entirely on `known_function_argument_locations` | `TestFalsePositiveControl` (5 synthetic cases) + real-fixture test (`fixtureArgInt`'s single-argument call site never reports more than its one declared location) | Not yet | REPRODUCED - both synthetically and against real compiled output | None beyond the general "no real memory image" caveat |

## Phase 5 Go runtime struct source verification (performed)

`g`/`gobuf`/`stack` fields were read directly from the local `go1.26.2`
install (`runtime/runtime2.go`) before being encoded as a `StructLayout`
- see `docs/architecture/go-goroutines.md` for the full field table and
citations.

**Verification method, stronger than Phase 3/4's own precedent**: rather
than only computing offsets with this project's own `StructLayout`
engine, a throwaway Go program declaring a structurally identical struct
(same field sizes/order as `runtime.g`, local stand-in type names since
the real field types are unexported/internal to package `runtime`) was
compiled and run with the local `go1.26.2` toolchain, and its
`unsafe.Offsetof`/`unsafe.Sizeof` output was compared field-by-field
against `StructLayout.offsets()`. All 39 checked offsets matched exactly
(`tests/unit/test_go_runtime_layouts.py::TestGLayout`) - independent
confirmation from the authoritative source (the real compiler), not a
self-consistency check of this project's own tooling against itself.

`pcsp`'s exact relationship to a real stack frame's return-address
location was independently re-derived from `runtime/traceback.go`'s
`gentraceback` (not merely transcribed from the paper's prose) - see
`docs/architecture/go-goroutines.md`'s "Stack unwinding" section for the
full line-by-line citation, including confirming `sys.MinFrameSize == 0`
on amd64 (so the paper's simplified formula is exactly correct for this
project's one supported architecture, not merely assumed to be).

## Phase 5 functional validation (performed)

- Full `pytest` suite (414 passed, 1 skipped as of Phase 5 completion),
  including new modules: `test_go_runtime_goroutines.py` (32 cases:
  layout resolution, `validate_g` invariants including the dead-goroutine
  sp-check exemption, `AllgsParser` discovery/sampling/rejection,
  `GoroutineRecoveryEngine` end-to-end including the verified
  syscall-state substitution rule and the `gopc`/`startpc`/`sched_pc`
  non-conflation regression guard), `test_stack_unwind.py` (14 cases:
  single/two/negative-delta frame unwinds, every `UnwindStatus` stopping
  condition, a bounded 261-frame chain confirming the walk terminates
  rather than looping), plus new `TestGLayout` cases in
  `test_go_runtime_layouts.py` and `TestRecoverGoroutines` in
  `test_pipeline.py`.
- A genuine bug was found and fixed while writing this phase's tests, not
  hypothetical: a stray trailing comma in
  `GoroutineRecoveryEngine._build_goroutine`'s out-of-bounds-sp error
  message turned the `AnalysisError.message` string into a 1-tuple
  containing that string - caught by
  `test_out_of_bounds_sp_reduces_confidence_not_rejected` asserting on
  the message's actual content, not merely that *an* error was recorded.
- Covers, per the approved plan's negative-test checklist: invalid
  `allgs` slice (null ptr, `len > cap`, unreadable pointer array,
  majority-invalid sample), invalid `g` (unordered/misaligned/implausible
  stack, unrecognized status/waitreason, implausible goid), a malformed
  `g` that does not abort the rest of `allgs`, and every unwind stopping
  condition (unresolved function, SPWrite/special-FuncID frame,
  unreadable/out-of-bounds return-address slot, self-cycle, malformed
  pcsp, the `MAX_FRAMES` bound).
- No test downloads, executes, or requires real malware.

**Real fixture *binary file* validation performed, explicitly scoped**
(`tests/integration/test_go_runtime_goroutine_fixture.py`): confirms
`_func.pcsp` decodes to plausible, pointer-aligned frame-size values for
real compiled functions (spot-checked and swept across 200+ real
functions from the rebuilt fixture, which now includes two new
Phase 5 goroutine bodies - `channelBlockedWorker`, blocked on a plain
channel receive, and `cpuBoundWorker`, bounded repeated CPU work - kept
benign, no network/persistence/exec), and that `unwind_goroutine`'s
frame-delta arithmetic produces the correct result when given a real
function's real entry PC and real `pcsp`-decoded frame size (with a
synthetic, test-controlled "caller" and stack slot, since no real caller
frame can exist in a static file). This is real, non-fabricated
static-metadata validation - it is explicitly **not**, and must never be
represented as, goroutine *runtime-state* validation:
`runtime.allgs` has no populated data at all in a compiled executable
(it is a `var allgs []*g` slice the runtime only populates after a
process starts and creates goroutines), so `allgs` discovery, `g`
structural validation, and a genuine live stack unwind remain entirely
unexercised by any file-based test in this project.

**Not performed / explicitly pending - not fabricated**: end-to-end
`allgs` discovery, `g` validation, or stack unwinding against a *real*
captured memory image containing the benign fixture (now built with two
additional deterministic goroutine bodies for this purpose, ready for
when such an image becomes available). Same constraint as every prior
phase (no memory-acquisition tooling available in this development
environment) - `tests/integration/test_volatility_real.py::TestRealMemoryImage`
remains the gate and still reports **SKIPPED**.

## Phase 5 paper validation table

| Paper technique | Implementation | Test | Real-image validation | Status | Known limitation |
|---|---|---|---|---|---|
| `runtime.allgs` discovery via writable-region slice-header scan, validated by sampling well-formed `g` structures (Section 3.4) | `AllgsParser` | `test_go_runtime_goroutines.py::TestAllgsParser` (synthetic) | Not yet | REPRODUCED (logic); real-image pending | No anchor evidence beyond structural validation - genuinely weaker discovery guarantee than `pclntab`/`moduledata`, disclosed as such |
| `g` structural validation: stack bounds ordered/aligned, status recognized, goid plausible (Section 3.4) | `validate_g` | `TestValidateG` (9 cases) | Not yet | REPRODUCED (logic); real-image pending | `sched.sp`-in-bounds check applied conditionally (status-dependent), not unconditionally, per verified runtime semantics - an engineering refinement beyond the paper's one-sentence description |
| Stack unwinding via `g.sched`/pcsp frame-delta arithmetic (Section 3.4) | `stack_unwind.unwind_goroutine` | `test_stack_unwind.py` (14 cases, synthetic) + real-fixture test (real pcsp data, synthetic stack) | Not yet | REPRODUCED (algorithm independently re-verified against `runtime/traceback.go`, not just the paper's prose); real-image pending | x86-64 only; morestack/systemstack/async-preemption/cgo/signal frames explicitly stop rather than being specially unwound |
| Argument-boundary recovery at unwound frames (Section 3.4, final sentence: "individual argument boundaries are established using the argument type reference techniques described in Section 3.3") | Not implemented | N/A | N/A | **NOT REPRODUCED** - explicit Phase 5 scope decision | Frame `sp`/`function` are recovered; per-frame argument *value* recovery via Phase 4's ArgInfo/backward-analysis machinery at each unwound frame is deferred, not attempted in this phase |

## Planned validation per later phase

| Phase | Planned validation |
|---|---|
| 6-9 | Per the approved implementation plan's phase-by-phase acceptance criteria. |
| 10 - ARM64 | Full unit/integration/negative suite mirrored from the x86-64 suite, against real ARM64 Go binaries. |

## Paper reproduction

The reference paper's own case studies (BRICKSTORM, Obscura, Pantegana) are
**not reproducible today** - the corresponding samples are not present in
this repository and are not being downloaded automatically (CLAUDE.md
section 27/28). Any future reproduction attempt must be recorded as: paper
expectation, implementation result, difference, and reason - never
fabricated.

## Phase 5.5 — real memory image validation attempt

**Disposition: B — REAL MEMORY VALIDATION BLOCKED — NO APPROVED REAL
MEMORY IMAGE AVAILABLE.**

Phase 5.5 was an explicit, dedicated attempt to obtain and validate
against a real captured memory image, rather than continuing to defer
that gap into "future work" implicitly. Its own strict stop conditions
(no image discovered, no acquisition performed on any machine this
project can reach) were triggered at stage 5.5-C, before any real-image
analysis could be attempted. Nothing below should be read as validation
performed - it records exactly what was checked and why the attempt
stopped where it did.

### What was checked

- `evidence/` (the project's designated local-evidence directory):
  contains only `evidence/README.md` - no `.raw`/`.mem`/`.dmp`/`.lime`/
  `.vmem` candidate file, and none has ever been placed there in this
  development environment across Phases 0-5.
- `GOMEMFORENSICS_TEST_IMAGE` (the environment variable
  `tests/conftest.py`'s `real_memory_image_path` fixture resolves first):
  unset.
- No other path was searched - per the Phase 5.5 constraint, evidence
  discovery is scoped to `evidence/` and explicitly-configured paths only,
  never a whole-filesystem search.
- Conclusion: `tests/integration/test_volatility_real.py::TestRealMemoryImage::test_full_pipeline_against_real_image`
  remains **SKIPPED** (as it has every prior phase), and no acquisition
  was performed to change that - see `docs/validation/memory-acquisition.md`
  for the acquisition-options survey produced instead (documentation
  only; no tool listed there was installed or run).

### Result classification

Every capability's status uses the closed vocabulary `REAL_MEMORY_VALIDATED
/ PARTIALLY_REAL_MEMORY_VALIDATED / INCONCLUSIVE / UNVALIDATED /
UNSUPPORTED`. Because no real image was available, no capability can be
anything other than `UNVALIDATED` (already-established boundaries, e.g.
ARM64, remain `UNSUPPORTED`) - there is deliberately no partial credit
given for compiled-binary or synthetic-buffer testing here, since those
are already tracked separately (SOURCE_VERIFIED / SYNTHETIC_VALIDATED /
COMPILED_BINARY_VALIDATED elsewhere in this document) and must not be
blended into the real-memory-specific classification.

| Capability | Result classification | Evidence citation |
|---|---|---|
| Evidence validation / SHA-256 hashing | UNVALIDATED (against a real image specifically) | No real image hashed; synthetic-file hashing validated in `tests/unit/test_evidence.py` |
| Volatility 3 initialization / OS detection | UNVALIDATED | Exercised only against a synthetic garbage file (`tests/integration/test_volatility_real.py::TestVolatilityAgainstUnsupportedImage`) |
| Process enumeration | UNVALIDATED | No real image; unit-tested against mocked Volatility objects only |
| Go process / runtime detection (`pclntab`/`moduledata`) | UNVALIDATED | Real compiled-binary bytes only (`tests/integration/test_go_runtime_real_fixture.py`) - not a captured process image |
| Go string recovery | UNVALIDATED | Same real-binary-only boundary as above |
| Go function recovery | UNVALIDATED | Same real-binary-only boundary as above |
| Go goroutine discovery (`allgs`/`g`) | UNVALIDATED | No populated `allgs` exists in any static file - see `docs/architecture/go-goroutines.md` |
| Stack unwinding | UNVALIDATED | Real `pcsp` data validated from a compiled binary; no real live stack ever unwound |
| ARM64 (any capability) | UNSUPPORTED | Unchanged from `docs/supported-platforms/platforms.md` - Volatility 3 2.28.2 has no ARM/AArch64 translation layer at all |

### Failure taxonomy

Phase 5.5 introduced `gomemforensics.common.models.FailureReason`, a
closed enum (`EVIDENCE_UNAVAILABLE`, `EVIDENCE_INVALID`,
`EVIDENCE_TRUNCATED`, `VOLATILITY_UNSUPPORTED`,
`OS_PROCESS_DISCOVERY_FAILED`, `ADDRESS_SPACE_UNAVAILABLE`,
`GO_RUNTIME_NOT_FOUND`, `PCLNTAB_INVALID`, `MODULEDATA_INVALID`,
`UNSUPPORTED_GO_VERSION`, `UNSUPPORTED_ARCHITECTURE`, `ALLGS_NOT_FOUND`,
`G_VALIDATION_FAILED`, `STACK_UNAVAILABLE`, `PCSP_INVALID`,
`UNWIND_STOPPED`, `INSUFFICIENT_EVIDENCE`, `INTERNAL_ERROR`), added as an
optional `reason` field on the pre-existing `AnalysisError` (default
`None`, fully backward compatible with every error site that predates
this taxonomy). All 31 production `AnalysisError` construction sites
across `go_runtime/detector.py`, `go_runtime/functab.py`,
`go_runtime/goroutines.py`, `go_runtime/mspan.py`, `go_runtime/strings.py`,
`go_runtime/types.py`, `pipeline.py`, and `volatility/integration.py` were
reviewed and classified into this taxonomy (never left as a generic,
unclassified error) - the classification distinguishes three genuinely
different situations that were previously indistinguishable by message
string alone: an unexpected internal exception (`INTERNAL_ERROR`), a
specific structural candidate that was read successfully but failed
validation (`G_VALIDATION_FAILED`, `INSUFFICIENT_EVIDENCE`), and a memory
region that could not be read at all (`ADDRESS_SPACE_UNAVAILABLE`).
Representative call sites are regression-tested for their assigned reason
(`tests/unit/test_functab.py`, `tests/unit/test_go_runtime_goroutines.py`,
`tests/unit/test_pipeline.py`, `tests/integration/test_volatility_real.py`);
`tests/unit/test_failure_reason.py` tests the taxonomy's own completeness
and its JSON-serialization behavior.

### Evidence-integrity hardening performed without a real image

Independent of real-image availability, `tests/unit/test_evidence.py` was
extended with four tests that exercise integrity properties a real
acquisition workflow depends on but that were not previously
regression-tested: hash stability across repeated validation of the same
unmodified file, duplicate-content detection via matching hashes across
two differently-named files, an unreadable-evidence path (simulated I/O
failure, since permission bits are not reliably enforceable cross-platform
in a unit test) raising `EvidenceAccessError` rather than a bare
exception, and confirmation that a short/truncated file is *recorded*
(exact observed size and hash) rather than rejected - `EvidenceValidator`
has no expected-size reference to compare against, so truncation
detection, if ever added, belongs at the Volatility/OS layer where a
partial page table or incomplete process list would actually surface it,
not fabricated here.

### Why this stopped at stage 5.5-C

Per the Phase 5.5 constraints: this project must never acquire the host's
own RAM, must never search the filesystem beyond `evidence/`/configured
paths, must never fabricate a "memory image" from a PE/ELF binary, and
must never use the user's production machine for an acquisition
experiment. With no image discovered under those constraints, stages
5.5-D through 5.5-K (evidence integrity against a real image, Volatility
real-image bring-up, Go-runtime/string/function/goroutine validation
against real memory, performance measurement against a real image) could
not be attempted without violating one of those constraints. This is
recorded as blocked, not as failed or skipped-without-explanation.

## Phase 6A — Go network artifact analyzer

Full design and source archaeology: `docs/architecture/go-network-artifacts.md`.
Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| String-based classification (IPv4/IPv6/hostname/URL/host:port) | UNIT (`test_network_classification.py`, 53 cases, pure string logic - no Go-version/architecture dependency) | UNVALIDATED |
| Function/goroutine association via existing evidence chain | UNIT (`test_network_analyzer.py`, hand-built dataclass fixtures) | UNVALIDATED |
| Behavior against real compiled-binary string content | COMPILED_BINARY_VALIDATED (`test_network_artifacts_fixture.py` - ~1,976 real static strings recovered from the real Go 1.26.2 fixture binary; zero false positives observed, one injected synthetic artifact still correctly recognized amid that real noise) | UNVALIDATED |
| Structured network objects (`net.TCPAddr`, `netip.Addr`, `net/url.URL`, TLS state) | SOURCE_VERIFIED (field layouts only, where stable) | NOT IMPLEMENTED |

**`REAL_MEMORY_VALIDATION = UNVALIDATED`** for this entire analyzer -
unchanged by Phase 6A, since Phase 5.5 remains blocked (see above). No
claim of real-memory validation is made anywhere in Phase 6A's output or
documentation.

## Phase 6B — Go credential/secret artifact analyzer

Full design, taxonomy, and source archaeology:
`docs/architecture/go-credential-artifacts.md`. Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| String-based classification (20 credential-artifact types across the stage-2 taxonomy) | UNIT (`test_credential_classification.py`, 69 cases: every supported category plus the full stage-21 false-positive list) | REAL_MEMORY_VALIDATED = FALSE |
| Function/goroutine/network association via existing evidence chains | UNIT (`test_credential_analyzer.py`, hand-built dataclass fixtures) | REAL_MEMORY_VALIDATED = FALSE |
| Redaction and log-safety | UNIT (`TestRedactionAndLogSafety` - explicit test that an injected secret value never appears in captured log output) | REAL_MEMORY_VALIDATED = FALSE |
| Behavior against real compiled-binary string content | COMPILED_BINARY_VALIDATED (`test_credential_artifacts_fixture.py` - ~1,976 real static strings recovered from the real Go 1.26.2 fixture binary; zero false positives observed, one injected synthetic artifact still correctly recognized amid that real noise) | REAL_MEMORY_VALIDATED = FALSE |
| Basic-Auth decoding | SOURCE-VERIFIED ALGORITHM (mirrors `net/http`'s real `parseBasicAuth`, local go1.26.2 install) + UNIT (Go's own doc-comment example, "Aladdin:open sesame") | REAL_MEMORY_VALIDATED = FALSE |
| Structured Go objects (`net/url.Userinfo`, `net/http.Cookie`, `crypto/tls.Certificate`, `crypto/x509.Certificate`) | SOURCE_VERIFIED (field layouts only, where exported) | NOT IMPLEMENTED |
| Live process environment block | NOT ATTEMPTED | NOT IMPLEMENTED (OS-loader layer, not Go runtime - future work) |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire analyzer, per the
Phase 6B task's explicit requirement - unchanged by this phase, since
Phase 5.5 remains blocked (see above). No implementation or test implies
otherwise anywhere in Phase 6B's output or documentation. No credential
was validated, authenticated, or transmitted anywhere during this phase's
implementation or testing - all processing is local.

## Phase 6C — Go cryptographic artifact analyzer

Full design, taxonomy, and source archaeology:
`docs/architecture/go-crypto-artifacts.md`. Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| PEM public-key/certificate/chain string recognition | UNIT (`test_crypto_classification.py`, 41 cases including the full stage-21/28 false-positive list) | REAL_MEMORY_VALIDATED = FALSE |
| Crypto-context identifier recognition (AES/ChaCha/RSA/ECDSA/Ed25519/X25519/HMAC/TLS_* shapes) | UNIT (same file) | REAL_MEMORY_VALIDATED = FALSE |
| Evidence-backed AES key detection via Phase 4 call-site evidence | UNIT (`test_crypto_analyzer.py::TestAesKeyEvidence`, including negative controls for wrong length/function/argument index) | REAL_MEMORY_VALIDATED = FALSE |
| Private-key reuse from Phase 6B (never re-parsed) | UNIT (`TestPrivateKeyReuse`) | REAL_MEMORY_VALIDATED = FALSE |
| Function/goroutine/network/credential association via existing evidence chains | UNIT (hand-built dataclass fixtures) | REAL_MEMORY_VALIDATED = FALSE |
| Redaction, fingerprinting, log-safety | UNIT (`TestRedactionAndLogSafety`; explicit injected-secret-never-in-logs test) | REAL_MEMORY_VALIDATED = FALSE |
| Behavior against real compiled-binary string/function content | COMPILED_BINARY_VALIDATED (`test_crypto_artifacts_fixture.py` - ~1,976 real static strings and real recovered functions from the real Go 1.26.2 fixture binary; zero false positives, including zero AES-key false positives from real call sites that never target `crypto/aes.NewCipher`) | REAL_MEMORY_VALIDATED = FALSE |
| Structured Go crypto objects (RSA/ECDSA/Ed25519/X25519 keys, TLS Config/ConnectionState, hash/AEAD/cipher state) | SOURCE_VERIFIED (field layouts only, where exported) | NOT IMPLEMENTED |
| Certificate/public-key content parsing (subject/issuer/validity) | NOT ATTEMPTED | NOT IMPLEMENTED (no vetted local X.509/ASN.1 parser dependency) |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire analyzer, per the
Phase 6C task's explicit requirement - unchanged by this phase, since
Phase 5.5 remains blocked (see above). No decryption, key validation, key
cracking, or external network activity occurred anywhere during this
phase's implementation or testing - all processing is local, and all test
fixture material is synthetic/fake (no real keys, certificates, or
credentials).

## Phase 6D — Go malware persistence artifact analyzer

Full design, taxonomy, and OS/source archaeology:
`docs/architecture/go-persistence-artifacts.md`. Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| Windows persistence string/command/API recognition (registry Run/RunOnce, Winlogon, startup folder, scheduled tasks, services, WMI, AppInit, IFEO) | UNIT (`test_persistence_classification.py`, 61 cases including the full stage-24 false-positive list across both platforms) | REAL_MEMORY_VALIDATED = FALSE |
| Linux persistence string/command recognition (systemd, cron, shell profile, autostart, init scripts, authorized_keys, LD_PRELOAD) | UNIT (same file) | REAL_MEMORY_VALIDATED = FALSE |
| Function/goroutine/network/credential/crypto association via existing evidence chains | UNIT (`test_persistence_analyzer.py`, hand-built dataclass fixtures) | REAL_MEMORY_VALIDATED = FALSE |
| Redaction, log-safety | UNIT (`TestRedactionAndLogSafety` - explicit injected-value-never-in-logs test) | REAL_MEMORY_VALIDATED = FALSE |
| Behavior against real compiled-binary string content | COMPILED_BINARY_VALIDATED (`test_persistence_artifacts_fixture.py` - 1,976 real static strings from the real Go 1.26.2 fixture binary, extended with 5 inert fake persistence markers; all 5 correctly recognized, only one documented incidental real-stdlib match (`OpenSCManagerW`, correctly scored LOW), no other unexpected match) | REAL_MEMORY_VALIDATED = FALSE |
| Structured OS artifacts (Windows registry hive/SCM/Task Scheduler recovery via real, inspected Volatility 3 plugins) | Volatility API located and inspected (`hivelist`/`printkey`/`scheduled_tasks`/`svcscan`) | NOT IMPLEMENTED (architecturally whole-kernel, unvalidatable at any tier available in this environment - see architecture doc) |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire analyzer, per the
Phase 6D task's explicit requirement - unchanged by this phase, since
Phase 5.5 remains blocked (see above). No persistence mechanism was
created or modified, no command was executed, and no external network
activity occurred anywhere during this phase's implementation or
testing - all processing is local and read-only, and all fixture
persistence markers are inert, obviously-fake constants never written
anywhere.

## Phase 6E — IOC extraction and cross-artifact correlation

Full design, taxonomy, and prohibited-inference rules:
`docs/architecture/go-ioc-correlation.md`. Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| IOC promotion (network/credential/crypto/persistence allowlist), dedup-key computation, confidence combination, validation-status derivation | UNIT (`test_ioc_extraction.py`, 21 cases) | REAL_MEMORY_VALIDATED = FALSE |
| Cross-artifact correlation (all 13 `CorrelationType` edges, bounds, no-proximity guarantees) | UNIT (`test_correlation.py`, 22 cases, including explicit same-process/adjacent-address negative tests) | REAL_MEMORY_VALIDATED = FALSE |
| Pipeline integration | UNIT (`test_pipeline.py::TestRecoverIocs`/`TestRecoverCorrelations`) | REAL_MEMORY_VALIDATED = FALSE |
| Behavior against the full real Phase 6A-6E chain | COMPILED_BINARY_VALIDATED (`test_ioc_correlation_fixture.py` - real compiled Go 1.26.2 fixture binary, 1,976 real recovered strings and real recovered functions; all 5 previously-injected Phase 6D fake persistence markers correctly promoted to IOCs and correlated; deterministic across repeated runs; bounded, non-exploding result) | REAL_MEMORY_VALIDATED = FALSE |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire phase, per the
Phase 6E task's explicit requirement - unchanged, since Phase 5.5 remains
blocked (see above). No malware verdict, threat score, or reputation
lookup exists anywhere in this phase's output. No network/DNS/WHOIS
activity occurred anywhere during this phase's implementation or
testing.

## Phase 6F — findings and evidence assessment

Full design, taxonomy, and prohibited-inference rules:
`docs/architecture/go-findings.md`. Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| Finding-type evidence rules (17 closed types, IOC-category-scoped rule tables), severity table, deduplication by reused `dedup_key` | UNIT (`test_findings.py`, 45 cases) | REAL_MEMORY_VALIDATED = FALSE |
| Confidence/validation-status propagation, function/goroutine context, provenance | UNIT (same file) | REAL_MEMORY_VALIDATED = FALSE |
| Correlation-based findings (`MULTI_ARTIFACT_EVIDENCE`/`SHARED_SOURCE_EVIDENCE`), both-endpoints-must-be-IOCs rule | UNIT (`TestCorrelationFindings`) | REAL_MEMORY_VALIDATED = FALSE |
| Prohibited-inference controls (no C2/persistence-established/credential-theft/exfiltration/key-usage-confirmed claims) | UNIT (`TestProhibitedInference`) + COMPILED_BINARY_VALIDATED (real-fixture full-text scan) | REAL_MEMORY_VALIDATED = FALSE |
| Pipeline integration | UNIT (`test_pipeline.py::TestRecoverFindings`) | REAL_MEMORY_VALIDATED = FALSE |
| Behavior against the full real Phase 2-6F chain | COMPILED_BINARY_VALIDATED (`test_findings_fixture.py` - real compiled Go 1.26.2 fixture binary; 6 findings from 6 IOCs/6 correlations derived from 1,976 real recovered strings; deterministic across repeated runs; zero prohibited-inference phrases; zero score/verdict fields) | REAL_MEMORY_VALIDATED = FALSE |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire phase, per the
Phase 6F task's explicit requirement - unchanged, since Phase 5.5 remains
blocked (see above). No malware verdict, malware score, threat score, ML
classification, or reputation lookup exists anywhere in this phase's
output.

## Phase 6G — forensic reporting and report generation

Full design, taxonomy, and redaction/wording rules:
`docs/architecture/go-reporting.md`. Summary validation status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| `ReportModel` construction (required/optional key handling, executive summary, process summaries, limitations, evidence traceability), malformed-input handling | UNIT (`test_reporting_models.py`, 19 cases) | REAL_MEMORY_VALIDATED = FALSE |
| JSON/HTML rendering (field completeness, determinism, self-containment, HTML-escaping/XSS-safety, secret-leak prevention, truncation bounds, forbidden wording) | UNIT (`test_reporting_renderers.py`, 21 cases) | REAL_MEMORY_VALIDATED = FALSE |
| CLI `report` command (success for both formats, malformed JSON, missing required keys, missing file, unsupported format, never re-runs analysis) | UNIT (`test_cli.py` additions, 9 cases) | REAL_MEMORY_VALIDATED = FALSE |
| Behavior against the full real Phase 2-6F chain, report-count fidelity, determinism, secret-leak prevention against a real fixture plus a synthetic true-secret injection | COMPILED_BINARY_VALIDATED (`test_reporting_fixture.py` - real compiled Go 1.26.2 fixture binary; report correctly represents 1,976 strings/6 IOCs/6 correlations/6 findings; HTML self-contained; byte-for-byte identical output across repeated renders of the same data; evidence-traceability chains for all 6 findings resolve to the real evidence SHA-256) | REAL_MEMORY_VALIDATED = FALSE |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire phase, per the
Phase 6G task's explicit requirement - unchanged, since Phase 5.5 remains
blocked (see above). Rendering a report from a fixture-derived or
synthetic analysis JSON never changes this constant; every generated
report states it explicitly in its own Validation Status section,
distinguishing compiled-fixture/synthetic-negative validation from real-
memory validation. No malware verdict, malware score, threat score, or
process-suspiciousness ranking exists anywhere in this phase's output.
No network/DNS/WHOIS activity, and no external resource (CDN, remote
script, remote font) is referenced by the HTML report.

## Phase 6H — end-to-end integration and validation

Full design, integration contracts traced, and audit trail:
`docs/validation/phase-6h-end-to-end-validation.md`. Summary validation
status:

| Capability | Validation performed | Real-memory status |
|---|---|---|
| Complete pipeline (evidence -> Volatility -> processes -> Go runtime -> strings/functions/goroutines -> network/credential/crypto/persistence -> IOC -> correlation -> findings -> JSON -> HTML) run via the real, unmodified `run_analysis()`, only the Volatility image-parsing layer substituted | COMPILED_BINARY_VALIDATED (`test_end_to_end_pipeline.py`, 31 tests) | REAL_MEMORY_VALIDATED = FALSE |
| Cross-artifact reference integrity (IOC source/related-artifact ids, correlation endpoints, finding supporting-ioc/artifact/correlation/function/goroutine ids, all process-id consistency), using real fixture-produced ids | COMPILED_BINARY_VALIDATED (`TestCrossArtifactConsistency`, same file) | REAL_MEMORY_VALIDATED = FALSE |
| Determinism/repeatability across repeated full-pipeline runs (ids, ordering, structurally identical JSON, byte-identical JSON/HTML reports) | COMPILED_BINARY_VALIDATED (`TestDeterminism`, same file) - **found and fixed a genuine `GoRuntime.runtime_id` nondeterminism defect** (see below) | REAL_MEMORY_VALIDATED = FALSE |
| Partial-analysis behavior (empty categories distinct from analyzer failure), secret-safety end-to-end (6 synthetic sensitive values injected, never leaked in HTML/CLI stdout), JSON round-trip (unicode/escaping/null/empty-collection fidelity), resource bounds (real 2,193-row Functions table truncation with explicit notice, JSON always complete) | COMPILED_BINARY_VALIDATED (`TestPartialAnalysis`/`TestSecretSafetyEndToEnd`/`TestJsonRoundTrip`/`TestResourceBounds`, same file) | REAL_MEMORY_VALIDATED = FALSE |
| Dangling cross-collection reference handling (IOC/correlation/finding referencing a nonexistent id), malformed report input at the CLI boundary | UNIT/SYNTHETIC (`test_error_and_dangling_references.py`, 10 tests) | REAL_MEMORY_VALIDATED = FALSE |
| CLI end-to-end workflow (`--help`/`info`/`analyze`/`report`, exit codes, overwrite behavior, stdout/stderr, never re-runs analysis on `report`) | COMPILED_BINARY_VALIDATED (`test_cli_end_to_end.py`, 12 tests) | REAL_MEMORY_VALIDATED = FALSE |

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire phase, per the
Phase 6H task's explicit requirement - unchanged, since Phase 5.5 remains
blocked (see above). **REAL MEMORY VALIDATION REMAINS BLOCKED.** This
phase performed no new detection, no malware scoring/verdict/ML
classification, no network/DNS/WHOIS/reputation activity, no automatic
memory acquisition, and no ARM64 expansion. The one production code
change made in this phase - deriving `GoRuntime.runtime_id`
deterministically from the already-deterministic `pclntab` address
instead of `uuid.uuid4()` - is a minimal fix to a genuinely broken
reproducibility contract discovered while validating determinism, not a
new capability; see `docs/validation/phase-6h-end-to-end-validation.md`
Section 9 for the full before/after evidence.
