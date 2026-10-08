# Supported Platforms

**Status: Phase 5.5 - Real Memory Image Validation (blocked: no evidence
available; see `docs/validation/validation-plan.md`'s "Phase 5.5"
section).**

This document distinguishes project *scope* (what this project intends to
target) from *validated support* (what has actually been tested end to
end). As of Phase 5, evidence validation, the Volatility integration
layer, Go runtime detection, Go string recovery, Go function recovery, and
Go goroutine recovery are all implemented and exercised for real against a
synthetic (non-image) file and real compiled Go 1.26.2 binary bytes
(`pclntab` parsing, fixture marker-string content, function table/
classification/ArgInfo/backward-call-site recovery, and - Phase 5 -
`pcsp` decoding/unwind mechanics, all via a PE-section-mapped reader) -
but **end-to-end detection, string recovery, function recovery, or
goroutine recovery against a real captured memory image has not yet been
validated** - no such image was available in the development environment.
Goroutine recovery specifically has an even narrower ceiling on what a
compiled binary alone can prove: `runtime.allgs` has no populated data at
all outside a running process, so `allgs` discovery and `g` structural
validation are entirely unvalidated by any file-based test (see
`docs/architecture/go-goroutines.md`). Do not read "implemented" as
"validated against a real image" anywhere in this document.

## Operating systems

| OS | Project scope | Implemented | Validated against a real image | Notes |
|---|---|---|---|---|
| Windows | Yes (Phase 1 priority) | Yes | **No** | `windows.pslist.PsList`-based detection/enumeration implemented and unit/negative-tested; not yet run against a real Windows memory image. |
| Linux | Yes (Phase 1 priority) | Yes | **No** | `linux.pslist.PsList`-based detection/enumeration implemented and unit/negative-tested; not yet run against a real Linux memory image. |

## Architectures

| Architecture | Project scope | Implemented | Validated against a real image | Notes |
|---|---|---|---|---|
| x86-64 | Yes (Phase 1+ priority) | Yes (detection only) | **No** | Detected via Volatility's own layer metadata (`"Intel64"` -> `"x86_64"`); `gomemforensics.architecture.x86_64.X86_64Layout` (ISA facts for later ABI-aware analysis) is not yet consumed by any Phase 1 code. |
| ARM64 (Linux) | Planned, Phase 10 | No | No | **Not just unimplemented in GoMemForensics - the installed Volatility 3 (2.28.2) itself has no ARM/AArch64 translation-layer implementation at all** (verified by source inspection, `docs/architecture/volatility3-integration.md` section 10). An ARM64 image cannot be processed by this project's Volatility integration regardless of GoMemForensics' own architecture abstraction. |
| ARM64 (Windows) | Planned, Phase 10 | No | No | Same Volatility-level limitation as above. |
| x86 (32-bit) | Potential future work, unscheduled | Detection only (`"Intel32"` -> `"x86"`) | No | Not a current implementation target beyond OS-detection normalization; not planned in the phased roadmap. |

## Go versions

Magic-byte and struct-layout support (`gomemforensics.go_runtime.layouts`),
each entry traced to real Go source (local `go1.26.2` install or a
specific `github.com/golang/go` tag - see `docs/architecture/go-runtime.md`):

| Go versions | Magic recognized | pcHeader parsed | moduledata parsed | Validated against |
|---|---|---|---|---|
| 1.2-1.15 | Yes (`0xfffffffb`) | **No** - different, pre-redesign format, not implemented | No | N/A |
| 1.16-1.17 | Yes (`0xfffffffa`) | Yes | Yes | `go1.17.13` source (fetched); synthetic buffers |
| 1.18-1.19 | Yes (`0xfffffff0`) | Yes | Yes | `go1.19.13` source (fetched); synthetic buffers |
| 1.20-~1.21 | Yes (`0xfffffff1`, shared with next row) | Yes | Yes | `go1.20.14` + `go1.21.13` source (fetched); synthetic buffers |
| ~1.22+ | Yes (`0xfffffff1`, shared with previous row) | Yes | Yes | Local `go1.26.2` source; synthetic buffers **and** real compiled fixture binary bytes (`tests/integration/test_go_runtime_real_fixture.py`) |

The exact version boundary between "1.20-~1.21" and "~1.22+" was not
pinned down further than "somewhere after `go1.21.13`, at or before
`go1.26.2`" - `ModuledataParser` handles this by trying both candidate
layouts per magic family and accepting whichever validates structurally,
rather than guessing the boundary (see `docs/architecture/go-runtime.md`,
"Moduledata era ambiguity").

**None of the above has been validated against a real captured memory
image yet** - only real compiled binary file bytes (Go 1.26.2 only) and
synthetic buffers. This is recorded as pending, not fabricated, in
`docs/validation/validation-plan.md`.

### Go string recovery (`mspan`/`_type`) version coverage

Unlike `pcHeader`/`moduledata` above, `mspan` (heap span parsing) and
`_type`/`itab` (type metadata) are verified against **only the local
`go1.26.2` install** - an explicit, documented scope decision (see
`docs/architecture/go-runtime.md`, "mspan: single verified era"), not an
oversight. `gomemforensics.go_runtime.mspan.MSPAN_LAYOUTS_BY_GO_VERSION_RANGE`
currently has exactly one entry (`"1.22+"`); heap string recovery for any
other detected Go version range reports `UNSUPPORTED_RUNTIME_LAYOUT` and
is skipped (static-section recovery is unaffected, since it does not
depend on the `mspan` layout).

### Go function recovery (`_func`/`functab`) version coverage

Same explicit single-era scope decision as `mspan` above: `_func`/
`functab` are verified against **only the local `go1.26.2` install**.
`gomemforensics.go_runtime.layouts.FUNC_LAYOUTS_BY_GO_VERSION_RANGE`
currently has exactly one entry (`"1.22+"`); function recovery for any
other detected Go version range reports `UNSUPPORTED_RUNTIME_LAYOUT` and
is skipped entirely (string recovery is unaffected). Because of this, the
x86-64 ABI-era selection used by Capstone backward call-site analysis
(`gomemforensics.architecture.x86_64.is_register_based_abi`) is - in
practice, given the above - always resolved to the register-based
ABIInternal (Go >=1.17) path today; the stack-based ABI0 path exists and
is unit-tested (`tests/unit/test_backward_analysis.py::TestStackBasedAbi0`),
but has not yet been exercised against a real pre-1.17 binary, since no
`_func`/`functab` layout for that era has been verified yet.

### Go goroutine recovery (`g`/`gobuf`/`stack`) version coverage

Same explicit single-era scope decision, same reason:
`gomemforensics.go_runtime.layouts.G_LAYOUTS_BY_GO_VERSION_RANGE`
currently has exactly one entry (`"1.22+"`); goroutine discovery/
validation reports `UNSUPPORTED_RUNTIME_LAYOUT` for any other detected Go
version range. Stack unwinding is x86-64 only (verified against the
`!usesLR`/x86 branch of `runtime/traceback.go`'s real unwinder only - the
ARM64/link-register branch was neither read nor implemented); `g`/`allgs`
discovery and validation themselves are not architecture-gated (their
logic depends only on pointer size), but this is not a claim of ARM64
support - the project's Go-runtime-detection layer as a whole is
unreachable on ARM64 today regardless (see "Architectures" above),
Volatility 3 2.28.2 itself having no ARM/AArch64 translation layer.

Actual supported input formats depend entirely on the underlying Volatility
3 installation's capabilities (raw `physical.FileLayer` plus whichever
stacker recognizes the image, per `docs/architecture/volatility3-integration.md`
section 2). GoMemForensics does not restrict input by file extension - any
file is attempted. No specific format (`.raw`/`.mem`/`.dmp`/`.lime`) has
been confirmed against a real image of that format yet; this table will be
filled in once real fixtures are tested (CLAUDE.md section 8).

## Compatibility findings recorded during Phase 1

Extending the Phase 0 import-level checks, the following Volatility 3 APIs
were verified by direct source inspection AND exercised for real (against
a synthetic file, to confirm both the success and failure paths) during
Phase 1 - the full list with import paths and source locations is in
`docs/architecture/volatility3-integration.md`:

- `Context`, `automagic.available`/`choose_automagic`, `plugins.construct_plugin`
- `volatility3.plugins.windows.pslist.PsList` / `volatility3.plugins.linux.pslist.PsList`
  (`list_processes`/`list_tasks`, `add_process_layer`, PEB/`mm.exe_file` path access)
- `TranslationLayerInterface.read`/`is_valid`, `layer.metadata` (`os`, `architecture`)
- The real exception hierarchy (`UnsatisfiedException`, `InvalidAddressException`, `LayerException`)

**Explicitly still unverified:** all of the above against a *real* captured
memory image (only a synthetic/garbage file was used, to confirm the
graceful-unsupported-image path - see `docs/validation/validation-plan.md`).
