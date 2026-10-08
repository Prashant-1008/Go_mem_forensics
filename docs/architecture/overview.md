# Architecture Overview

**Status: Phase 2 - Go Process and Runtime Detection. Evidence validation,
the Volatility 3 integration layer, and Go runtime detection
(pclntab/pcHeader/moduledata, Go version ranging) are implemented; Go
string/function/goroutine recovery are not.**

## What this component covers

The overall GoMemForensics system architecture: how a memory image flows
from evidence validation through Volatility 3 integration, Go runtime
detection/reconstruction, artifact extraction, correlation, and reporting.

## Target pipeline

```text
Memory Image (Windows/Linux)
  -> Evidence Validation (hash, metadata, read-only guarantee)      [implemented]
  -> Volatility 3 Layer (context/automagic/plugin construction)     [implemented]
  -> OS Detection / Architecture Detection                          [implemented]
  -> Process Enumeration + per-process memory access                [implemented]
  -> Go Process Detector                                            [implemented]
  -> Go Runtime Parser (pclntab / moduledata)                       [implemented]
  -> Go Strings / Go Functions / Goroutines                          [not implemented - Phases 3-5]
  -> Artifact Correlation                                           [not implemented - Phase 7]
  -> IOC Extraction                                                 [not implemented - Phase 6]
  -> Findings / Confidence                                          [not implemented - Phase 6-7]
  -> Forensic Report (JSON implemented; HTML / PDF not yet)         [partially implemented - Phase 8]
```

## What exists today (Phase 2)

- `src/gomemforensics/acquisition/evidence.py` - read-only evidence
  validation and chunked SHA-256 hashing.
- `src/gomemforensics/common/memory.py` - the `MemoryReader` abstraction;
  `MockMemoryReader` for unit testing; (Phase 1) `VolatilityMemoryReader`
  in `volatility/integration.py` as the real Volatility-backed
  implementation; (Phase 2) `MemoryRegion`, the OS-independent region
  abstraction the Go runtime layer scans.
- `src/gomemforensics/architecture/` - the `ArchitectureLayout` abstraction
  (`x86_64.py` fully described; `arm64.py` a deliberately unimplemented
  future extension point). Still not consumed by any implemented code (no
  ABI-aware analysis exists yet) - Volatility's own layer metadata is what
  architecture detection actually uses.
- `src/gomemforensics/os/` - a minimal OS profile abstraction (name,
  support status, target architectures).
- `src/gomemforensics/volatility/runner.py` - `VolatilityRunner`: real,
  OS-agnostic Volatility Context/automagic/plugin construction. See
  `docs/architecture/volatility3-integration.md` for every verified API
  this is built from.
- `src/gomemforensics/volatility/integration.py` - `VolatilityIntegration`:
  the stable facade (`initialize`/`detect_os`/`detect_architecture`/
  `enumerate_processes`/`get_process_memory`/(Phase 2) `get_process_regions`)
  plus `VolatilityMemoryReader`.
- `src/gomemforensics/go_runtime/` (new in Phase 2) - `layouts.py`
  (source-verified struct field layouts), `version.py`
  (`GoVersionDetector`), `pclntab.py` (`PclntabParser`), `moduledata.py`
  (`ModuledataParser`/`ModuledataValidator`), `detector.py`
  (`GoProcessDetector`, the per-process orchestrator), `scanning.py`
  (resilient chunked region scanning), `models.py` (`GoRuntime`,
  `PclntabCandidate`, `ModuledataCandidate`). See
  `docs/architecture/go-runtime.md` for the full writeup.
- `src/gomemforensics/pipeline.py` - orchestrates evidence validation +
  Volatility integration + (Phase 2) per-process Go runtime detection into
  a single `AnalysisResult`, with JSON serialization (`write_json`).
- `src/gomemforensics/common/models.py` - `ArtifactProvenance`,
  `AnalysisError`, `AnalysisStatistics`, and `ProcessInfo` (Phase 2:
  `is_go_candidate`/`go_confidence`/`go_version`/`go_runtime_id` are now
  populated for real, gated on the confidence policy in
  `docs/architecture/go-runtime.md`).

## Design principle carried through every later phase

Every stage after Go runtime reconstruction (Phase 2+) will depend only on
the reconstructed runtime model (parsed `pcHeader`, `moduledata`,
type/interface indices, and a version-and-architecture-keyed
`RuntimeLayout`), not on Volatility internals directly. Analyzer logic is
written and unit-tested against the `MemoryReader` interface so it never
requires a real memory image or a live Volatility context to test -
`VolatilityMemoryReader` (Phase 1) is the first concrete proof this seam
works: it satisfies the same `MemoryReader` interface `MockMemoryReader`
does.

## Known limitations at this phase

- `pclntab`/`moduledata` detection exists; type/interface metadata,
  string, function, and goroutine recovery have not been implemented
  (Phase 3+).
- Go 1.2-1.15 (pre-pcHeader-redesign format) is magic-recognized but not
  struct-parsed - see `docs/architecture/go-runtime.md`.
- Volatility 3's own translation-layer support in the installed version
  (2.28.2) covers only Intel (x86/x86-64); there is no ARM64 layer
  implementation at all in this Volatility version, so ARM64 images cannot
  currently be processed regardless of GoMemForensics' own architecture
  abstraction (see `docs/architecture/volatility3-integration.md` section 10).
- Windows executable-path recovery uses the process's own PEB
  (`ProcessParameters.ImagePathName`); Linux executable-path recovery is a
  best-effort dentry-path walk (`mm.exe_file` -> `dentry.path()`) that is
  not guaranteed to succeed for every process.
- No real captured memory image was available in the development
  environment to validate end-to-end OS/architecture/process/Go-runtime
  detection against; a benign fixture Go program exists and builds
  successfully (`tests/fixtures/go/`), but was not captured into a memory
  image (no acquisition tooling available - see
  `docs/validation/validation-plan.md`, not fabricated). Real compiled
  fixture-binary *file* bytes (not a memory image) were used to validate
  `pclntab` parsing for real, though.
- No correlation, IOC extraction, or non-JSON reporting exists yet.
