# PHASE 7B — FIRST REAL-MEMORY VALIDATION REPORT

**Status: Phase 7B - first genuine-memory validation attempt against an
investigator-supplied real Windows RAM image. `REAL_MEMORY_VALIDATED`
status is determined strictly by the acceptance criteria in Section 19,
not asserted in advance.**

## 1. Baseline

Before this phase: `__version__ = 0.14.0`, `PROJECT_PHASE = "Phase 6H -
End-to-End Integration and Validation"`, `REAL_MEMORY_VALIDATED = False`,
976 passed / 1 skipped. No production code changes had been made during
Phase 7A. Per Step 9 of the Phase 7B brief, version/`PROJECT_PHASE` are
**not** bumped merely to perform this validation.

## 2. Evidence Identity

Supplied by the investigator at `D:\prashant\projects\GoMemForensics\evidence\windows\`.
Recorded directly from the files themselves and their companion
metadata (never fabricated):

| Field | Value |
|---|---|
| case_id | `CASE-7B-BLUESKY` (assigned during this validation - none was supplied in advance) |
| image_id | `BLUESKY-20260702-074119` |
| original filename | `BLUESKY-20260702-074119.dmp` |
| absolute path | `D:\prashant\projects\GoMemForensics\evidence\windows\BLUESKY-20260702-074119.dmp` |
| acquisition date/time | `2026-07-02T07:47:52.524Z` (from the companion `.json`'s `machineInfo.date`) |
| acquisition duration | `6:24` (`serviceInfo.acquisitionTime`, minutes:seconds) |
| acquisition tool | DumpIt (Comae/Magnet), `serviceVersion "3.0.20171228.1"` (from the companion `.json`) |
| source host / machine | `machineName "BLUESKY"`, `machineId "04622EC4-FC1F-11EC-80F2-6C2408E92AD8"`, `userName "jainp"`, `workgroupName "WORKGROUP"` |
| OS | Windows, `buildNumber 26200`, `majorVersion 10`, `minorVersion 0`, `productType 1` (workstation) |
| architecture | `architectureType "x64"` (companion `.json`); independently confirmed `Intel64`/`x86_64` by Volatility (Section 5) |
| physical RAM (reported) | `maxPhysicalMemory 11555307520` bytes (~10.76 GiB) per the companion `.json` |
| physical RAM (captured) | `totalPhysicalPages 2045774` pages, `totalAccessiblePages 2045774` (100% accessible per DumpIt), `totalInaccessiblePages 0` - **note**: the reported installed-RAM figure and the captured-page count do not correspond to the same value (2,045,774 × 4096 ≈ 8.38 GB, matching the image size exactly, not the 10.76 GiB figure); recorded as observed, not reconciled or guessed at |
| image format | Microsoft Windows 64-bit **Complete Memory Dump** (`DumpType 0x1`) - independently confirmed (Section 3), not assumed from the `.dmp` extension |
| image size | 8,379,498,496 bytes (matches the companion `.json`'s `fileInfo.fileSize` exactly) |
| SHA-256 (primary .dmp) | `1878c9ae15ac99cf023e297f50cf1a91c58cc560be1dd7165374f7e171787172` |
| SHA-256 (.json) | `4c909104e301745946118a246c95819288f928d5b3a34f9978436730c4c05bc1` |
| SHA-256 (.cfg) | `391a70d22212c673050e902f2901ec79f30b448289b99031bfbb530bdf79a97d` |
| Windows kernel debug info | `pdbName "ntkrnlmp.pdb"`, `pdbGuid "11D7FE79-CC24-5612-0555-03EE86BB0E3E"`, `pdbAge 1` (from the companion `.json`) |
| Filesystem timestamps | `.dmp`/`.json` both `2026-07-02 13:17` (local); `.cfg` `2026-09-14 14:45` (local) - the `.cfg`'s filesystem timestamp is materially later than the `.dmp`/`.json`, suggesting it was copied/touched after the original acquisition rather than being byte-identical to whatever DumpIt wrote at 07:47:52 UTC on 2026-07-02; recorded as an observation, not treated as a defect since its own content (the process snapshot) is still genuine acquisition-time data and was not used as a basis for any pass/fail determination in this report |
| README.md | **Not present.** The investigator's evidence-set description mentioned a `README.md` alongside the three files; only `.dmp`/`.json`/`.cfg` actually exist under `evidence/windows/`. Recorded as a discrepancy, not treated as a blocker (it is supporting documentation, not evidence). |
| Read-only (filesystem) | The `.dmp` carries only the `A` (Archive) and `I` (Not-Content-Indexed) Windows file attributes - **no OS-level read-only attribute is set**. This analysis never opened the file for writing (Section 3's `EvidenceValidator.read_only` field below), but the file itself is not filesystem-protected against modification; recorded as an acquisition-hygiene observation for the investigator, not a GoMemForensics defect. |

**Disqualification check (per Step 1): this file is NOT** the project's
own `fixture.exe`/fixture ELF, an arbitrary binary, an executable file,
or a synthetic random test image - independently confirmed in Section 3
via the file's own magic bytes and Volatility's own format recognition,
not assumed from the `.dmp` extension.

## 3. Evidence Integrity

All three files were hashed and their **original bytes were never
modified, rewritten, normalized, or deleted** at any point in this
validation.

- **Independent magic-byte inspection** (before running any project
  code): first 8 bytes of the `.dmp` are `50 41 47 45 44 55 36 34` =
  ASCII `"PAGEDU64"`. `file(1)` independently identifies it as: *"MS
  Windows 64bit crash dump, version 15.26200, 4 processors, DumpType
  (0x1), 2045774 pages"* - internally consistent with the companion
  `.json`'s `buildNumber 26200`, `numberProcessors 4`, and
  `totalPhysicalPages 2045774`. **This is genuinely a Microsoft Windows
  crash-dump-format image, not a raw flat physical dump, and not merely
  assumed valid from its extension.**
- **SHA-256, computed via the actual production
  `gomemforensics.acquisition.evidence.EvidenceValidator`** (not a
  standalone script): `1878c9ae15ac99cf023e297f50cf1a91c58cc560be1dd7165374f7e171787172`,
  `file_size = 8379498496`, `read_only = True` (the validator's own
  read-only-open guarantee). **This matches, byte-for-byte, the SHA-256
  DumpIt itself recorded in the companion `.json` at acquisition time**
  - independent confirmation the file has not been altered since
    acquisition.
- File exists: yes. Readable: yes. Size non-zero: yes (8,379,498,496
  bytes). SHA-256 recorded: yes, and matches the acquisition-time
  record. No modification occurred (hash match). Analysis operated
  read-only throughout - no write, rename, or delete call was ever made
  against any of the three evidence files by any step in this
  validation.

**All Step 2 integrity checks pass. Validation proceeds.**

## 4. Volatility Initialization

Used the project's actual, unmodified
`gomemforensics.volatility.integration.VolatilityIntegration` class -
**not** a fake, mock, or alternate implementation (confirmed by direct
inline invocation of the real class against the real file).

- **Volatility version**: 2.28.2 (unchanged, already installed).
- **Layer stack** (confirmed by direct inspection of
  `context.layers`): `base_layer` (`FileLayer`, raw file access) →
  `memory_layer` (`WindowsCrashDump64Layer` - Volatility 3's native
  crash-dump-format translation layer, confirmed genuinely present and
  exercised in this installed version) → the kernel's own Intel64
  paging layer (`WindowsIntel32e`).
- **Symbol/ISF source**: Windows kernel symbols were resolved for
  `ntkrnlmp.pdb` / GUID `11D7FE79-CC24-5612-0555-03EE86BB0E3E`. **The
  first `initialize()` call took 70.6 seconds**; a second, independent
  `initialize()` call against the identical file later in this
  validation took **1.6 seconds**. Cross-referencing Volatility's own
  cache directory (`%APPDATA%\volatility3\`, `constants.CACHE_PATH`)
  shows freshly-created `data_*.cache`/`identifier.cache` files dated to
  this session - **consistent with Volatility fetching the matching
  symbol table remotely on first use and caching it locally for reuse**,
  exactly the operational prerequisite Phase 7A's readiness audit
  flagged (`docs/validation/phase-7a-readiness.md` Section 4).
  Confirmed: internet access was required and used for this step; no
  symbol substitution occurred (a mismatched/wrong symbol table would
  have caused `pslist` field decoding to fail outright, not silently
  succeed with plausible-looking process names).
- **OS detection result**: see Section 5 - initially **incorrect**
  (`"unknown"`), root-caused and fixed during this validation (Section
  17).
- **Architecture**: `x86_64`, correct from the first run.
- **Initialization errors/warnings**: none raised; `initialize()`
  completed successfully both times.
- **Process enumeration result**: succeeded, 245 processes, 0 errors
  (Section 6).

## 5. OS / Architecture

- `detect_architecture()` = `"x86_64"` - correct on the very first run,
  matching the companion `.json`'s `architectureType "x64"` and `file(1)`'s
  independent identification.
- `detect_os()` = **`"unknown"` on the first run** - **incorrect**,
  despite the image being unambiguously, independently confirmed
  Windows (Section 3) and despite Windows-specific plugin construction
  and kernel-symbol resolution having genuinely succeeded (245 real
  Windows processes were correctly enumerated by name in the very same
  run - see Section 6). Root cause identified and fixed; see Section 17
  for the full before/after evidence. **After the fix, `detect_os()` =
  `"windows"`**, confirmed on a subsequent real run against the same
  file.

## 6. Process Enumeration

Enumerated through the real, unmodified
`VolatilityIntegration.enumerate_processes()` → real Windows
`pslist.PsList.list_processes()`. **245 processes, 0 errors.**
Cross-checked against DumpIt's own companion `.cfg`
(its own independent, acquisition-time process snapshot, captured by a
different tool at a slightly different logical moment): 244 named-process
lines recorded there versus 245 from Volatility's own post-hoc
enumeration against the frozen dump - a 1-process difference, consistent
with two different enumeration methods/moments, not investigated further
(not required for this milestone and not a discrepancy that affects any
acceptance criterion). Both listings show the same recognizable set of
real Windows system/user processes (`smss.exe`, `csrss.exe`, `lsass.exe`,
`explorer.exe`, `svchost.exe` ×~90, Norton/McAfee/Lenovo/Intel utility
processes, Microsoft Edge/WebView2, Power Automate Desktop, etc.) - this
is a genuine, normal Windows workstation's process list, not a
purpose-built minimal VM snapshot.

**Both the `.cfg` and Volatility's own real enumeration contain a small
number of anomalous trailing entries** with hexadecimal-address-like
"names" (`None`) and implausibly large PID-like numbers (e.g.
`167154669161840`) - present in both independent listings. These are
recorded as an observed anomaly in the raw process-walk output, not
interpreted as evidence of anything (no behavioral, malicious, or
"hidden process" claim is made anywhere in this report - that would be
overclaiming beyond what this evidence and this project's scope
support).

## 7. Go Process Identification

**No process resembling the project's known Go fixture was found.**
Searched exhaustively, by two independent real methods, for any process
name containing `gomemforensics`, `fixture`, `golang`, or ending in
`.go` (case-insensitive, including Windows' own 15-character
`ImageFileName` truncation, which would still have left `gomemforensics`
fully visible):

1. DumpIt's own acquisition-time `.cfg` process snapshot: **no match**.
2. The real Volatility `pslist` enumeration against the `.dmp` (Section
   6, all 245 processes): **no match**.

**Outcome: FAIL** (not INCONCLUSIVE - this is positive evidence of
absence from two independent real sources against the same acquisition,
not merely an absence of evidence). The process list is consistent with
a genuine, normal Windows workstation's ordinary running state at
capture time, not a session where the project's benign Go fixture
(`gomemforensics_fixture_windows_amd64.exe`) was running.

Given the impracticality of running the Go detector against all 245
processes unconditionally (Section 9 records real per-process timing:
one process alone took 109 seconds; a full unconditional sweep was
estimated to require multiple hours and was judged out of proportion to
this milestone), this report does **not** claim to have run the Go
detector against every process in the image. Section 9 documents a
partial, real sample used for negative validation (Section 15) instead
of an exhaustive sweep - this is disclosed explicitly, not glossed over.

**Because no Go process was identified, Steps 8-10 (pclntab, Go version,
moduledata, static strings) have no target process to run against in
this image and are recorded as NOT ATTEMPTED below (Sections 10-13) -
never reinterpreted as a pass, and never run against an incorrect
substitute process.**

## 8. MemoryReader Validation

Demonstrated against a real, arbitrarily-chosen process with an
accessible memory layer (`pid=668`, `wininit.exe`) via the real,
unmodified `VolatilityIntegration.get_process_memory()`/
`get_process_regions()` - chosen only because its memory layer was
already confirmed accessible during an earlier probe, not because it is
expected to be Go-related (it is a standard Windows system process and
is not claimed to be Go-related anywhere in this report).

- 67 memory regions recovered, 66 marked readable (VAD-sourced).
- **Readable mapped address**: `0x2a4e3000000` (a 16 MiB VAD region,
  `readable=True writable=True executable=False source=vad`).
  `is_valid(0x2a4e3000000) = True`.
- **Pointer-sized read**: `read(0x2a4e3000000, 8)` → `0000000100000000`
  (real bytes from the real image).
- **Byte-range read**: `read(0x2a4e3000000, 256)` → 256 real bytes
  returned.
- **A second, distinct resident region**: `0x2a4e2710000` → `read(..., 8)`
  → `0100f10910012001` (real bytes).
- **Boundary/error behavior - deliberately invalid address**:
  `is_valid(0xfffffffffffffff0) = False`;
  `read(0xfffffffffffffff0, 8)` correctly raised
  `gomemforensics.common.memory.MemoryAccessError` (wrapping Volatility's
  own `PagedInvalidAddressException`) rather than returning zero-filled
  or garbage data.
- **Boundary/error behavior - a genuinely present, real forensic
  edge case**: one VAD-reported "readable" region
  (`0x7df5a6230000`) raised the *same* correct `MemoryAccessError` when
  read - the page described by that VAD entry was not actually resident
  in the captured physical memory (a normal, expected real-memory
  phenomenon: VAD metadata describes what the process's virtual address
  space *can* map, not a guarantee every page within it was captured).
  **The reader's "never silently zero-fill or substitute data" contract
  held correctly under a real, not synthetic, example of this
  condition.**

**MemoryReader semantics were not modified to accommodate this image -
they worked correctly, including the correct-failure case, without any
change.**

## 9. Go Candidate Detection

Ran the real, unmodified `gomemforensics.go_runtime.detector.GoProcessDetector`
- **never manually pointed at a known address**; the detector was given
only `(pid, architecture, pointer_size, reader, regions)` for each
process attempted and independently performed its own pclntab/pcHeader
scan.

**Full, unconditional detection was not run against all 245 processes**
(explained in Section 7: real per-process timing observed was highly
variable and, for at least one process, prohibitively slow for this
milestone's scope - `csrss.exe` alone took 109.22 seconds). Four real
processes were scanned to completion before this was stopped:

| PID | Name | Regions | pclntab candidates | Validated `GoRuntime`? | Time |
|---|---|---|---|---|---|
| 128 | Registry | 132 | 128 | No | 0.53s |
| 624 | smss.exe | 25 | 40 | No | 17.44s |
| 664 | csrss.exe | 125 | 6 | No | 109.22s |
| 668 | wininit.exe | 67 | 128 | No | 8.10s |

**No process produced a validated `GoRuntime`.** Several produced
structural pclntab *candidates* (magic-byte or structural
coincidences within non-Go binaries/data), correctly rejected by the
detector's own validation rules rather than promoted to a confirmed
runtime - this is expected, correct behavior for non-Go processes, and
directly serves as real evidence for Section 15 (negative validation).

**No Go candidate was independently detected anywhere in the processes
sampled.** No address, confidence, or provenance can be recorded for a
candidate that does not exist - recorded as NOT RECOVERED, not
reinterpreted.

## 10. PCLNTAB Validation

**NOT ATTEMPTED.** No process in this image was identified as the known
Go fixture (Section 7), and no process sampled in Section 9 produced a
validated `GoRuntime` whose pclntab could be further examined. There is
no target to validate pclntab structure, magic, pointer size, text
range, function table structure, or pcHeader against. Recorded as NOT
RECOVERED / NOT APPLICABLE for this image - not fabricated, not inferred
from the compiled-fixture's own build-time values.

## 11. Go Version Validation

**NOT ATTEMPTED**, for the same reason as Section 10. Ground truth
(expected Go 1.26.2, from the project's own fixture toolchain) exists,
but there is nothing to compare it against in this image. Recorded as
**NOT RECOVERED** - not lowered in confidence to manufacture a
comparison, and not silently skipped without explanation.

## 12. Moduledata Validation

**NOT ATTEMPTED**, for the same reason as Sections 10-11.

## 13. Static String Validation

**NOT ATTEMPTED.** None of the fixture's known static markers
(`GOMEMFORENSICS_FIXTURE_STATIC_MARKER_39f1`,
`gomemforensics benign go runtime fixture`,
`GOMEMFORENSICS_REPEAT_MARKER`,
`GOMEMFORENSICS_UNICODE_MARKER_héllo_wörld_日本語_🔍`,
`GOMEMFORENSICS_LONG_MARKER_...`, and the shared-backing-array pair) were
searched for as a raw memory-wide string scan, because doing so would
not constitute Go **string recovery** in this project's sense (Go string
recovery is runtime-structure-driven - Phase 3 - and requires a
recovered `GoRuntime`/`moduledata`, which does not exist for this
image). A raw, ungrounded byte-pattern search across an 8+ GB image
would not exercise `gomemforensics.go_runtime.strings.StringRecoveryEngine`
at all and would misrepresent what was actually validated - not
performed, per this project's own "never fabricate ground truth"
principle. Every marker is classified **NOT_FOUND** for this milestone,
consistent with Section 7's finding that the fixture process itself is
not present.

## 14. Ground-Truth Comparison

| Artifact | Ground Truth | Expected | Recovered | Status | Confidence | Evidence/Reason |
|---|---|---|---|---|---|---|
| Evidence integrity | SHA-256 recorded by DumpIt at acquisition | Hash match | `1878c9ae...` matches exactly | **PASS** | HIGH | Independent hash computed via real `EvidenceValidator` |
| Genuine RAM image (not a stand-in) | N/A | A real captured-memory format | Confirmed: Microsoft Windows 64-bit Complete Memory Dump (`PAGEDU64`/`DumpType 0x1`) | **PASS** | HIGH | Magic bytes + `file(1)` + Volatility's native `WindowsCrashDump64Layer` all agree |
| Volatility initialization | N/A | Successful construction against a supported OS | Succeeded, real (unmocked) `VolatilityIntegration` | **PASS** | HIGH | Section 4 |
| OS identification | Windows | `"windows"` | `"unknown"` (before fix) → `"windows"` (after fix) | **PASS (after fix)** | HIGH | Section 17 |
| Architecture identification | x86-64 | `"x86_64"` | `"x86_64"` | **PASS** | HIGH | Correct on first run |
| Process enumeration | N/A | Non-zero, real Windows processes | 245 processes, 0 errors | **PASS** | HIGH | Section 6 |
| Known Go fixture process | Should be running at acquisition (per this milestone's design) | A process named/derived from `gomemforensics_fixture_windows_amd64.exe` | **Not found** (two independent real sources) | **FAIL** | HIGH (in the negative finding) | Section 7 |
| MemoryReader real reads | N/A | Successful reads + correct boundary errors | Both demonstrated, against real regions and a real non-resident-page case | **PASS** | HIGH | Section 8 |
| Go candidate detection | Should detect the fixture's runtime | A validated `GoRuntime` | None found (4 real non-Go processes sampled; full sweep impractical) | **FAIL** (no target found) | N/A | Section 9 |
| pclntab | Known fixture pclntab shape | Structural validation | Not attempted (no target) | **NOT RECOVERED** | N/A | Section 10 |
| Go version | 1.26.2 | `"1.26.2"` or a version range including it | Not attempted (no target) | **NOT RECOVERED** | N/A | Section 11 |
| moduledata | Known fixture moduledata shape | Structural validation | Not attempted (no target) | **NOT RECOVERED** | N/A | Section 12 |
| Static string markers | 6 static markers + 1 shared-backing-array pair (`docs/validation/phase-7a-readiness.md` Section 11) | Multiple markers found | Not attempted (no target) | **NOT RECOVERED** | N/A | Section 13 |
| Known function/goroutine/network/persistence markers | Fixture-defined (Phase 7A Section 11) | N/A for this image | Not attempted (no target) | **NOT RECOVERED** | N/A | Downstream of Section 7's finding |

## 15. Negative Validation

Not a complete negative-validation campaign (per the brief's own scope
limitation) - a false-positive sanity check using the four real,
non-Go, known Windows system processes already scanned in Section 9:

- **`Registry`** (pid 128): 128 structural pclntab candidates found (a
  128 MiB+ registry hive region scanned structurally), **zero** promoted
  to a validated `GoRuntime`.
- **`smss.exe`** (pid 624): 40 structural candidates, **zero** validated.
- **`csrss.exe`** (pid 664): 6 structural candidates, **zero** validated.
- **`wininit.exe`** (pid 668): 128 structural candidates, **zero**
  validated.

**In all four cases, the detector correctly declined to report a Go
runtime despite finding raw structural (magic-byte-level) coincidences**
- direct, real evidence that `GoProcessDetector` does not manufacture a
Go artifact from a non-Go process merely because some bytes happen to
resemble a pcHeader. This is consistent with every prior phase's
synthetic/compiled-binary negative tests, now additionally confirmed
against real, non-synthetic Windows system process memory.

## 16. Test Suite

Full suite run after the Section 17 production fix:

**984 passed, 1 skipped** (baseline before this phase: 976 passed, 1
skipped; +8 net-new tests, all in `tests/unit/test_volatility_integration.py::TestResolveOs`,
the focused reproducer for Section 17's fix). The 1 skip is unchanged -
`tests/integration/test_volatility_real.py::TestRealMemoryImage::test_full_pipeline_against_real_image`,
still skipped because the `GOMEMFORENSICS_TEST_IMAGE` environment
variable was not set and no image was placed under `evidence/` at the
top level during this session's test runs (the evidence used in this
report lives under `evidence/windows/`, a subdirectory
`tests/conftest.py`'s `_discover_real_memory_image()` does not descend
into - noted here as a real, minor, easily-actionable gap, not fixed in
this phase since it is not required for any Section 19 acceptance
criterion and fixing it was not demonstrated as necessary by a
reproduced failure).

No existing test was deleted or weakened. No regression occurred.

## 17. Production Code Changes

**One production code change was required and made**, following the
brief's own required process (reproduce → minimal fix → re-run suite →
re-run real-memory check → document before/after):

**1. Failure observed**: `VolatilityIntegration.detect_os()` returned
`"unknown"` against a genuinely, independently-confirmed Windows image
(Section 5), despite `detect_architecture()` correctly returning
`"x86_64"` and `enumerate_processes()` correctly enumerating 245 real
Windows processes in the very same run.

**2. Classification**: a **code defect** in
`gomemforensics.volatility.integration._resolve_system_info()` - not an
unsupported memory layout (the image processed correctly in every other
respect), not a symbol issue (kernel symbols resolved correctly - see
Section 4), not an acquisition/image issue (the image is genuinely,
unambiguously Windows), and not an environmental issue.

**Root cause** (diagnosed by direct inspection of the real layer stack
against this image, not guessed): the kernel layer's own `"os"` metadata
key remained `"Unknown"` throughout the entire layer chain
(`base_layer` → `memory_layer` (`WindowsCrashDump64Layer`) →
`layer_name` (`WindowsIntel32e`)) for this image. Per
`docs/architecture/volatility3-integration.md` §10, the `"os"` metadata
key is set only by the OS-specific automagic modules
(`framework/automagic/windows.py` for Windows) - and in this installed
Volatility 3 2.28.2, that tagging did not occur when the underlying
physical layer came from `WindowsCrashDumpStacker`/`WindowsCrashDump64Layer`
rather than the standard raw-file `physical.FileLayer` pathway, even
though Windows-specific plugin construction and kernel-symbol resolution
both genuinely succeeded. `VolatilityIntegration.initialize()` already
independently and reliably records `self._os_kind` (`"windows"` or
`"linux"`) from which OS-specific plugin actually satisfied its
requirements - a real, already-verified signal, previously unused as a
fallback.

**3. Reproducer**: `tests/unit/test_volatility_integration.py::TestResolveOs`
(8 new tests) - a pure-function-level reproduction of the exact
condition (`_resolve_os("Unknown", "windows") == "windows"` and
`_resolve_os(None, "windows") == "windows"`), requiring no real
Volatility context or memory image, added *before* the production fix
and confirmed to describe the desired (not yet implemented) behavior.

**4. Minimal fix**: added `_resolve_os(metadata_os, os_kind)` (a small,
pure function, `src/gomemforensics/volatility/integration.py`) that
prefers the metadata-derived value (unchanged, primary signal) and falls
back to `os_kind` only when the metadata value is `"unknown"` - never
overriding a metadata value that already resolved to something usable.
`_resolve_system_info()` was changed from
`self._os = _normalize_os(kernel_layer.metadata.get("os"))` to
`self._os = _resolve_os(kernel_layer.metadata.get("os"), self._os_kind)`.
No other logic was touched; `_normalize_os`/`_normalize_architecture`
and every other method are unchanged. This is not a refactor of unrelated
code.

**5. Full suite re-run**: 984 passed, 1 skipped (Section 16) - zero
regressions.

**6. Real-memory re-run**: `detect_os()` re-confirmed `"windows"`
against the real image after the fix (Section 5), with `initialize()`
now completing in 1.6 seconds (symbol cache reuse).

**7. Before/after**:

| | Before | After |
|---|---|---|
| `detect_os()` | `"unknown"` | `"windows"` |
| `detect_architecture()` | `"x86_64"` (unchanged) | `"x86_64"` (unchanged) |
| `enumerate_processes()` | 245 processes, 0 errors (unchanged) | 245 processes, 0 errors (unchanged) |
| Full test suite | 976 passed, 1 skipped | 984 passed, 1 skipped |

No other production code change was made or is proposed. In particular,
no change was made to `GoProcessDetector`, `StringRecoveryEngine`,
`MemoryReader`, or any Go-runtime-analysis code - none of those modules
was exercised against a real Go process in this image (Section 7), so no
defect in them was discovered or could be discovered by this
validation.

## 18. Problems / Limitations

- **No process resembling the project's known Go fixture was found in
  this specific image** (Section 7) - this is the dominant limitation of
  this validation round. The image is a genuine, real, normal Windows
  workstation capture, not a purpose-built capture of the fixture
  running in isolation.
- A full, unconditional Go-candidate-detection sweep across all 245
  processes was not performed (impractical timing - Section 9); only 4
  real processes were sampled for negative validation.
- `evidence/windows/` is a subdirectory the existing
  `real_memory_image_path` pytest fixture does not auto-discover
  (Section 16) - a minor, un-fixed gap, not required by any acceptance
  criterion.
- The companion `.cfg`'s filesystem timestamp is later than the `.dmp`/
  `.json` (Section 2) - noted, not investigated further.
- The described `README.md` companion file does not exist (Section 2).
- The reported installed-RAM figure and the captured-page count in the
  companion `.json` do not correspond to the same value (Section 2) -
  recorded as observed, not reconciled.
- pclntab/Go-version/moduledata/static-string validation (Sections
  10-13) could not be attempted at all in this image, through no fault
  of the code paths that would perform them.

## 19. Acceptance Criteria

| # | Criterion | Result |
|---|---|---|
| A | Evidence integrity verified | **PASS** |
| B | Genuine RAM image confirmed | **PASS** |
| C | Volatility initializes successfully | **PASS** |
| D | Correct OS/architecture identified | **PASS** (after the Section 17 fix) |
| E | Known Go process independently recovered | **FAIL** |
| F | Production MemoryReader reads the process address space | **PASS** |
| G | Go candidate independently detected | **FAIL** (no target process exists in this image) |
| H | pclntab structurally validated | **FAIL** (not attempted - no target) |
| I | Go version recovered consistently with ground truth | **FAIL** (not attempted - no target) |
| J | moduledata recovered and structurally validated | **FAIL** (not attempted - no target) |
| K | Multiple known static string markers recovered | **FAIL** (not attempted - no target) |
| L | Ground-truth comparison is documented | **PASS** (Section 14) |
| M | No material regression in the existing test suite | **PASS** (Section 16) |
| N | All results have provenance | **PASS** (every result above traces to a specific command/section in this report) |

**Criteria E, G, H, I, J, K are not satisfied. Per Step 14, ALL criteria
must be satisfied for the milestone to succeed.**

## 20. REAL_MEMORY_VALIDATED Status

**`REAL_MEMORY_VALIDATED = FALSE`.**

This is not a partial or provisional TRUE - six of fourteen acceptance
criteria are not satisfied, all stemming from a single root cause
(Section 7: the known Go fixture process is not present in this specific
image). `REAL_MEMORY_VALIDATED` remains `False` and is **not** changed
by this phase. What *was* genuinely, newly established in this phase:
real Volatility 3 initialization against a real Windows crash-dump
image, real OS/architecture detection (after a real bugfix), real
process enumeration, real `MemoryReader` reads (including a real
non-resident-page boundary case), and real negative validation against
real non-Go processes - all COMPILED-IMAGE/REAL-VOLATILITY validated,
but **not** a validation of Go-runtime recovery against real memory,
since no Go process existed in this image to recover.

## 21. Phase 7C Boundary

Not started. Per the brief, this phase does not automatically proceed
into Linux validation, a second memory image, downstream-analyzer
validation, malware-memory validation, performance benchmarking,
large-scale corpus testing, or Phase 7C implementation.

**What this phase establishes for whoever picks up Phase 7C**: the
project's Volatility integration, evidence handling, and MemoryReader
are now confirmed to work correctly against a real, non-synthetic
Windows crash-dump image - a genuine step forward from Phase 7A's
purely theoretical readiness assessment. What remains completely
unvalidated: the entire Go-runtime-recovery path (candidate detection,
pclntab, Go version, moduledata, strings, and everything downstream)
against real memory, because no image containing a real, running Go
process (the project's own fixture or otherwise) has yet been supplied
and analyzed. **The concrete blocker for Phase 7C is unchanged from
Phase 7A's own recommendation**: acquire one genuine memory image while
the project's own compiled fixture
(`gomemforensics_fixture_windows_amd64.exe`,
`GOMEMFORENSICS_FIXTURE_DURATION_SECONDS` environment variable already
supports a comfortably long capture window) is actually running and
verifiably alive at the moment of acquisition -
`docs/validation/phase-7a-readiness.md` Section 10's acquisition plan is
unchanged and still the recommended path. This image (`BLUESKY-20260702-074119`)
remains valuable as a durable Tier-2-class regression fixture for
Volatility-integration/OS-detection/MemoryReader correctness (the
`_resolve_os` fix this phase produced was found and proven against it),
but cannot itself deliver the Tier 3 milestone.
