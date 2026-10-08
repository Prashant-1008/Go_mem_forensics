# PHASE 7C — CONTROLLED GO MEMORY VALIDATION

**Status: Phase 7C - preparation complete (Steps 1-5), STOPPED for
human-operated acquisition (Step 6) per this phase's own instructions.
Sections 8-26 are NOT YET PERFORMED and are explicitly marked as such
below - they will be completed only after a genuine, investigator-
acquired RAM image containing the running fixture is supplied.
`REAL_MEMORY_VALIDATED` remains `False` and version/`PROJECT_PHASE` are
unchanged (`0.14.0` / "Phase 6H - End-to-End Integration and
Validation"), per this phase's own explicit instruction not to bump
either merely because this phase started.**

## 1. Objective

Validate GoMemForensics against a **genuine Windows x86-64 RAM image
containing a known, benign, controlled Go process** (the project's own
fixture, actually running at the moment of acquisition) - the specific
milestone Phase 7B's supplied evidence (`BLUESKY-20260702-074119.dmp`)
could not deliver, because that image did not contain the fixture
(`docs/validation/phase-7b-first-real-memory-validation.md` Section 7).
This is a ground-truth validation: every recovered artifact is compared
against facts established independently of GoMemForensics' own output
(the fixture's own source code, its build configuration, and the
acquisition record).

## 2. Baseline

Verified directly against the installed package before making any
change:

```
__version__            = 0.14.0
PROJECT_PHASE           = "Phase 6H - End-to-End Integration and Validation"
REAL_MEMORY_VALIDATED   = False
```

Phase 7B's final state (unchanged, re-confirmed here, not re-derived
from memory): 984 passed, 1 skipped; one production change
(`src/gomemforensics/volatility/integration.py`, the `_resolve_os()`
fallback); the Phase 7B evidence set
(`evidence/windows/BLUESKY-20260702-074119.dmp`,
SHA-256 `1878c9ae15ac99cf023e297f50cf1a91c58cc560be1dd7165374f7e171787172`)
is untouched and **remains a separate, unrelated evidence item** - this
phase's new evidence (once supplied) will be a **distinct** file, never
confused with or substituted for BLUESKY.

## 3. Fixture Ground Truth

Read directly from `tests/fixtures/go/fixture.go` in this session (not
recalled from an earlier phase's summary) - confirmed byte-identical to
Phase 7A's own reading via `sha256sum`
(`a0e2fc18a20625bd76911914d16c587c803f9673960bedcfc0045fd40f57f17a`), so
no fixture behavior has drifted since Phase 7A's audit.

| Ground Truth | Value | Source |
|---|---|---|
| Target OS (this phase) | Windows | `scripts/fixtures/build_fixture.ps1` (`$env:GOOS = "windows"`) |
| Target architecture | amd64 (x86-64) | `scripts/fixtures/build_fixture.ps1` (`$env:GOARCH = "amd64"`) |
| Output executable name | `gomemforensics_fixture_windows_amd64.exe` | build script |
| Static string marker (short) | `markerStatic = "GOMEMFORENSICS_FIXTURE_STATIC_MARKER_39f1"` | `fixture.go:41` |
| Static string marker (banner) | `markerBanner = "gomemforensics benign go runtime fixture"` | `fixture.go:42` |
| Static string marker (empty) | `markerEmpty = ""` | `fixture.go:43` |
| Static string marker (repeated) | `markerRepeated = "GOMEMFORENSICS_REPEAT_MARKER"` (printed 3×) | `fixture.go:44`, `fixture.go:262` |
| Static string marker (Unicode) | `markerUnicode = "GOMEMFORENSICS_UNICODE_MARKER_héllo_wörld_日本語_🔍"` | `fixture.go:45` |
| Static string marker (long) | `markerLong = "GOMEMFORENSICS_LONG_MARKER_...AAAA...NNNN..._END_OF_LONG_MARKER"` | `fixture.go:46-49` |
| Dynamically-assembled shared-backing string pair | `markerSharedOriginal`/`markerSharedAlias`, both `"GOMEMFORENSICS_SHARED_MARKER_one-backing-array"` | `fixture.go:279-281` |
| Heap-allocated marker labels | 8 records, `Label = "GOMEMFORENSICS_FIXTURE_HEAP_MARKER_%02d"` (00-07), each a distinct heap-resident `fixtureRecord` | `fixture.go:69-80`, `newHeapMarker(8)` called at `fixture.go:283` |
| Known functions (10, all `//go:noinline`) | `fixtureArgInt`, `fixtureArgString`, `fixtureArgMulti`, `fixtureArgPointer`, `fixtureArgZero`, `fixtureArgConstant`, `fixtureArgGlobalAddress`, `fixtureInnermost`/`fixtureInner`/`fixtureOuter` (nested), `fixtureStdlibCall`, `fixtureHelperA`/`fixtureHelperB` (app-to-app) | `fixture.go:100-173`, all invoked from `runFixtureFunctionCatalog()` at `fixture.go:178-191` |
| Known function arguments | int, string, multi (int+string+bool), pointer (`*fixtureRecord`), zero-arg, constant, global/static-address (`&globalStaticTarget`), nested-call chain, stdlib call (`strings.ToUpper`), app-to-app call | same function bodies, `fixture.go:100-173` |
| Known goroutines (6 total) | 4× `worker` (ticker-based, identical), 1× `channelBlockedWorker` (blocks on plain channel receive), 1× `cpuBoundWorker` (bounded CPU loop + short sleep) | `fixture.go:195-257`, launched at `fixture.go:291-306` |
| Known network-related markers | **None.** The fixture performs no network I/O and defines no network-shaped string constant. | Confirmed by full re-read of `fixture.go` - no `net`/`net/http` import, no socket/URL/IP-shaped literal anywhere |
| Known credential/secret markers | **None defined in `fixture.go` itself.** (Phase 6B's own credential-analyzer test fixtures are separate, synthetic, unit-test-only data - never part of this compiled fixture.) | Confirmed by re-read; already flagged as a known gap in `docs/validation/phase-7a-readiness.md` Section 11/13 (blocker 6) |
| Known crypto markers | **None defined in `fixture.go` itself.** Same caveat as credentials. | Confirmed by re-read |
| Known persistence markers (5) | `markerFakeRegistryRun`, `markerFakeSchtasks`, `markerFakeSystemdUnit`, `markerFakeCronPath`, `markerFakeAutostart` - all inert string literals, printed to stdout only, never written to the registry/filesystem/service manager/cron/systemd | `fixture.go:55-59`, printed at `fixture.go:269-273` |
| Opens sockets / external communication | **No.** | Confirmed by import list (`fmt`, `os`, `strings`, `sync`, `time` only) and full body re-read |
| Launches child processes | **No.** | Same confirmation - no `os/exec` import, no `exec.Command` call anywhere |
| Deterministic long-running mode | **Yes, already built in, no fixture change needed.** Default run duration is 5 minutes (`time.Sleep(runDuration)`, `fixture.go:310-317`); overridable via the `GOMEMFORENSICS_FIXTURE_DURATION_SECONDS` environment variable, read at `fixture.go:311-316` | `fixture.go:308-317` |

No fixture modification was made or is needed for this phase (Step 2's
explicit instruction).

## 4. Fixture Build Information

Verified by actually re-running the project's existing, unmodified build
mechanism in this session (`scripts/fixtures/build_fixture.ps1`) - not
reusing the stale binaries left over from an earlier phase's build,
and not creating a second/alternate fixture or build path.

```
Go toolchain: go version go1.26.2 windows/386   (host toolchain binary's own
                                                   platform; GOOS/GOARCH below
                                                   are the actual build targets,
                                                   set explicitly by the script,
                                                   independent of host arch)
GOOS   = windows
GOARCH = amd64
```

| Field | Value |
|---|---|
| Build command | `powershell.exe -File scripts\fixtures\build_fixture.ps1` (Windows PowerShell 5.1 - `pwsh`/PowerShell Core is not installed in this environment; the script itself is PowerShell-5.1-compatible and required no change) |
| Output path | `tests\fixtures\go\bin\gomemforensics_fixture_windows_amd64.exe` |
| Output file size | 2,814,464 bytes |
| Output SHA-256 | `0fe619c89eeb902af3070167423bfcef9dae6142353444e86fcff687afe766cf` |
| PE `Machine` field | `0x8664` (IMAGE_FILE_MACHINE_AMD64 - independently confirmed via `pefile`, not assumed from the `.exe` extension or build flags alone) |
| PE `Subsystem` | `3` (IMAGE_SUBSYSTEM_WINDOWS_CUI - console application, consistent with the fixture's `fmt.Println`-based output) |
| PE `ImageBase` | `0x140000000` |
| Companion Linux build (not this phase's target, built by the same script run, recorded for completeness) | `gomemforensics_fixture_linux_amd64`, 2,726,141 bytes, SHA-256 `61561fe09c9f4f2afd86bbfe56c823146060f8a0baf16d14e00e0963109c81e3` |

**This executable SHA-256 (`0fe619c8...`) is ground-truth metadata about
the fixture binary only - it is never to be confused with the RAM-image
SHA-256 that will be recorded once an image is acquired (Section 7).**

The build completed with no errors or warnings and required no change to
the existing build script or fixture source (Step 3's "do NOT create a
second fixture... do NOT change the fixture unless the existing build is
actually broken" - it was not broken).

## 5. Acquisition Procedure

**This is a human-operated procedure. GoMemForensics performs none of
these steps automatically, and this document does not claim any of them
have been performed yet - they are instructions for the operator.**

1. On a disposable/controlled Windows x86-64 VM (never the analysis
   host, never a production machine - consistent with
   `docs/validation/memory-acquisition.md`'s existing non-action
   clause), copy `tests\fixtures\go\bin\gomemforensics_fixture_windows_amd64.exe`
   (SHA-256 `0fe619c89eeb902af3070167423bfcef9dae6142353444e86fcff687afe766cf`,
   Section 4) onto the VM.
2. Start the fixture with a duration comfortably longer than the
   acquisition is expected to take, e.g. (PowerShell, inside the VM):
   ```
   $env:GOMEMFORENSICS_FIXTURE_DURATION_SECONDS = "900"
   Start-Process -FilePath .\gomemforensics_fixture_windows_amd64.exe -PassThru
   ```
   (`Start-Process -PassThru` returns a process object whose `.Id` is the
   PID - record it immediately.)
3. **Record, at process start**: process name
   (`gomemforensics_fixture_windows_amd64.exe`), PID (from step 2's
   `-PassThru` object or Task Manager/`Get-Process`), full executable
   path on the VM, the executable's own SHA-256 (recompute on the VM
   with `Get-FileHash` and confirm it matches `0fe619c89e...` from
   Section 4 - confirms the correct, unmodified binary was actually
   copied), and a wall-clock start timestamp.
4. **Verify the process is still running** immediately before
   acquisition (e.g. `Get-Process -Id <PID>` succeeds, or the console
   window is still visibly printing/alive) - do not assume it is still
   alive from step 2 alone.
5. **Verify expected fixture behavior is active** - the fixture prints
   all of its static/persistence markers to its own console window at
   startup (`fixture.go:260-273`) and prints goroutine-start confirmation
   (`"started %d worker goroutines\n"`, `fixture.go:295`); confirm this
   output is visible before proceeding.
6. Keep the process running (do not close its window/let it exit) and
   run **DumpIt** (the same tool used for Phase 7B's BLUESKY evidence,
   `docs/validation/memory-acquisition.md`) manually, exactly as
   documented there - GoMemForensics does not invoke it.
7. Save the resulting `.dmp` (and any companion `.json`/`.cfg`/other
   acquisition-metadata files DumpIt produces) into
   `evidence/windows/` in this repository - **a distinct filename from
   `BLUESKY-20260702-074119.*`**, never overwriting or renaming that
   existing Phase 7B evidence set.
8. Do not modify, rewrite, normalize, compress, or convert the resulting
   `.dmp` in any way.
9. Compute the image's SHA-256 immediately after acquisition, on the
   acquisition machine, before any transfer.
10. Record the acquisition timestamp (from DumpIt's own companion
    `.json`, as Phase 7B's evidence already demonstrated it provides
    one).
11. Transfer the evidence set to the analysis machine without in-place
    modification; recompute SHA-256 there and confirm it matches exactly
    (this project's `EvidenceValidator` will do this automatically once
    supplied the file, exactly as it did for BLUESKY in Phase 7B).

**THE FIXTURE MUST BE RUNNING AT THE MOMENT OF MEMORY ACQUISITION.** This
document does not, and will not, claim otherwise once an image is
supplied - Section 10 of the eventual completed report will independently
re-verify this against the actual process-enumeration result, not merely
take the operator's word for it.

## 6. Evidence Provenance

**Not yet available.** No new RAM image has been supplied as of this
document's current state. This section will be completed once an image
is supplied (Step 7 onward).

## 7. Evidence SHA-256

**Not yet available.** Same reason as Section 6.

## 8. Volatility Validation

**NOT YET PERFORMED.**

## 9. Process Enumeration

**NOT YET PERFORMED.**

## 10. Go Fixture Process Identity

**NOT YET PERFORMED.**

## 11. Go Candidate Detection

**NOT YET PERFORMED.**

## 12. pclntab Recovery

**NOT YET PERFORMED.**

## 13. pcHeader / Go Version Recovery

**NOT YET PERFORMED.**

## 14. moduledata Recovery

**NOT YET PERFORMED.**

## 15. GoRuntime Validation

**NOT YET PERFORMED.**

## 16. String Ground-Truth Comparison

**NOT YET PERFORMED.**

## 17. Function Ground-Truth Comparison

**NOT YET PERFORMED.**

## 18. Goroutine Ground-Truth Comparison

**NOT YET PERFORMED.**

## 19. Downstream Artifact Validation

**NOT YET PERFORMED.**

## 20. Unexpected / False-Positive Observations

**NOT YET PERFORMED.**

## 21. Ground Truth vs Actual Recovery

**NOT YET PERFORMED.**

## 22. Test Results

Current baseline carried forward from Phase 7B, re-confirmed unchanged
in this session (no production code was touched in Steps 1-5): **984
passed, 1 skipped.** No test has been added yet in this phase - Step 15
explicitly scopes new tests to "genuinely necessary deterministic
validation behavior" discovered once real evidence exists, not added
speculatively in preparation.

## 23. Production Changes

**None in this phase so far** (Steps 1-5 are audit/build-verification/
documentation only). Per Step 17, any future change requires a
documented, reproduced, minimal-fix justification - none has arisen yet.

## 24. Limitations

- No new genuine RAM image has been acquired or supplied as of this
  document's current state - Sections 6-21 above are placeholders, not
  results.
- Per Step 3's fixture ground-truth table (Section 3), the fixture
  itself defines no network/credential/crypto markers - Section 19
  (downstream artifact validation), once performed, will be limited to
  what the fixture actually contains (persistence markers only, beyond
  runtime/strings/functions/goroutines) - this is a pre-existing fixture
  design characteristic, not a gap introduced by this phase.
- This phase targets Windows x86-64 only, consistent with the existing
  fixture/build scope; no Linux acquisition is planned in this phase.

## 25. REAL_MEMORY_VALIDATED Status

**`REAL_MEMORY_VALIDATED = FALSE`.** Unchanged. No real-memory validation
against a genuine Go-fixture-containing image has been performed yet in
this phase.

## 26. Phase 7D Boundary

Not applicable yet - this phase itself has not completed. Once a genuine
image containing the running fixture is supplied and Sections 6-21 are
completed, this section will be filled in with the actual Phase 7D
boundary (likely: Linux x86-64 acquisition, and/or expanding downstream-
analyzer validation, depending on what Sections 16-21 actually show).
