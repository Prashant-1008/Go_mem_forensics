# Phase 7A — Real-Memory Validation Readiness & Sample Acquisition Audit

**Status: Phase 7A - readiness/audit only. No real memory image was
acquired, analyzed, or downloaded during this phase. No production code
was changed. `REAL_MEMORY_VALIDATED` remains `False`.**

## 1. Objective

Determine exactly what is required, and what is currently available, to
perform legitimate real-memory validation of GoMemForensics - without
performing that validation yet. This document answers: what do we have,
what can we use, what is missing, what exact image should be acquired
first, what tools/commands that will require, and what ground truth must
be recorded.

## 2. Current validation state

Verified directly against the installed package, not assumed from prior
reports:

```
__version__          = 0.14.0
PROJECT_PHASE         = "Phase 6H - End-to-End Integration and Validation"
REAL_MEMORY_VALIDATED = False
```

Full suite (unchanged by this phase): 976 passed, 1 skipped - the 1 skip
is `tests/integration/test_volatility_real.py::TestRealMemoryImage::test_full_pipeline_against_real_image`
(marked `@pytest.mark.memory_image`), skipped because no real image is
configured (see Section 4/Section 11's `real_memory_image_path` fixture
discussion).

## 3. Environment

Recorded directly from this development environment (not assumed):

| Item | Value |
|---|---|
| Host OS | Windows 10 Pro, build 10.0.19045 |
| Host architecture | x86-64 |
| Shell | Git Bash (MSYS2) over PowerShell/cmd.exe |
| Python (project venv) | 3.14.3 |
| Go toolchain | go1.26.2 (host `GOARCH` defaults to `386`, but `scripts/fixtures/build_fixture.ps1` explicitly cross-compiles `GOOS=windows/linux GOARCH=amd64` regardless of host arch - already verified working, both fixture binaries are present under `tests/fixtures/go/bin/`) |
| `volatility3` | 2.28.2 (installed in `.venv`) |
| `capstone` | 5.0.9 |
| `pefile` | 2024.8.26 |
| `click` / `pytest` | 8.5.0 / 8.4.2 |
| Total RAM | ~28.0 GiB (`TotalVisibleMemorySize` 29,306,124 KB) |
| Free RAM at audit time | ~15.7 GiB |
| Free disk (project volume) | 2.9 TiB of 3.7 TiB |
| Administrator/root capability | **Not available in this shell** (`net session` reports "not elevated") - memory acquisition tools (Section 9) universally require elevated/root privileges this session does not have |
| WSL | Present, WSL2, default distribution Ubuntu |
| Docker | Present (`Docker version 29.2.1`) - **not equivalent to a VM for memory acquisition**: a container shares the host kernel, so there is no separate, isolatable "guest physical memory" to image the way a true VM provides; Docker is not treated as a viable acquisition target for this project |
| VirtualBox / VMware CLI (`VBoxManage`, `vmware.exe`) | **Not found on PATH** |
| Hyper-V | **Unknown** - `Get-WindowsOptionalFeature` requires elevation this session does not have; must be checked by the project owner directly |

**Nothing was installed or system state changed during this audit.**

## 4. Volatility readiness

Volatility 3's actual installed API surface was already verified in
Phase 1 by reading the real installed source
(`docs/architecture/volatility3-integration.md`, 2.28.2) - re-confirmed
present and unchanged in this phase (file still exists, package version
still 2.28.2, no re-verification needed since no upgrade occurred).
Summary of what is already proven to work, against real (not mocked)
Volatility machinery:

- `Context`/`automagic.available`/`automagic.choose_automagic`/
  `plugins.construct_plugin` - the full construction path is exercised
  for real in `tests/integration/test_volatility_real.py` against a
  synthetic "garbage" file, confirming the graceful-unsupported path
  (`VolatilityInitializationError`) is real code, not a mock.
- Windows layer support: `LayerStacker`, `KernelPDBScanner`, Windows
  `pslist.PsList.list_processes`, `EPROCESS.add_process_layer()` - all
  traced to real source, none yet exercised against a real Windows
  image.
- Linux layer support: `LinuxSymbolFinder`, Linux
  `pslist.PsList.list_tasks`, `task_struct.add_process_layer()` - same
  status.
- Process-region access (Windows VAD / Linux VMA) - implemented in
  `gomemforensics.volatility.integration`, unit-tested with synthetic
  layer objects, never yet exercised against a real image.
- Image-format support: only `physical.FileLayer` (a flat/raw file) has
  ever been exercised, and only against a synthetic file. AFF4 and
  Microsoft crash-dump (`.dmp`) layer support is unverified (documented
  as such in `docs/validation/memory-acquisition.md`).

**New finding this phase, not previously documented anywhere in the
project: symbol/profile resource availability.** Volatility 3 resolves
kernel symbols via `KernelPDBScanner` (Windows, PDB-based) and
`LinuxSymbolFinder` (Linux, kernel-banner-matched ISF). Inspecting the
installed package directly:

```
.venv/Lib/site-packages/volatility3/symbols/
├── generic/vmcs/   (Intel VMCS layout JSON only - unrelated to OS kernels)
└── __init__.py
```

**No Windows PDB-derived ISF and no Linux kernel ISF is bundled or
cached locally.** This means the *first* real-image analysis attempt
against either OS will require Volatility 3 to either (a) fetch the
matching symbol table from its remote ISF server / Microsoft's public
symbol server at analysis time (requires outbound internet access on the
*analysis* machine, not GoMemForensics' own doing - Volatility 3's own
`SQLiteCache`/remote-ISF machinery, unrelated to and not modified by
this project), or (b) have a pre-built ISF file for the exact target
kernel/Windows build placed under Volatility's local symbol cache ahead
of time (for Linux, built with `dwarf2json` against the exact running
kernel's own debug symbols - which must be captured *from the VM*, not
guessed). This is an **operational requirement for whoever performs
acquisition**, not a GoMemForensics code gap - no analyzer code needs to
change - but it must be planned for explicitly before attempting the
first real image (see Section 9/13).

## 5. Local evidence / memory image inventory

Searched the entire repository (`evidence/`, and every path) for
`*.raw`, `*.mem`, `*.vmem`, `*.lime`, `*.dmp`, `*.bin`, `*.elf`, `*.aff4`,
and other documented memory-image extensions.

**Result: zero memory-image candidates found anywhere in this repository
or development environment.** `evidence/` contains only `README.md`
(the directory-usage policy document). The only built binary artifacts
present are the fixture's own compiled executables:

| File | Format | Purpose | Is a memory image? |
|---|---|---|---|
| `tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe` | PE executable | Compiled benign Go fixture (Windows) | **No** - a compiled binary file, read via a PE-section-mapped reader (COMPILED_BINARY_VALIDATED), never a captured process memory image |
| `tests/fixtures/go/bin/gomemforensics_fixture_linux_amd64` | ELF executable | Compiled benign Go fixture (Linux) | **No**, same distinction |

The `real_memory_image_path` pytest fixture (`tests/conftest.py`) is
already wired to auto-discover a real image two ways: the
`GOMEMFORENSICS_TEST_IMAGE` environment variable, or the first file
under `evidence/` whose suffix is `.raw`/`.mem`/`.dmp`/`.lime`/`.vmem`.
**This wiring already exists and required no change in this phase** -
placing a real image at either location will automatically un-skip
`TestRealMemoryImage::test_full_pipeline_against_real_image`.

## 6. Authors' repository findings

Audited `https://github.com/HalaAli198/Go-Memory-Forensics` directly.

**Directory structure (confirmed):**

```
Linux_Plugins/            (go_strings.py, go_functions.py, go_goroutines.py,
                            go_entire_heap.py, go_file_classifier.py,
                            third_party_analyzer.py)
Windows_Plugins/
file_func_params_extractor/  (per-Go-version function-line JSON databases)
required_heap_json_files/
  heap_strings_pid_1100.json   <- Obscura PID 1100 (see Section 7)
  heap_strings_pid_2004.json   <- BRICKSTORM PID 2004
  heap_strings_pid_2795.json   <- Pantegana PID 2795
Results/
  Table1_go_strings_Obsecura.txt
  Table2+Table3+Table4+Figure5+Figure6_go_functions_BRICKSTORM.txt
  Figure7_go_strings_Pantegana.txt
  Figure4_go_strings_Screenshotter.txt
LICENSE
README.md
```

**Confirmed explicitly: no `.raw`/`.mem`/`.vmem`/`.lime`/`.dmp`/`.aff4`
file exists anywhere in this repository.** No GitHub Releases exist
("There aren't any releases here"). No Git LFS usage or external
dataset-hosting link (Zenodo, Google Drive, academic repository) was
found in the README or repository content.

**The `heap_strings_pid_*.json` files and the `Results/*.txt` files are
derived reference OUTPUT, not the original memory images.** They are the
authors' own recorded tool output (heap-address/string JSON and
paper table/figure text), useful only for comparing a *future*
independent reproduction's output shape against the paper's, never as
input to Volatility or GoMemForensics themselves.

**Explicit statement per Step 5's requirement: original RAM image not
verified as publicly downloadable** for Obscura, BRICKSTORM, or
Pantegana. Nothing in the author repository, its README, or its releases
makes the original captured memory images available.

## 7. Public memory image findings

### 7a. Author's named samples - availability of the underlying malware/image

Cross-referenced against the paper itself (arXiv 2605.14020, fetched
directly - the reference PDF's own citation text, not guessed):

| Sample | OS | Go version | PID | Image publicly downloadable? |
|---|---|---|---|---|
| Obscura (ransomware) | Windows | 1.15 | 1100 | **Not verified as publicly available.** Paper attributes first observation to August 2025 threat reporting; does not state the memory image or executable is obtainable via VirusTotal/MalwareBazaar/other repository. |
| BRICKSTORM (backdoor) | Linux | 1.16.3 | 2004 | **Not verified as publicly available.** Attributed to UNC5221; paper does not state the executable or image is obtainable. |
| Pantegana (RAT) | Linux | 1.25.5 | 2795 | **Confirmed NOT independently available even to the paper's own authors as a "real-world" sample**: the paper states the original GitHub repository was removed, and the authors obtained "a preserved copy of the original source code" and recompiled it themselves in a controlled environment. This is closer to this project's own "own controlled Go image" approach (Section 8) than to a genuinely acquired in-the-wild malware image. |
| Screenshotter (reproducibility sample) | not stated (Linux/Windows-portable Go source) | 1.24.10 | n/a (reproducibility only) | **Source code is publicly available** - see Section 7b. Not itself a memory image; would need to be compiled and run to produce one. |

**None of the paper's four samples' original RAM images were found to be
publicly downloadable.** This confirms and sharpens the concern the
Phase 7A prompt raised: the presence of derived JSON/text output must
never be mistaken for image availability.

### 7b. Screenshotter's actual source - important safety caveat

The paper cites Screenshotter as `[omaidf, 2025]`,
`https://github.com/omaidf/go-malware/tree/master`. This repository was
inspected (read-only, description/README only - **not cloned, built, or
executed**) and found to be **self-described functional malware-
technique source code**, not a benign utility:

- README header: "⚠️ WARNING: Educational Purpose Only ⚠️"
- Explicit disclaimer: "examples of malware techniques implemented in Go
  for educational purposes... DO NOT use this code for malicious
  purposes... Using this code against systems without explicit
  permission is illegal."
- Contains eight modules: `ProcessInjection`, `Persistence`,
  `CredentialStealer`, `PrivilegeEscalation`, `Dropper`, `ExfilDocs`,
  `OutlookExfil`, and `Screenshotter` (the one component the paper
  actually used).
- MIT-licensed, targets Go 1.21+.

**This is not treated as equivalent to this project's own benign
fixture.** Even though the paper used only the `Screenshotter` module
(apparently a lower-risk screen-capture utility), the repository as a
whole is explicitly framed and licensed as functional offensive
tooling. Per this project's non-negotiable boundaries ("do not download
malware", "do not execute malware") and per CLAUDE.md sections 32/33,
**GoMemForensics' own development/test workflow does not clone, build,
or run this repository**, and this document does not recommend doing so
without a separate, explicit, human-authorized decision, legal
clearance, and a fully isolated/disposable/network-air-gapped VM. If a
future investigator chooses to pursue this path independently, it would
be a **Tier 4** activity (Section 11), not Tier 3, precisely because of
its origin repository - never presented as a "controlled benign Go
fixture" equivalent.

### 7c. Generic public memory images (no Go process, useful only for Tier 2)

The canonical, Volatility-Foundation-maintained index
(`https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples`)
was fetched directly and lists roughly 15 Windows samples and 3 Linux
samples from various sources (NIST/CFReDS, DFRWS challenges, Honeynet
challenges, "Art of Memory Forensics" companion images, malware-specific
specimens such as Cridex/Shylock/R2D2, and generic distribution images
from Second Look/Pikeworks). **Explicitly confirmed: none of these is
documented to contain a Go-language process** - they predate Go's
widespread malware/tooling adoption and are generic Windows XP/2003/
Vista/CentOS/Ubuntu/Debian samples. Many of the listed links use
now-defunct hosts or shortened URLs (`t.co`, `skydrive.live.com`,
`sendspace.com`) dated to roughly 2011-2013 and their current live
availability was **not individually verified** (out of scope for this
audit - "identify sources at this stage" only, no download attempted).

A second, more likely-current source was identified: **MemLabs**
(`github.com/stuxnet999/MemLabs`), an actively maintained, MIT-licensed,
educational CTF-style set of 7 Windows memory-dump challenges
("Lab 0" through "Lab 6"). All images are explicitly documented as
Windows. Exact hosting location/format/size were not resolved from the
README alone (likely per-lab external links, not committed to the repo
directly) and would need direct verification before any download
attempt. **No Go-process presence is claimed or expected** - these are
CTF puzzle images.

**Conclusion for Section 7c: a generic public Windows or Linux image can
validate Volatility integration/process enumeration/OS detection (Tier
2), but no publicly available generic image can validate Go runtime
extraction (Tier 3), because none contains a Go process.**

### 7d. A note on academic "memory forensics" datasets - a real trap avoided

`CIC-MalMem-2022` (Canadian Institute for Cybersecurity) was found in
initial search results and is a commonly cited "memory forensics
malware dataset." **Verified before citing it as usable: this dataset
contains only 55 pre-extracted CSV features per sample (via
VolMemLyzer), never the raw memory dump files themselves** - it is
explicitly the same "derived output, not original image" trap this
phase's Step 5 warned about for the author's own `heap_strings_*.json`
files. It is **not usable** as an image source for GoMemForensics and is
recorded here only so a future search does not waste time re-discovering
and re-rejecting it.

## 8. Go-specific memory image findings

Combining Sections 7a/7b/7c/7d: **no legitimately downloadable memory
image containing a genuine Go process (malicious or benign) was found
anywhere in this audit.** The only realistic path to a Tier 3 image
(Section 11) is acquiring one ourselves against our own controlled
benign fixture (Section 9), which this project already has 100% of the
non-privileged tooling for (Section 4/8's build scripts, the fixture's
own long-running mode).

## 9. Acquisition-tool availability

Checked local availability directly (not assumed from prior
documentation) - **none of the following is installed in this
environment**, and none was installed during this audit:

| Tool | OS | Local availability | Notes |
|---|---|---|---|
| WinPmem | Windows | Not installed | Requires Administrator (loads a signed kernel driver); not present on PATH or in the venv |
| DumpIt (Comae/Magnet) | Windows | Not installed | Same privilege requirement |
| Magnet RAM Capture | Windows | Not installed | Same privilege requirement |
| AVML (Microsoft) | Linux | Not installed (host is Windows; would need to run inside a Linux VM or WSL2, not the host) | Requires root |
| LiME | Linux | Not installed | Requires root, loads a kernel module built against the exact running kernel version |

Full tradeoff table (format, expected Volatility compatibility,
privilege requirements, hash workflow) was already documented in Phase
5.5's `docs/validation/memory-acquisition.md` and is **not duplicated
here** - it remains accurate and unchanged. This audit's only addition:
**this specific development environment currently has none of these
tools installed and is not running elevated**, so acquisition cannot
happen from this shell/session as configured; it requires either (a) an
elevated session on this host used *only* against a disposable VM's
memory, never this host's own RAM (per the explicit non-action clause
already in `memory-acquisition.md` and this phase's own boundaries), or
(b) root access inside a purpose-built Linux VM/WSL2 instance for the
Linux target.

## 10. Controlled Go memory image acquisition plan

Inspected `tests/fixtures/go/fixture.go` and
`scripts/fixtures/build_fixture.ps1` directly (not assumed). Findings:

- **A deterministic long-running mode already exists and requires no
  fixture modification.** `GOMEMFORENSICS_FIXTURE_DURATION_SECONDS`
  (env var) overrides the default 5-minute run duration - set it to
  whatever value gives the acquisition tool comfortable working time.
- **Known ground truth already baked into the fixture, verified by
  reading its source directly:**
  - 6 static string markers: `markerStatic`, `markerBanner`,
    `markerEmpty` (empty string), `markerRepeated`, `markerUnicode`
    (non-ASCII/emoji), `markerLong` (long concatenated literal) - plus
    one dynamically-assembled shared-backing-array pair
    (`markerSharedOriginal`/`markerSharedAlias`).
  - 5 inert fake persistence markers (`markerFakeRegistryRun`,
    `markerFakeSchtasks`, `markerFakeSystemdUnit`, `markerFakeCronPath`,
    `markerFakeAutostart`) - printed to stdout only, never written
    anywhere.
  - 8 heap-allocated `fixtureRecord` objects (`newHeapMarker(8)`), each
    with a runtime-`Sprintf`-built `Label` string - genuine heap string
    ground truth, distinct from the static markers above.
  - 10 `//go:noinline` functions covering the full Phase 4 argument-
    shape catalog (int/string/multi/pointer/zero/constant/global-
    address arguments, nested calls, a stdlib call, an app-to-app call).
  - 6 goroutines: 4 identical ticker-based `worker` goroutines, 1
    channel-blocked goroutine (`channelBlockedWorker`), 1 CPU-bound
    goroutine (`cpuBoundWorker`) - three distinct wait/run states for
    goroutine-recovery ground truth.
  - Both Windows (`gomemforensics_fixture_windows_amd64.exe`) and Linux
    (`gomemforensics_fixture_linux_amd64`) binaries are already built
    and present under `tests/fixtures/go/bin/` (gitignored build
    artifacts, rebuildable via `scripts/fixtures/build_fixture.ps1`).

**Concrete acquisition plan (Windows x86-64):**

1. Provision a disposable Windows x86-64 VM (version/build to be chosen
   by the investigator; must be a version Volatility 3 has kernel-
   symbol support for - see Section 4's ISF caveat). Never the
   investigator's or this project's own host machine.
2. Copy `gomemforensics_fixture_windows_amd64.exe` into the VM (rebuild
   fresh via `scripts/fixtures/build_fixture.ps1` if the binary's own
   provenance needs to be re-established for the ground-truth manifest).
3. Compute and record the executable's own SHA-256 *before* running it
   (`Get-FileHash` or equivalent) - this becomes `executable_hash` in
   the ground-truth manifest (Section 11).
4. Launch it with a duration comfortably longer than the acquisition is
   expected to take, e.g. `$env:GOMEMFORENSICS_FIXTURE_DURATION_SECONDS=600; .\gomemforensics_fixture_windows_amd64.exe`.
5. Record the process PID (the fixture prints its own markers to
   stdout/console on startup, which also confirms it is the correct,
   running process before acquisition).
6. While the process is still running, acquire physical memory with an
   elevated acquisition tool (Section 9) to write-once/controlled media.
7. Compute SHA-256 of the acquired image immediately, on the
   acquisition VM.
8. Shut down / discard the disposable VM.
9. Transfer the image to the analysis machine; recompute SHA-256; it
   must match exactly before proceeding (this is exactly what
   `gomemforensics validate <image>` / `EvidenceValidator` already do -
   no code change needed).
10. Fill in the ground-truth manifest (Section 11) completely before
    running `gomemforensics analyze`.
11. Run `gomemforensics analyze <image> --case-id <...>`, then
    `gomemforensics report <analysis.json>`.

**Linux x86-64 plan is identical in structure**, substituting
`gomemforensics_fixture_linux_amd64`, a Linux VM, and a root-privileged
acquisition tool (AVML or LiME); Linux additionally requires a
kernel-matched ISF (Section 4) built or fetched for that exact VM
kernel.

## 11. Ground-truth manifest schema

Minimum fields for every future real-memory image (image-level,
recorded once per acquisition):

```
case_id
image_id
acquisition_timestamp
acquisition_tool
acquisition_tool_version
source_host              (VM identifier/hostname - never a production or personal machine)
OS
OS_version
architecture
RAM_size
image_format
image_size
SHA256
process_pid
process_name
executable_hash
Go_version
Go_architecture
```

For the benign Go fixture specifically, additionally record (derived
directly from Section 10's source inspection, not guessed):

```
known_strings                    (6 static markers + 1 shared-backing-array pair; see Section 10)
known_functions                  (10 //go:noinline functions; see Section 10)
known_goroutine_count            (6: 4 worker + 1 channel-blocked + 1 CPU-bound)
known_network_markers            (none - the fixture performs no network I/O and defines no network-shaped strings)
known_credential_test_markers    (none defined in fixture.go - Phase 6B credential fixtures live only in the compiled-binary test suite's own synthetic data, not in fixture.go itself)
known_crypto_test_markers        (none defined in fixture.go - same caveat as above)
known_persistence_test_markers   (5: markerFakeRegistryRun, markerFakeSchtasks, markerFakeSystemdUnit, markerFakeCronPath, markerFakeAutostart)
```

**This schema explicitly distinguishes three separate concepts, never
collapsed into one:**

- **ground-truth-known**: what is verified to exist in the fixture's own
  source code (the lists above) or in the acquisition record itself
  (PID, hashes, timestamps) - established independently of
  GoMemForensics' own output.
- **expected-to-be-recovered**: a documented, evidence-based prediction
  of what GoMemForensics *should* find given its own already-verified
  Phase 2-6H capabilities (e.g. "the 6 static markers should appear as
  static-region `StringArtifact`s"; "no network/credential/crypto
  artifacts are expected, since the fixture defines none").
  Note: `known_credential_test_markers`/`known_crypto_test_markers` are
  correctly empty above because fixture.go itself defines none - this
  is itself an important, previously-undocumented gap noted in Section
  13.
- **actually-recovered**: the real output of a real `gomemforensics
  analyze` run against the real acquired image - only this counts toward
  `REAL_MEMORY_VALIDATED`, and only after comparison against the first
  two categories above.

## 12. Validation tiers

Defined per the Phase 7A prompt, never collapsed:

| Tier | Definition | Current project status |
|---|---|---|
| **TIER 0** | Synthetic tests (hand-built buffers/objects, no real file or image) | Extensively covered, Phase 0-6H unit suites |
| **TIER 1** | Compiled-binary validation (real compiled Go binary file bytes, read at their real virtual addresses via a PE/ELF-section-mapped reader - never an OS memory layer) | **Current project status** - every fixture-based integration test through Phase 6H |
| **TIER 2** | Genuine memory image, but no known Go process (validates Volatility integration/process enumeration/OS detection only) | Not yet attempted - candidate sources identified in Section 7c, none acquired |
| **TIER 3** | Genuine memory image with a known benign Go process (validates the full Go runtime extraction path) | Not yet attempted - this is the recommended first real-memory milestone (Section 13) |
| **TIER 4** | Genuine memory image with a controlled/approved Go malware sample | Not yet attempted, and not planned by this project without separate, explicit human authorization (see Section 7b) |

**Current project status remains TIER 1 (compiled-binary/synthetic
validated). `REAL_MEMORY_VALIDATED = FALSE`.** A Tier 2 image, if
acquired, could validate Volatility plumbing but **cannot by itself**
justify setting `REAL_MEMORY_VALIDATED = True` for Go-runtime-extraction
claims, since no Go process would be present to exercise Phase 2-6D at
all - Tier 2 and Tier 3 must never be conflated in whatever report
eventually documents a real-memory result.

## 13. First real-memory milestone

**Recommended: Tier 3, Windows x86-64 first, then Linux x86-64** -
exactly the order the Phase 7A prompt prefers, and consistent with
Phase 5.5's own prior recommendation in `docs/validation/memory-acquisition.md`.

**Concrete target**: one genuine Windows x86-64 RAM image, acquired from
a disposable VM running `gomemforensics_fixture_windows_amd64.exe` with
its markers/heap/functions/goroutines all live at acquisition time
(Section 10's plan), analyzed with a smoke-test scope - **not every
downstream analyzer is required for this first milestone**:

Required for the first milestone to count as a genuine Tier 3 result:

- real Volatility initialization succeeds against the image (no
  `volatility_unsupported` error)
- real process enumeration finds the fixture's own PID
- real per-process address space / `MemoryReader` access succeeds
- Go candidate detection recognizes the process
- `pclntab`/`pcHeader` recovered and validated
- Go version correctly identified (or correctly left `None`/range,
  never guessed)
- `moduledata` recovered and validated
- at least the fixture's known static strings are recovered
- evidence SHA-256 correctly computed and matches the pre-transfer hash
- provenance recorded end-to-end for every recovered artifact

Downstream analyzers (functions, goroutines, network/credential/crypto/
persistence, IOC/correlation/findings, reporting) are **not required**
to pass for this specific first-milestone claim, though running them is
expected to be low-additional-cost once the above succeeds (the
existing `tests/integration/test_volatility_real.py::TestRealMemoryImage`
test already exercises the full pipeline, not just the smoke-test
subset - a stronger bar than this milestone's minimum, achievable in the
same acquisition run).

## 14. Blockers

Per Step 13's required format (document, locate, explain, propose
smallest fix, do not implement unless strictly necessary):

1. **No real memory image exists anywhere in this environment or
   locally reachable source.** Not a code defect - an acquisition gap.
   No fix proposed; requires a human-performed acquisition per Section
   10.
2. **No acquisition tool is installed locally, and this shell is not
   elevated.** Not a code defect. Requires either explicit elevation on
   this host (used only against a disposable VM's memory, per the
   existing non-action clause) or a separate VM environment with its own
   privileged access.
3. **No VM software (VirtualBox/VMware CLI) was detected on PATH; Hyper-V
   status is unknown (requires elevation to check).** Requires the
   project owner to confirm/enable a hypervisor - out of scope for this
   audit to change.
4. **No Windows PDB-derived ISF or Linux kernel ISF is cached locally**
   (Section 4) - the first real-image analysis attempt will need either
   outbound internet access on the analysis machine (Volatility 3's own
   remote-symbol-fetch machinery) or a pre-built ISF matching the exact
   target kernel. Not a GoMemForensics code gap; an operational
   prerequisite to plan for before acquisition, not before this audit.
5. **`fixture.go`'s own header comment references
   `scripts/fixtures/build_fixture.sh`, but only `build_fixture.ps1`
   exists.** A minor, pre-existing documentation inconsistency noticed
   during Section 10's inspection - **not fixed in this phase** (no
   code/doc change was made; Step 13 explicitly prefers zero production
   changes, and this is cosmetic, not a readiness blocker, since the
   PowerShell script already builds both OS targets from any host).
6. **`fixture.go` defines no credential- or crypto-shaped ground-truth
   markers** (Section 11's `known_credential_test_markers`/
   `known_crypto_test_markers` are correctly empty) - meaning a first
   real-memory run cannot independently ground-truth-validate Phase 6B/
   6C recovery the way it can for strings/functions/goroutines/
   persistence. Not a blocker for the Tier 3 smoke-test milestone
   (Section 13 does not require it), but worth flagging as a known gap
   for whoever designs a *later*, more complete real-memory validation
   round - **not implemented in this phase**, since Step 13 forbids
   fixture changes without a demonstrated blocking need, and this does
   not block the first milestone.

**No production code change was made or is proposed as required for
Phase 7A.** All identified gaps are acquisition/environment/operational,
not code defects.

## 15. Required next actions

In order, for whoever picks this up next (explicitly not started in
this phase):

1. Project owner decides on and provisions a hypervisor (Hyper-V/
   VirtualBox/VMware) with explicit administrator action.
2. Provision one disposable Windows x86-64 VM.
3. Choose/verify an acquisition tool (Section 9) and confirm its
   current download/checksum out-of-band (none of Section 9's tools was
   downloaded or verified in this phase).
4. Pre-stage or plan for symbol/ISF resolution (Section 4's blocker 4).
5. Execute the acquisition plan in Section 10 for Windows first.
6. Populate the ground-truth manifest (Section 11) completely before
   running any analysis.
7. Run `gomemforensics validate` then `gomemforensics analyze` then
   `gomemforensics report` against the acquired image.
8. Compare actual output against ground-truth-known and
   expected-to-be-recovered fields; document any discrepancy honestly.
9. Only after a genuine, reproducible Tier 3 Windows result, repeat for
   Linux x86-64.
10. Only after both succeed does Phase 7B (implementing whatever the
    real-image results show is still needed, and formally setting
    `REAL_MEMORY_VALIDATED = True` if and only if warranted) become
    appropriate to plan.

## 16. Files changed

**None.** This phase produced exactly one new file
(`docs/validation/phase-7a-readiness.md`, this document) and made no
change to any production code, test, or other documentation file. No
`.gitignore`, evidence-handling, or artifact-semantics change was made
or needed.

## 17. REAL_MEMORY_VALIDATED status

**`REAL_MEMORY_VALIDATED = FALSE`.** No real-memory validation was
performed in Phase 7A. No genuine, approved memory image was acquired,
downloaded, or analyzed. This audit only surveyed availability and
readiness; it did not and could not change this constant.
