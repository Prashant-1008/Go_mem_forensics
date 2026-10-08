# Real Memory Image Acquisition — Options Assessment

**Status: documentation only. No acquisition tool listed here has been
installed, executed, or invoked by GoMemForensics or by this
documentation effort (Phase 5.5, stage B).** GoMemForensics itself never
acquires memory - it only ever analyzes an already-acquired image supplied
by the investigator. This document exists so that a future acquisition
step (performed by a human investigator, on hardware and under legal
authority they control - never this project's own CI or development
environment, and never the machine GoMemForensics itself runs on) can
choose a tool with the tradeoffs already understood, and so that the
"why has no real image ever been used" gap recorded throughout
`docs/validation/validation-plan.md` has a documented, actionable next
step rather than being left as an unexplained omission.

**Explicit non-action clause (CLAUDE.md sections 32/33, Phase 5.5
constraints):** GoMemForensics must never acquire its own host's RAM,
must never install a kernel driver, must never run a privileged
acquisition tool automatically, and must never treat a compiled
executable or any file assembled by this project as a substitute for a
real captured image. Nothing below changes that; it is a survey, not an
integration.

## Windows

| Tool | Acquisition format | Expected Volatility 3 compatibility | Privileges required | Changes system state? | Recommended hash workflow | Typical output size | Directly consumable by GoMemForensics? |
|---|---|---|---|---|---|---|---|
| WinPmem | `.raw` (flat physical memory dump), optionally AFF4 container | Raw output: yes, via Volatility 3's `physical.FileLayer` + Windows stacker (as already exercised against a synthetic file in `tests/integration/test_volatility_real.py`). AFF4 container: **not verified** - would require Volatility 3's AFF4 layer support, not inspected in this environment. | Administrator (loads a signed kernel driver to read physical memory) | Loads a kernel driver for the duration of acquisition; does not modify disk contents of the target beyond the driver's own temporary presence | Compute SHA-256 of the output file immediately after acquisition, before any transfer; compare again after transfer to the analysis machine | Equal to installed RAM (multi-GiB) | Yes, if raw `.raw` output - same "any file is attempted" path already implemented (`docs/supported-platforms/platforms.md`) |
| DumpIt (Comae/Magnet) | `.raw` or `.dmp` (Microsoft crash-dump-compatible) | Raw: yes, same as above. Crash-dump `.dmp` format specifically: **not verified** - Volatility 3's Windows crash-dump layer was not inspected in this environment. | Administrator | Same kernel-driver caveat as WinPmem | Same SHA-256-before/after-transfer workflow | Equal to installed RAM | Raw output: yes (unverified specifically). `.dmp`: unverified |
| Magnet RAM Capture | `.raw` | Same as WinPmem's raw path (unverified specifically, but architecturally identical - a flat physical dump) | Administrator | Same kernel-driver caveat | Same SHA-256 workflow | Equal to installed RAM | Unverified specifically, but expected yes for raw output |

## Linux

| Tool | Acquisition format | Expected Volatility 3 compatibility | Privileges required | Changes system state? | Recommended hash workflow | Typical output size | Directly consumable by GoMemForensics? |
|---|---|---|---|---|---|---|---|
| AVML (Microsoft) | `.lime` (LiME format) or raw | LiME: Volatility 3 ships a LiME layer (`framework/layers/`, not exercised end-to-end in this environment - unverified specifically). Raw: same `physical.FileLayer` path already exercised against a synthetic file. | Root (reads `/dev/mem` or `/proc/kcore`, or a loaded kernel module depending on mode) | No kernel module required in its default `/proc/kcore`-based mode on modern kernels; may load a module on older kernels | SHA-256 immediately post-acquisition and again post-transfer | Equal to installed RAM | Raw output: yes (unverified specifically). `.lime`: unverified |
| LiME (Linux Memory Extractor) | `.lime` | Same LiME-layer caveat as AVML | Root, loads a kernel module built against the exact running kernel version | Loads a kernel module for the duration of acquisition | Same SHA-256 workflow | Equal to installed RAM | Unverified specifically |

## What "expected Volatility 3 compatibility" means here

Every "yes" above traces only to the two things this project has actually
exercised (`docs/architecture/volatility3-integration.md`,
`docs/supported-platforms/platforms.md`): (1) Volatility 3's raw
`physical.FileLayer` plus the Windows/Linux `pslist`-driven stacker
against a **synthetic garbage file** (to confirm the graceful-unsupported
path), and (2) real compiled Go 1.26.2 binary bytes read through a
PE-section-mapped reader that is **not** an OS memory layer at all. No
tool in this table's output has been fed through GoMemForensics or bare
Volatility 3 in this development environment. Every "unverified"
annotation above is intentional - CLAUDE.md section 8 ("Never claim a
format is supported without testing it") applies to acquisition-format
support exactly as it does to Go-version support.

## Recommended acquisition + hash workflow (for a future investigator)

1. Acquire on the target system using one of the tools above, writing
   output to write-once or otherwise controlled media, never back onto
   the target's own primary volume if avoidable.
2. Compute SHA-256 of the output immediately, on the acquisition machine.
3. Transfer the image (network transfer or physical media) to the
   analysis machine without any in-place modification (no decompression
   that discards the original compressed file, no format conversion that
   overwrites the original).
4. Compute SHA-256 again on the analysis machine; the two hashes must
   match exactly before any GoMemForensics analysis begins. This is
   exactly what `gomemforensics.acquisition.evidence.EvidenceValidator`
   is designed to compute (see `tests/unit/test_evidence.py`,
   `test_hash_is_stable_across_repeated_validation`) - GoMemForensics
   validates the hash of whatever file it is given, but it has no way to
   know what the *pre-transfer* hash was unless the investigator records
   it separately at acquisition time.
5. Run `gomemforensics validate <image>` before `analyze` to confirm the
   file is readable and hashed before committing to a full run.

## Recommended first real-memory-image target (per Phase 5.5 request)

The lowest-risk way to obtain the project's first `REAL_MEMORY_VALIDATED`
result is **not** the investigator's own production machine (explicitly
excluded by the Phase 5.5 constraints): a disposable virtual machine
(Windows or Linux x86-64, matching Phase 1's implemented targets),
running the project's own benign fixture (`tests/fixtures/go/fixture.go`,
already built for both OSes via `scripts/fixtures/build_fixture.ps1`),
acquired with one of the tools above, then discarded. This keeps the
acquired image's contents fully known and benign (no real investigative
evidence, no third-party data), while still being a genuine captured
process memory image - something no compiled binary or synthetic buffer
in this project's test suite can ever substitute for (see
`docs/architecture/go-goroutines.md`'s discussion of why `allgs`/`g`
recovery specifically has no file-based equivalent).
