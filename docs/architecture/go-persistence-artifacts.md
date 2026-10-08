# Go Malware Persistence Artifact Analyzer (Phase 6D)

**Status: Phase 6D - Go Malware Persistence Artifact Analyzer. Extraction
only. Never persistence creation/modification, never command execution,
never target-system modification of any kind (CLAUDE.md section 20 /
Phase 6D CORE OBJECTIVE).**

## CORE OBJECTIVE, restated precisely

This analyzer finds persistence-*related evidence* - it never proves
malware persistence, never proves persistence was successfully
established, never modifies or creates persistence, and never executes
recovered commands. A recovered string such as
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` is evidence that
that *string* exists in the binary's memory. It is **not** proof that:

- the registry key exists
- the key was written
- persistence succeeded
- the process executed anything

Every `PersistenceArtifact`'s `notes` field uses one of exactly five
precise, non-overclaiming phrases - never a stronger claim:

| Phrase | Used when |
|---|---|
| `PERSISTENCE_ARTIFACT_OBSERVED` | A complete, self-contained artifact was recognized (e.g. a full SSH `authorized_keys` line, a bare API-name reference) |
| `PERSISTENCE_PATH_OBSERVED` | A specific persistence-related path/registry-key shape was recognized |
| `PERSISTENCE_COMMAND_OBSERVED` | A persistence-related command-line shape (`schtasks /create`, `sc create`, `systemctl enable`, `crontab -e`) was recognized |
| `PERSISTENCE_CONFIGURATION_REFERENCED` | Multiple related configuration markers were found together (e.g. a systemd unit's `[Service]`/`ExecStart=`, two related WMI class names) |
| `PERSISTENCE_FUNCTION_ASSOCIATED` | Appended when an explicit Phase 4 call-site evidence chain links the artifact to a recovered function |

`PERSISTENCE_CONFIRMED`, `PERSISTENCE_ESTABLISHED`, and `COMMAND_EXECUTED`
**never appear anywhere in this module** (grep-verified in the Phase 6D
final report's Deep Audit Findings).

## Taxonomy (Phase 6D stage 2)

### Windows

| Category | Status | Notes |
|---|---|---|
| A/B. Registry Run/RunOnce keys | SUPPORTED | Full path pattern (`HK(CU\|LM)\Software\Microsoft\Windows\CurrentVersion\Run(Once)?`) - HIGH confidence, unambiguous. |
| C. Winlogon-related persistence | SUPPORTED | `Winlogon\Shell`/`Winlogon\Userinit` key-suffix or the full Winlogon registry path - MEDIUM confidence. |
| D. Startup folder paths | SUPPORTED | Full `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` path - HIGH confidence. |
| E. Scheduled Task references | SUPPORTED (string/command only) | `schtasks /create`, `New-ScheduledTask(Action)?`, `Register-ScheduledTask` - MEDIUM confidence. Structured Task Scheduler database recovery: see "Structured OS artifacts" below - NOT_IMPLEMENTED. |
| F. Windows Service references | SUPPORTED (string/API/command only) | `sc create` (MEDIUM), `CreateService[AW]?`/`OpenSCManager[AW]?`/`StartService[AW]?` bare API names (LOW - see the real-fixture finding below), `ImagePath=` value assignment (MEDIUM). Structured SCM database recovery (`svcscan`): NOT_IMPLEMENTED, see below. |
| G. Service executable/image paths | SUPPORTED | `ImagePath=` contextual match, folded into F. |
| H. WMI persistence references | SUPPORTED (contextual) | A single WMI class name (`__EventFilter`, `__FilterToConsumerBinding`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `root\subscription`) - LOW confidence, never claimed as a confirmed subscription; two or more distinct class names found together in the same string - MEDIUM confidence, `PERSISTENCE_CONFIGURATION_REFERENCED`. |
| I. DLL search/order hijacking indicators | NOT_IMPLEMENTED | No reliable string/context pattern exists - DLL search-order hijacking is a *behavioral* technique (which DLL a loader resolves first), not a distinguishable string shape; would require a fundamentally different (and out-of-scope) analysis capability. |
| J. AppInit/AppCert-related indicators | SUPPORTED | `AppInit_DLLs`/`AppCertDLLs` value-name match - MEDIUM confidence. |
| K. IFEO-related indicators | SUPPORTED | Full `Image File Execution Options` phrase required (not the ambiguous "IFEO" acronym alone) - MEDIUM confidence. |
| L. Startup command lines | SUPPORTED | Folded into the command-line detectors above (schtasks/sc/systemctl/crontab). |
| M. Shell/userinit references | SUPPORTED | Folded into C (Winlogon). |

### Linux

| Category | Status | Notes |
|---|---|---|
| N/O. systemd service/user units | SUPPORTED | Full unit-file path (`/etc\|/usr/lib\|/lib/systemd/system/*.service`, `~/.config/systemd/user/*.service`) - HIGH confidence. Unit *content* (`[Service]`/`[Install]` plus `ExecStart=`) - HIGH confidence, `PERSISTENCE_CONFIGURATION_REFERENCED`. `systemctl (--user )?enable` command - MEDIUM confidence. |
| P/Q/R. cron paths | SUPPORTED | `/etc/cron.{d,daily,hourly,weekly,monthly}/`, `/etc/crontab`, `/var/spool/cron/crontabs?/` - HIGH confidence (specific, unambiguous paths). `crontab -[elru]` command - MEDIUM. Structural *cron-entry* recognition (a 5-field schedule + command) is explicitly NOT_IMPLEMENTED - a "5 space-separated tokens" shape is far too common in ordinary text to safely validate without filesystem-path provenance this project does not have for Go string evidence (stage 24's false-positive discipline). |
| S/T. Shell profile paths | SUPPORTED | `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, `/etc/profile`, `/etc/bash.bashrc` - MEDIUM confidence (path alone, never claims the file was modified). |
| U. Init scripts | SUPPORTED | `/etc/init.d/*` - MEDIUM confidence. |
| V. rc.local | SUPPORTED | `/etc/rc.local` - MEDIUM confidence. |
| W/X. XDG autostart / desktop entries | SUPPORTED | `~/.config/autostart/*.desktop` path - MEDIUM. Full `.desktop` content (`[Desktop Entry]` plus `Exec=`) - HIGH, `PERSISTENCE_CONFIGURATION_REFERENCED`. |
| Y. SSH authorized_keys | SUPPORTED | Path (`~/.ssh/authorized_keys`) - MEDIUM. A complete, syntactically valid SSH public-key line (`ssh-rsa`/`ssh-ed25519`/`ssh-dss`/`ecdsa-sha2-nistp*` + base64 + optional comment) - HIGH, distinguished from the path as its own type (`LINUX_AUTHORIZED_KEY_ENTRY`); never claims the entry was actually installed to a filesystem `authorized_keys` file. |
| Z. LD_PRELOAD / loader persistence | SUPPORTED | `LD_PRELOAD=` env-style assignment (MEDIUM), `/etc/ld.so.preload` path (HIGH). |
| AA. Environment/profile persistence | SUPPORTED (folded into S/Z) | No separate category - the same shell-profile and LD_PRELOAD detectors cover this. |

No `UNKNOWN_PERSISTENCE_ARTIFACT` catch-all exists.

## Structured OS artifacts: genuinely investigated, NOT_IMPLEMENTED

Stage 6D-7 explicitly required inspecting whether the installed
Volatility 3 (2.28.2) provides real registry/service/scheduled-task
recovery **before** deciding - this was done, not assumed:

| Plugin | Path | What it does |
|---|---|---|
| `HiveList` | `volatility3/framework/plugins/windows/registry/hivelist.py` | Walks the kernel's `CMHIVE` linked list to enumerate loaded registry hives. |
| `PrintKey` | `volatility3/framework/plugins/windows/registry/printkey.py` | Walks a hive's key/value cell tree. |
| `scheduled_tasks` | `volatility3/framework/plugins/windows/registry/scheduled_tasks.py` | Parses Task Scheduler configuration from the `SOFTWARE`/`SCHEDLGU` registry structures (builds on `hivelist`). |
| `svcscan` | `volatility3/framework/plugins/windows/svcscan.py` | Scans for Windows service-record structures, using version-specific symbol files (e.g. `services-win10-19041-x64.json`). |

All four are real, genuinely inspected `interfaces.plugins.PluginInterface`
implementations requiring the **full Windows kernel translation layer**
(a `context`/`kernel` module, exactly like `windows.pslist.PsList` -
see `docs/architecture/volatility3-integration.md`) - they operate at the
whole-image/kernel level, not on a specific Go process's own memory.
Wiring them in was deliberately **not done this phase**, for two
concrete, honest reasons:

1. **Architectural mismatch**: every other Phase 2-6C capability in this
   project reads a *specific process's* memory via `MemoryReader`.
   Registry/service/scheduled-task recovery is a *system-wide*, kernel-
   level capability unrelated to any particular Go runtime - integrating
   it now would be a different kind of subsystem, not a natural extension
   of the existing per-process analyzer model.
2. **Unvalidatable in this environment**: this project's
   COMPILED_BINARY_VALIDATED tier - real compiled binary bytes read at
   their real virtual addresses - has **no equivalent for registry/
   service/task data at all**: a compiled `.exe` file contains no
   registry hive, no SCM database, and no Task Scheduler database. Any
   implementation of these plugins could only be tested against fully
   mocked Volatility objects (proving nothing about correctness against
   the real API) or a real memory image (which Phase 5.5 established does
   not exist in this environment). Merging real-memory-dependent,
   currently-unverifiable code contradicts CLAUDE.md's governing
   principle: prefer reliable output over more output.

This is recorded as **PARTIALLY_SUPPORTED at the taxonomy level** (a real
API was located and its interface documented) and **NOT_IMPLEMENTED at
the capability level** (no code calls it) - future work, to be
implemented together with whatever unblocks Phase 5.5, not merged
untested beforehand.

## Real-fixture finding: an incidental stdlib string match

Running the analyzer against the real compiled Go 1.26.2 fixture binary's
1,976 real static strings (`tests/integration/test_persistence_artifacts_fixture.py`)
surfaced one genuine, unplanned finding: the string `OpenSCManagerW`
(a real Windows Service Control Manager API name) is present in the
binary's own `.rodata`, sandwiched among clearly Go-runtime-internal
strings (`"unsafe.Pointer on zero Value"`, `"userArenaState"`, `"GC
(dedicated)"`) - almost certainly referenced internally by Go's own
standard library/runtime Windows support code, **not** by the fixture's
own (persistence-free) application logic. This is correctly classified
as `WINDOWS_SERVICE_REFERENCE` at **LOW** confidence (a bare API name
reference, explicitly never a claim of a configured service) - a real,
independently-observed demonstration of the confidence model working as
designed: even a completely benign Go binary can incidentally contain
low-level Windows API name strings, and this analyzer does not overclaim
when it encounters one.

## Association (stages 17/19/20/21/22)

Identical evidence-chain mechanism to Phase 6A/6B/6C -
`function_id`/`goroutine_id` via the existing `string_ref:<id>` call-site
evidence and unwound-frame `function_id` fields; `network_artifact_id`/
`credential_artifact_id`/`crypto_artifact_id` via shared source-string
linkage with the corresponding prior-phase artifact - never proximity.
`tests/unit/test_persistence_analyzer.py` explicitly asserts no artifact's
`notes` ever claims "goroutine established persistence" or "downloaded
and installed".

## Redaction (stage 23)

Same generic `redact_value()` policy as Phase 6B/6C (a separate copy in
`analyzers/persistence.py`, matching the established per-module
independence pattern): short values fully masked, longer values keep a
3-character prefix/suffix. `raw_value` is never altered or destroyed.

## Bounds (stage 29)

`MAX_PERSISTENCE_VALUE_LENGTH = 4096`, `MAX_ARTIFACTS_PER_PROCESS = 5000`
(cap recorded via `PersistenceAnalysisStats.capped` plus a recoverable
`AnalysisError`, never silent). `MAX_COMMAND_LENGTH`/
`MAX_CONFIG_BLOCK_LENGTH` are documented aliases of the general length
bound - this analyzer never extracts a command/config *substring*
independent of the whole recovered string value, so a separate bound
would be redundant, not a different limit.

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire analyzer - identical
status to every other Phase 2-6C capability (Phase 5.5 remains blocked).
Validation performed:

- UNIT: `tests/unit/test_persistence_classification.py` (61 tests: every
  taxonomy category across both platforms, plus the full stage-24
  false-positive list) and `tests/unit/test_persistence_analyzer.py` (19
  tests: function/goroutine/network/credential/crypto association, dedup,
  bounds, redaction, log-safety), plus
  `tests/unit/test_pipeline.py::TestRecoverPersistenceArtifacts`.
- COMPILED_BINARY_VALIDATED: `tests/integration/test_persistence_artifacts_fixture.py`
  runs the real classifier against the real compiled Go 1.26.2 fixture
  binary's real recovered strings (the fixture was extended with five
  inert, obviously-fake persistence-marker constants - never written to
  the registry/filesystem/service manager/cron/systemd, never executed) -
  all five are correctly recognized amid the real string set, with only
  the one documented, independently-confirmed incidental stdlib match
  (`OpenSCManagerW`) alongside them - no other unexpected match.

## Limitations

- No structured OS artifact (registry hive, SCM record, scheduled-task
  database entry) is recovered - genuinely investigated, documented
  NOT_IMPLEMENTED with specific architectural and testability reasons,
  never a blanket excuse.
- Cron *entry* (schedule + command) structural recognition beyond the
  path/command level is not implemented - too high a false-positive risk
  without filesystem-path provenance.
- DLL search-order hijacking has no implementable string/context pattern.
- Cross-string relationships (e.g. a service name in one string and its
  `ImagePath` in another) are never inferred from proximity - only the
  same explicit evidence chains used throughout Phase 6A-6D.
