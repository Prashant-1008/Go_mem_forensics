# Go Goroutine Recovery (Phase 5)

**Status: Phase 5 - Go Goroutine Recovery.** Covers
`gomemforensics.go_runtime.goroutines`/`stack_unwind`: `runtime.allgs`
discovery, structural `g` validation, scheduler/syscall PC-SP extraction,
and (x86-64 only) `pcsp`-based stack unwinding, reusing Phase 4's
function-table metadata rather than a second, independent function
parser.

Terminology is kept aligned with the reference paper ("Memory Forensics
Techniques for Automated Detection and Analysis of Go Malware", Section
3.4) throughout this document, per CLAUDE.md section 41.

## Source of truth for struct layouts

Every field/offset in this subsystem is transcribed from real Go runtime
source (local `go1.26.2` install), the same "only one verified era"
scope decision Phase 3's `mspan` and Phase 4's `_func` already made -
`g`/`gobuf`/`stack` are large, GC/scheduler-internal structs, not
re-verified across historical tagged releases the way `pcHeader`/
`moduledata` were in Phase 2.

**Verification method, stronger than a self-consistency check**: `g`'s
declared field offsets were not only computed by this project's own
`StructLayout` engine, but independently cross-checked against a
throwaway Go program - a structurally identical struct (same field
sizes/order, using local stand-in type names since `runtime.g`'s real
field types are unexported/internal to package `runtime` and cannot be
imported from outside it) - compiled and run with the local `go1.26.2`
toolchain, whose `unsafe.Offsetof`/`unsafe.Sizeof` output was compared
field-by-field against `StructLayout.offsets()`. Every one of 39 checked
offsets matched exactly (`tests/unit/test_go_runtime_layouts.py::TestGLayout`).

## `g` / `gobuf` / `stack`

Per the paper (Section 3.4): "Each goroutine's execution state is stored
in the `g.sched` field, which stores the current stack pointer (`sp`) and
program counter (`pc`)."

`gomemforensics.go_runtime.layouts.G_GO1_26` declares only the struct
**prefix** through `startpc` - everything this phase's stated objectives
(candidate discovery, validation, current PC/SP, stack bounds, status,
wait reason, the assigned `m`, and the goroutine's creation PC) actually
need, verified field-by-field against `runtime/runtime2.go`'s `type g
struct`:

| Field | Source declaration | Why required |
|---|---|---|
| `stack.lo`/`stack.hi` | `stack stack` (`type stack struct { lo, hi uintptr }`) | Stack bounds - candidate validation, unwind boundary |
| `stackguard0`/`stackguard1` | `uintptr` | Declared for correct offset accounting only - not consumed |
| `_panic`/`_defer` | `*_panic`/`*_defer` | Declared for correct offset accounting only - not consumed |
| `m` | `*m` | Assigned OS thread, if any - provenance/context |
| `sched.sp`/`sched.pc` | `gobuf` (`sp, pc, g, ctxt, lr, bp uintptr/guintptr/unsafe.Pointer`) | Saved scheduler PC/SP - unwind start point |
| `syscallsp`/`syscallpc` | `uintptr` | Saved syscall-state PC/SP - see "sched vs syscall PC/SP" below |
| `syscallbp`, `stktopsp`, `param` | various | Declared for correct offset accounting only - not consumed |
| `atomicstatus` | `atomic.Uint32` (4 bytes; wrapped `noCopy` is zero-sized) | Goroutine status (masked against `_Gscan`) |
| `stackLock` | `uint32` | Declared for correct offset accounting only |
| `goid` | `uint64` | Goroutine identifier |
| `schedlink` | `guintptr` | Declared for correct offset accounting only |
| `waitsince` | `int64` | Declared for correct offset accounting only - not consumed |
| `waitreason` | `waitReason` (`uint8`) | Wait-reason classification, when `status == _Gwaiting` |
| `preempt` .. `runningCleanups` (15 bool/small fields) | various 1-byte types | Declared for correct offset accounting only - not consumed (approved plan: "do not assume every field is needed") |
| `sig`, `secret`, `writebuf` (`[]byte`, 3 words), `sigcode0/1`, `sigpc`, `parentGoid` | various | Declared for correct offset accounting only |
| `gopc` | `uintptr` | PC of the `go` statement that created this goroutine - creation context, never current execution |
| `ancestors` | `*[]ancestorInfo` | Declared for correct offset accounting only |
| `startpc` | `uintptr` | PC of the goroutine's entry function - creation context, never current execution |

Fields after `startpc` (`racectx`, `waiting`, `cgoCtxt`, `labels`,
`timer`, `sleepWhen`, `selectDone`, `goroutineProfiled`, ...) are not
declared at all - out of scope for this phase's stated objectives.

## Status constants

Verified verbatim against `runtime/runtime2.go`'s untyped status-constant
block:

| Value | Name | Source doc comment (summarized) |
|---|---|---|
| 0 | idle | just allocated, not yet initialized |
| 1 | runnable | on a run queue, not executing |
| 2 | running | may execute user code, stack owned |
| 3 | syscall | executing a system call, stack owned |
| 4 | waiting | blocked in the runtime, stack not owned except under a channel lock |
| 5 | moribund_unused | unused, hardcoded in gdb scripts |
| 6 | dead | unused/exited/free-list/initializing |
| 7 | enqueue_unused | unused |
| 8 | copystack | stack is being moved |
| 9 | preempted | stopped itself for a suspendG preemption |
| 10 | leaked | leaked goroutine caught by the GC |
| 11 | deadextra | dead goroutine attached to an extra M for cgo callbacks |
| `0x1000` bit | `_Gscan` | GC-scanning flag, OR'd onto any of the above - masked off (`status & ~0x1000`) to get the base state, reported separately as `is_scanning` rather than silently discarded |

`gomemforensics.go_runtime.layouts.G_WAIT_REASON_NAMES` transcribes all
46 `waitReason` values (`runtime/runtime2.go`'s const block, cross-checked
against the real `waitReasonStrings` array literal) verbatim - index 0
(`""`) is a real, valid "no wait reason" value, not a decode failure.

## allgs discovery (5B)

Per the paper: "Go maintains a global slice, `runtime.allgs`, containing
pointers to all goroutine structures. As stripped binaries lack this
symbol, we scan writable memory regions for candidate slice headers and
validate them by ensuring that the referenced array contains pointers to
well-formed `g` structures."

Verified against `runtime/proc.go`: `allgs` is a genuine `var allgs []*g`
- a real 3-word (`ptr, len, cap`) Go slice header at a fixed package-level
location - but, unlike `pclntab`/`moduledata`, has **no equivalent anchor
evidence**: it is not part of `moduledata`, and no other validated
runtime structure's address gives an indirect way to find it. Discovery
here is therefore a genuine structural scan
(`gomemforensics.go_runtime.goroutines.AllgsParser`), deliberately
analogous to Phase 3's `AllspansParser` (`allspans` has the identical
problem, for the identical reason) - never a fabricated scan signature,
but also never as strong an anchor as `pclntab`'s magic bytes or
`moduledata`'s pointer-equality anchor.

**Validation** (matching the paper's own two-stage description): a
candidate header (`ptr` non-null and pointer-aligned, `0 < len <= cap`
within a plausibility bound) is sampled - up to `MAX_ALLGS_SAMPLE` (64)
of its entries are read and each is structurally validated as a `g` (see
below); the candidate is accepted only if `>= MIN_VALID_G_SAMPLE_RATIO`
(50%, the same threshold Phase 3 uses) of the sample validates. Multiple
candidates (accepted or rejected) are preserved
(`gomemforensics.go_runtime.models.AllgsCandidate`) - never "first
found"; `select_best_allgs_candidate` ranks by confidence then
validated-sample count.

## g validation (5C)

`gomemforensics.go_runtime.goroutines.validate_g` - a **separate**
function from discovery (approved plan: "do not combine discovery and
validation into one opaque function") - implements the paper's stated
invariants:

- stack bounds pointer-aligned and ordered (`lo < hi`), within a
  plausibility bound (not a language invariant - a safety bound, same
  pattern as every other `MAX_PLAUSIBLE_*` constant in this project)
- `atomicstatus` (masked against `_Gscan`) is a recognized status value
- `goid` within a generous plausibility bound
- `waitreason` is a recognized value

**Explicitly not required unconditionally**: `sched.sp` falling within
`[stack.lo, stack.hi)`. Verified against `runtime/runtime2.go`'s own
status doc comments (e.g. `_Gwaiting`: "the stack is not owned *except*
that a channel operation may read or write parts of the stack under the
appropriate channel lock") - stack ownership is status-dependent, so this
check is applied separately, conditionally, by
`GoroutineRecoveryEngine._build_goroutine` (skipped entirely for
`_Gdead`, and downgrades confidence to `MEDIUM` rather than rejecting the
candidate for other statuses) - approved plan: "do not over-reject
legitimate parked/dead/system goroutines".

## sched / syscall PC-SP (5D)

**Verified substitution rule**, not the naive "always use `g.sched.pc`/
`g.sched.sp`" the struct's own field comments alone might suggest:
`runtime/traceback.go`'s `gentraceback` selects the starting PC/SP as:

```go
if gp.syscallsp != 0 {
    pc0 = gp.syscallpc
    sp0 = gp.syscallsp
} else {
    pc0 = gp.sched.pc
    sp0 = gp.sched.sp
}
```

- a nonzero `syscallsp` is the real signal, not literally `status ==
_Gsyscall` (the two are correlated but the real code checks the former).
`GoroutineRecoveryEngine` implements exactly this rule and records
`GoroutineArtifact.used_syscall_state` so the provenance of the reported
`sched_pc`/`sched_sp` is never ambiguous.

**`g.gopc`/`g.startpc` are never labeled as current execution PC**
(approved plan, verbatim requirement): they are surfaced as
`GoroutineArtifact.go_pc`/`start_pc`, resolved to
`go_pc_function_name`/`start_function_name` via the same
`gomemforensics.go_runtime.functab.FunctionIndex` used for
`sched_pc`/`current_function_name` - three distinct fields, never
conflated (`test_gopc_and_startpc_never_reported_as_sched_pc`).

## Stack unwinding (5E)

The highest-risk component. Implemented and verified only after 5A-5D,
per the approved plan's stage-gating.

**Verified line-by-line against the real unwinder** (`runtime/traceback.go`,
`gentraceback`, the `!usesLR` / x86 branch only - `usesLR` is an
ARM64/link-register concept this project neither implements nor claims):

```
funcspdelta(f, pc) == pcvalue(f, f.pcsp, pc, true)      -- symtab.go:1210-1216
    (the EXACT decoder gomemforensics.go_runtime.pctab already
    implements for pcfile/pcln, reused verbatim via
    read_pc_value_from_reader - never a second decoder)

fp = sp + funcspdelta(f, pc)                             -- traceback.go:327
if !usesLR: fp += ptrSize                                -- traceback.go:330
    ("On x86, call instruction pushes return PC before
    entering new function.")

lrPtr = fp - ptrSize  (== sp + funcspdelta(f, pc))        -- traceback.go:378
lr = *(*uintptr)(lrPtr)                                   -- traceback.go:379

argp = fp + sys.MinFrameSize                              -- traceback.go:411
    MinFrameSize == 0 for amd64 (verified:
    internal/goarch/goarch_amd64.go) -> argp == fp for
    this project's only supported architecture. The
    paper's own simplified "sp + sp_delta + ptrSize"
    description is exactly correct for x86-64 - confirmed
    independently, not merely trusted.

frame.pc = frame.lr; frame.sp = frame.fp                  -- traceback.go:495,497
```

`gomemforensics.go_runtime.stack_unwind.unwind_goroutine` implements
exactly this. `_func.pcsp` is now decoded and surfaced on every
`FunctionArtifact` (`pcsp_offset`, added in Phase 5 alongside `func_id`/
`func_flag`, decoded from the same `_func` bytes Phase 4 already reads -
no second function parser).

### Stopping conditions

All source-verified, never invented (`internal/abi/symtab.go`'s
`FuncFlag`/`FuncID` doc comments):

| Condition | `UnwindStatus` | Verified basis |
|---|---|---|
| Current function has `FuncFlagTopFrame` | `COMPLETE` | "The traceback routine stop[s] at such a function and consider[s] that a successful, complete traversal" (e.g. `goexit`, `mstart` - confirmed against the real fixture binary, see below) |
| Return address reads as `0` | `COMPLETE` | The real unwinder treats `frame.lr == 0` as "no further caller", not a decode failure |
| Current function has `FuncFlagSPWrite` | `UNSUPPORTED_FRAME` | "Stopping at an SPWrite function is considered to be an incomplete unwinding of the stack" - `pcsp` cannot encode an arbitrary SP write |
| Current function's `FuncID` is one of `morestack`/`systemstack`/`systemstack_switch`/`asyncPreempt`/`sigpanic`/`gogo`/`mcall`/`asmcgocall`/`cgocallback`/`debugCallV2` | `UNSUPPORTED_FRAME` | Real, named special cases the real unwinder handles specially (stack-transition trampolines, signal/panic/preemption entry points) - never replicated here (approved plan: "do not implement special handling unless source-verified") |
| Return address does not resolve to any recovered function | `UNRESOLVED_FUNCTION` (frame 0) / `INVALID_RETURN_ADDRESS` (later frames) | - |
| Computed return-address slot outside `[stack.lo, stack.hi)` | `STACK_BOUNDS_EXCEEDED` | - |
| Return-address slot unreadable | `UNREADABLE_STACK` | - |
| `pcsp` decode fails, or `pcsp_offset` unavailable, or the decoded delta is not pointer-aligned (verified debug invariant: `runtime/symtab.go:1212`, `x&(goarch.PtrSize-1) != 0`) | `MALFORMED_PCSP` | - |
| Return address equals the current PC (self-cycle) | `INVALID_RETURN_ADDRESS` | Never a legitimate caller; stops rather than looping |
| `MAX_FRAMES` (256) reached | `BOUNDED` | Safety bound, not a Go semantic - CLAUDE.md section 44 |

### Special cases explicitly investigated, not implemented

morestack, systemstack, async preemption, cgo frames, and
signal/preemption frames are all real `FuncID`s the real unwinder
special-cases (see table above) - this project's unwinder recognizes
them by name and **stops** (`UNSUPPORTED_FRAME`) rather than attempting
to replicate their handling, per the approved plan. Inlined/wrapper
functions: no inline-tree metadata is parsed in this phase - a frame
always reflects the physical (non-inlined) function the recovered
`_func`/`ftab` entry describes; no logical inline frame is fabricated.
This is a real, disclosed limitation, not a silent gap.

## Artifact model / provenance (5F)

`gomemforensics.go_runtime.models.GoroutineArtifact`/`GoroutineFrame`
carry every field listed in the approved plan that this phase can
meaningfully populate, plus full `ArtifactProvenance` (pid, `g` address,
`allgs_index`, discovery method, confidence). `UnwindStatus` (distinct
from `Confidence`, the same two-axis pattern Phase 4.1's
`ArgumentRecoveryStatus` established) records how far/successfully
unwinding proceeded, independent of how much any individual frame is
trusted.

## Confidence model

Reuses `HIGH`/`MEDIUM`/`LOW`/`UNKNOWN` (CLAUDE.md section 14). `HIGH`:
directly enumerated from a `HIGH`-confidence `allgs` candidate,
structurally valid `g`, and (where applicable) sp/stack invariants hold.
`MEDIUM`: a validated `g` whose effective sp fell outside its own stack
bounds for a status where that invariant should normally hold - reduced
confidence, never rejection (see "g validation" above). Never a numeric
score; never equates a recovered goroutine's existence with maliciousness.

## Real-fixture validation status

**Confirmed against the real fixture binary**
(`tests/integration/test_go_runtime_goroutine_fixture.py`): `_func.pcsp`
decodes to plausible, pointer-aligned frame-size values for real
functions (spot-checked and swept across 200+ real functions), and the
unwinder's frame-delta arithmetic (`unwind_goroutine`) was exercised
against a real function's real entry PC and real `pcsp`-decoded frame
size. `runtime.goexit`/`runtime.mstart`'s real `_func.flag` was
separately confirmed (during the Phase 4.1 audit) to have
`FuncFlagTopFrame` set, exactly as the real unwinder relies on.

**Explicitly NOT validated, and cannot be from a compiled binary alone**:
`allgs` discovery, `g` structural validation, and a genuine live stack
unwind - `runtime.allgs` has no populated data at all in a static file
(see module docstring in the test file above). This remains
**UNVALIDATED** until a real captured memory image is available (see
`docs/validation/validation-plan.md`) - `tests/integration/test_volatility_real.py::TestRealMemoryImage`
remains the gate and still reports **SKIPPED**.

## Known limitations

- `g`/`gobuf`/`stack` have only one verified layout era (local
  `go1.26.2`) - a Go version outside `"1.22+"` reports
  `UNSUPPORTED_RUNTIME_LAYOUT`, never guessed.
- `allgs` discovery has no anchor evidence beyond structural
  slice-header + sampled-`g` validation - a genuinely weaker discovery
  guarantee than `pclntab`/`moduledata`'s magic-byte/pointer-equality
  anchors, disclosed as such, not papered over.
- Stack unwinding is x86-64 only; ARM64 `g`/allgs discovery is not
  gated by architecture (pointer-size-only logic), but unwinding is,
  since the verified return-address formula is specific to x86's "call
  pushes return PC" convention.
- Inline-tree metadata is not parsed - frames reflect physical, not
  logical/inlined, functions.
- morestack/systemstack/async-preemption/cgo/signal frames stop
  unwinding (`UNSUPPORTED_FRAME`) rather than being specially handled.
- No real memory image has been used to validate `allgs`/`g`
  discovery, validation, or live unwinding - see "Real-fixture
  validation status" above.
