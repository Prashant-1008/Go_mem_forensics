# Forensic Methodology

**Status: Phase 5 - Go Goroutine Recovery.** Sections below marked
"implemented" describe techniques actually implemented and tested (see
`docs/architecture/go-runtime.md`/`docs/architecture/go-goroutines.md`
for the full technical narrative and `docs/validation/validation-plan.md`
for what has and has not been validated against a real memory image);
sections still marked "planned" describe techniques not yet implemented.

## Purpose

This document will explain, for each implemented capability, how
GoMemForensics recovers and validates forensic artifacts from Go process
memory, and how it distinguishes:

- **Observed Evidence** - directly recovered, structurally validated data.
- **Analytical Interpretation** - an investigator-facing explanation of what
  observed evidence might mean.
- **Detection Heuristic** - an explicitly documented, non-authoritative
  signal used to prioritize investigator attention.

These three categories must never be merged into a single undifferentiated
claim, per the project's governing methodology (`CLAUDE.md`).

## Confidence model (implemented in Phase 0)

`gomemforensics.common.models.Confidence` defines four levels:
`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`. Confidence must always be grounded in
the strength of structural validation applied to an artifact - never a
numeric "malware score" - per CLAUDE.md section 14. No analyzer exists yet
to assign these values to real artifacts; only the model itself is
implemented.

## Evidence handling (implemented in Phase 0)

`gomemforensics.acquisition.evidence.EvidenceValidator`:

- opens evidence files read-only (`"rb"`) only,
- computes SHA-256 via chunked reads (never loads a full image into RAM),
- never writes to, renames, or otherwise modifies the evidence file,
- records file size, hash, and an ISO-8601 UTC timestamp.

## Go runtime metadata extraction methodology (implemented, Phase 2)

**Classification: paper-derived** (Section 3.1). `pclntab`/`pcHeader` are
located by scanning process regions for the paper's documented per-Go-era
magic byte sequences, then structurally validated (padding zero, plausible
`minLC`/`ptrSize`/`nfunc`/`nfiles`) before being trusted - a magic-byte
match alone is Detection Heuristic strength only, never Observed Evidence,
until it passes every invariant. `moduledata` is located by anchoring on
the already-recovered `pcHeader`'s address (a pointer-equality scan of
writable regions) and validated by ordered region bounds and well-formed
slice headers. Go version is reported only as the range the evidence
actually supports (e.g. `"1.20+"`), narrowed further only when a second,
independent structural fact (which `moduledata` layout era validated)
corroborates it - never an invented exact patch version. **Engineering
addition**: the structural (non-magic) pclntab fallback and the
multi-candidate-preserved (never "first found") selection strategy are
practical additions the paper motivates but does not fully specify. Full
detail: `docs/architecture/go-runtime.md`.

## Go string recovery methodology (implemented, Phase 3)

**Classification: paper-derived** (Section 3.2, Figure 2). Two
structurally separate paths, never merged: heap-based recovery walks
`allspans` → validated `mspan` records → allocation-bitmap-derived live
object addresses → two-machine-word objects interpreted as Go string
header candidates, corroborated where possible by a minimal `_type`/`itab`
size-and-kind index; static-section recovery pattern-scans readable,
non-pure-executable regions for the same `(ptr, len)` header shape,
capped below `HIGH` confidence since it is pattern-derived rather than
allocator-validated. Every candidate is validated (pointer/length
plausibility, backing bytes actually readable, UTF-8-or-printable
content) before being reported; a candidate that fails validation is
never emitted as an artifact - Observed Evidence, not Analytical
Interpretation. **Engineering addition**: UTF-8 is treated as a
confidence *signal*, not an absolute admission requirement (a
deliberately-obfuscated byte sequence is still a real Go string). Full
detail: `docs/architecture/go-runtime.md`.

## Go function recovery and classification methodology (implemented, Phase 4)

**Classification: paper-derived** (Section 3.3), with one
**engineering-addition** subcomponent and one **experimental**
subcomponent called out explicitly below.

- **Function table walk and name/source resolution (paper-derived,
  Section 3.3.1)**: `moduledata.ftab` → `_func` → name via `funcnametab`,
  source file/line via the pctab `pcfile`/`pcln` streams and
  `cutab`/`filetab` - all without any OS/ELF/PE symbol table, the central
  design goal the paper states and this implementation confirms end-to-end
  against real compiled output (`docs/validation/validation-plan.md`).
  This is Observed Evidence: a structurally-located `_func` record with a
  resolved name/source path.
- **Classification (paper-derived, Section 3.3.2)**: a deterministic
  function of the recovered source path alone (`runtime` /
  `runtime_internal` / `stdlib` / `third_party` / `application` /
  `unknown`) - Analytical Interpretation of Observed Evidence (the
  recovered path), never a Detection Heuristic and never influenced by the
  function's name. **Never used to infer maliciousness** (CLAUDE.md
  section 7/20) - `application` classification means "not part of a known
  runtime/stdlib/third-party package," nothing more.
- **Argument shape via ArgInfo/ArgsPointerMaps (paper-derived, Section
  3.3.3)**: `funcdata`-declared argument leaf count/size/aggregation -
  Observed Evidence about a function's *signature shape*, explicitly never
  a claim about any argument's *value* at any specific call.
- **x86-64 ABI-aware argument-register assignment (engineering addition
  built on paper-derived ABI documentation)**: implements Go's own
  documented (`cmd/compile/abi-internal.md`) register-assignment algorithm
  to interpret ArgInfo's shape data correctly for the two ABI eras
  (pre-1.17 stack-based, >=1.17 register-based) - a necessary
  interpretive layer the paper's own Figure/Section text does not spell
  out to this level of algorithmic detail.
- **Capstone backward call-site argument-value analysis (experimental,
  Section 3.3.4)**: recovers an actual argument *value* only where a small
  set of controlled instruction patterns immediately preceding a call
  provide direct evidence - every result is explicitly tagged
  `SUPPORTED`/`EXPERIMENTAL`/`UNSUPPORTED` (approved plan Step 11), and
  this tri-state is deliberately never conflated with the separate
  `Confidence` model. This is the project's most explicitly experimental
  component: a `SUPPORTED` result is Observed Evidence (the instruction
  stream genuinely shows that value being set), but the *absence* of a
  recovered value for a given call site is not evidence of anything -
  real, optimized Go code frequently uses instruction patterns outside
  this analyzer's current recognized set (confirmed directly: both real
  call sites inspected in the real compiled fixture recovered no value).

Full detail, including the real-fixture bug this phase's own validation
work found and fixed: `docs/architecture/go-runtime.md`,
`docs/validation/validation-plan.md`.

## Goroutine discovery and stack unwinding methodology (implemented, Phase 5)

**Classification: paper-derived** (Section 3.4), flagged in the approved
plan as the highest-risk component - implemented last, only after every
prerequisite (function-table metadata, the pctab decoder) was already
implemented and tested in Phase 4.

- **`allgs` discovery (paper-derived)**: "Go maintains a global slice,
  `runtime.allgs`... As stripped binaries lack this symbol, we scan
  writable memory regions for candidate slice headers and validate them
  by ensuring that the referenced array contains pointers to well-formed
  `g` structures" - implemented exactly as described
  (`gomemforensics.go_runtime.goroutines.AllgsParser`). A validated
  candidate is Observed Evidence (a real slice header whose sampled
  entries structurally validate); it is not proof that every entry in
  the full slice is genuine, only that the candidate itself is
  plausible - the same evidentiary standard Phase 3's `allspans`
  discovery already established for the identical structural problem.
- **`g` validation (paper-derived)**: "stack bounds are properly aligned
  and ordered, its status field encodes a correct runtime state, and its
  goroutine identifier falls within reasonable bounds" - implemented as
  a dedicated, separate function (`validate_g`) from discovery, per this
  project's general principle of never merging discovery and validation
  into one opaque step.
- **Stack unwinding (paper-derived)**: the pcsp-delta return-address
  formula described in Section 3.4 - independently re-verified against
  the real `runtime/traceback.go` unwinder (not merely transcribed from
  the paper's prose) before being implemented, confirming the paper's
  simplified description is exactly correct for x86-64 specifically
  (`sys.MinFrameSize == 0` on amd64) rather than assuming it. Every
  recovered frame answers this project's core forensic-reporting
  requirement (CLAUDE.md section 42: what/where/which process/how/how
  confident) via `GoroutineFrame`'s own fields plus `unwind_method`.
- **Engineering addition**: the explicit `UnwindStatus` taxonomy
  (`COMPLETE`/`BOUNDED`/`UNSUPPORTED_FRAME`/...) is this project's own
  addition, built on top of the paper's described algorithm, so an
  investigator can distinguish a genuinely complete unwind from one that
  stopped at a safety bound or a real, named special case (morestack,
  systemstack, ...) the real runtime itself treats specially and this
  project deliberately does not attempt to replicate.
- **Never validated against a real memory image**: `allgs` has no
  populated data at all in a static compiled binary - see
  `docs/architecture/go-goroutines.md`'s real-fixture-validation section
  for the precise boundary of what a compiled binary *can* validate here
  (pcsp decoding, unwind mechanics) versus what it fundamentally cannot
  (live goroutine/allgs state).

Full detail: `docs/architecture/go-goroutines.md`,
`docs/validation/validation-plan.md`.

## Go network artifact extraction methodology (implemented, Phase 6A)

**Paper-derived**: none directly - the reference paper does not describe
a dedicated network-artifact-extraction methodology; this is an
engineering addition built on top of the paper-derived Go string
recovery methodology above.

**Engineering addition**: `gomemforensics.analyzers.network` classifies
already-recovered Go string *values* (never re-scanning memory) against a
fixed, deterministic set of network shapes - IPv4/IPv6 (delegated to
Python's `ipaddress` stdlib module), hostnames (multi-label, TLD-
allowlist-gated), URLs (`http`/`https` only, via `urlsplit`), and
`host:port` endpoints. Function/goroutine association reuses Phase 4's
`string_ref:<id>` call-site evidence and Phase 5's unwound-frame
`function_id` fields - never address proximity. This is artifact
extraction, explicitly never malware classification (CLAUDE.md section
20): no artifact is ever labeled malicious, suspicious, or assigned a
threat score.

**Experimental**: none - a candidate that does not pass full
deterministic structural validation is never emitted as an artifact at
all (no "low confidence, keep anyway" path exists for this analyzer,
unlike e.g. `PclntabCandidate`).

**Future work**: structured Go network object recovery (`net.TCPAddr`,
`netip.Addr`, `net/url.URL`, TLS connection state) - investigated and
explicitly documented as NOT IMPLEMENTED, see
`docs/architecture/go-network-artifacts.md`'s source-verification table
for why each one was rejected (addressability, or - for `netip.Addr` -
an explicitly unexported/unstable internal representation). OS-level
socket correlation is also future work; this methodology never assumes a
Go `net.Conn` implies a live OS socket or an actual network connection.

Full detail: `docs/architecture/go-network-artifacts.md`.

## Go credential/secret artifact extraction methodology (implemented, Phase 6B)

**Paper-derived**: none directly - same as Phase 6A, this is an
engineering addition built on the paper-derived Go string recovery
methodology.

**Engineering addition**: `gomemforensics.analyzers.credentials`
recognizes secret-like shapes (passwords, tokens, API keys, PEM private
keys, database credentials, cookies, JWTs, ...) within already-recovered
Go string values via deterministic, context-gated pattern matching -
never entropy alone. Explicitly distinguishes four things per its CORE
OBJECTIVE: observed secret-like data, structurally identified secret
material, associated context (via the same Phase 4/5/6A evidence chains,
never proximity), and interpretation - never a claim that a recovered
value is a valid, live, or actually-used credential. Every artifact
carries a deterministic, separate `redacted_value` alongside the
unaltered `raw_value` (CLAUDE.md section 18). No credential is validated,
authenticated, or transmitted anywhere - all processing is local
(CLAUDE.md sections 5/32/33).

**Experimental**: none - as with Phase 6A, a candidate that does not pass
full deterministic structural/contextual validation is never emitted as
an artifact.

**Future work**: cross-string username/password pairing via call-site
evidence, certificate/private-key pairing, structured Go object recovery
(`net/url.Userinfo`, `net/http.Cookie`, TLS/x509 certificate structs -
investigated, documented as NOT IMPLEMENTED), and live process
environment-block recovery (an OS-loader-layer concern, not a Go runtime
one). See `docs/architecture/go-credential-artifacts.md`'s taxonomy table
for the full per-category SUPPORTED/PARTIALLY_SUPPORTED/HEURISTIC_ONLY/
NOT_IMPLEMENTED/UNSUPPORTED classification.

Full detail: `docs/architecture/go-credential-artifacts.md`.

## Go cryptographic artifact extraction methodology (implemented, Phase 6C)

**Paper-derived**: none directly - same as Phase 6A/6B, an engineering
addition built on the paper-derived Go string/function recovery
methodology.

**Engineering addition**: `gomemforensics.analyzers.crypto` identifies
PEM public-key/certificate/certificate-chain boundaries, a curated set of
source-verified algorithm/cipher-suite identifier strings, and - the only
structured-key-material path implemented - AES key material via Phase
4's own call-site argument evidence, matched against
`crypto/aes.NewCipher`'s real, source-verified key-length requirement
(16/24/32 bytes). Private-key material is never re-parsed: Phase 6B's
already-produced evidence is reused and cross-referenced. Every artifact
explicitly distinguishes observed material, structurally identified
objects, cryptographic context, and interpretation - never asserting that
encryption/decryption/authentication occurred or that a key was used
(`KEY_MATERIAL_PASSED_AS_ARGUMENT`, never `KEY_USED`). No decryption, key
cracking, or external validation occurs anywhere (CLAUDE.md sections 5/
19/32/33).

**Experimental**: none - a candidate that does not pass full deterministic
structural/evidence-based validation is never emitted.

**Future work**: ChaCha20-Poly1305/HMAC key detection, IV/nonce/salt
detection (would require chaining evidence across two call sites),
certificate/public-key content parsing (no vetted local X.509 parser
dependency), and all structured Go crypto objects (RSA/ECDSA/Ed25519/
X25519 keys, TLS state) - investigated, documented as NOT IMPLEMENTED
with individual reasons in `docs/architecture/go-crypto-artifacts.md`'s
taxonomy table.

Full detail: `docs/architecture/go-crypto-artifacts.md`.

## Go malware persistence artifact extraction methodology (implemented, Phase 6D)

**Paper-derived**: none directly - same as Phase 6A/6B/6C, an engineering
addition built on the paper-derived Go string/function recovery
methodology.

**Engineering addition**: `gomemforensics.analyzers.persistence`
recognizes platform-specific (Windows/Linux, never mixed) persistence-
related paths, registry keys, commands, and configuration content within
already-recovered Go string values - registry Run/RunOnce/Winlogon/
AppInit/IFEO, startup folders, scheduled-task and service references,
WMI event-filter/consumer relationships, systemd units, cron paths, shell
profiles, XDG autostart, SSH authorized_keys, and LD_PRELOAD/loader
references. A recovered string is evidence of that *string*, never proof
that a registry key exists, a service was created, or a command executed
- every artifact's interpretation uses one of five precise phrases
(`PERSISTENCE_ARTIFACT_OBSERVED`, `PERSISTENCE_PATH_OBSERVED`,
`PERSISTENCE_COMMAND_OBSERVED`, `PERSISTENCE_CONFIGURATION_REFERENCED`,
`PERSISTENCE_FUNCTION_ASSOCIATED`), never `PERSISTENCE_CONFIRMED`/
`PERSISTENCE_ESTABLISHED`/`COMMAND_EXECUTED`. No persistence mechanism is
ever created, modified, or executed - all analysis is local and
read-only (CLAUDE.md sections 3/32/33).

**Experimental**: none - a candidate that does not pass full
deterministic structural/contextual validation is never emitted.

**Future work**: structured Windows OS artifact recovery (registry hive,
SCM service records, Task Scheduler database) via real, genuinely
inspected Volatility 3 plugins (`hivelist`/`printkey`/`scheduled_tasks`/
`svcscan`) - deferred because these are whole-kernel-symbol-dependent
plugins architecturally unrelated to a specific Go process's memory, and
currently unvalidatable at any tier available in this development
environment (a compiled Go binary has no registry hive/SCM database/task
database at all). Structural cron-entry recognition, DLL search-order
hijacking detection, and cross-string relationship inference are also not
implemented - see `docs/architecture/go-persistence-artifacts.md`'s
taxonomy table for the full per-category classification.

Full detail: `docs/architecture/go-persistence-artifacts.md`.

## IOC extraction and cross-artifact correlation methodology (implemented, Phase 6E)

**Paper-derived**: none - an engineering addition consuming the paper-
derived and engineering-added artifacts from every prior phase.

**Engineering addition**: `gomemforensics.analyzers.correlation`
transforms already-recovered network/credential/crypto/persistence
artifacts into normalized `IOCArtifact` records (a closed, reuse-only
type taxonomy - no new detection, no `UNKNOWN_IOC` catch-all) and
restates each artifact's already-existing evidence-chain fields
(`source_artifact_id`, `function_id`, `goroutine_id`,
`network_artifact_id`/`credential_artifact_id`/`crypto_artifact_id`) as
explicit, typed `CorrelationRecord` graph edges - never a new inference,
never memory-proximity or same-process/same-goroutine-alone correlation.
Deduplication groups IOCs that normalize to the same real-world indicator
via a deterministic `dedup_key` without ever merging or discarding
individual evidence records. No malware score, verdict, or threat
reputation exists anywhere in this phase's output, and no DNS/WHOIS/
reputation/network lookup occurs (CLAUDE.md sections 16/20/32/33).

**Experimental**: none.

**Future work**: a Finding/verdict layer (explicitly not created this
phase - CLAUDE.md's planned `detection/` package remains unimplemented),
HTML/PDF reporting of IOCs/correlations.

Full detail: `docs/architecture/go-ioc-correlation.md`.

## Findings and evidence assessment methodology (implemented, Phase 6F)

**Paper-derived**: none - an engineering addition consuming the Phase
6A-6E artifacts/IOCs/correlations from every prior phase.

**Engineering addition**: `gomemforensics.analyzers.findings` summarizes
already-recovered IOCs and correlation records into a closed, 17-value
`FindingType` taxonomy, each mapped from a specific, documented
`IOCType`/`CorrelationType` evidence rule (never an arbitrary string,
proximity, process name, or function name alone). Every Finding keeps
`observed_evidence` and `interpretation` as separate fields, and every
interpretation uses evidence-accurate wording that explicitly denies
overclaiming (e.g. "this is not proof that... persistence was
established"). Deduplication reuses Phase 6E's own `dedup_key` rather
than inventing a second mechanism. Severity is a fixed, documented,
per-`FindingType` table representing forensic/reporting importance only
- never a maliciousness probability, never aggregated into an overall
process score. No malware verdict, malware/threat/risk score, ML
classification, or reputation lookup exists anywhere (CLAUDE.md sections
16/20/32/33).

**Experimental**: none.

**Future work**: HTML/PDF reporting of findings; any capability that
would require structured OS/TLS/key-object evidence beyond what
Phase 6A-6D already recovered.

Full detail: `docs/architecture/go-findings.md`.

## Forensic reporting methodology (implemented, Phase 6G)

**Paper-derived**: none - an engineering addition rendering the Phase
2-6F `AnalysisResult`/analysis JSON as an examiner-readable report.

**Engineering addition**: `gomemforensics.reporting` is a presentation-
only layer (`AnalysisResult -> ReportModel -> JSON/HTML renderer`) that
performs no new forensic discovery - no `MemoryReader` access, no
Volatility call, no new artifact/IOC/correlation/finding is ever created
here. `ReportModel` construction is the only place any computation
happens (executive-summary counts, per-process summaries derived in
original process order, evidence-traceability chains built only from
already-existing IDs, and limitations restricted to what actually
applies to the run); both the JSON and HTML renderers are pure formatting
passes over an already-built `ReportModel`. The JSON report reproduces
every existing field plus these computed sections and never truncates
any list. The HTML report is a single self-contained static document (no
external network resources, no CDN, no remote JavaScript, no external
font) with 21 fixed sections, every evidence-derived value HTML-escaped,
and every credential/crypto/persistence/IOC table rendering redacted
values only - never a raw secret (the Strings section is a documented
exception, showing full raw evidence since `StringArtifact` predates the
Phase 6B redaction convention; secret-*shaped* string content is
separately redacted at the credential/crypto/persistence layers, which
is what those dedicated tables render). No malware verdict, malware/
threat/risk score, or process ranking by suspiciousness is computed or
displayed anywhere in a report (CLAUDE.md sections 14/20/32/33). Given
identical input, both renderers produce byte-for-byte identical output
except for the report-generation timestamp, which is explicitly
distinguished from the evidence's own analysis timestamp.

**Experimental**: none.

**Future work**: PDF report generation - explicitly deferred, since no
PDF-capable dependency (`reportlab`/`weasyprint`/`fpdf`) is installed in
this project; JSON and HTML already satisfy the phase's minimum
report-type requirement, and PDF is not a prerequisite for any core
analysis capability.

Full detail: `docs/architecture/go-reporting.md`.

## End-to-end integration and validation methodology (implemented, Phase 6H)

**Paper-derived**: none - a pure integration/validation exercise over
the already-implemented Phase 2-6G pipeline; no new forensic recovery
method was added.

**Engineering addition**: Phase 6H validates that the complete pipeline -
evidence, Volatility integration, process discovery, Go runtime
detection, string/function/goroutine recovery, network/credential/
crypto/persistence extraction, IOC extraction, correlation, findings,
`AnalysisResult`, and the Phase 6G JSON/HTML report - behaves as one
coherent, contract-respecting workflow, by running the real, unmodified
`gomemforensics.pipeline.run_analysis()` function against the real
compiled Go fixture binary with only the Volatility image-parsing layer
substituted by a small, interface-compatible fake (never a hand-
assembled shortcut that skips the real `_recover_*` wrapper functions).
This validated: cross-artifact reference integrity (every IOC/
correlation/finding id resolves to a real object using the fixture's own
real ids, never hard-coded synthetic ones), end-to-end provenance
preservation, deterministic output across repeated runs, correct
partial-analysis behavior, end-to-end secret safety, JSON round-trip
fidelity, resource-bound behavior against the real 2,193-row Functions
table, and a full CLI `analyze -> report` workflow. In the course of
this validation, one genuine reproducibility defect was found and fixed:
`GoRuntime.runtime_id` was generated with `uuid.uuid4()`, making two
runs against byte-identical evidence produce different output; it is now
derived deterministically from the already-deterministic `pclntab`
address, matching the convention every other artifact id in the project
already follows. This was the only production code change made in this
phase - not new capability, a minimal correction to an existing
contract.

**Experimental**: none.

**Future work**: real-memory-image validation (Phase 7) - Phase 5.5
remains blocked, and this phase did not attempt to unblock it.

Full detail: `docs/validation/phase-6h-end-to-end-validation.md`.

## Planned methodology sections (not yet written)

The following will be documented once the corresponding phase is
implemented and validated - they are intentionally left as stubs rather
than fabricated:

- Correlation methodology - planned for Phase 7.

Each of these sections must, when written, classify itself as
paper-derived, engineering addition, experimental, or future work per
CLAUDE.md section 2, and must not claim validation results that have not
actually been produced.
