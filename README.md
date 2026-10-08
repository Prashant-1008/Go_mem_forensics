# GoMemForensics

**Automated Go Malware Memory Forensics and Runtime Artifact Analysis**

GoMemForensics is a defensive digital-forensics and malware-analysis
framework for analyzing Windows and Linux memory images to identify,
reconstruct, correlate, and report artifacts associated with Go-based
executables, including potentially malicious Go programs.

**Primary goal:** automated forensic recovery and analysis of Go runtime
artifacts from Windows and Linux memory images.

This project implements the research methodology described in
[*"Memory Forensics Techniques for Automated Detection and Analysis of Go
Malware"*](reference/Memory%20Forensics%20Techniques%20for%20Automated%20Detection%20and%20Analysis%20of%20Go%20Malware.pdf)
(Ali, Case, Ahmed) as a practical, reproducible, investigator-oriented
forensic tool, built on top of [Volatility 3](https://github.com/volatilityfoundation/volatility3).

## Forensic posture

GoMemForensics is **offline and passive by default**. It analyzes acquired
memory images and does not modify the original evidence. It never executes
recovered code or commands, and it never automatically contacts recovered
network indicators (IPs, domains, C2 infrastructure). See `CLAUDE.md` for
the full set of forensic-integrity and confidence-model requirements that
govern this project.

## Current status

**Phase 6H - End-to-End Integration and Validation.** Phase 5.5 (a
dedicated attempt to validate the full pipeline against a real captured
memory image) remains **blocked: no approved real memory image is
available** in this development environment - see
`docs/validation/validation-plan.md`'s "Phase 5.5" section and
`docs/validation/memory-acquisition.md`. Phases 6A-6D added network,
credential/secret, cryptographic, and persistence artifact analyzers;
Phase 6E added an IOC extraction and cross-artifact correlation layer;
Phase 6F added a findings/evidence-assessment layer
(`gomemforensics.analyzers.findings`) that summarizes already-recovered
IOCs/correlations into a closed, 17-value, evidence-backed `Finding`
taxonomy - always separating `observed_evidence` from `interpretation`,
**never** a malware verdict, malware score, threat score, reputation
result, or automatic attribution (CLAUDE.md section 20); Phase 6G added a
presentation-only reporting layer (`gomemforensics.reporting`) that
renders an already-produced analysis JSON as a deterministic, self-
contained JSON or HTML forensic report - **no new memory access, no new
detection, no malware verdict/score** at this layer either. Phase 6H adds
no new analyzer: it validates the complete Phase 0-6G pipeline as one
coherent, deterministic, provenance-preserving workflow end-to-end
(evidence through HTML report), via the real, unmodified `run_analysis()`
function run against the real compiled fixture binary with only the
Volatility image-parsing layer substituted - and, in doing so, found and
fixed one genuine reproducibility defect (`GoRuntime.runtime_id` was
previously generated from `uuid.uuid4()`, making two runs against
identical evidence produce different ids; it is now derived
deterministically from the already-deterministic `pclntab` address, like
every other artifact id in the project). See
`docs/validation/phase-6h-end-to-end-validation.md`,
`docs/architecture/go-reporting.md`, `docs/architecture/go-findings.md`,
`docs/architecture/go-ioc-correlation.md`,
`docs/architecture/go-persistence-artifacts.md`,
`docs/architecture/go-crypto-artifacts.md`,
`docs/architecture/go-credential-artifacts.md`, and
`docs/architecture/go-network-artifacts.md` for the full design, source
archaeology, and taxonomy - `REAL_MEMORY_VALIDATED = FALSE` throughout.

`gomemforensics analyze <memory-image>` performs evidence
validation/hashing, Volatility 3 initialization, OS/architecture
detection, process enumeration, Go process/runtime detection
(`pclntab`/`pcHeader` recovery and validation, Go version ranging,
`moduledata` recovery and validation), Go string recovery (heap-based via
`allspans`/`mspan`/allocation-bitmap traversal, and static-section header
scanning), Go function recovery (`ftab`/`_func` metadata, name/source
resolution without any OS symbol table, source-path-based classification,
`ArgInfo`/`ArgsPointerMaps` argument shape, and - x86-64 with a
confidently-resolved ABI era only - Capstone backward call-site argument
*value* analysis), and now **Go goroutine recovery** (`runtime.allgs`
discovery, structural `g` validation, scheduler/syscall PC-SP extraction,
and - x86-64 only - `pcsp`-based stack unwinding, reusing the same
function-table metadata rather than a second parser), with structured
JSON output. See `docs/architecture/go-runtime.md`/
`docs/architecture/go-goroutines.md` for the full design (every struct
offset traced to real Go source, never invented) and
`docs/validation/validation-plan.md` for what has and has not been
validated against a real memory image - goroutine recovery in particular
has an even narrower ceiling on what a compiled binary alone can prove,
since live goroutine state does not exist at all outside a running
process.

## Implemented capabilities (Phase 6H)

- Evidence validation and chunked SHA-256 hashing (read-only, never
  modifies the input image)
- Volatility 3 context/automagic/plugin construction (Windows and Linux
  `pslist`), OS-agnostic at the engine level
- OS detection (Windows / Linux / unknown) and architecture detection
  (x86-64 / x86 / unknown; ARM64 identification only - see Supported
  platforms below)
- Process enumeration, normalized into a single OS-independent model, with
  per-process errors recorded rather than aborting the whole run
- Per-process memory access via a Volatility-backed `MemoryReader`
  (read-only; unmapped memory raises rather than silently returning zeros)
- Normalized, OS-independent memory regions (Windows VAD / Linux VMA) for
  bounded, targeted scanning
- Go process detection: `pclntab`/`pcHeader` discovery (magic-byte, with a
  structural fallback), full invariant validation, Go version range
  detection, and `moduledata` discovery/validation anchored on the
  recovered `pcHeader` - covering Go 1.16 through the current Go 1.26.2
  struct shape, with every candidate (accepted or rejected) preserved and
  explicit confidence levels (never a bare magic-byte match treated as
  proof)
- Go string recovery: heap-based (via `allspans` discovery, `mspan`
  parsing, and allocation-bitmap traversal - `object_addr = startAddr +
  bit_index*elemsize`) and static-section header pattern scanning, each
  with independent confidence levels (never HIGH for static), minimal
  `_type`-based size-to-type corroboration, `itab`-based interface
  disambiguation, and deterministic shared-backing-data grouping - never
  classified as malicious, never modifying evidence
- Go function recovery: `moduledata.ftab` → `_func` metadata, name/source
  resolution via `funcnametab`/`filetab`/`cutab` (no OS/ELF/PE symbol
  table required), a faithful pctab PC-value decoder, deterministic
  source-path-based classification (`runtime` / `runtime_internal` /
  `stdlib` / `third_party` / `application` / `unknown` - never inferred
  from the function's name), `ArgInfo`/`ArgsPointerMaps` argument-*shape*
  decoding - ABI-mapped to physical register/stack locations via the
  verified x86-64 register-assignment algorithm - and, x86-64 only and
  only when the Go version confidently resolves to one ABI era,
  Capstone-based backward call-site analysis recovering argument
  *values*, driven entirely by each callee's own recovered argument
  locations (never a blanket sweep of whatever registers happen to hold
  a value) for a documented set of controlled instruction patterns, each
  result explicitly tagged SUPPORTED/EXPERIMENTAL/UNSUPPORTED (never a
  guess presented as fact); validated against real compiled output, not
  just synthetic buffers - see `docs/validation/validation-plan.md`
- Go goroutine recovery: `runtime.allgs` discovery via a writable-region
  slice-header scan (no `moduledata` anchor exists for `allgs`, unlike
  `pclntab`/`moduledata` themselves - a genuine structural scan,
  deliberately analogous to Phase 3's `allspans` discovery), structural
  `g` validation (stack bounds, status, wait reason, goid - never
  over-rejecting legitimate parked/dead goroutines), a verified
  scheduler-vs-syscall-state PC/SP substitution rule (`g.gopc`/
  `g.startpc` never mislabeled as current execution PC), and - x86-64
  only - `pcsp`-based stack unwinding independently re-verified against
  the real Go runtime's own unwinder, with an explicit, source-derived
  set of stopping conditions (a real completion marker, a bounded frame
  cap, and named special cases the real runtime itself treats specially,
  never guessed past); `allgs`/`g` recovery is genuinely unvalidated
  against a real memory image (impossible from a compiled binary alone -
  see `docs/architecture/go-goroutines.md`)
- Go network artifact extraction (Phase 6A): IPv4/IPv6/hostname/URL/
  `host:port` recognition within already-recovered Go strings (never a
  second independent memory scan), with a curated TLD allowlist and
  `ipaddress`/`urlsplit`-backed structural validation as explicit
  false-positive controls, deterministic (never merged) per-evidence-
  location artifacts, and function/goroutine association only via an
  existing, explicit evidence chain (never address proximity) - see
  `docs/architecture/go-network-artifacts.md` for the full source
  archaeology, including which structured Go network objects
  (`net.TCPAddr`, `netip.Addr`, `net/url.URL`, `crypto/tls.ConnectionState`)
  were investigated and are explicitly NOT implemented, and why. Extraction
  only - never a maliciousness verdict, threat score, or "C2 confidence"
  (CLAUDE.md section 20)
- Go credential/secret artifact extraction (Phase 6B): context-gated
  recognition of password/token/API-key/client-secret/session-token/
  cookie/Authorization-header/Basic-Auth/JWT-shaped/PEM-private-key/
  database-credential/environment-and-config-secret-shaped values within
  already-recovered Go strings - 20 taxonomy categories, each explicitly
  classified SUPPORTED/PARTIALLY_SUPPORTED/HEURISTIC_ONLY/NOT_IMPLEMENTED/
  UNSUPPORTED (see `docs/architecture/go-credential-artifacts.md`); never
  entropy-only classification, deterministic redaction (`redacted_value`
  alongside an always-unaltered `raw_value`), and function/goroutine/
  network-artifact association only via an existing, explicit evidence
  chain. Extraction only - never a claim that a recovered value is a
  valid, live, or actually-used credential, and never a maliciousness
  verdict (CLAUDE.md section 20). No credential is validated,
  authenticated, or transmitted anywhere - all processing is local
- Go cryptographic artifact extraction (Phase 6C): PEM public-key/
  certificate/certificate-chain boundary recognition (content such as
  subject/issuer/validity is deliberately not parsed - no vetted local
  X.509/ASN.1 dependency), a curated set of source-verified crypto-
  context/cipher-suite identifier strings (verified against the exact
  `TLS_*` naming convention in `crypto/tls/cipher_suites.go`), and
  evidence-backed AES key-material recognition via Phase 4 call-site
  argument evidence matched against `crypto/aes.NewCipher`'s own real,
  source-verified key-length requirement (16/24/32 bytes) - see
  `docs/architecture/go-crypto-artifacts.md` for the full taxonomy
  (categories A-X, each classified SUPPORTED/PARTIALLY_SUPPORTED/
  NOT_IMPLEMENTED with individual reasons) and why no other structured Go
  crypto object (RSA/ECDSA/Ed25519/X25519 keys, TLS state) is recovered.
  Private-key material is reused from Phase 6B, never re-parsed. Never a
  claim that encryption/decryption/authentication occurred or that a key
  was used (`KEY_MATERIAL_PASSED_AS_ARGUMENT`, never `KEY_USED`), and
  never a maliciousness verdict. No decryption, key cracking, or external
  validation occurs anywhere - all processing is local
- Go malware persistence artifact extraction (Phase 6D): platform-aware
  (Windows/Linux, never mixed) recognition of registry Run/RunOnce/
  Winlogon/AppInit/IFEO paths, startup-folder paths, scheduled-task and
  service command/API references, WMI event-filter/consumer
  relationships, systemd unit paths/content, cron paths, shell-profile
  paths, XDG autostart/desktop-entry content, SSH authorized_keys paths/
  entries, and LD_PRELOAD/loader references within already-recovered Go
  strings - see `docs/architecture/go-persistence-artifacts.md` for the
  full taxonomy (27 categories, each classified SUPPORTED/
  PARTIALLY_SUPPORTED/NOT_IMPLEMENTED with individual reasons) and why
  structured Windows OS artifact recovery (registry hive/SCM/Task
  Scheduler, via real, genuinely inspected Volatility 3 plugins) is not
  implemented. A recovered string is evidence of that string only - never
  proof a registry key exists, a service was created, or persistence was
  actually established; interpretation always uses one of five precise
  phrases (`PERSISTENCE_ARTIFACT_OBSERVED`/`PERSISTENCE_PATH_OBSERVED`/
  `PERSISTENCE_COMMAND_OBSERVED`/`PERSISTENCE_CONFIGURATION_REFERENCED`/
  `PERSISTENCE_FUNCTION_ASSOCIATED`), never `PERSISTENCE_CONFIRMED`/
  `PERSISTENCE_ESTABLISHED`/`COMMAND_EXECUTED`. No persistence mechanism
  is ever created, modified, or executed - all processing is local and
  read-only
- IOC extraction and cross-artifact correlation (Phase 6E): normalizes
  qualifying network/credential/crypto/persistence artifacts into
  `IOCArtifact` records (a closed, reuse-only taxonomy - no new
  detection, no `UNKNOWN_IOC` catch-all) with deterministic
  deduplication (`dedup_key`, never merging or discarding individual
  evidence records) and confidence combination; restates each artifact's
  already-existing evidence-chain fields as explicit, typed
  `CorrelationRecord` graph edges (13 closed relationship types) - never
  a new inference, never memory-proximity or same-process/same-goroutine-
  alone correlation (explicitly tested); no malware score, verdict, or
  threat reputation exists anywhere, and no DNS/WHOIS/reputation/network
  lookup occurs - see `docs/architecture/go-ioc-correlation.md`
- Findings and evidence assessment (Phase 6F): summarizes already-
  recovered IOCs/correlations into a closed, 17-value, evidence-backed
  `Finding` taxonomy (each type mapped from a specific, documented
  `IOCType`/`CorrelationType` evidence rule - no `UNKNOWN_FINDING`
  catch-all), always separating `observed_evidence` from
  `interpretation`, with deterministic deduplication (reusing Phase 6E's
  own `dedup_key`), confidence propagation (highest-ranked contributing
  source, never averaged), and a fixed per-type severity table
  representing forensic/reporting importance only - **never** a
  maliciousness probability, malware score, threat score, reputation
  result, or automatic attribution; no ML classification, no opaque
  heuristics - every rule is a fixed, inspectable table. Correlation-
  based findings require both linked artifacts to already be IOC-
  eligible. See `docs/architecture/go-findings.md`
- Deterministic JSON output (`case`, `evidence`, `environment`, `system`,
  `processes`, `go_runtimes`, `go_candidates`, `strings`, `functions`,
  `goroutines`, `network_artifacts`, `credential_artifacts`,
  `crypto_artifacts`, `persistence_artifacts`, `iocs`, `correlations`,
  `findings`, `errors`, `statistics`)
- Forensic reporting (Phase 6G): `gomemforensics report <analysis.json>
  --format json|html` renders an already-produced analysis JSON as a
  deterministic report - never re-scans memory, never calls Volatility,
  never creates a new artifact/IOC/correlation/finding. The JSON report
  reproduces every field plus a computed executive summary, per-process
  summary, methodology, limitations, and evidence-traceability chains
  (never truncated). The HTML report is a single self-contained document
  (no external network resources, no CDN, no remote JavaScript) with 21
  sections, HTML-escaped evidence content, and redacted values in every
  credential/crypto/persistence/IOC table - never a raw secret. No
  malware verdict, score, or process ranking by suspiciousness exists at
  this layer. PDF generation is deferred (no PDF dependency is
  installed) - see `docs/architecture/go-reporting.md`
- End-to-end integration validation (Phase 6H): the complete Phase 0-6G
  pipeline (evidence through HTML report) is exercised via the real,
  unmodified `run_analysis()` function against the real compiled fixture
  binary, with only the Volatility image-parsing layer substituted -
  proving cross-artifact reference integrity (every IOC/correlation/
  finding id resolves to a real object, never a dangling or fabricated
  reference), full provenance preservation, deterministic output across
  repeated runs (byte-for-byte identical JSON/HTML, once the two
  legitimately time-varying timestamp fields are isolated), correct
  partial-analysis behavior ("nothing found" never conflated with
  "analysis failed"), end-to-end secret safety, and a complete CLI
  `analyze` -> `report` workflow. No new analyzer or artifact type was
  added; one genuine reproducibility defect found during this validation
  (a random `GoRuntime.runtime_id`) was fixed - see
  `docs/validation/phase-6h-end-to-end-validation.md`

## Planned capabilities

The following are designed but **not yet implemented**:

- Structured Go network object recovery (`net.TCPAddr`, `netip.Addr`,
  `net/url.URL`, TLS connection state - see
  `docs/architecture/go-network-artifacts.md` for why)
- Structured Go credential object recovery (`net/url.Userinfo`,
  `net/http.Cookie`, TLS/x509 certificate structs), cross-string
  username/password pairing, certificate/private-key pairing, and live
  process environment-block recovery - see
  `docs/architecture/go-credential-artifacts.md` for why
- Structured Go crypto object recovery (RSA/ECDSA/Ed25519/X25519 keys,
  `crypto/tls.Config`/`ConnectionState`, hash/AEAD/cipher state),
  ChaCha20-Poly1305/HMAC key detection, IV/nonce/salt detection, and
  certificate/public-key content (subject/issuer/validity) parsing - see
  `docs/architecture/go-crypto-artifacts.md` for why
- Structured Windows OS artifact recovery (registry hive, SCM service
  records, Task Scheduler database - real Volatility 3 plugins were
  located and inspected but not wired in, since they are whole-kernel-
  symbol-dependent and unvalidatable at any tier available in this
  environment), structural cron-entry recognition, and DLL search-order
  hijacking detection - see `docs/architecture/go-persistence-artifacts.md`
  for why
- A malware verdict/scoring layer (Findings - a structured, evidence-
  backed assessment - are implemented as of Phase 6F, see above, but a
  malware verdict/probability/threat-score concept is deliberately not
  built on top of them; CLAUDE.md's planned `detection/` package remains
  unimplemented)
- PDF reporting (JSON and HTML are implemented as of Phase 6G - see
  `docs/architecture/go-reporting.md` for why PDF is deferred rather than
  guessed at)

## Supported platforms

| OS | Architecture | Status |
|---|---|---|
| Windows | x86-64 | Current target (implementation not yet started) |
| Linux | x86-64 | Current target (implementation not yet started) |
| Linux | ARM64 | Planned future support - **not currently supported** |
| Windows | ARM64 | Planned future support - **not currently supported** |

ARM64 support is an engineering extension planned for a later phase; it is
not inherited from the reference paper, which targets x86-64 only. See
`docs/supported-platforms/platforms.md`.

## Installation (development)

Requires Python **3.11+**. Verified during Phase 0 against Python 3.14.3
(Windows x86-64) - see `docs/validation/validation-plan.md` for details.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -e ".[dev]"
```

## CLI usage

```bash
gomemforensics --help
gomemforensics version
gomemforensics info
gomemforensics validate <memory-image>
gomemforensics analyze <memory-image> --output reports/analysis.json
```

At this phase, `analyze` performs evidence validation, Volatility
initialization, OS/architecture detection, process enumeration, Go
process/runtime detection, and Go string recovery, then writes a JSON
report (default: `reports/analysis.json`, never inside the evidence
file's own directory). It performs no Go function/goroutine analysis yet.
If Volatility cannot process the image at all (unsupported/corrupted, or
not a currently-targeted OS), a partial report is still written - evidence
hash and the failure itself are recorded - and the command exits non-zero.

## Test fixtures

`tests/fixtures/go/fixture.go` is a small, deliberately benign Go program
(no network, no command execution, no persistence) used as ground truth
for Go runtime detection and string recovery testing - it includes marker
strings covering short/long/repeated/Unicode/empty static literals, a
heap-created dynamic string, and a string shared between two variables.
Build it for Windows/Linux x86-64 via:

```bash
# PowerShell
scripts/fixtures/build_fixture.ps1
```

Built binaries are gitignored build artifacts, not evidence.

## Project methodology

See `CLAUDE.md` for the full governing methodology: forensic evidence
handling rules, the confidence model, the phased implementation roadmap,
and the distinction this project draws between paper-derived functionality,
engineering additions, experimental functionality, and future work.

## License

MIT - see `LICENSE`.
