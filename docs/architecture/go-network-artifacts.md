# Go Network Artifact Analyzer (Phase 6A)

**Status: Phase 6A - Go Network Artifact Analyzer. Extraction only, never
malware classification (CLAUDE.md section 20).**

## What this analyzer is

`gomemforensics.analyzers.network` recognizes network-related shapes
(IPv4/IPv6 addresses, hostnames, URLs, `host:port` endpoints) within Go
strings **already recovered** by Phase 3
(`gomemforensics.go_runtime.strings.StringRecoveryEngine`). It is not a
second memory scanner: every `NetworkArtifact` traces back to exactly one
`StringArtifact` via `source_artifact_id`, and the analyzer never reads
process memory directly.

This is a deliberate, load-bearing design choice: it means the network
analyzer inherits Phase 3's already-established Go-version/architecture
boundaries (heap string recovery is gated on a source-verified `mspan`
layout; static-section recovery is layout-independent) without having to
re-derive or re-verify any Go runtime struct of its own. The classifier
itself operates on plain, already-decoded Python `str` values - it has
**no Go version or architecture dependency**.

## Source archaeology (Phase 6A stage 3)

| Structure | Source file (local go1.26.2 install) | Fields | Recoverable from memory? | Verification |
|---|---|---|---|---|
| `net.TCPAddr` | `net/tcpsock.go` | `IP net.IP; Port int; Zone string` | Fields are exported and stable, but **no reliable instance-address discovery mechanism exists** - no anchor comparable to `moduledata`; would require heap-object type-index correlation (Phase 3's `mspan.py`/`types.py`), and the type descriptor is only present in the binary if the analyzed program imports `net` via an interface conversion (Go dead-code elimination) - the project's own fixture does not. | Field layout SOURCE_VERIFIED; NOT IMPLEMENTED (addressability) |
| `net.UDPAddr` | `net/udpsock.go` | `IP net.IP; Port int; Zone string` | Same addressability gap as `net.TCPAddr`. | SOURCE_VERIFIED; NOT IMPLEMENTED |
| `net.IP` | `net/ip.go` | `type IP []byte` | A plain byte slice; same addressability gap - and even if located, deciding "this `[]byte` is an IP and not any other byte slice" without an enclosing typed struct is itself a guess. | SOURCE_VERIFIED; NOT IMPLEMENTED |
| `netip.Addr` | `net/netip/netip.go` | `addr uint128; z unique.Handle[addrDetail]` | The `z` field is a `unique.Handle[addrDetail]` - Go's own interned-value handle, an **intentionally unexported, explicitly-undocumented-as-stable internal representation**. Parsing it would mean guessing a private, unstable layout - forbidden by CLAUDE.md section 40 and this phase's "SOURCE FIRST" principle. | Permanently NOT IMPLEMENTED - not an addressability gap, a stability gap |
| `net/url.URL` | `net/url/url.go` | `Scheme, Opaque, Host, Path, Fragment, RawQuery string; User *Userinfo` | Exported, stable string fields, but the same addressability gap as `net.TCPAddr` applies, and many `url.URL` values never escape to the heap at all (stack-allocated by the Go compiler's escape analysis, so no heap scan could ever find them even in principle). | SOURCE_VERIFIED; NOT IMPLEMENTED |
| `crypto/tls.ConnectionState` | `crypto/tls/common.go` | Large, multi-field, references further structures (certificates, cipher state) | Not source-archaeology-complete for this phase; explicitly out of the Phase 6A effort budget. | NOT ATTEMPTED; NOT IMPLEMENTED |

**Conclusion**: no structured Go network object is recovered by this
phase. This is documented, not silently omitted, per stage 9's explicit
permission: "If these conditions cannot be satisfied: DOCUMENT the
structure as NOT IMPLEMENTED / UNSUPPORTED." The only implemented layer
is string-based (stage 4), which has no such addressability or stability
problem, since it operates on Go string *values* Phase 3 has already
located and decoded.

## Classification algorithm

`gomemforensics.analyzers.network.classify_network_string(value: str)`
applies a fixed, deterministic ordering - see the function's own
docstring for the exact rationale of each ordering choice:

1. URL (`scheme://...`, scheme restricted to `http`/`https`) - parsed via
   Python's `urllib.parse.urlsplit`.
2. IPv6 (Python's `ipaddress.IPv6Address`, strict - handles compressed,
   full, and IPv4-mapped forms without any custom regex).
3. `host:port` (regex-delimited, host validated as IPv4, bracketed IPv6,
   `localhost`, or an allowlisted-TLD hostname; port range-checked
   0-65535).
4. IPv4 (Python's `ipaddress.IPv4Address`, strict - rejects ambiguous
   leading-zero octets, non-4-octet forms, out-of-range octets).
5. Hostname/domain (multi-label, RFC-1035-derived label syntax with a
   documented underscore relaxation, gated by a curated common-TLD
   allowlist - see "False-positive controls" below).

A string matching none of these produces no artifact at all - there is no
"low confidence, keep anyway" path for text extraction (unlike, e.g.,
`PclntabCandidate`, which preserves rejected candidates for diagnostic
purposes): a false structural match on arbitrary text has no forensic
value worth preserving as a distinct object.

### False-positive controls (Phase 6A stage 6)

The dominant, deliberate control is the **TLD allowlist**
(`_TLD_ALLOWLIST` in `network.py`, ~70 common TLDs): a bare
`label.label` string is only recognized as a hostname if its final label
matches a real, common TLD. This is what prevents Go source-level
selector expressions (`io.Reader`, `time.Now`, `os.Exit`) and package
paths from being misclassified - their trailing "label" essentially never
coincides with a real TLD, whereas an actual hostname's TLD does by
definition. The documented, accepted cost: a legitimate hostname under an
exotic/very new TLD not in the allowlist will not be recognized.

Other explicit controls:

- A path separator (`/` or `\`) anywhere in the string disqualifies it
  from hostname classification outright (Go import paths, Windows/Linux
  filesystem paths).
- IPv4/IPv6 parsing is delegated entirely to Python's `ipaddress` stdlib
  module rather than a custom regex - it already correctly rejects
  leading-zero octets (avoids octal ambiguity), wrong octet counts, and
  malformed IPv6 group counts (naturally rejecting things like MAC
  addresses and most timestamps, which do not have a valid 8-group-or-
  compressed IPv6 shape).
- A bare port is never extracted - only ever as part of a validated
  `host:port` or URL artifact (stage 4's explicit requirement).
- Email addresses, UUIDs, SHA-256 hashes, and semantic versions are never
  special-cased as *rejections* - they are simply not accepted by any of
  the five recognized shapes above, and are verified as such by
  `tests/unit/test_network_classification.py::TestFalsePositives`.

**Known, irreducible, documented ambiguity**: a 4-part dotted numeric
string (e.g. a hypothetical 4-component build number `10.0.19045.1`) is
*syntactically indistinguishable* from an IPv4 address - `ipaddress`
cannot and does not disambiguate by context. This is not a bug; it is
inherent to string-only analysis and is why every emitted artifact
carries `confidence=MEDIUM` (see "Confidence" below), never `HIGH` - the
project does not claim certainty it cannot support.

## Function/goroutine association (stages 7/8)

Both associations reuse an **existing, explicit evidence chain** - never
address proximity:

- **Function**: Phase 4.1's backward analysis already records, for a
  resolved call-site argument identified as a string reference,
  `ArgumentArtifact.value = "string_ref:<StringArtifact.id>"`
  (`gomemforensics.go_runtime.backward_analysis._classify_rip_target`).
  `_build_function_string_references` in `network.py` inverts this into
  `StringArtifact.id -> {FunctionArtifact.id, ...}` by scanning every
  function's own `recovered_call_sites` - the string reference occurs
  within that specific function's disassembled instruction window, a
  direct fact, not an inference.
- **Goroutine**: a goroutine's unwound `GoroutineFrame.function_id`
  values and its own `current_function_id` are direct field references
  (Phase 5). `_build_goroutine_function_references` inverts these into
  `FunctionArtifact.id -> {GoroutineArtifact.id, ...}`.

`NetworkArtifact.function_id`/`.goroutine_id` are **singular** fields
(matching the Phase 6A model spec), but a string can legitimately be
referenced by more than one function (e.g. a shared constant). Rather
than silently dropping the other associations to fit a singular field,
the deterministic lowest-sorted id is stored there and the **complete**
set of associated function/goroutine ids is preserved in
`provenance.related_artifacts` - no evidence is discarded.

Neither association is ever presented as proof that a network operation
occurred - `NetworkArtifact` never claims "this goroutine contacted this
IP" (stage 8's explicit prohibition); it records only that a specific,
traceable evidence chain connects the string to that function/goroutine.

## Confidence and validation status

Per stage 12's explicit principle ("MEDIUM: validated string-derived
network artifact"), **every** artifact this phase produces gets
`confidence=Confidence.MEDIUM` - there is no structured-object path
implemented yet that would ever justify `HIGH`, and nothing this analyzer
does is a "low-confidence heuristic guess" either (every emitted artifact
passed full deterministic structural validation, so `LOW`/`UNKNOWN` are
never used for an *emitted* artifact - a candidate that fails validation
is never emitted at all, not emitted with a low confidence).

`validation_status` is always `NetworkValidationStatus.STRUCTURALLY_VALID`
for an emitted artifact, for the same reason.
`NetworkValidationStatus.UNSUPPORTED_STRUCTURE` exists in the enum only
as a reservation for a future structured-object recovery path; nothing in
Phase 6A ever sets it.

## Deduplication (stage 11)

Phase 6A performs **no artifact merging at all**. Because every
`NetworkArtifact` is produced 1:1 from a single `StringArtifact` (the
classifier examines a string's whole value, never sub-scans it for
multiple embedded artifacts), two `StringArtifact`s with identical values
at different addresses simply produce two independent `NetworkArtifact`s
with independent `id`s, `address`es, and `source_artifact_id`s - this
trivially satisfies "same value/different addresses must remain
traceable to both locations" without any explicit dedup logic to get
wrong. See `tests/unit/test_network_analyzer.py::TestDeduplicationAndProvenance`.

## Bounds (stage 17)

- `MAX_STRING_VALUE_LENGTH = 4096`: a recovered string longer than this
  is never regex/`urlsplit`-processed by this analyzer (still fully
  preserved as its own `StringArtifact` - only network classification of
  it is skipped); recorded in `NetworkAnalysisStats.strings_skipped_length_bound`.
- `MAX_ARTIFACTS_PER_PROCESS = 5000`: a hard cap on emitted artifacts per
  process. When reached, remaining strings are left unclassified for that
  process; this is recorded explicitly (`NetworkAnalysisStats.capped`
  plus a recoverable `AnalysisError`), never silently truncated.
- No unbounded/backtracking-prone regex is used anywhere in this module;
  IPv4/IPv6 parsing is delegated to the `ipaddress` stdlib module, URL
  parsing to `urlsplit` - both linear-time.

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATION = UNVALIDATED`** for this entire analyzer, same
as every other Phase 2-5 capability (see
`docs/validation/validation-plan.md`'s Phase 5.5 section - no approved
real memory image has ever been available in this development
environment). Validation performed:

- UNIT: `tests/unit/test_network_classification.py` (53 tests, pure
  string classification, no Go runtime involved at all) and
  `tests/unit/test_network_analyzer.py` (19 tests: provenance,
  function/goroutine association, dedup, bounds, pipeline semantics),
  plus `tests/unit/test_pipeline.py::TestRecoverNetworkArtifacts`.
- COMPILED_BINARY_VALIDATED: `tests/integration/test_network_artifacts_fixture.py`
  runs the real classifier against ~1,976 real static strings recovered
  from the real compiled Go 1.26.2 fixture binary (static-section
  recovery only - heap recovery has no on-disk equivalent, per
  `tests/integration/test_go_runtime_string_fixture.py`'s established
  scope boundary) - the real, observed result is zero false positives
  from that real string set, with a mixed-in synthetic network string
  still correctly recognized amid that real noise.
- No SYNTHETIC_VALIDATED category is distinct here beyond UNIT, since the
  unit tests already operate on hand-built (but structurally realistic)
  dataclass instances.
