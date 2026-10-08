# Phase 6H — End-to-End Integration and Validation

**Status: Phase 6H - End-to-End Integration and Validation. This phase
adds no new analyzer and no new artifact type; it validates that the
already-implemented Phase 0-6G pipeline works as one coherent forensic
workflow, and fixes one genuine integration-contract defect found while
doing so (a non-deterministic `GoRuntime.runtime_id`).**

## 1. Objective

Prove that the complete implemented pipeline - evidence, Volatility
integration, process discovery, Go candidate detection, `pclntab`, Go
runtime, strings, functions, goroutines, network/credential/crypto/
persistence artifacts, IOC extraction, cross-artifact correlation,
findings, `AnalysisResult`, JSON report, HTML report - works together as
one coherent, contract-respecting, deterministic, provenance-preserving
workflow, and that its failure/partial-failure/bounds/secret-safety
behavior is correct end-to-end, not just correct at each individual
analyzer's own unit-test boundary.

## 2. Scope

Integration and validation only. No new forensic artifact type, no new
detection heuristic, no malware scoring/verdict/ML classification, no
network/DNS/WHOIS/reputation lookup, no automatic memory acquisition, no
ARM64 expansion, and no real-memory-image validation attempt (Phase 5.5
remains blocked - see below). The one code change made in this phase is
a minimal, targeted fix to a genuinely broken integration contract
(reproducibility), not new capability.

## 3. Pipeline under test

```
Evidence -> Volatility integration -> process discovery -> Go candidate
detection -> pclntab -> Go runtime -> strings -> functions -> goroutines
-> network artifacts -> credential/secret artifacts -> crypto artifacts
-> persistence artifacts -> IOC extraction -> cross-artifact correlation
-> findings/evidence assessment -> AnalysisResult -> JSON report -> HTML
report
```

Exercised via the **real, unmodified** `gomemforensics.pipeline.run_analysis()`
function - not a hand-assembled shortcut that directly constructs the
final `AnalysisResult`. The only substitution is
`gomemforensics.volatility.integration.VolatilityIntegration`, replaced
by a small, interface-compatible fake
(`_FakeVolatilityIntegration` in `tests/integration/test_end_to_end_pipeline.py`
and duplicated in `tests/integration/test_cli_end_to_end.py`, consistent
with this project's established per-file fixture-boilerplate convention)
that implements exactly the six methods `run_analysis()` actually calls
(`initialize`/`detect_os`/`detect_architecture`/`enumerate_processes`/
`get_process_memory`/`get_process_regions`), backed by a PE-section-
mapped reader over the real compiled fixture binary file - the same
real-file-bytes boundary every Phase 6A-6G fixture test already uses.
This is the only piece of the pipeline that genuinely requires a captured
memory image, which remains unavailable (Phase 5.5). Every other stage -
evidence hashing, OS/architecture propagation, all nine `pipeline._recover_*`
wrapper functions, statistics aggregation, `AnalysisResult` assembly,
JSON serialization, and Phase 6G reporting - runs unmodified, through the
actual production code path.

## 4. Integration contracts

Traced (not assumed) before writing any test:

- `run_analysis()`'s per-process loop (`pipeline.py`) - each
  `_recover_*` wrapper's exact call signature and return shape.
- `AnalysisResult.to_json_dict()` - the exact 21-key JSON schema every
  downstream consumer (the `report` CLI command, `ReportModel`) depends on.
- `IOCArtifact.source_artifact_id`/`source_artifact_type` - confirmed by
  reading `gomemforensics.analyzers.correlation._network_candidate`/
  `_credential_candidate`/`_crypto_candidate`/`_persistence_candidate`:
  `source_artifact_id` is copied from the *derived* artifact's own
  `source_artifact_id`, which points to the *originating `StringArtifact`*
  - not to the derived artifact itself. The derived artifact's own id is
  carried separately, in the category-specific `related_network_artifact_id`/
  `related_credential_artifact_id`/`related_crypto_artifact_id`/
  `related_persistence_artifact_id` field. (An initial draft of this
  phase's cross-artifact-consistency test assumed the opposite and was
  corrected after tracing the actual source - see Section 5.)
- `CorrelationRecord.source_id`/`source_type`/`target_id`/`target_type` -
  confirmed against `analyzers/models.py`.
- `Finding.supporting_ioc_ids`/`supporting_artifact_ids`/
  `supporting_correlation_ids`/`function_ids`/`goroutine_ids` - confirmed
  against `analyzers/models.py`.
- `ReportModel._build_evidence_traceability` - confirmed it omits, never
  fabricates, an unresolvable link.

## 5. Fixture used

The real compiled Go 1.26.2 Windows x86-64 fixture binary
(`tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe`), the
same one every Phase 2-6G fixture test uses. Evidence metadata (including
SHA-256) is computed by the real `EvidenceValidator().validate()` against
this real on-disk file - not fabricated, not a placeholder hash.

## 6. Validation tiers

**COMPILED_BINARY_VALIDATED** for this entire phase - real compiled Go
binary bytes read at their real virtual addresses through the real
pipeline code path. This is explicitly **not** REAL_MEMORY_VALIDATED: no
captured process memory image was read, and the Volatility 3 layer
itself (automagic, layer stacking, live kernel-symbol-driven process
enumeration) never ran. `REAL_MEMORY_VALIDATED` remains `False`
throughout - see Section 19.

## 7. Provenance checks

Confirmed end-to-end, using real ids produced by the real fixture run
(never hard-coded fake ids):

- PID/process identity, Go version, and architecture are consistent
  across every artifact/IOC/correlation/finding collection
  (`TestCrossArtifactConsistency::test_all_process_ids_consistent_across_every_collection`).
- Every `IOCArtifact.function_id`/`goroutine_id`, when populated, resolves
  against the real `functions`/`goroutines` collections
  (`test_ioc_function_and_goroutine_ids_resolve_if_present`).
- Every `Finding.function_ids`/`goroutine_ids`, when populated, resolve
  the same way (`test_finding_function_and_goroutine_ids_resolve_if_present`).
- The full evidence-traceability chain resolves through real ids for all
  6 real findings, terminating at the real fixture's own evidence SHA-256
  (`tests/integration/test_reporting_fixture.py::test_findings_traceable_through_evidence_chain`,
  reconfirmed against the real pipeline path in this phase).

## 8. Cross-artifact checks

- `IOCArtifact.source_artifact_id` resolves against `strings`
  (`test_every_ioc_source_artifact_resolves`).
- `IOCArtifact`'s category-specific `related_*_artifact_id` resolves
  against the matching derived-artifact collection
  (`test_ioc_related_artifact_matches_its_own_category`).
- Every `CorrelationRecord` endpoint (`source_id`/`target_id`) resolves
  against the collection implied by its own `source_type`/`target_type`
  (`test_every_correlation_endpoint_resolves`).
- Every `Finding.supporting_ioc_ids`/`supporting_artifact_ids`/
  `supporting_correlation_ids` resolves against the real IOC/string/
  correlation collections
  (`test_every_finding_supporting_ioc_resolves`,
  `test_every_finding_supporting_artifact_resolves`,
  `test_every_finding_supporting_correlation_resolves`).
- No correlation record uses a relationship type outside the 13-value
  closed `CorrelationType` taxonomy, and no forbidden "same
  function/goroutine implies behavior" relationship exists
  (`test_no_correlation_claims_relationship_analyzers_do_not_support`) -
  this project's analyzers do not claim proximity-based or same-
  function/goroutine-alone correlation, and this phase does not introduce
  one.

All of the above run against the **real fixture's real output** (six
real findings, six real IOCs, six real correlations), not synthetic
placeholder ids.

## 9. Determinism checks

**A genuine nondeterminism bug was found and fixed** (see Section 21 for
the audit trail). `gomemforensics.go_runtime.detector._build_go_runtime`
previously generated `GoRuntime.runtime_id` as
`f"GORUNTIME-{pid}-{uuid.uuid4().hex[:8]}"` - a random value, unlike
every other artifact id in the project (`STR-{pid}-{sequence}`,
`FUNC-{pid}-{address}`, `PCLNTAB-{pid}-{sequence}`,
`MODULEDATA-{pid}-{sequence}`, all deterministic). This ID then
propagated into `process.go_runtime_id` and every string/function
provenance record's `related_artifacts` list, meaning two consecutive
`run_analysis()` calls against the byte-identical fixture produced
different JSON output on every run - a direct violation of CLAUDE.md
section 34 ("A report should be reproducible as far as technically
possible"). This was never caught by any prior phase's test suite
because no earlier fixture test ran the full pipeline (via
`GoProcessDetector().detect()`) twice and compared the resulting JSON;
each ran it once per test module.

**Fix** (minimal, targeted, the only production code change in this
phase): `runtime_id` is now derived from the already-deterministic
`pclntab.address` (`f"GORUNTIME-{pid}-{pclntab.address:x}"`), matching
the address-derived convention `FUNC-` ids already use. At most one
`GoRuntime` is ever built per `(pid, pclntab address)`, so this remains
collision-free. See `src/gomemforensics/go_runtime/detector.py`.

After the fix, two consecutive full-pipeline runs against the identical
fixture produce:

- identical ids, in identical order, for every artifact/IOC/correlation/
  finding collection
  (`TestDeterminism::test_repeated_full_pipeline_runs_produce_identical_ids_and_ordering`)
- structurally identical JSON, once the two legitimately time-varying
  fields are isolated (see below)
  (`test_repeated_runs_produce_structurally_identical_json`)
- byte-for-byte identical rendered JSON and HTML reports
  (`test_report_rendering_deterministic_across_repeated_pipeline_runs`)

**Legitimately time-varying fields, isolated, never hidden**:
`evidence.analysis_timestamp`/`environment.analysis_timestamp` (each
`run_analysis()` call performs its own fresh evidence validation, exactly
like two separate `gomemforensics analyze` invocations) and each
`AnalysisError.timestamp` (an event-time field, `default_factory=utc_now_iso`,
analogous to `report_metadata.report_generated_at`, which Phase 6G
already isolates the same way). No id, ordering, count, or evidentiary
value is stripped or reordered to manufacture a false "pass" - the test
comment (`_strip_run_timestamps`) documents exactly and only these two
clock-reading fields.

## 10. Partial-analysis behavior

Verified that a category producing zero artifacts is never accompanied
by a non-recoverable error for that category (`TestPartialAnalysis::test_empty_categories_are_distinct_from_analyzer_failure`)
and that the HTML report renders the documented explicit empty-state
message ("No credential artifacts recovered.", "No crypto artifacts
recovered.") rather than an error/unavailable marker when a section is
legitimately empty (`test_report_renders_empty_sections_with_explicit_empty_message_not_error`).
"Nothing found" and "analyzer failed"/"analyzer unavailable" remain
textually and structurally distinct throughout the pipeline and the
report.

## 11. Error handling

New integration-layer coverage (`tests/integration/test_error_and_dangling_references.py`,
10 tests) for the seam Phase 6G/6H introduced - what `ReportModel`/the
`report` CLI command do when a cross-referenced id in an otherwise-valid
analysis JSON does not resolve:

- a dangling `IOCArtifact.source_artifact_id` - does not crash, is
  preserved verbatim in the JSON report, and is correctly omitted (never
  fabricated) from the evidence-traceability chain
- a dangling `CorrelationRecord` endpoint - does not crash, is preserved
  verbatim, rendered as-is in HTML
- a forward-compatible/unrecognized correlation endpoint type - does not
  crash (never reinterpreted as something it is not)
- a `Finding` with every supporting id dangling
  (`supporting_ioc_ids`/`supporting_artifact_ids`/`supporting_correlation_ids`/
  `function_ids`/`goroutine_ids`) - does not crash, ids remain visible in
  the HTML for examiner review, and the evidence-traceability chain
  contains only the finding/process/evidence-hash links that are
  genuinely resolvable
- malformed report input at the CLI boundary: a top-level JSON array
  instead of an object, an empty file, and truncated/incomplete JSON -
  all fail with `EXIT_REPORT_ERROR` and a clear message, never a crash
  and never a fabricated placeholder report
- a minimal-but-valid analysis JSON with no findings/IOCs renders a
  complete report with the correct explicit empty-state text, confirming
  "fail clearly OR render only what is real" holds even at the minimum
  valid input

Per-analyzer malformed-structure handling (invalid pclntab/moduledata,
unsupported architecture/Go version, invalid string/network/credential/
crypto/persistence artifact construction) was not re-tested here - it is
already exhaustively covered where each analyzer actually lives, and
this phase's remit is integration, not re-deriving already-established
analyzer-level correctness:

| Failure mode | Existing coverage |
|---|---|
| Unreadable/truncated evidence | `tests/unit/test_evidence.py` |
| Malformed analysis JSON / missing required `AnalysisResult`/report fields | `tests/unit/test_reporting_models.py` (`TestConstruction`), `tests/unit/test_cli.py` |
| Unsupported Go version (ABI era not resolvable) | `pipeline._recover_functions`, exercised in `tests/unit/test_pipeline.py::TestRecoverFunctions` |
| Malformed pclntab / moduledata | `tests/unit/test_go_runtime_pclntab.py`, `tests/unit/test_go_runtime_moduledata.py`, `tests/unit/test_go_runtime_detector.py` |
| Invalid string/network/credential/crypto/persistence artifact construction | `tests/unit/test_strings.py`/`test_static_strings.py`, `test_network_analyzer.py`, `test_credential_analyzer.py`, `test_crypto_analyzer.py`, `test_persistence_analyzer.py` |
| `FailureReason` taxonomy itself (closed, 18 values) | `tests/unit/test_failure_reason.py` |

The existing `FailureReason` taxonomy was reused throughout; no new
free-form error category was introduced anywhere in this phase.

## 12. Secret-safety validation

End-to-end, using the real fixture's own recovered artifacts plus six
synthetic sensitive values injected to represent each Phase 6B credential
category the fixture itself does not happen to contain (password, basic
auth, bearer token, cookie/session token, database credential, RSA
private key) - `TestSecretSafetyEndToEnd` in
`tests/integration/test_end_to_end_pipeline.py`:

- the raw value of every injected secret is confirmed **absent** from the
  rendered HTML report
- the corresponding redacted form **is** present
- the CLI `report` command's own stdout summary never contains a raw
  secret

Consistent with the artifact model's own design (raw values may
legitimately remain in the JSON artifact-storage record, which is the
canonical machine-readable evidence; only the presentation layer's
default views - HTML, CLI stdout - must never leak them), and consistent
with Phase 6G's own renderer-level secret-safety tests, which this phase
does not weaken or duplicate but extends to the full pipeline path.

## 13. CLI validation

`tests/integration/test_cli_end_to_end.py` (12 tests): `--help`/`info`
exit 0; `analyze` against the real fixture (via the same fake-Volatility
substitution) succeeds, reports progress without secrets, fails cleanly
before touching Volatility when given a missing file, and cleanly
overwrites a prior output on a second run (no stale merge); `report`
renders both JSON and HTML from real `analyze` output, never touches
Volatility/`MemoryReader` (confirmed by asserting neither "Validating
evidence" nor "Volatility" appears in its output), overwrites
deterministically, and never emits an `"[!]"` error marker on the success
path; a full `analyze` -> `report` (HTML) -> `report` (JSON) workflow
round-trips the case ID and the real fixture's counts correctly.

## 14. HTML security validation

Re-confirmed at integration level, using the real pipeline's actual
output plus explicit injected payloads (`<script>alert(1)</script>`,
in a synthetic string value - see Section 15): no `<script`, no
`http://`/`https://` resource reference, no CDN, no external font/CSS/
JS anywhere in the rendered document; the injected payload appears only
in its HTML-escaped form. This is the same self-containment/escaping
contract Phase 6G already established
(`docs/architecture/go-reporting.md`), re-verified here against real
pipeline output rather than only hand-built synthetic `ReportModel`
input.

## 15. Resource-bound / large-result validation

The real fixture's own Functions table (2,193 rows) already exceeds
`MAX_TABLE_ROWS_HTML = 2000`, so this phase's resource-bound tests
exercise the truncation path against genuine real-pipeline output rather
than an artificially constructed large list: the HTML report discloses
the truncation explicitly ("the complete, untruncated set is in the JSON
report"), while the JSON report is confirmed to contain the full,
untruncated 2,193-row set. `MAX_STRING_VALUE_LENGTH`/`MAX_ARTIFACTS_PER_PROCESS`/
`MAX_IOCS_PER_PROCESS`/`MAX_CORRELATIONS_PER_PROCESS`/PEM-length bounds
were not re-tested here (each already has dedicated unit coverage in its
owning analyzer's test file, e.g. `test_correlation.py::test_correlation_cap_enforced_and_recorded`)
- this phase confirms the reporting-layer bound (`MAX_TABLE_ROWS_HTML`/
`MAX_STRING_DISPLAY_LENGTH_HTML`) specifically, since that is the bound
this phase's own pipeline (Phase 6G) introduced.

## 16. Performance/complexity sanity review

No benchmarking was performed (out of scope). A targeted code-level
review confirmed the one place a naive implementation could have become
quadratic - `SAME_SOURCE_STRING` correlation, which pairs every derived
artifact sharing one source string - is explicitly bounded:
`gomemforensics.analyzers.correlation.MAX_SAME_SOURCE_GROUP_SIZE = 8`
caps the pairwise expansion **per group**, not across the whole
process's artifact population; a group exceeding the cap is skipped with
a recoverable `AnalysisError`, never silently truncated and never
allowed to explode (already unit-tested:
`tests/unit/test_correlation.py::test_group_size_bound_skips_pairwise_expansion`,
`test_correlation_cap_enforced_and_recorded`). Every other analyzer
(network/credential/crypto/persistence/IOC/findings) processes its input
list once, with a `MAX_ARTIFACTS_PER_PROCESS`/`MAX_IOCS_PER_PROCESS`/
`MAX_FINDINGS_PER_PROCESS` cap and no nested full-population comparison.
`ReportModel` construction builds a small number of `pid`/`id`-indexed
dicts (`_index_by_pid`/`_index_by_id`) once and looks up against them -
O(N) in the total artifact count, not O(N²). No recursive or unbounded
provenance-chain traversal exists anywhere in this codebase (every
provenance/traceability chain is built from a fixed, small set of
already-known fields, never a recursive walk).

## 17. Test totals

See Section 19 (in the final report) for exact numbers; new test files
added by this phase:

- `tests/integration/test_end_to_end_pipeline.py` (31 tests)
- `tests/integration/test_cli_end_to_end.py` (12 tests)
- `tests/integration/test_error_and_dangling_references.py` (10 tests)

## 18. Known limitations

- COMPILED_BINARY_VALIDATED only - no real captured memory image was
  read; Volatility 3's own automagic/layer-stacking/live-kernel-symbol
  machinery never ran in this phase's tests (only its documented
  interface was faked).
- Only one process (the fixture binary itself) is exercised per pipeline
  run - multi-process cross-referencing at scale (e.g. hundreds of
  processes, some Go and some not) remains validated only at the unit
  level (`pipeline._recover_*` wrapper tests), not end-to-end.
- Only Windows x86-64 is exercised end-to-end in this phase (the only
  fixture binary this repository has real compiled bytes for); Linux
  x86-64 remains validated at the unit/analyzer level, consistent with
  every prior phase's documented status.
- No performance benchmarking was performed - Section 16 is a structural/
  code-level review, not a timed measurement.
- No real-memory validation - see Section 19.

## 19. `REAL_MEMORY_VALIDATED` status

**`REAL_MEMORY_VALIDATED = False`.** Unchanged. **REAL MEMORY VALIDATION
REMAINS BLOCKED** - Phase 5.5 found no approved real memory image
available in this development environment, and this phase did not
attempt to acquire one (explicitly out of scope per this phase's own
instructions). Every test and every generated report in this phase is
COMPILED_BINARY_VALIDATED (real compiled binary file bytes, read at
their real virtual addresses) or, for the malformed-input/dangling-
reference tests, SYNTHETIC_VALIDATED - neither is presented as, or
treated as equivalent to, real-memory validation anywhere in this
project's code, tests, or documentation.

## 20. Phase 7 boundary

Not started, and not touched by this phase. Real-memory-image validation
(the actual Phase 5.5 objective, still blocked) belongs to Phase 7, along
with any capability this phase's audit noticed was still missing but
which requires new analysis capability rather than an integration fix -
none was found; the single code change this phase made (the
`runtime_id` determinism fix) was a minimal correction to an already-
existing contract, not new capability, and is explicitly out of Phase
7's scope to redo.
