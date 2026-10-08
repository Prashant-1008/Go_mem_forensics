# Forensic Reporting (Phase 6G)

**Status: Phase 6G - Forensic Reporting and Report Generation. This is a
presentation-only layer: it performs no new forensic discovery, no memory
access, and no Volatility calls, and it never becomes a second analyzer
(CLAUDE.md sections 23/42).**

## What the reporting layer is, and is not

`gomemforensics.reporting` renders an already-produced analysis JSON (the
exact schema of `AnalysisResult.to_json_dict()`) as an examiner-readable
report. It is **not**:

- a second detection pass (no `MemoryReader`, no Volatility plugin call,
  no new artifact/IOC/correlation/finding is ever created here)
- a scoring/ranking layer (no malware score, threat score, risk score,
  process ranking by "suspiciousness", or overall verdict)
- a replacement for the JSON produced by `gomemforensics analyze` (the
  report *consumes* that JSON; it never re-derives it)

Architecture:

```
Evidence -> AnalysisResult -> analysis JSON
                                   |
                                   v
                    gomemforensics report <json>
                                   |
                                   v
                    ReportModel.from_analysis_dict()
                                   |
                    +--------------+--------------+
                    |                             |
                    v                             v
            json_renderer.py              html_renderer.py
        (render_json_dict/text)              (render_html)
```

`ReportModel` construction (`reporting/models.py`) is the **only** place
that computes anything (executive-summary counts, per-process summaries,
limitations, evidence-traceability chains) - both renderers are pure
formatting passes over an already-built `ReportModel` and perform no
forensic calculation of their own (stage 24: `AnalysisResult -> ReportModel
-> JSON/HTML Renderer`).

## Architecture search (stage 1)

Before implementing, the repository and dependency set were searched for
existing report/HTML/PDF/templating infrastructure. None existed - no
`reporting/` package, no `report` CLI command, no HTML/PDF generation
anywhere. The installed virtual environment was probed directly
(`importlib.import_module`) for `jinja2`, `reportlab`, `weasyprint`,
`fpdf`, and `markdown` - **none are installed**. Given the report's
structure is fixed and known in advance (not user-templatable), HTML is
hand-rolled with pure stdlib (`html.escape` + f-strings) rather than
adding a templating dependency, and PDF generation is explicitly
**deferred** rather than adding a new dependency speculatively (see
"PDF: deferred" below).

## `ReportModel` (`reporting/models.py`)

A single dataclass with 25 fields, built once via
`ReportModel.from_analysis_dict(data, *, report_timestamp=None)`:

| Field | Source |
|---|---|
| `report_metadata` | computed: schema version, tool version, report-generation timestamp |
| `case`, `evidence`, `environment` | passed through from the analysis JSON verbatim |
| `validation` | computed: `real_memory_validated` plus an explanatory note |
| `executive_summary` | computed: counts only, explicitly no malware verdict/score |
| `processes` | passed through |
| `process_summaries` | computed: one row per process, original order preserved |
| `go_runtimes`, `strings`, `functions`, `goroutines`, `network_artifacts`, `credential_artifacts`, `crypto_artifacts`, `persistence_artifacts`, `iocs`, `correlations`, `findings` | passed through (shallow-copied where a `process_name` is added, e.g. `go_runtimes`) |
| `errors`, `warnings` | the analysis JSON's `errors` list split on `recoverable` |
| `methodology` | computed: fixed prose statements (see below) |
| `limitations` | computed: always-applicable statements plus conditional ones derived from actual `FailureReason` values present in `errors` |
| `evidence_traceability` | computed: one evidence chain per finding |
| `statistics` | passed through from the analysis JSON |

`from_analysis_dict` validates the input is a `dict` and that
`case`/`evidence`/`environment`/`system`/`processes` are present, raising
`ReportGenerationError` (never a bare `KeyError`/`TypeError`) otherwise.
Every optional list key (`strings`, `iocs`, `findings`, ...) defaults to
`[]` if absent, rather than crashing. The input `dict` is never mutated.

### Executive summary (stage 12)

Computed once, in `_build_executive_summary`: `analysis_status`
(`COMPLETE` / `COMPLETE_WITH_ERRORS`), evidence identity, platform/
architecture, process/Go-candidate/runtime counts, string/function/
goroutine counts, per-category artifact counts, `ioc_count` **and**
`unique_ioc_count` (deduplicated via each IOC's existing `dedup_key` -
Phase 6E's own field, never re-derived), `correlation_count`,
`finding_count`, `findings_by_severity`, `errors_count`/`warnings_count`,
and `real_memory_validated`. It explicitly carries **no** field named
`malware_score`, `threat_score`, `risk_score`, `verdict`, or similar -
`tests/unit/test_reporting_models.py::TestExecutiveSummary::test_no_malware_score_or_verdict_field`
asserts this directly. Every summary carries a `note` string restating
that it is observed-evidence counts only.

### Per-process summaries (stage 13)

`_build_process_summaries` iterates `processes` in **original order** -
the same order Volatility/the pipeline produced them in - and never sorts
by any "suspiciousness" heuristic. Each row is a flat dict of counts
(strings/functions/goroutines/network/credential/crypto/persistence/IOC/
correlation/finding/error counts for that PID) plus `is_go_candidate`,
`go_version`, `go_confidence`, `runtime_recovered`. No key on this row
contains "risk", "suspicio", or "malicious" -
`tests/unit/test_reporting_models.py::TestProcessSummaries::test_no_suspiciousness_field_exists`
asserts this.

### Limitations (stage 19)

`_ALWAYS_APPLICABLE_LIMITATIONS` (5 fixed sentences: no real-memory
validation, no structured OS persistence artifacts, no structured crypto
key objects, no external threat intel/enrichment, no malware verdict/
score/attribution) are always present. `_REASON_TO_LIMITATION` maps 12
`FailureReason` values to additional sentences, added **only** if that
reason actually appears in the run's `errors` - never every theoretical
limitation, only what actually applies to this run (stage 19's explicit
requirement).

### Evidence traceability (stage 22)

`_build_evidence_traceability` builds one chain per Finding:
`finding -> ioc(s) -> origin artifact (network/credential/crypto/
persistence, via `_ORIGIN_ID_FIELD_BY_CATEGORY`) -> source string artifact
-> function/goroutine (if the IOC carries one) -> process -> evidence
SHA-256`. Every link is a real, existing-ID lookup against the already-
built indexes; a missing link is simply **omitted**, never invented -
`tests/unit/test_reporting_models.py::TestEvidenceTraceability::test_never_invents_missing_links`
and the real-fixture
`tests/integration/test_reporting_fixture.py::test_findings_traceable_through_evidence_chain`
both assert this.

## JSON renderer (`reporting/json_renderer.py`)

`render_json_dict(report)` returns a plain dict with **fixed field
order** (a literal, not a sorted dict) covering all 25 `ReportModel`
fields under the top-level keys documented above.
`render_json_text(report)` wraps it in `json.dumps(..., indent=2,
default=str)`. The JSON report is the **canonical, complete**
machine-readable form and **never truncates** any list, however large -
`tests/unit/test_reporting_renderers.py::TestTruncationBounds::test_json_never_truncates_large_lists`
and the real-fixture
`test_json_render_preserves_fixture_counts` (1,976 strings represented in
full) confirm this.

## HTML renderer (`reporting/html_renderer.py`)

`render_html(report)` produces one self-contained `<!DOCTYPE html>`
document: inline `<style>` (no external stylesheet), no `<script>` tag,
no CDN reference, no external font, no `http://`/`https://` resource
link anywhere in the document. 21 sections in a fixed order (`_SECTIONS`),
each with a sticky top navigation bar linking to its `id`:

1. Cover / Case Information
2. Executive Summary
3. Evidence
4. Validation Status
5. Environment
6. Processes
7. Go Runtime Analysis
8. Strings
9. Functions
10. Goroutines
11. Network Artifacts
12. Credential Artifacts
13. Crypto Artifacts
14. Persistence Artifacts
15. IOCs
16. Correlations
17. Findings
18. Errors / Warnings
19. Methodology
20. Limitations
21. Evidence Traceability

### HTML-escaping (XSS safety)

Every evidence-derived value passes through `_e()` (`html.escape`) before
insertion - process names, string values, error messages, artifact
values are all treated as untrusted text, never as pre-sanitized HTML.
`tests/unit/test_reporting_renderers.py::TestHtmlEscaping` injects
`<script>`/`<img onerror=...>` payloads as a process name and a string
value and asserts the raw tag never appears unescaped in the rendered
document.

### Redaction and secret safety (stage 30)

Every table that can hold sensitive material - Credentials, Crypto,
Persistence, IOCs - renders `redacted_value`, never `raw_value`, and
never reconstructs a raw value from a redacted/normalized one
(`_render_credentials`, `_render_crypto`, `_render_persistence`,
`_render_iocs` in `html_renderer.py`). The one documented exception to
"redacted_value only" is IOCs whose `ioc_category == "network"`: those
never had a `redacted_value` field to begin with (network data was never
classified as sensitive by any Phase 6A-6E analyzer - `NetworkArtifact`
has no `redacted_value` field at all), so `_render_iocs` falls back to
`normalized_value` for that category only - traced against the actual
Phase 6A-6E analyzer code before being accepted as safe.

**The Strings section is a deliberate, documented exception to "show only
redacted values".** `StringArtifact` (Phase 3) predates the Phase 6B
redaction convention and has no `redacted_value` field. Rather than
retrofitting a blanket redaction onto every recovered string - which
would make the Strings section useless for examining ordinary, benign
recovered content such as Go package paths - strings are shown **in
full**, truncated only for HTML display-length bounds
(`MAX_STRING_DISPLAY_LENGTH_HTML`), never for secrecy. Any string whose
*content* is secret-shaped is already separately recognized and redacted
at the credential/crypto/persistence layers; that redacted copy is what
appears in those dedicated tables. This means a raw fake-secret value
used only as a persistence/registry-path marker can legitimately still
appear once, in full, in the Strings section - confirmed against the real
fixture in
`tests/integration/test_reporting_fixture.py::test_html_render_uses_redacted_values_in_sensitive_artifact_tables`,
which checks the *sensitive-artifact tables* use `redacted_value`, not
that the string never appears anywhere in the document. A genuinely
secret-shaped credential value is separately confirmed to never leak
anywhere in the HTML in
`test_synthetic_true_secret_never_leaks_in_fixture_report` and in
`tests/unit/test_reporting_renderers.py::TestSecretLeakPrevention`.

### Wording discipline (stages 15-18, 26)

Each artifact-category section carries a fixed disclaimer restating the
same evidence-not-behavior boundary established by the underlying
analyzer phase:

- **Network** (`_render_network`): "observed/recovered/classified values
  only - never a claim of contact, connection, or C2 activity."
- **Credentials** (`_render_credentials`): "never a claim that a
  credential was used, transmitted, or stolen."
- **Crypto** (`_render_crypto`): "never a claim that encryption,
  decryption, signing, or a key exchange/TLS session actually occurred."
- **Persistence** (`_render_persistence`): "this project has no
  structured OS-level registry/service/Task-Scheduler/systemd validation
  ... never a claim that persistence was actually established."
- **Correlations** (`_render_correlations`): a relationship restates an
  already-recorded evidence field as an explicit edge (e.g. "artifacts
  share the same source string evidence"), never a behavioral claim such
  as "the process used the credential to contact the endpoint".
- **Findings** (`_render_findings`): "Severity describes forensic/
  reporting importance only ... never a malware probability, threat
  score, or maliciousness score. There is no overall per-process or
  per-case severity/risk score."

`tests/unit/test_reporting_renderers.py::TestNoForbiddenWording` and the
real-fixture chain (via `test_no_prohibited_inference_language_anywhere`
upstream in Phase 6F, whose output text is what this layer renders
verbatim) both guard this.

### Bounds and truncation (stage 33/44)

`MAX_TABLE_ROWS_HTML = 2000`: any HTML table with more rows is truncated
to that many, with an explicit `<p class="truncation-notice">Showing N of
M entries ...the complete, untruncated set is in the JSON report.</p>`
notice - truncation is always disclosed, never silent, and never affects
the JSON report. Confirmed against the real fixture, whose Functions
table (2,193 rows) legitimately triggers this path
(`tests/integration/test_reporting_fixture.py::test_html_render_succeeds_and_is_self_contained`).
`MAX_STRING_DISPLAY_LENGTH_HTML = 500`: long string/artifact values are
truncated for display with a `[+N more chars, see JSON]` notice; the full
value remains in the JSON report.

## Report versioning and integrity (stage 32)

`REPORT_SCHEMA_VERSION = "6G.1"` is recorded in every report's
`report_metadata.report_schema_version`, separate from
`report_metadata.tool_version` (the GoMemForensics package version) and
separate again from `evidence.sha256` (the evidence file's own hash).
**These three are never confused**: `report_schema_version` describes the
shape of the report JSON, `tool_version` describes which GoMemForensics
build produced it, and `evidence.sha256` is the cryptographic identity of
the original memory image - none of them is a hash of the report itself.
No report-content hash is computed or stored; this is a **deliberate
non-feature** for this phase, not an oversight - a report hash would
invite confusing "report integrity" with "evidence integrity", and no
requirement in this phase calls for verifying a report file against a
recorded hash. `report_metadata.report_generated_at` is explicitly
distinguished (via an accompanying `note` field) from
`evidence.analysis_timestamp` - the former is when the report was
rendered, the latter is when the underlying evidence was analyzed; they
are never the same clock reading and are never conflated in either
renderer.

## Determinism (stage 31)

Given the same `AnalysisResult`/analysis JSON, both renderers produce
identical output on repeated calls - no random IDs, no unordered-set
iteration order, no hash-dependent ordering. The one intentionally
time-varying field is `report_metadata.report_generated_at`; passing an
explicit `report_timestamp=` to `from_analysis_dict` pins even that,
which is how the determinism tests
(`tests/unit/test_reporting_renderers.py::*::test_determinism_across_multiple_renders`,
`tests/integration/test_reporting_fixture.py::test_report_determinism_across_repeated_renders`)
assert byte-for-byte identical output.

## Methodology statements

`METHODOLOGY_STATEMENTS` (`reporting/models.py`) is a fixed 9-sentence
tuple covering: external acquisition, read-only evidence, SHA-256
identity, Volatility 3 OS/process context, version/layout-aware Go
runtime analysis, analyzers consuming already-recovered evidence only
(never an independent re-scan), evidence-derived IOC extraction, findings
as evidence assessments separating observed evidence from interpretation,
and the explicit statement that no automatic malware verdict is produced
at any stage. This is a concise restatement of the pipeline, not a
duplicate of `docs/forensic-methodology/methodology.md`.

## CLI (stage 34)

```
gomemforensics report <analysis.json> [--output PATH] [--format json|html]
```

- `--format` defaults to `html`; only `json`/`html` are accepted
  (`click.Choice`) - `pdf` is rejected by Click before this command's own
  code runs.
- Default output: `reports/report.<format>` (never inside the evidence
  file's own directory, consistent with `analyze`'s own default).
- Reads and `json.loads()`s the supplied file only - **never** re-runs
  evidence validation, Volatility, or any analyzer
  (`tests/unit/test_cli.py::test_cli_report_never_reruns_analysis`
  confirms no "Validating evidence"/"Volatility" output appears).
- Fails safely and distinctly for each error mode (stage 33): an
  unreadable file, malformed JSON, or a `ReportGenerationError` (missing
  required top-level key) all exit `EXIT_REPORT_ERROR = 4` with a clear
  message on stderr; a missing file argument is rejected by Click itself
  (`exists=True`) before this code runs, exit code `2`.
- Never fabricates placeholder evidence - if a required key is missing,
  the command reports the error and exits; it does not attempt to render
  a partial report with invented data.

## PDF: deferred (stage 8)

No PDF report is implemented in Phase 6G. `reportlab`, `weasyprint`,
`fpdf`, and `markdown` were confirmed **not installed** in this project's
virtual environment before this decision was made (see "Architecture
search" above) - this is a documented, deliberate deferral per CLAUDE.md
section 9 ("Never claim a format is supported without testing it") and
the Phase 6G brief's explicit instruction not to invent a PDF dependency
requirement. JSON and HTML together already satisfy the phase's minimum
report-type requirement. PDF generation is **not** a prerequisite for any
core analysis capability and its absence blocks nothing else in the
pipeline.

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATED = FALSE`** - unchanged, Phase 0's boundary
remains in force. Rendering a report from a fixture-derived or synthetic
analysis JSON never changes this constant; every report's Validation
Status section states it explicitly and prominently (with a `.notice
critical` style when `False`). Validation performed for this layer:

- UNIT: `tests/unit/test_reporting_models.py` (`ReportModel` construction,
  executive summary, process summaries, limitations, evidence
  traceability, malformed-input handling), `tests/unit/test_reporting_renderers.py`
  (JSON/HTML field completeness, determinism, self-containment,
  HTML-escaping, secret-leak prevention, truncation bounds, forbidden
  wording), and `tests/unit/test_cli.py` additions for the `report`
  command (success, malformed JSON, missing required keys, missing file,
  unsupported format, never-reruns-analysis).
- COMPILED_BINARY_VALIDATED: `tests/integration/test_reporting_fixture.py`
  runs the full Phase 2-6F chain against the real compiled Go 1.26.2
  fixture binary, assembles a genuine `AnalysisResult`, and confirms the
  report correctly represents the fixture's verified real counts (1,976
  strings, 6 IOCs, 6 correlations, 6 findings), that HTML rendering is
  self-contained and does not leak a genuinely secret-shaped synthetic
  value, and that both renderers are deterministic across repeated
  renders of the same data.

## Limitations

- No PDF report (see "PDF: deferred" above).
- No report-content hash/signature - deliberately not implemented (see
  "Report versioning and integrity" above).
- The HTML report is a static document with no client-side filtering/
  search beyond the browser's own in-page find - no JavaScript is used,
  by design (self-containment requirement).
- Large tables (over `MAX_TABLE_ROWS_HTML` rows) are truncated for HTML
  display only; the JSON report is always complete.
- No real-memory validation - see above.
