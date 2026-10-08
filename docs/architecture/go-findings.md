# Findings and Evidence Assessment (Phase 6F)

**Status: Phase 6F - Findings and Evidence Assessment. A Finding is an
evidence assessment, never a malware verdict, malware score, threat
score, reputation result, or automatic attribution (CLAUDE.md section
20).**

## What a Finding is, and is not

A Finding summarizes already-recovered Phase 6E evidence (IOCs and
correlation records) into a structured, evidence-first record. It is
**not**:

- a malware verdict
- a malware/threat/risk/maliciousness score
- a reputation result
- an automatic attribution
- a statement that an artifact was actually used
- a statement that network communication occurred
- a statement that persistence was established
- a statement that credentials were stolen

`gomemforensics.analyzers.findings` implements **zero new detection and
no independent memory scan** - it never imports `MemoryReader`, never
reads a `StringArtifact` directly, and consumes only
`IOCArtifact`/`CorrelationRecord` objects Phase 6E already produced. If a
required artifact/IOC/correlation does not already exist, no Finding is
generated for it - this module never re-scans memory to manufacture one
(stage 24).

## Architecture search (stage 3)

Before implementing, the repository was searched for `Finding`,
`verdict`, `score`, `severity`, `assessment`, `detection` (case-
insensitive). No `Finding`/`Severity`/`Verdict` class existed anywhere;
the only prior "severity" mention was a denial comment in Phase 6B's
`CredentialArtifact` docstring ("never records... a credential-severity
score"). `Confidence`, `ArtifactProvenance`, and `AnalysisError` are
already established in `gomemforensics.common.models` and are reused
here exactly as-is - `FindingValidationStatus` mirrors
`IOCValidationStatus`'s three-value pattern precisely (never a new
"MALICIOUS"/"VERIFIED_MALICIOUS" state).

## Finding taxonomy and evidence rules (stages 5/7)

Findings deliberately summarize at a **coarser grain** than the
`IOCType`/`CorrelationType` layers beneath them - that is what makes a
Finding a reporting-level summary rather than a restated IOC. Every
value below was derived by inspecting the actual Phase 6A-6E artifact
taxonomy, never invented in advance:

| FindingType | Evidence rule (exact `IOCType` values) | Severity |
|---|---|---|
| `NETWORK_IP_OBSERVED` | `IPV4`, `IPV6` | INFORMATIONAL |
| `NETWORK_HOSTNAME_OBSERVED` | `HOSTNAME` | INFORMATIONAL |
| `NETWORK_URL_OBSERVED` | `URL` | INFORMATIONAL |
| `NETWORK_ENDPOINT_OBSERVED` | `HOST_PORT` | INFORMATIONAL |
| `AUTHORIZATION_MATERIAL_OBSERVED` | `BEARER_TOKEN`, `BASIC_AUTH` | MEDIUM |
| `SESSION_MATERIAL_OBSERVED` | `COOKIE`, `SESSION_TOKEN` | MEDIUM |
| `DATABASE_CREDENTIAL_OBSERVED` | `DATABASE_CREDENTIAL` | MEDIUM |
| `TOKEN_OBSERVED` | `JWT`, `API_KEY`, `CLOUD_CREDENTIAL` | MEDIUM |
| `CRYPTO_PUBLIC_KEY_OBSERVED` | `PUBLIC_KEY` | LOW |
| `CERTIFICATE_OBSERVED` | `CERTIFICATE`, `CERTIFICATE_CHAIN` | LOW |
| `CRYPTO_CONTEXT_OBSERVED` | `CRYPTO_CONTEXT` | LOW |
| `CRYPTO_PRIVATE_KEY_OBSERVED` | `PRIVATE_KEY` | HIGH |
| `AES_KEY_OBSERVED` | `AES_KEY` | HIGH |
| `WINDOWS_PERSISTENCE_REFERENCE` | any of the 8 `WINDOWS_*` persistence types | MEDIUM |
| `LINUX_PERSISTENCE_REFERENCE` | any of the 8 `LINUX_*` persistence types | MEDIUM |
| `MULTI_ARTIFACT_EVIDENCE` | a `CorrelationRecord` of type `NETWORK_TO_CREDENTIAL`/`NETWORK_TO_CRYPTO`/`NETWORK_TO_PERSISTENCE`/`CREDENTIAL_TO_CRYPTO`/`CREDENTIAL_TO_PERSISTENCE`/`CRYPTO_TO_PERSISTENCE`, **both endpoints already promoted to IOC status** | MEDIUM |
| `SHARED_SOURCE_EVIDENCE` | a `CorrelationRecord` of type `SAME_SOURCE_STRING`, both endpoints already promoted | MEDIUM |

No `UNKNOWN_FINDING` catch-all - an IOC or correlation record not listed
above simply produces no finding. Every rule table is a fixed Python
dict, directly inspectable in `gomemforensics/analyzers/findings.py`.

## Observation vs. interpretation (stage 6)

Every Finding keeps `observed_evidence` and `interpretation` as two
separate string fields - never collapsed into one sentence that could be
misread as a behavioral claim. Example (`WINDOWS_PERSISTENCE_REFERENCE`):

```
observed_evidence:
  "A string matching a Windows persistence-related registry path,
   startup path, service/scheduled-task/WMI reference, AppInit, or
   IFEO pattern was recovered."

interpretation:
  "Persistence-related configuration reference observed in process
   memory. This is not proof that the registry key/service/task exists
   on the operating system or that persistence was established."
```

Every finding type's exact wording is a fixed table
(`_WORDING` in `findings.py`) - never generated or templated from
untrusted input, and never uses prohibited phrasing (see below).

## Prohibited inference (stages 8-11, 22)

None of the following phrases exist anywhere in this module's output,
and are explicitly tested against
(`tests/integration/test_findings_fixture.py::test_no_prohibited_inference_language_anywhere`):
"the malware...", "the attacker...", "is malicious", "confirmed C2",
"confirmed malware", "credential theft", "credentials were stolen",
"data exfiltrat...", "key usage confirmed", "C2 established",
"persistence established" (as a positive claim - the wording tables'
own *denials* of this phrase are, correctly, still present in
`interpretation` text, e.g. "this is not proof that... persistence was
established").

Specifically:

- **Persistence findings** (stage 8): Phase 6D confirmed no structured
  registry/SCM/Task-Scheduler recovery exists - `WINDOWS_PERSISTENCE_REFERENCE`/
  `LINUX_PERSISTENCE_REFERENCE` are the *only* persistence finding types;
  there is no `PERSISTENCE_ESTABLISHED` type and there will not be one
  until structured OS evidence exists.
- **Credential findings** (stage 9): only "material recovered" types
  exist (`AUTHORIZATION_MATERIAL_OBSERVED`/`SESSION_MATERIAL_OBSERVED`/
  `DATABASE_CREDENTIAL_OBSERVED`/`TOKEN_OBSERVED`) - there is no
  `CREDENTIAL_THEFT`/`CREDENTIAL_EXFILTRATION`/`AUTHENTICATION_SUCCESS`
  type.
- **Network findings** (stage 10): only "observed" types exist - there
  is no `C2_ESTABLISHED`/`CONNECTION_ESTABLISHED`/`BEACONING`/
  `DATA_EXFILTRATION` type, and an IP+port pair is never automatically
  labeled "C2 endpoint".
- **Crypto findings** (stage 11): only "observed" types exist - there is
  no `ENCRYPTION_PERFORMED`/`KEY_EXCHANGE_PERFORMED`/`TLS_SESSION_ESTABLISHED`
  type.

## Function/goroutine context (stage 13)

A Finding's `function_ids`/`goroutine_ids` are populated only from the
supporting IOCs' own already-populated `function_id`/`goroutine_id`
fields (Phase 4/5 evidence chains) - never turned into a behavioral
claim. Correct: "The network artifact is associated with recovered
function X." Never written: "Function X contacted the endpoint."
(`tests/unit/test_findings.py::TestFunctionGoroutineContext` asserts
this directly.)

## Confidence and validation (stage 14/15)

`Finding.confidence` reuses the existing `Confidence` enum exactly - no
numeric probability. When a Finding aggregates multiple supporting IOCs
(a dedup group, or a correlation's two endpoints), confidence is the
**highest-ranked** contributing value (HIGH > MEDIUM > LOW > UNKNOWN),
never averaged - identical rule to Phase 6E's own `_combine_confidence`,
kept as a separate per-module copy. `FindingValidationStatus` mirrors
`IOCValidationStatus`'s evidence-oriented three states exactly
(`STRUCTURALLY_VALID`/`PARTIALLY_VALID`/`STRUCTURALLY_INCOMPLETE`) - no
"verified malicious" state exists or will exist.

## Severity semantics (stage 16)

**Severity is forensic/reporting importance, never a maliciousness
probability.** Each `FindingType` maps to a *fixed*, documented severity
in `_SEVERITY_TABLE` (see the taxonomy table above) - never computed from
"this looks like malware", never aggregated into an overall per-process
score. A private-key/AES-key finding (HIGH) is more sensitive material
to flag for investigator attention than an IP address (INFORMATIONAL) -
that is a statement about evidentiary sensitivity, not a statement that
the process holding it is malicious. `tests/unit/test_findings.py::TestSeverity::test_severity_is_not_a_maliciousness_score`
asserts the enum has exactly the four documented values and none named
after probability/maliciousness.

## Deduplication (stage 18)

One Finding per `(finding_type, dedup_key)` group for IOC-based findings
- **reusing** Phase 6E's own `IOCArtifact.dedup_key` rather than
inventing a second grouping mechanism. All contributing IOC/artifact ids
are preserved in `supporting_ioc_ids`/`supporting_artifact_ids` - no
evidence is discarded by grouping. Critically, two IOCs mapping to the
*same* `FindingType` but *different* `dedup_key`s (e.g. two distinct
Windows persistence paths) remain **separate** Findings - confirmed by
the real-fixture integration test, which observes 3 distinct
`WINDOWS_PERSISTENCE_REFERENCE` findings (not 1) from 3 distinct
evidence values sharing that finding type.

## Provenance (stage 19)

Every `Finding.provenance` (`ArtifactProvenance`) records `analyzer`,
`analyzer_version`, `extraction_method`, `confidence`, `pid`, and
`related_artifacts` (the full set of supporting artifact/IOC ids). Case
ID and evidence SHA-256 are **not** duplicated per-Finding - consistent
with every other Phase 3-6E artifact type (`ArtifactProvenance.case_id`
is never populated at this per-process analyzer layer anywhere in the
project; case ID and evidence SHA-256 are recorded once at the top-level
`AnalysisResult.evidence`/`.case` objects). An examiner traces
`Finding -> supporting IOC -> supporting artifact -> source address ->
process -> Go runtime -> evidence SHA-256` by following ids across the
single JSON report, never by re-deriving or duplicating the hash on
every record.

## Pipeline/JSON (stage 20)

`findings` added to `AnalysisResult`/JSON output; `strings`/`functions`/
`goroutines`/`network_artifacts`/`credential_artifacts`/`crypto_artifacts`/
`persistence_artifacts`/`iocs`/`correlations` all unchanged. New
statistics: `findings_generated`, `findings_by_type` (as
`findings_<type>` keys, mirroring the `iocs_by_type`/
`correlation_relationships_by_type` convention).

## CLI (stage 21)

The CLI prints only `Findings generated: N` plus a type-count summary
(names and counts only) - never a raw secret value, matching every prior
phase's default-output redaction discipline. No private key, bearer
token, cookie, password, or raw secret material is ever printed by
default.

## Bounds (mirrors Phase 6A-6E)

`MAX_FINDINGS_PER_PROCESS = 5000` - cap recorded via `FindingStats.capped`
plus a recoverable `AnalysisError`, never silent.

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATED = FALSE`** - unchanged, Phase 5.5 remains
blocked. Validation performed:

- UNIT: `tests/unit/test_findings.py` (45 tests: every evidence rule,
  deduplication, confidence/validation propagation, severity, correlation
  findings, function/goroutine context, all prohibited-inference checks,
  bounds, provenance), plus
  `tests/unit/test_pipeline.py::TestRecoverFindings`.
- COMPILED_BINARY_VALIDATED: `tests/integration/test_findings_fixture.py`
  runs the full Phase 2-6F chain against the real compiled Go 1.26.2
  fixture binary - 6 findings generated from 6 IOCs/6 correlations
  derived from 1,976 real recovered strings, deterministic across
  repeated runs, zero prohibited-inference phrases found anywhere in the
  generated text, zero score/verdict fields on any record.

## Limitations

- No ML classification, no opaque heuristics - every rule is a fixed,
  inspectable Python dict.
- No structured OS/TLS/RSA/ECDSA/Ed25519 finding types beyond what
  Phase 6A-6D already recovered.
- Correlation-based findings require *both* linked artifacts to already
  be IOC-eligible; a correlation edge touching a non-promoted artifact
  (e.g. a raw `PASSWORD` credential) produces no finding, though the
  underlying `CorrelationRecord` remains available in the JSON output.
- No real-memory validation - see above.
