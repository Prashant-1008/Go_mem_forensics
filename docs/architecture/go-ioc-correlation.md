# IOC Extraction & Cross-Artifact Correlation (Phase 6E)

**Status: Phase 6E - IOC Extraction and Cross-Artifact Correlation.
Evidence-derived, deterministic, offline, non-reputational. Never a
malware verdict (CLAUDE.md section 20).**

## What this phase is, and is not

Phase 6E transforms already-recovered Phase 6A-6D artifacts into:

1. normalized `IOCArtifact` records
2. deterministic evidence relationships (`CorrelationRecord`)
3. a bounded, explainable correlation summary

Think: `artifact -> evidence -> normalized IOC -> relationship`. **Never**
`artifact -> malware verdict`. This module implements **zero new
detection** - `gomemforensics.analyzers.correlation` never reads a
`StringArtifact` directly, never touches a `MemoryReader`, and never
performs a DNS/WHOIS/reputation/network lookup of any kind (grep-verified
in the Phase 6E final report's Deep Audit Findings).

No artifact is ever described as having been actually used, contacted,
executed, downloaded, installed, authenticated, encrypted, decrypted, or
persisted unless that fact is *directly* represented by pre-existing
evidence (it never is, in this phase - see "Prohibited inference" below).

## IOC taxonomy and promotion allowlist

Only artifact types the Phase 6E task explicitly names are promoted -
every other Phase 6A-6D type remains an artifact only, never an
`UNKNOWN_IOC` catch-all:

| Category | Promoted types | Excluded (stay artifact-only) | Why excluded |
|---|---|---|---|
| Network | all 5 `NetworkArtifactType` (IPv4, IPv6, hostname, URL, host:port) | — | The task's NETWORK list matches exactly. |
| Credential | `BEARER_TOKEN`, `BASIC_AUTH`, `COOKIE`, `SESSION_TOKEN`, `JWT`, `DATABASE_CREDENTIAL`, `API_KEY`, `CLOUD_CREDENTIAL` | `ACCESS_TOKEN`, `AUTH_TOKEN`, `PASSWORD`, `USERNAME`, `USERNAME_PASSWORD`, `CLIENT_SECRET`, `AUTHORIZATION_HEADER`, `ENV_SECRET_LIKE`, `CONFIG_SECRET_LIKE` | Raw per-instance secret material, not the kind of shareable/correlatable indicator the task's closed taxonomy names. |
| Credential (private keys) | — | `PEM_PRIVATE_KEY`, `SSH_PRIVATE_KEY`, `PRIVATE_KEY_FRAGMENT` | Already reused as `CryptoArtifactType.PRIVATE_KEY` by Phase 6C - promoting both would duplicate one piece of evidence into two IOC records (CLAUDE.md section 36). |
| Crypto | all 6 `CryptoArtifactType` | — | The task's CRYPTO list matches exactly. |
| Persistence | all 16 `PersistenceArtifactType` | — | The task listed 14 mechanisms; `WINDOWS_WINLOGON` is included too for 1:1, information-preserving coverage of an already-verified Phase 6D type rather than an arbitrary omission. |

Every `IOCType` enum value's string is **identical** to the corresponding
source artifact type's own value - a genuine reuse of already-verified
taxonomy, never a parallel/invented type system.

## IOC model

`IOCArtifact` is produced **1:1** from a single source artifact - never
merged with other source artifacts at the record level, upholding the
same "never destroy distinct evidence locations" principle every prior
phase established. Records that normalize to the same real-world
indicator share a `dedup_key` (see "Deduplication" below) so they can be
grouped for reporting without any evidence being discarded.

Fields: `id`, `pid`, `process_name`, `ioc_type`, `ioc_category`,
`raw_value`, `normalized_value`, `redacted_value`, `address`, `length`,
`memory_region`, `source_artifact_id`, `source_artifact_type`,
`dedup_key`, `function_id`, `goroutine_id`,
`related_network_artifact_id`, `related_credential_artifact_id`,
`related_crypto_artifact_id`, `related_persistence_artifact_id`,
`confidence`, `validation_status`, `extraction_method`, `go_version`,
`architecture`, `provenance`, `notes`.

## Normalization

Phase 6E performs **no new normalization** - every `normalized_value`
field is copied verbatim from the already-computed Phase 6A-6D
normalization (Python's `ipaddress`/`urlsplit`-backed IPv4/IPv6/URL
normalization from Phase 6A, the PEM-label/DB-URI parsing from Phase 6B/
6C, the exact-match path/command recognition from Phase 6D). `raw_value`
is likewise copied unaltered. No DNS resolution, WHOIS, reputation
lookup, IP geolocation, or network request occurs anywhere in this phase
(CLAUDE.md sections 16/32/33) - `gomemforensics.analyzers.correlation`
has no networking import at all (grep-verified).

## Deduplication

`dedup_key` is computed deterministically per `IOCType`, using only each
type's own already-normalized fields:

| IOC type | `dedup_key` basis |
|---|---|
| IPv4/IPv6 | canonical `normalized_value["ip"]` |
| Hostname | already-lowercased `normalized_value["hostname"]` |
| URL | `scheme://hostname:port/path` from normalized fields only |
| host:port | `host:port` from normalized fields only |
| Everything else (credential/crypto/persistence) | the exact recovered `raw_value` - no invented normalization, no Windows-to-Linux path conversion, no case-folding beyond what the source analyzer already performed |

Two `IOCArtifact` records sharing a `dedup_key` are **never merged** -
each keeps its own `id`, `address`, `source_artifact_id`, and
`confidence`. `IOCExtractionStats.unique_iocs` reports the distinct
`dedup_key` count separately from `iocs_extracted` (the total record
count), so both "how much evidence" and "how many distinct indicators"
are independently inspectable in the JSON output without any provenance
loss.

A dedup group containing both `STRUCTURALLY_VALID` and
`STRUCTURALLY_INCOMPLETE` members has every member's `validation_status`
recorded as `PARTIALLY_VALID` (a fact about the *group*, applied to each
member's own record - never a merge).

## Cross-artifact correlation

`CorrelationRecord` is a closed, 13-value `CorrelationType` enum, each
value tracing directly to an already-existing field:

| Relationship | Evidence basis |
|---|---|
| `SAME_SOURCE_STRING` | Two derived artifacts share the same `source_artifact_id` |
| `STRING_TO_NETWORK`/`_CREDENTIAL`/`_CRYPTO`/`_PERSISTENCE` | A derived artifact's own `source_artifact_id` |
| `NETWORK_TO_CREDENTIAL`/`_CRYPTO`/`_PERSISTENCE` | The derived artifact's own `network_artifact_id` field (already populated by Phase 6B/6C/6D) |
| `CREDENTIAL_TO_CRYPTO`/`_PERSISTENCE` | `credential_artifact_id` |
| `CRYPTO_TO_PERSISTENCE` | `crypto_artifact_id` |
| `FUNCTION_REFERENCES_ARTIFACT` | `function_id` (Phase 4's `string_ref:<id>` call-site evidence) |
| `GOROUTINE_FRAME_REFERENCES_ARTIFACT` | `goroutine_id` (Phase 5's unwound-frame `function_id` evidence) |

Every record is a **restatement**, never a new inference - this is why
`CorrelationRecord` deliberately has no `confidence` field (see the
model's own docstring): the edge either exists as an already-recorded
field or it does not, there is no independent uncertainty to grade.
`evidence_basis` names the exact field that justified each edge, so every
record is independently auditable.

### Prohibited inference

Per stages 9-13, correlation **never** infers:

- "Function N contacted the IP" from a `FUNCTION_REFERENCES_ARTIFACT`
  edge - it means only that Phase 4's call-site evidence connects that
  function to that artifact.
- "credential was sent to URL" from a `NETWORK_TO_CREDENTIAL` edge
  (`SHARED_SOURCE_EVIDENCE` is the correct reading, not a transmission
  claim).
- TLS connection / encrypted traffic / encryption / decryption /
  certificate usage from a `NETWORK_TO_CRYPTO` edge - Phase 6C never
  implemented structured TLS state, and this phase respects that limit.
- Key usage / signing / decryption / authentication from a
  `CREDENTIAL_TO_CRYPTO` edge - a private key and credential sharing a
  source string are not automatically "used together".
- Downloaded / installed / executed persistence from any
  `*_TO_PERSISTENCE` edge.
- **Any correlation from memory proximity, same-process membership, or
  same-goroutine membership alone** - `tests/unit/test_correlation.py::TestNoProximityCorrelation`
  explicitly proves two artifacts in the same process with adjacent
  addresses and no shared evidence field produce zero edges.

## Confidence and validation semantics

`IOCArtifact.confidence` is **not** invented or averaged. Stage 14's
deterministic rule: each record keeps its own source artifact's
confidence exactly (never redefined); a `unique_iocs` dedup group's
*strongest* member confidence is what stage 14 calls "the group's
effective confidence" for reporting purposes, computed via
`_combine_confidence()` (max by rank: HIGH > MEDIUM > LOW > UNKNOWN) -
but this is a reporting-time aggregate, never written back into or
replacing any individual record's own confidence value.

`IOCValidationStatus` (`STRUCTURALLY_VALID`/`PARTIALLY_VALID`/
`STRUCTURALLY_INCOMPLETE`) describes artifact *validity*, never threat
reputation - there is no "verified malicious" state and never will be.

## Finding/verdict separation

No malware score, maliciousness flag, suspiciousness score, threat
score, or confidence-as-a-percentage exists anywhere in this phase's
models (`tests/unit/test_ioc_extraction.py::TestNoMalwareVerdict`
explicitly asserts none of `score`/`threat_score`/`malware_score`/
`suspiciousness_score`/`malicious`/`verdict` appear as JSON keys on any
`IOCArtifact`). An IOC is an observed forensic artifact. This project has
no "Finding" concept yet (CLAUDE.md's planned `detection/` package does
not exist) - Phase 6E does not create one, and does not auto-promote any
IOC into one.

## Bounds (stage 21)

- `MAX_IOCS_PER_PROCESS = 5000` (mirrors Phase 6A-6D).
- `MAX_CORRELATIONS_PER_PROCESS = 20000`.
- `MAX_SAME_SOURCE_GROUP_SIZE = 8` - `SAME_SOURCE_STRING` pairwise
  expansion within one source-string group is capped explicitly (a
  string producing more than 8 distinct derived artifacts is
  architecturally implausible today - at most 4 analyzers can each
  produce one - but the bound exists and is recorded when hit, rather
  than assumed).
- All correlation construction is O(N): one pass per artifact list,
  reading only that artifact's own already-populated fields; the only
  quadratic-shaped step (`SAME_SOURCE_STRING` pairwise expansion) is
  bounded *per source-string group*, never across the whole artifact
  population - `tests/unit/test_correlation.py::TestBoundsAndDeterminism`
  confirms deterministic, bounded output.

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATED = FALSE`** - unchanged, Phase 5.5 remains
blocked. Validation performed:

- UNIT: `tests/unit/test_ioc_extraction.py` (21 tests) and
  `tests/unit/test_correlation.py` (22 tests), plus
  `tests/unit/test_pipeline.py::TestRecoverIocs`/`TestRecoverCorrelations`.
- COMPILED_BINARY_VALIDATED: `tests/integration/test_ioc_correlation_fixture.py`
  runs the full Phase 6A-6E chain against the real compiled Go 1.26.2
  fixture binary's 1,976 real recovered strings and real recovered
  functions - all previously-injected fake persistence markers (Phase
  6D) are correctly promoted to IOCs and correlated, with a bounded,
  deterministic, non-exploding result (6 IOCs, 6 correlations from 1,976
  strings, reproduced identically across repeated runs).

## Limitations

- No structured OS/TLS/RSA/ECDSA/Ed25519 object correlation beyond what
  Phase 6A-6D already recovered.
- No cross-string relationship inference beyond the `SAME_SOURCE_STRING`/
  `*_TO_*` fields Phase 6B/6C/6D already populate.
- No Finding/verdict layer exists yet - IOCs and correlations are the
  final output of this phase.
- No real-memory validation - see above.
