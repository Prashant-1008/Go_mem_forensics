# Go Credential / Secret Artifact Analyzer (Phase 6B)

**Status: Phase 6B - Go Credential/Secret Artifact Analyzer. Extraction
only, never credential validation and never malware classification
(CLAUDE.md section 20 / Phase 6B CORE OBJECTIVE).**

## CORE OBJECTIVE, restated precisely

This analyzer's job is to **find secret-LIKE artifacts** - never to
prove that a recovered value is a valid credential, and never to prove
that the process actually used it. Every `CredentialArtifact` keeps four
things distinct and never collapses them:

1. **OBSERVED SECRET-LIKE DATA** - `raw_value` (never altered),
   `address`/`memory_region` (where it was observed).
2. **STRUCTURALLY IDENTIFIED SECRET MATERIAL** - `artifact_type` +
   `validation_status` (what shape was recognized, and how completely).
3. **ASSOCIATED CONTEXT** - `function_id`/`goroutine_id`/
   `network_artifact_id`, populated only via an explicit evidence chain -
   never address proximity.
4. **INTERPRETATION** - `confidence` and `notes`, which never assert
   validity, liveness, or actual use.

No artifact is ever contacted, authenticated, validated externally, or
sent anywhere (stages 5/7). All processing is local and offline.

## Taxonomy (Phase 6B stage 2)

| Category | Status | Notes |
|---|---|---|
| A. API keys | PARTIALLY_SUPPORTED | Small curated vendor-prefix set (AWS `AKIA`, GitHub `gh_`, Google `AIza`, Slack `xox`) + generic `api_key=`/`apikey=`/`x-api-key=` context. No provider attribution claimed beyond these four unambiguous, publicly documented shapes. |
| B. Access tokens | SUPPORTED | `access_token=` context. |
| C. Bearer tokens | SUPPORTED | `Authorization: Bearer <token>` and bare `Bearer <token>`, token68-charset validated to reject "Bearer of good news"-style prose. |
| D. Authentication tokens | SUPPORTED | `auth_token=`/`authtoken=` (MEDIUM); bare `token=` (LOW - ambiguous keyword). |
| E. Password-like values | SUPPORTED | `password=`/`passwd=`/`pwd=` context only - never the bare word "password" alone. |
| F. Username/password pairs | SUPPORTED (same-string only) | Explicit `username=X password=Y` / `user:X pass:Y` shape in a single string. Cross-string pairing via call-site argument evidence is NOT_IMPLEMENTED (see "Future work" below) - proximity alone is never used. |
| G. Client secrets | SUPPORTED | `client_secret=` context. |
| H. Session tokens | PARTIALLY_SUPPORTED | A `Cookie:`/`Set-Cookie:` name matching a session-ish keyword (`session`, `sid`, `jsessionid`, ...) - a subtype of I, not independently detected outside a cookie header. |
| I. Cookie values | SUPPORTED | Structural `Cookie:`/`Set-Cookie:` header recognition; cookie *name* preserved, full string preserved as `raw_value`, never specially exposed beyond that in summaries. |
| J. Authorization headers | SUPPORTED (Bearer/Basic); PARTIALLY_SUPPORTED (other schemes) | Any other named scheme (Digest, AWS4-HMAC-SHA256, NTLM, ...) is recognized structurally but not further decoded. |
| K. Basic-auth material | SUPPORTED | Local decode only, mirroring Go's own `net/http` `parseBasicAuth` exactly (see Source Verification Matrix) - never authenticated. |
| L. JWT-like tokens | SUPPORTED (structural only) | Three-segment base64url shape; header decoded locally to check for `alg` (confidence graduated by whether that succeeds). Signature never verified - never called "valid". |
| M. SSH private-key material | SUPPORTED | `-----BEGIN OPENSSH PRIVATE KEY-----` PEM boundary. |
| N. PEM encoded private keys | SUPPORTED | Any `-----BEGIN ... PRIVATE KEY-----`/`-----END ... PRIVATE KEY-----` matched pair. Bare `CERTIFICATE`/`PUBLIC KEY` blocks are explicitly excluded (public material, not secret-like). |
| O. Certificate/private-key pairs | NOT_IMPLEMENTED | Pairing a certificate block with a private-key block would require either same-string co-occurrence (not attempted - two full PEM blocks rarely share one Go string literal) or cross-string proximity (explicitly forbidden). |
| P. Cloud credentials | PARTIALLY_SUPPORTED | Covered via the API-key prefix set (`AKIA...`) plus `aws_access_key_id=`/`aws_secret_access_key=` context - no cloud-SDK-specific struct parsing. |
| Q. Database connection credentials | SUPPORTED | `scheme://user[:pass]@host[/db]` structural parse, restricted to a curated set of DB-shaped schemes (never `http`/`https` - that is Phase 6A's scope). |
| R. Environment-variable secrets | SUPPORTED (as `ENV_SECRET_LIKE`) | `KEY=value` context for a small set of classically-env-style names (`DATABASE_URL`, `DB_PASSWORD`, ...). **Never claims the value is actually loaded into a live environment variable** - see "Why ENV_SECRET_LIKE, never ENV_SECRET" below. |
| S. Configuration-file credentials | PARTIALLY_SUPPORTED (as `CONFIG_SECRET_LIKE`) | Same keyword-context mechanism, generalized to `=`, `:`, and JSON-quoted (`"key": "value"`) separators - inherently format-ambiguous (could be JSON, YAML, INI, or a Go source literal), so never attributed to a specific config format. |
| T. Hardcoded secret constants | UNSUPPORTED (general case); PARTIALLY_SUPPORTED (prefix set only) | An unlabeled, context-free string can only be classified via the same small vendor-prefix set as category A/P - entropy-only classification is explicitly forbidden (stage 6/21), so an arbitrary hardcoded random string with no recognizable shape is never flagged. |

No `UNKNOWN_SECRET` catch-all is implemented - a candidate that does not
match one of the above deterministic shapes is never emitted as an
artifact (same design principle as Phase 6A: no "low confidence, keep
anyway" path exists here).

### Why `ENV_SECRET_LIKE`, never `ENV_SECRET`

Stage 15 is explicit: "Do not assume the value is actually loaded into an
environment variable merely because the string looks like an environment
assignment." This project could, in principle, attempt to recover a
process's *actual* live environment block (on Linux, from the initial
process stack's env vector; on Windows, from the PEB's `Environment`
pointer) - but that is an **OS/process-loader concern, not a Go runtime
concern**, entirely outside this phase's Go-runtime-focused source
archaeology, and the existing `gomemforensics.os` layer does not expose
it today. This analyzer only ever recognizes a Go *string value* that has
an env-assignment *shape* - never a confirmed, live environment variable.
Recovering the real environment block is documented as future work, not
silently implied.

## Source archaeology (Phase 6B stage 3)

| Artifact/Structure | Go Source | Version | Fields Used | Recovery Method | Status |
|---|---|---|---|---|---|
| HTTP Basic-Auth decoding | `net/http/request.go` (`parseBasicAuth`) | go1.26.2 (local install) | N/A (algorithm, not a struct) | Local re-implementation mirroring the real algorithm exactly: strip case-insensitive `"Basic "` prefix, standard-base64-decode, split on the *first* `:` only | SOURCE-VERIFIED ALGORITHM |
| `net/url.Userinfo` | `net/url/url.go` | go1.26.2 | `username string; password string; passwordSet bool` (all unexported) | Would require heap-object type-index correlation (same mechanism Phase 6A's structured-object analysis investigated) - and the fields are unexported, inaccessible without reflection tricks this project does not use | SOURCE-VERIFIED (fields); NOT IMPLEMENTED (no addressability, unexported fields) |
| `net/http.Cookie` | `net/http/cookie.go` | go1.26.2 | `Name, Value string; ...` (exported) | Same addressability gap as Phase 6A's `net.TCPAddr` - no anchor, and the type descriptor is only present if the binary imports `net/http` via an interface conversion | SOURCE-VERIFIED (fields); NOT IMPLEMENTED - cookie recognition is string-based only (an HTTP header is transmitted as literal text, so no struct parsing is needed for that layer anyway) |
| `crypto/tls.Certificate` | `crypto/tls/common.go` | go1.26.2 | `Certificate [][]byte; PrivateKey crypto.Signer (interface)` | `PrivateKey` is an interface whose concrete type (RSA/ECDSA/Ed25519) varies and has its own unaddressed, unverified internal representation | SOURCE-VERIFIED (top-level fields only); NOT IMPLEMENTED |
| `crypto/x509.Certificate` | `crypto/x509/x509.go` | go1.26.2 | Large struct (`Raw []byte`, `PublicKey any`, `pkix.Name`, `big.Int` fields, ...) | Not source-archaeology-complete for this phase's effort budget; `PublicKey any` is itself another interface-typed field | NOT ATTEMPTED; NOT IMPLEMENTED |
| `os.Environ()` / live process environment block | `os/env.go` -> `syscall.Environ()` | go1.26.2 | N/A | Recovering the actual live environment requires OS-loader-layer work (Linux stack env vector / Windows PEB `Environment` pointer) - not a Go runtime structure at all, outside this phase's scope | NOT ATTEMPTED (OS-layer, future work); string-shape recognition only, see `ENV_SECRET_LIKE` above |
| AWS access-key-id shape (`AKIA[0-9A-Z]{16}`) | N/A - publicly documented vendor convention | N/A | N/A | Whole-string `fullmatch` | VENDOR-DOCUMENTED STRING FORMAT (not Go source) |
| GitHub token shape (`gh[oprsu]_[A-Za-z0-9]{36}`) | N/A - publicly documented vendor convention | N/A | N/A | Whole-string `fullmatch` | VENDOR-DOCUMENTED STRING FORMAT |
| Google API key shape (`AIza[0-9A-Za-z_-]{35}`) | N/A - publicly documented vendor convention | N/A | N/A | Whole-string `fullmatch` | VENDOR-DOCUMENTED STRING FORMAT |
| Slack token shape (`xox[baprs]-...`) | N/A - publicly documented vendor convention | N/A | N/A | Whole-string `fullmatch` | VENDOR-DOCUMENTED STRING FORMAT |
| Everything else (PEM boundaries, `Authorization:`/`Cookie:` header syntax, JWT three-segment shape, database URI syntax, generic `keyword=value` context) | N/A - these are text/wire-format conventions (RFC 6750, RFC 7519, RFC 6265, PEM/RFC 7468), not Go-specific at all | N/A | N/A | Regex/`urllib`/`base64`/`json` structural parsing | HEURISTIC STRING PATTERN (deterministic, documented, not Go-runtime-derived) |

**Conclusion, matching Phase 6A's**: no structured Go object (as opposed
to a text/wire-format shape) is parsed by this analyzer. Every detector
either mirrors a real, cited Go source algorithm (Basic-Auth decoding),
recognizes a publicly documented vendor string format, or recognizes a
documented text/wire-format convention (PEM, JWT, HTTP headers, DB URIs)
- never a guessed Go runtime offset.

## Redaction policy (Phase 6B stage 20)

`CredentialArtifact` carries both `raw_value` (exact, unaltered - never
destroyed, per CLAUDE.md section 4) and `redacted_value` (a separate,
deterministically-derived masked form):

- Generic values: `redact_value()` - values of 8 characters or fewer are
  fully masked (`"*" * len(value)`); longer values keep a 3-character
  prefix and suffix (`"abc...xyz"`).
- PEM private keys: never partially reveal key material at all - the
  redacted form is `"-----BEGIN <label>----- [REDACTED, N bytes]
  -----END <label>-----"`, naming only the key type and byte length.

**Policy**: the machine-readable JSON record (`AnalysisResult.to_json_dict()`)
preserves `raw_value` - this matches the project's existing evidence
policy applied uniformly to `StringArtifact.value` and
`NetworkArtifact.raw_value` throughout Phases 3-6A (CLAUDE.md section 18:
"Allow investigators to explicitly request full values when appropriate"
- the JSON report is exactly that explicit request, produced locally,
never transmitted). The CLI's human-readable progress output prints only
an artifact *count*, never a value, redacted or otherwise (see
`tests/unit/test_credential_analyzer.py::TestRedactionAndLogSafety`,
which also proves no secret value reaches Python logging output).
`redacted_value` exists specifically for any future human-readable report
renderer (HTML/PDF, not yet implemented) to use instead of `raw_value`.

## Association (stages 17/18/19)

Identical evidence-chain mechanism to Phase 6A (see
`docs/architecture/go-network-artifacts.md`'s "Function/goroutine
association" section) - `function_id`/`goroutine_id` populated only via
the existing `string_ref:<id>` call-site evidence (Phase 4.1) and
unwound-frame `function_id` fields (Phase 5), never proximity.
`network_artifact_id` (new in Phase 6B) links a credential artifact to a
Phase 6A `NetworkArtifact` only when both were produced from the
*identical source `StringArtifact`* (e.g. a database connection string
classified as both `DATABASE_CREDENTIAL` here and as a `URL`/`host_port`
by Phase 6A) - never inferred from two different strings being merely
related in content.

None of these associations is ever interpreted as proof of actual
credential use (stages 18/19's explicit prohibition) -
`tests/unit/test_credential_analyzer.py::TestGoroutineAssociation`/
`TestNetworkAssociation` assert this directly (no "used"/"authenticated"/
"contacted"/"connected" language in any artifact's `notes`).

## Deduplication (stage 23)

Identical no-merge design to Phase 6A: each `CredentialArtifact` is
produced 1:1 from a single `StringArtifact`, so two identical secret
values at different addresses are always two independent artifacts with
independent `id`s/`address`es/`source_artifact_id`s.

## Bounds (mirrors Phase 6A stage 17)

- `MAX_STRING_VALUE_LENGTH = 4096` (per-string classification skip,
  recorded in `CredentialAnalysisStats.strings_skipped_length_bound`).
- `MAX_ARTIFACTS_PER_PROCESS = 5000` (hard cap, recorded via
  `CredentialAnalysisStats.capped` plus a recoverable `AnalysisError`).
- No unbounded/backtracking-prone regex; base64/base64url/JSON decoding
  used only on already-length-bounded segments.

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire analyzer - identical
status to every other Phase 2-6A capability (Phase 5.5 remains blocked,
see `docs/validation/validation-plan.md`). Validation performed:

- UNIT: `tests/unit/test_credential_classification.py` (69 tests: every
  taxonomy category plus the full stage-21 false-positive list) and
  `tests/unit/test_credential_analyzer.py` (22 tests: provenance,
  function/goroutine/network association, dedup, bounds, redaction, and
  an explicit log-output-never-contains-the-secret test), plus
  `tests/unit/test_pipeline.py::TestRecoverCredentialArtifacts`.
- COMPILED_BINARY_VALIDATED: `tests/integration/test_credential_artifacts_fixture.py`
  runs the real classifier against ~1,976 real static strings recovered
  from the real compiled Go 1.26.2 fixture binary - the real, observed
  result is zero false positives from that real string set, with an
  injected synthetic secret-shaped string still correctly recognized
  amid that real noise.

## Future work (explicitly not attempted in Phase 6B)

- Cross-string username/password pairing via call-site argument evidence
  (two different strings referenced as different arguments of the same
  call site) - same-string pairing only is implemented today.
- Certificate/private-key pairing (category O).
- Structured Go object recovery for any of the investigated types.
- Live process environment block recovery (OS-loader layer, not Go
  runtime).
- Crypto analysis, persistence analysis, IOC correlation, malware
  scoring - all explicitly out of scope for Phase 6B and not started.
