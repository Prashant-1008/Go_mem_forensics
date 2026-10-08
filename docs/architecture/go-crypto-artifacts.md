# Go Cryptographic Artifact Analyzer (Phase 6C)

**Status: Phase 6C - Go Cryptographic Artifact Analyzer. Extraction only.
Never decryption, key validation, key cracking, or malware classification
(CLAUDE.md section 20 / Phase 6C CORE OBJECTIVE).**

## CORE OBJECTIVE, restated precisely

This analyzer identifies cryptographic artifacts - it never proves
malicious cryptographic activity, never proves a key was used, never
decrypts or cracks anything, and never validates a secret against an
external service. Every `CryptoArtifact` keeps four things distinct:

1. **OBSERVED CRYPTOGRAPHIC MATERIAL** - `raw_value`/`redacted_value`,
   `address`/`memory_region`.
2. **STRUCTURALLY IDENTIFIED CRYPTOGRAPHIC OBJECTS** - `artifact_type`/
   `algorithm`/`key_type`/`validation_status`.
3. **CRYPTOGRAPHIC CONTEXT** - `function_id`/`goroutine_id`/
   `network_artifact_id`/`credential_artifact_id`, only via an explicit
   evidence chain.
4. **INTERPRETATION** - `confidence`/`notes`, which never assert that
   encryption/decryption/authentication occurred or that a key was
   actually used. At most, when Phase 4 call-site evidence supports it,
   `notes` states `KEY_MATERIAL_PASSED_AS_ARGUMENT` - never `KEY_USED` or
   `ENCRYPTION_OCCURRED`.

No decryption, no key cracking, no external validation, no network
activity of any kind occurs anywhere in this analyzer.

## Taxonomy (Phase 6C stage 2)

| Category | Status | Notes |
|---|---|---|
| A. Symmetric keys (generic) | NOT_IMPLEMENTED (beyond B) | No verified constructor beyond AES (see B). |
| B. AES key material | PARTIALLY_SUPPORTED | Evidence-backed only: a call site targeting `crypto/aes.NewCipher` whose argument-0 resolves to a known string of length 16/24/32 (source-verified against the real `switch k { case 16, 24, 32 }` in `crypto/aes/aes.go`). Reported as `KEY_MATERIAL_PASSED_AS_ARGUMENT`, never `KEY_USED`. |
| C. ChaCha20/ChaCha20-Poly1305 key material | NOT_IMPLEMENTED | The constructor lives in `golang.org/x/crypto` (external module, not in this project's local GOROOT source tree used for verification) - not source-archaeology-complete for this phase. |
| D. HMAC key material | NOT_IMPLEMENTED | `crypto/hmac.New(h, key []byte)` has no fixed key-length requirement (unlike AES), so the length-match evidence pattern this phase relies on does not apply. |
| E. Hash/digest artifacts | NOT_IMPLEMENTED | Would require *forward* dataflow tracking of a hash function's *return value* (e.g. `sha256.Sum256`'s result), not argument recovery - Phase 4's `backward_analysis` is backward-only; adding forward/return-value tracking is new analysis infrastructure, arguably generic dataflow analysis (explicitly out of scope). A bare N-byte value is never classified as a hash by length alone (stage 9/21). |
| F. Nonces | NOT_IMPLEMENTED | See H (same reasoning - no single-call-site fixed-length evidence path was verified within this phase's effort budget). |
| G. IVs | NOT_IMPLEMENTED | `cipher.NewCBCEncrypter(b Block, iv []byte)` requires `len(iv) == b.BlockSize()`, but `b`'s block size depends on a *separate*, earlier call site (chained evidence across two call sites) - not implemented this phase; documented as a future-work opportunity following the same evidence methodology as B. |
| H. Salts | NOT_IMPLEMENTED | No verified fixed-length constructor argument identified. |
| I. Public keys | SUPPORTED (PEM boundary only) | `-----BEGIN PUBLIC KEY-----`/`RSA PUBLIC KEY`/`EC PUBLIC KEY`. Algorithm taken only from the label text itself (RSA/EC) - never inferred from unparsed DER content. |
| J. Private keys | SUPPORTED (reused from Phase 6B) | Never re-parsed - `CredentialArtifact` of type `PEM_PRIVATE_KEY`/`SSH_PRIVATE_KEY`/`PRIVATE_KEY_FRAGMENT` is reused and cross-referenced via `credential_artifact_id`. |
| K. RSA keys (structured) | NOT_IMPLEMENTED | `rsa.PublicKey{N *big.Int; E int}`/`rsa.PrivateKey` - `*big.Int` fields have no reliably addressable/parseable internal representation without heap-object type-index correlation this phase does not attempt (same conclusion as Phase 6A/6B's structured-object analysis). |
| L. ECDSA keys (structured) | NOT_IMPLEMENTED | `ecdsa.PublicKey` embeds `elliptic.Curve` (an interface) plus `*big.Int` coordinates - same conclusion as K. |
| M. Ed25519 keys (structured) | NOT_IMPLEMENTED | `ed25519.PublicKey`/`PrivateKey` are bare `[]byte` type aliases - indistinguishable from any other byte slice in memory without a type-descriptor anchor (same addressability problem as Phase 6A's `net.IP`). |
| N. X25519 keys (structured) | NOT_IMPLEMENTED | `crypto/ecdh` key types have the same interface/opaque-representation problem. |
| O. Curve25519-related material | NOT_IMPLEMENTED | Covered by M/N's conclusions; string-shaped `X25519` identifier text is recognized only as `CRYPTO_CONTEXT` (category T below), never as key material. |
| P. Certificates | SUPPORTED (PEM boundary only) | `-----BEGIN CERTIFICATE-----`. Content (subject/issuer/serial/validity) is deliberately NOT parsed - no vetted local X.509/ASN.1 parser is a project dependency (adding `cryptography` was considered and rejected as out-of-scope for this conservative phase). |
| Q. Certificate chains | PARTIALLY_SUPPORTED | Two or more complete `CERTIFICATE` PEM blocks found in the *same* string are reported as one `CERTIFICATE_CHAIN` artifact; chains spanning multiple separate strings are not linked (would require cross-string proximity, forbidden). |
| R. TLS configuration/state | NOT_IMPLEMENTED | `tls.Config`/`tls.ConnectionState` are large structs with interface-typed and slice-typed fields - same addressability conclusion as K/L. |
| S. TLS session/key material | NOT_IMPLEMENTED | No structural recovery path; bare strings like `"TLS"`/`"ClientHello"` are explicitly excluded from `CRYPTO_CONTEXT` (stage 13's explicit prohibition - too weak/ambiguous). |
| T. Cipher configuration | SUPPORTED (as `CRYPTO_CONTEXT`) | A curated, source-verified set of algorithm/cipher-suite identifier string shapes (AES-*-GCM/CBC, ChaCha20-Poly1305, RSA-*, ECDSA-P*, Ed25519, X25519, HMAC-SHA*, and the exact `TLS_*` naming convention verified against `crypto/tls/cipher_suites.go`'s own literal constant strings). Evidence that the identifier is *referenced*, never that the algorithm was used. |
| U. Hash state objects | NOT_IMPLEMENTED | `hash.Hash` is an interface; concrete implementations (`sha256.digest`, etc.) are unexported, unaddressable. |
| V. AEAD state | NOT_IMPLEMENTED | `cipher.AEAD` is an interface; same conclusion. |
| W. `crypto/cipher` objects | NOT_IMPLEMENTED | `cipher.Block`/`cipher.Stream`/`cipher.BlockMode` are all interfaces. |
| X. `crypto/tls` cryptographic structures | NOT_IMPLEMENTED | Same as R. |

No `UNKNOWN_CRYPTO_ARTIFACT` catch-all is implemented (stage 5's explicit
prohibition on classifying arbitrary high-entropy memory).

## Source archaeology (Phase 6C stage 3/4)

| Structure | Go Source | Version | Fields | Layout Verified | Address Discovery | Status |
|---|---|---|---|---|---|---|
| `crypto/aes.NewCipher` key-length check | `crypto/aes/aes.go` | go1.26.2 (local install) | N/A (algorithm: `k := len(key); switch k { case 16, 24, 32 }`) | Yes - literal source read | N/A (call-site argument evidence, not an instance scan) | SOURCE-VERIFIED ALGORITHM; PARTIALLY_SUPPORTED |
| `crypto/cipher.NewCBCEncrypter` IV-length check | `crypto/cipher/cbc.go` | go1.26.2 | `len(iv) != b.BlockSize()` | Yes - literal source read | Requires chaining evidence from a separate, earlier call site (`b`'s own constructor) - not implemented | SOURCE-VERIFIED ALGORITHM; NOT IMPLEMENTED (multi-call-site evidence chaining out of this phase's budget) |
| `crypto/rsa.PublicKey`/`PrivateKey` | `crypto/rsa/rsa.go` | go1.26.2 | `N *big.Int; E int` / embeds PublicKey, `D *big.Int`, `Primes []*big.Int` | Yes - literal source read | No - `*big.Int` internal representation has no reliable addressable layout without dedicated `math/big` archaeology this phase does not attempt | SOURCE-VERIFIED (top-level fields); NOT IMPLEMENTED |
| `crypto/ecdsa.PublicKey`/`PrivateKey` | `crypto/ecdsa/ecdsa.go` | go1.26.2 | embeds `elliptic.Curve` (interface), `X, Y *big.Int` / `D *big.Int` | Yes | No - interface + big.Int, same conclusion as RSA | SOURCE-VERIFIED (top-level fields); NOT IMPLEMENTED |
| `crypto/ed25519.PublicKey`/`PrivateKey` | `crypto/ed25519/ed25519.go` | go1.26.2 | `type PublicKey []byte`, `type PrivateKey []byte` | Yes | No - bare byte-slice type alias, no type-descriptor anchor distinguishes it from any other `[]byte` in memory | SOURCE-VERIFIED (fields); NOT IMPLEMENTED |
| `crypto/tls.Config` | `crypto/tls/common.go` | go1.26.2 | Large struct (`Rand io.Reader`, `Time func() time.Time`, many more) | Yes (top-level only) | No | SOURCE-VERIFIED (top-level fields only); NOT IMPLEMENTED |
| `crypto/tls` cipher suite name constants | `crypto/tls/cipher_suites.go` | go1.26.2 | Literal string constants, e.g. `"TLS_AES_128_GCM_SHA256"`, `"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"` | Yes - literal source read confirms the exact `TLS_[A-Z0-9_]+` naming convention | N/A (string-shape recognition) | SOURCE-VERIFIED STRING FORMAT; SUPPORTED (as `CRYPTO_CONTEXT`) |
| PEM boundary syntax (`-----BEGIN/END ...-----`) | N/A - RFC 7468 text/wire-format convention, not a Go structure | N/A | N/A | N/A (not Go source) | N/A (text boundary matching) | TEXT/WIRE-FORMAT CONVENTION; SUPPORTED for public keys/certificates (`gomemforensics.analyzers.pem`, shared with Phase 6B's private-key detector) |

**Critical distinction upheld throughout**: every "SOURCE-VERIFIED" row
above that is also marked NOT IMPLEMENTED confirms the field layout is
real and correctly cited, but that verification alone does **not** imply
the object can be located and read out of memory - stage 4's explicit
requirement. No entry in this table claims otherwise.

## Why AES key detection is the *only* structured key-material path

Per stage 6C-4's six questions, applied honestly to `crypto/aes.NewCipher`:

1. *How is an instance discovered?* Not an instance scan at all - a
   **call-site argument**, via Phase 4's already-verified backward
   analysis (`string_ref:<id>` evidence chain).
2. *How is its type established?* The call site's `target_function`
   exactly matches `"crypto/aes.NewCipher"` (Phase 4's own recovered,
   package-qualified function name).
3. *How is its address validated?* It is the address of an already-
   independently-recovered `StringArtifact` (Phase 3's own validation
   applies).
4. *How is its runtime version established?* Irrelevant here - this is a
   compile-time-stable stdlib function signature, not a runtime struct.
5. *How is the object distinguished from arbitrary bytes?* By the triple
   of (a) exact target-function-name match, (b) exact argument-position
   match (index 0), and (c) exact length match against the constructor's
   own source-verified `case 16, 24, 32`. No other candidate in this
   analyzer's scope satisfies all three simultaneously.
6. *What false-positive controls exist?* All three conditions above must
   hold simultaneously; a 32-byte string with no call-site evidence at
   all produces nothing (see `tests/unit/test_crypto_classification.py::TestFalsePositives`).

Every other candidate investigated (ChaCha20-Poly1305, HMAC, IV/nonce/
salt, hash digests) failed at least one of these six questions within
this phase's effort budget and is documented NOT_IMPLEMENTED above rather
than approximated.

## Redaction and fingerprinting (stages 19/20)

Identical policy to Phase 6B (`gomemforensics.analyzers.credentials.redact_value`) -
a separate copy in `analyzers/crypto.py` (`redact_value`) so this module
never depends on `credentials.py`'s internals: short values fully masked,
longer values keep a 3-character prefix/suffix. PEM material (public
keys, certificates) is redacted via `_redact_pem` - byte-count and label
only, never partial key-body characters.

`fingerprint_value()` computes a deterministic SHA-256 digest of a
recovered value, stdlib `hashlib` only (no new dependency) - **for
evidence correlation only**. It is explicitly not a validity check, not
a key-cracking aid, and not a malware score (stage 20's explicit
distinction between "fingerprint" and "original key" - the fingerprint
never reveals or reconstructs the original value, and is never used
anywhere in this phase to test the value against anything).

## Association (stages 14/15/16/17/18)

Identical evidence-chain mechanism to Phase 6A/6B - `function_id`/
`goroutine_id`/`network_artifact_id` via the existing `string_ref:<id>`
call-site evidence and unwound-frame `function_id` fields, never
proximity. `credential_artifact_id` links a reused private-key artifact
back to its Phase 6B origin. Crypto-package function *names* alone
(`crypto/aes`, `crypto/tls`, ...) are never emitted as a standalone
artifact or used to claim "encryption occurred" - they only ever
strengthen an already-evidence-backed artifact's association, exactly as
the AES key detector does. `tests/unit/test_crypto_analyzer.py::TestGoroutineAssociation`
explicitly asserts no artifact's `notes` ever claims a goroutine
"performed encryption".

## Bounds (stage 27)

- `MAX_STRING_VALUE_LENGTH = 4096` (per-string classification skip).
- `MAX_ARTIFACTS_PER_PROCESS = 5000` (hard cap, recorded via
  `CryptoAnalysisStats.capped` plus a recoverable `AnalysisError`).
- `MAX_PEM_BODY_LENGTH = 65536` - a PEM body longer than this is still
  fully reported (never truncated), with `normalized_value["bounded"] =
  True` recording the condition explicitly rather than silently
  measuring/storing an unbounded body length.
- No external network access anywhere in this module (grep-verified, see
  the final report's Deep Audit Findings).

## Real-memory validation boundary

**`REAL_MEMORY_VALIDATED = FALSE`** for this entire analyzer - identical
status to every other Phase 2-6B capability (Phase 5.5 remains blocked).
Validation performed:

- UNIT: `tests/unit/test_crypto_classification.py` (41 tests: PEM
  public-key/certificate/chain recognition, crypto-context identifiers,
  redaction/fingerprint determinism, and the full stage-21/28
  false-positive list - arbitrary 16/24/32/64-byte data, UUIDs, MD5/
  SHA-256/SHA-512-shaped hex, random base64/hex, IPs, timestamps, hashes
  in comments, normal URLs, Go package names, bare algorithm words) and
  `tests/unit/test_crypto_analyzer.py` (24 tests: private-key reuse from
  Phase 6B, evidence-backed AES key detection including negative controls
  for wrong length/wrong function/wrong argument index, function/
  goroutine/network/credential association, dedup, bounds, redaction,
  log-safety), plus `tests/unit/test_pipeline.py::TestRecoverCryptoArtifacts`.
- COMPILED_BINARY_VALIDATED: `tests/integration/test_crypto_artifacts_fixture.py`
  runs the real classifier against ~1,976 real static strings and real
  recovered functions from the real compiled Go 1.26.2 fixture binary -
  zero false positives observed (including zero AES-key false positives
  from the fixture's real call sites, which never call
  `crypto/aes.NewCipher`), with an injected synthetic crypto-context
  string still correctly recognized amid that real noise.

## Limitations

- No structured Go crypto object (RSA/ECDSA/Ed25519/X25519 keys, TLS
  state, hash/AEAD/cipher state) is recovered - all documented
  NOT_IMPLEMENTED above with specific, individual reasons, never a single
  blanket excuse.
- Certificate/public-key content (subject, issuer, serial, validity,
  public-key algorithm) is never parsed - PEM boundary recognition only.
- IV/nonce/salt detection is not implemented - the one candidate
  evidence path identified (`cipher.NewCBCEncrypter`'s IV) requires
  chaining evidence across two call sites, out of this phase's budget.
- ChaCha20-Poly1305/HMAC key detection is not implemented (no fixed-
  length, single-call-site evidence path verified).
- `CRYPTO_CONTEXT` string recognition proves only that an identifier
  string is *referenced somewhere* in the binary - never that the
  algorithm was actually invoked.
