"""Phase 6C — Go cryptographic artifact analyzer.

Identifies observable cryptographic artifacts already present in Go
runtime evidence recovered by earlier phases. Like Phase 6A/6B, this is
artifact *extraction*, never malware classification (CLAUDE.md section
20). Specific to this phase's CORE OBJECTIVE: no artifact is ever
presented as proof that encryption/decryption/authentication occurred, or
that a key was actually used - at most, when Phase 4 call-site evidence
supports it, that key-shaped material was passed as an argument to a
named crypto constructor (``KEY_MATERIAL_PASSED_AS_ARGUMENT``, never
``KEY_USED`` or ``ENCRYPTION_OCCURRED``).

Source grounding (Phase 6C stage 3/4 - full table in
``docs/architecture/go-crypto-artifacts.md``): this module implements
**no structured Go crypto object parsing at all**. Every candidate
structure investigated (``crypto/rsa.PrivateKey``/``PublicKey``,
``crypto/ecdsa.PrivateKey``/``PublicKey``, ``crypto/ed25519.PrivateKey``/
``PublicKey``, ``crypto/tls.Config``/``ConnectionState``) was confirmed,
against the local go1.26.2 install, to be either interface-typed,
``*big.Int``-backed, or a bare ``[]byte`` type alias with no anchor for
instance discovery - the same addressability problem Phase 6A/6B already
established for ``netip.Addr``/``net.IP``/``net/url.Userinfo``. Two
detectors ARE implemented, each with a distinct, honest grounding:

- PEM public-key/certificate boundary recognition - a text/wire-format
  convention (RFC 7468), not a Go structure at all, sharing
  :mod:`gomemforensics.analyzers.pem`'s boundary detector with Phase 6B's
  private-key recognition (never a duplicate parser).
- AES key-material recognition via Phase 4 call-site argument evidence -
  grounded directly in ``crypto/aes.NewCipher``'s own real source
  (``crypto/aes/aes.go``: ``switch k { case 16, 24, 32 }``), never a
  bare "16/24/32 bytes looks key-shaped" guess (stage 8's explicit
  exception: known function + known argument position + known,
  source-verified length requirement).
- CRYPTO_CONTEXT string recognition - a small, curated set of algorithm/
  cipher-suite identifier shapes, including the exact ``TLS_*`` naming
  convention verified against ``crypto/tls/cipher_suites.go``'s own
  literal constant name strings.

Private-key material is never re-parsed here: Phase 6B already recognizes
it (``CredentialArtifact`` of type ``PEM_PRIVATE_KEY``/
``SSH_PRIVATE_KEY``/``PRIVATE_KEY_FRAGMENT``) - this module *reuses* that
evidence (stage 7/18), producing a linked ``CryptoArtifact`` that
cross-references the originating ``CredentialArtifact`` rather than
re-scanning the same string.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from itertools import count

from gomemforensics.analyzers.models import (
    CredentialArtifact,
    CredentialArtifactType,
    CryptoArtifact,
    CryptoArtifactType,
    CryptoValidationStatus,
    NetworkArtifact,
)
from gomemforensics.analyzers.pem import find_all_pem_blocks
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence
from gomemforensics.go_runtime.models import FunctionArtifact, GoroutineArtifact, StringArtifact

ANALYZER_VERSION = "analyzers.crypto/1"

#: Safety bounds (mirrors analyzers/network.py and analyzers/credentials.py
#: exactly - not Go runtime invariants).
MAX_STRING_VALUE_LENGTH = 4096
MAX_ARTIFACTS_PER_PROCESS = 5000
#: Applies to PEM body length specifically (stage 27's MAX_PEM_SIZE /
#: MAX_CERTIFICATE_SIZE) - a PEM block whose body exceeds this is still
#: reported (never silently truncated), but flagged via
#: ``normalized_value["bounded"]`` rather than measured further.
MAX_PEM_BODY_LENGTH = 65536

_CAT = CryptoArtifactType


@dataclass(frozen=True)
class _Classification:
    artifact_type: CryptoArtifactType
    algorithm: str | None
    key_type: str | None
    normalized: dict
    confidence: Confidence
    validation_status: CryptoValidationStatus
    notes: str | None = None


# ---------------------------------------------------------------------------
# PEM public-key / certificate detection (stages 11/12)
# ---------------------------------------------------------------------------

_PUBLIC_KEY_LABELS = frozenset({"PUBLIC KEY", "RSA PUBLIC KEY", "EC PUBLIC KEY"})
_CERTIFICATE_LABEL = "CERTIFICATE"


def _algorithm_from_pem_label(label: str) -> str | None:
    """The PEM boundary label itself is the only algorithm evidence this
    analyzer trusts - a generic ``PUBLIC KEY``/``PRIVATE KEY`` (PKCS#8/
    SPKI) boundary does not self-declare an algorithm (it is embedded in
    the DER body, which this analyzer does not parse - stage 12: "Only
    extract metadata if local parsing is safe and deterministic", and no
    vetted local ASN.1/X.509 parser is available in this project's
    dependencies), so ``None`` is returned rather than guessed."""
    if label.startswith("RSA "):
        return "RSA"
    if label.startswith("EC "):
        return "EC"
    return None


def _classify_pem_public_material(value: str) -> _Classification | None:
    blocks = find_all_pem_blocks(value)
    if not blocks:
        return None

    certificate_blocks = [b for b in blocks if b.label == _CERTIFICATE_LABEL]
    if len(certificate_blocks) >= 2 and all(b.complete for b in certificate_blocks):
        return _Classification(
            _CAT.CERTIFICATE_CHAIN,
            None,
            "certificate_chain",
            {"count": len(certificate_blocks), "complete": True},
            Confidence.HIGH,
            CryptoValidationStatus.STRUCTURALLY_VALID,
            None,
        )

    first = blocks[0]
    if first.label == _CERTIFICATE_LABEL:
        if not first.complete:
            return _Classification(
                _CAT.CERTIFICATE,
                None,
                "certificate",
                {"complete": False},
                Confidence.LOW,
                CryptoValidationStatus.STRUCTURALLY_INCOMPLETE,
                "PEM CERTIFICATE boundary found without a matching END boundary in this string.",
            )
        bounded = first.body_length > MAX_PEM_BODY_LENGTH
        return _Classification(
            _CAT.CERTIFICATE,
            None,
            "certificate",
            {"complete": True, "body_length": first.body_length, "bounded": bounded},
            Confidence.HIGH,
            CryptoValidationStatus.STRUCTURALLY_VALID,
            # Deliberately no subject/issuer/serial/validity extraction -
            # no vetted local X.509/ASN.1 parser is a project dependency
            # (stage 12); this is boundary recognition only.
            "PEM boundary recognized only - no certificate content (subject/issuer/validity) was parsed.",
        )

    if first.label in _PUBLIC_KEY_LABELS:
        algorithm = _algorithm_from_pem_label(first.label)
        if not first.complete:
            return _Classification(
                _CAT.PUBLIC_KEY,
                algorithm,
                "public",
                {"label": first.label, "complete": False},
                Confidence.LOW,
                CryptoValidationStatus.STRUCTURALLY_INCOMPLETE,
                f"PEM BEGIN boundary ({first.label}) found without a matching END boundary in this string.",
            )
        bounded = first.body_length > MAX_PEM_BODY_LENGTH
        return _Classification(
            _CAT.PUBLIC_KEY,
            algorithm,
            "public",
            {"label": first.label, "complete": True, "body_length": first.body_length, "bounded": bounded},
            Confidence.HIGH,
            CryptoValidationStatus.STRUCTURALLY_VALID,
            None,
        )

    return None  # e.g. a PRIVATE KEY block - handled via CredentialArtifact reuse, not here


# ---------------------------------------------------------------------------
# CRYPTO_CONTEXT: curated algorithm/cipher-suite identifier shapes
# ---------------------------------------------------------------------------

#: Each pattern is a *specific, documented* algorithm/cipher-suite name
#: shape - never a bare word like "AES" or "hash" alone (stage 21: no
#: false-positive flood from generic crypto vocabulary). The TLS_*
#: alternative is verified against the literal constant name strings in
#: the local go1.26.2 crypto/tls/cipher_suites.go.
_CRYPTO_CONTEXT_RE = re.compile(
    r"^(?:"
    r"AES-(?:128|192|256)-(?:GCM|CBC|CTR|CFB|OFB|ECB)"
    r"|ChaCha20-Poly1305"
    r"|XChaCha20-Poly1305"
    r"|RSA-(?:1024|2048|3072|4096)"
    r"|ECDSA-P(?:224|256|384|521)"
    r"|Ed25519"
    r"|X25519"
    r"|HMAC-SHA(?:1|224|256|384|512)"
    r"|TLS_[A-Z0-9_]+"
    r")$"
)


def _classify_crypto_context(value: str) -> _Classification | None:
    if not _CRYPTO_CONTEXT_RE.match(value):
        return None
    return _Classification(
        _CAT.CRYPTO_CONTEXT,
        value,
        "context",
        {"identifier": value},
        Confidence.LOW,
        CryptoValidationStatus.STRUCTURALLY_VALID,
        "A recognized algorithm/cipher-suite identifier string - evidence that this name is referenced "
        "somewhere in the binary, not evidence that the algorithm was actually used.",
    )


def classify_crypto_string(value: str) -> _Classification | None:
    """Classify one already-recovered Go string's value for crypto
    artifacts this analyzer's string-based layer supports: PEM public
    keys/certificates, then a curated crypto-context identifier shape.
    Private-key PEM material is intentionally excluded here - see the
    module docstring (Phase 6B reuse).
    """
    if not value or len(value) > MAX_STRING_VALUE_LENGTH:
        return None
    return _classify_pem_public_material(value) or _classify_crypto_context(value)


# ---------------------------------------------------------------------------
# AES key material via Phase 4 call-site argument evidence (stage 8)
# ---------------------------------------------------------------------------

#: function full name (as recovered by Phase 4, package-qualified) ->
#: (algorithm, valid argument byte lengths, argument index). Verified
#: directly against the real go1.26.2 source (crypto/aes/aes.go:
#: `k := len(key); switch k { case 16, 24, 32 }`) - not guessed. Kept
#: deliberately tiny (one entry): this is the only stdlib constructor in
#: this analyzer's scope whose argument-length requirement is both fixed
#: and directly verifiable from the constructor's own source, independent
#: of any other call (unlike e.g. crypto/cipher.NewCBCEncrypter's IV
#: length, which depends on a separately-constructed cipher.Block's block
#: size - documented as NOT_IMPLEMENTED, see the architecture doc).
_CRYPTO_CONSTRUCTOR_ALLOWLIST: dict[str, tuple[str, tuple[int, ...], int]] = {
    "crypto/aes.NewCipher": ("AES", (16, 24, 32), 0),
}


def _find_key_material_call_sites(
    functions: list[FunctionArtifact], strings_by_id: dict[str, StringArtifact]
) -> list[tuple[FunctionArtifact, str, str, int]]:
    """Returns ``(caller_function, algorithm, string_id, arg_length)``
    tuples for every call site whose target function is a known crypto
    constructor and whose matching-position argument resolved to a known
    string reference of the exact required length - never a guess, never
    proximity (stage 15)."""
    results = []
    for func in functions:
        for call_site in func.recovered_call_sites:
            target = call_site.target_function
            if target not in _CRYPTO_CONSTRUCTOR_ALLOWLIST:
                continue
            algorithm, valid_lengths, arg_index = _CRYPTO_CONSTRUCTOR_ALLOWLIST[target]
            for argument in call_site.recovered_arguments:
                if argument.index != arg_index:
                    continue
                if argument.type_hint != "string" or not argument.value or not argument.value.startswith("string_ref:"):
                    continue
                string_id = argument.value[len("string_ref:") :]
                source_string = strings_by_id.get(string_id)
                if source_string is None or source_string.length not in valid_lengths:
                    continue
                results.append((func, algorithm, string_id, source_string.length))
    return results


# ---------------------------------------------------------------------------
# Redaction (mirrors analyzers/credentials.py's policy exactly)
# ---------------------------------------------------------------------------


def redact_value(value: str) -> str:
    """Deterministic, generic redaction - see
    :func:`gomemforensics.analyzers.credentials.redact_value` (kept as a
    separate copy so this module never depends on credentials.py's
    internals changing underneath it)."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}...{value[-3:]}"


def _redact_pem(label: str, body_length: int) -> str:
    return f"-----BEGIN {label}----- [REDACTED, {body_length} bytes] -----END {label}-----"


def fingerprint_value(value: str) -> str:
    """Deterministic SHA-256 digest of ``value``, for evidence
    *correlation* only (stage 20) - never a validity check, never a
    cracking/brute-force aid, never a malware score. Returns the full hex
    digest; callers display a truncated prefix where a short label is
    wanted."""
    return hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()


# ---------------------------------------------------------------------------
# Association (stages 16/17/18) - explicit evidence chains only.
# ---------------------------------------------------------------------------


def _build_function_string_references(functions: list[FunctionArtifact]) -> dict[str, set[str]]:
    """Identical evidence chain to Phase 6A/6B's own copies - kept
    separate per module by design (see those modules' docstrings)."""
    refs: dict[str, set[str]] = {}
    for func in functions:
        for call_site in func.recovered_call_sites:
            for argument in call_site.recovered_arguments:
                if argument.type_hint == "string" and argument.value and argument.value.startswith("string_ref:"):
                    string_id = argument.value[len("string_ref:") :]
                    refs.setdefault(string_id, set()).add(func.id)
    return refs


def _build_goroutine_function_references(goroutines: list[GoroutineArtifact]) -> dict[str, set[str]]:
    refs: dict[str, set[str]] = {}
    for goroutine in goroutines:
        function_ids: set[str] = set()
        if goroutine.current_function_id:
            function_ids.add(goroutine.current_function_id)
        for frame in goroutine.frames:
            if frame.function_id:
                function_ids.add(frame.function_id)
        for function_id in function_ids:
            refs.setdefault(function_id, set()).add(goroutine.id)
    return refs


def _build_network_artifact_references(network_artifacts: list[NetworkArtifact]) -> dict[str, str]:
    refs: dict[str, list[str]] = {}
    for artifact in network_artifacts:
        refs.setdefault(artifact.source_artifact_id, []).append(artifact.id)
    return {string_id: min(ids) for string_id, ids in refs.items()}


_PRIVATE_KEY_CREDENTIAL_TYPES = frozenset(
    {
        CredentialArtifactType.PEM_PRIVATE_KEY,
        CredentialArtifactType.SSH_PRIVATE_KEY,
        CredentialArtifactType.PRIVATE_KEY_FRAGMENT,
    }
)


@dataclass(frozen=True)
class CryptoAnalysisStats:
    """Per-process crypto-analyzer counters (mirrors
    :class:`~gomemforensics.analyzers.network.NetworkAnalysisStats`)."""

    strings_scanned: int = 0
    credential_artifacts_reused: int = 0
    call_sites_evaluated: int = 0
    artifacts_extracted: int = 0
    strings_skipped_length_bound: int = 0
    capped: bool = False
    artifacts_by_type: dict[str, int] = field(default_factory=dict)


def extract_crypto_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
) -> tuple[list[CryptoArtifact], list[AnalysisError], CryptoAnalysisStats]:
    """Extract :class:`CryptoArtifact` records from one process's already-
    recovered evidence (never an independent memory scan, CLAUDE.md
    section 24 applies exactly as Phase 6A/6B: one malformed/unexpected
    item never aborts the rest).

    Three independent sources, each with its own grounding (see module
    docstring): (1) PEM public-key/certificate boundaries found directly
    in strings, (2) crypto-context identifier strings, (3) AES key
    material reused from Phase 4 call-site evidence, and (4) private-key
    material *reused* from Phase 6B's already-produced
    :class:`CredentialArtifact` objects, never re-parsed.
    """
    errors: list[AnalysisError] = []
    artifacts: list[CryptoArtifact] = []
    artifacts_by_type: dict[str, int] = {}
    strings_skipped_length_bound = 0
    capped = False
    id_counter = count(1)

    def _next_id() -> str:
        return f"CRYPTO-{pid}-{next(id_counter):04d}"

    def _record(
        classification: _Classification,
        source: StringArtifact | None,
        raw_value: str | None,
        redacted_value: str | None,
        function_id: str | None,
        goroutine_id: str | None,
        network_artifact_id: str | None,
        credential_artifact_id: str | None,
        extraction_method: str,
        provenance_source_id: str | None,
    ) -> None:
        artifact_id = _next_id()
        related_artifacts = []
        if provenance_source_id:
            related_artifacts.append(provenance_source_id)
        if function_id:
            related_artifacts.append(function_id)
        if goroutine_id:
            related_artifacts.append(goroutine_id)
        if network_artifact_id:
            related_artifacts.append(network_artifact_id)
        if credential_artifact_id:
            related_artifacts.append(credential_artifact_id)
        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type=f"crypto_{classification.artifact_type.value}",
            analyzer="analyzers.crypto.extract_crypto_artifacts",
            extraction_method=extraction_method,
            confidence=classification.confidence,
            pid=pid,
            virtual_address=f"0x{source.data_address:x}" if source is not None else None,
            memory_region=source.region if source is not None else None,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=related_artifacts,
        )
        artifacts.append(
            CryptoArtifact(
                id=artifact_id,
                pid=pid,
                process_name=process_name,
                artifact_type=classification.artifact_type,
                algorithm=classification.algorithm,
                key_type=classification.key_type,
                raw_value=raw_value,
                redacted_value=redacted_value,
                normalized_value=classification.normalized,
                address=source.data_address if source is not None else None,
                length=len(raw_value) if raw_value is not None else None,
                memory_region=source.region if source is not None else None,
                source_artifact_id=provenance_source_id,
                function_id=function_id,
                goroutine_id=goroutine_id,
                network_artifact_id=network_artifact_id,
                credential_artifact_id=credential_artifact_id,
                extraction_method=extraction_method,
                confidence=classification.confidence,
                validation_status=classification.validation_status,
                go_version=go_version,
                architecture=architecture,
                provenance=provenance,
                notes=classification.notes,
            )
        )
        type_key = classification.artifact_type.value
        artifacts_by_type[type_key] = artifacts_by_type.get(type_key, 0) + 1

    function_refs = _build_function_string_references(functions)
    goroutine_refs = _build_goroutine_function_references(goroutines)
    network_refs = _build_network_artifact_references(network_artifacts)
    strings_by_id = {s.id: s for s in strings if s.pid == pid}

    # --- Layer 1: PEM public-key/certificate + crypto-context strings ---
    strings_scanned = 0
    for source in strings:
        if source.pid != pid:
            continue
        strings_scanned += 1

        if len(artifacts) >= MAX_ARTIFACTS_PER_PROCESS:
            capped = True
            continue
        if len(source.value) > MAX_STRING_VALUE_LENGTH:
            strings_skipped_length_bound += 1
            continue

        try:
            classification = classify_crypto_string(source.value)
        except Exception as exc:  # one malformed/unexpected string must not abort the rest
            errors.append(
                AnalysisError(
                    component="analyzers.crypto",
                    message=f"Crypto classification failed unexpectedly for string {source.id}: {exc}",
                    pid=pid,
                )
            )
            continue
        if classification is None:
            continue

        function_ids = function_refs.get(source.id, set())
        goroutine_ids: set[str] = set()
        for function_id in function_ids:
            goroutine_ids |= goroutine_refs.get(function_id, set())

        redacted = (
            _redact_pem(classification.normalized.get("label", classification.key_type or "KEY"), classification.normalized.get("body_length", 0))
            if classification.artifact_type in (_CAT.PUBLIC_KEY, _CAT.CERTIFICATE, _CAT.CERTIFICATE_CHAIN)
            else redact_value(source.value)
        )
        _record(
            classification,
            source,
            source.value,
            redacted,
            min(function_ids) if function_ids else None,
            min(goroutine_ids) if goroutine_ids else None,
            network_refs.get(source.id),
            None,
            "go_string_crypto_classification",
            source.id,
        )

    # --- Layer 2: private-key material reused from Phase 6B ---
    credential_artifacts_reused = 0
    for credential in credential_artifacts:
        if credential.pid != pid:
            continue
        if credential.artifact_type not in _PRIVATE_KEY_CREDENTIAL_TYPES:
            continue
        if len(artifacts) >= MAX_ARTIFACTS_PER_PROCESS:
            capped = True
            continue
        credential_artifacts_reused += 1
        label = (credential.normalized_value or {}).get("label", "PRIVATE KEY")
        is_fragment = credential.artifact_type == CredentialArtifactType.PRIVATE_KEY_FRAGMENT
        classification = _Classification(
            _CAT.PRIVATE_KEY,
            "OpenSSH" if credential.artifact_type == CredentialArtifactType.SSH_PRIVATE_KEY else _algorithm_from_pem_label(label),
            "private",
            dict(credential.normalized_value or {}),
            credential.confidence,
            CryptoValidationStatus.STRUCTURALLY_INCOMPLETE if is_fragment else CryptoValidationStatus.STRUCTURALLY_VALID,
            "Reused from Phase 6B credential evidence (private-key PEM material) - not re-parsed here.",
        )
        source = strings_by_id.get(credential.source_artifact_id)
        _record(
            classification,
            source,
            credential.raw_value,
            credential.redacted_value,
            credential.function_id,
            credential.goroutine_id,
            credential.network_artifact_id,
            credential.id,
            "reused_from_phase_6b_credential_artifact",
            credential.source_artifact_id,
        )

    # --- Layer 3: AES key material via Phase 4 call-site evidence ---
    call_sites_evaluated = sum(len(f.recovered_call_sites) for f in functions)
    for func, algorithm, string_id, arg_length in _find_key_material_call_sites(functions, strings_by_id):
        if len(artifacts) >= MAX_ARTIFACTS_PER_PROCESS:
            capped = True
            break
        source = strings_by_id.get(string_id)
        if source is None:
            continue
        goroutine_ids = goroutine_refs.get(func.id, set())
        classification = _Classification(
            _CAT.AES_KEY,
            algorithm,
            "symmetric",
            {"key_length_bytes": arg_length, "constructor": "crypto/aes.NewCipher"},
            Confidence.MEDIUM,
            CryptoValidationStatus.STRUCTURALLY_VALID,
            "KEY_MATERIAL_PASSED_AS_ARGUMENT to crypto/aes.NewCipher (source-verified key-length match: "
            "16/24/32 bytes). This is evidence of a call-site argument, not proof that encryption occurred "
            "or that this value is genuinely a cryptographic key.",
        )
        _record(
            classification,
            source,
            source.value,
            redact_value(source.value),
            func.id,
            min(goroutine_ids) if goroutine_ids else None,
            network_refs.get(string_id),
            None,
            "call_site_argument_evidence",
            string_id,
        )

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.crypto",
                message=(
                    f"Crypto artifact cap ({MAX_ARTIFACTS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining evidence was not classified (bounded analysis, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    stats = CryptoAnalysisStats(
        strings_scanned=strings_scanned,
        credential_artifacts_reused=credential_artifacts_reused,
        call_sites_evaluated=call_sites_evaluated,
        artifacts_extracted=len(artifacts),
        strings_skipped_length_bound=strings_skipped_length_bound,
        capped=capped,
        artifacts_by_type=artifacts_by_type,
    )
    return artifacts, errors, stats
