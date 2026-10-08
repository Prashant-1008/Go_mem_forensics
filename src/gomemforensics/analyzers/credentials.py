"""Phase 6B — Go credential / secret artifact analyzer.

Recovers credential-like and secret-like artifacts that are already
observable in Go strings recovered by Phase 3
(:mod:`gomemforensics.go_runtime.strings`). Like Phase 6A's network
analyzer, this is artifact *extraction*, never malware classification
(CLAUDE.md section 20): no artifact produced here is ever labeled
malicious, and - specific to this phase's CORE OBJECTIVE - no artifact is
ever presented as proof that a recovered value is a *valid* credential or
that a process *used* it. Every :class:`CredentialArtifact` records only:

1. OBSERVED SECRET-LIKE DATA (``raw_value``/``address``/``memory_region``)
2. STRUCTURALLY IDENTIFIED SECRET MATERIAL (``artifact_type``/
   ``validation_status``)
3. ASSOCIATED CONTEXT (``function_id``/``goroutine_id``/
   ``network_artifact_id`` - only via an explicit evidence chain)
4. INTERPRETATION (``confidence``/``notes`` - never validity or liveness)

Source grounding (Phase 6B stage 3 - full table in
``docs/architecture/go-credential-artifacts.md``): like Phase 6A, this
module does **not** parse any Go runtime or standard-library struct.
Classifying a recovered string's *textual* shape has no Go version or
architecture dependency. Two exceptions are explicitly source-grounded
rather than invented:

- Basic-Auth decoding (:func:`_decode_basic_auth`) mirrors the real
  ``net/http`` implementation field-for-field
  (``net/http/request.go``'s unexported ``parseBasicAuth``: strip a
  case-insensitive ``"Basic "`` prefix, standard-base64-decode the rest,
  split on the *first* ``:`` only) - verified against the local go1.26.2
  install, not guessed.
- Structured Go objects that could in principle hold credential material
  (``net/url.Userinfo``, ``net/http.Cookie``, ``crypto/tls.Certificate``,
  ``crypto/x509.Certificate``) were investigated and are explicitly NOT
  implemented - see the architecture doc for why (the same addressability
  problem as Phase 6A's structured network objects, plus - for
  ``net/url.Userinfo`` specifically - genuinely unexported fields).

Provider-prefix token recognition (AWS ``AKIA``, GitHub ``gh_``, Google
``AIza``, Slack ``xox``) is grounded differently: these are **publicly
documented, stable vendor token-format conventions** (not Go source, and
not guessed) - see the architecture doc's explicit "VENDOR-DOCUMENTED
STRING FORMAT" category, kept deliberately small (stage 7: "Do not
create dozens of provider-specific patterns").
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from itertools import count

from gomemforensics.analyzers.models import (
    CredentialArtifact,
    CredentialArtifactType,
    CredentialValidationStatus,
    NetworkArtifact,
)
from gomemforensics.analyzers.pem import find_pem_block
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence
from gomemforensics.go_runtime.models import FunctionArtifact, GoroutineArtifact, StringArtifact

ANALYZER_VERSION = "analyzers.credentials/1"

#: Safety bounds (Phase 6B stage - mirrors analyzers/network.py exactly,
#: not Go runtime invariants).
MAX_STRING_VALUE_LENGTH = 4096
MAX_ARTIFACTS_PER_PROCESS = 5000

_CT = CredentialArtifactType


# ---------------------------------------------------------------------------
# Redaction (stage 20) - deterministic, never replaces raw_value.
# ---------------------------------------------------------------------------


def redact_value(value: str) -> str:
    """Deterministic, generic redaction for human-readable/log-safe display.

    Never used to replace ``raw_value`` - only to populate the separate
    ``redacted_value`` field. Short values are fully masked (a partial
    reveal of a short secret leaks too much of it); longer values keep a
    small prefix/suffix, matching common secret-scanner conventions.
    """
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}...{value[-3:]}"


def _redact_pem(label: str, body_length: int) -> str:
    return f"-----BEGIN {label}----- [REDACTED, {body_length} bytes] -----END {label}-----"


# ---------------------------------------------------------------------------
# Structural detectors
# ---------------------------------------------------------------------------

#: Only PRIVATE-KEY-shaped PEM labels are secret-like - a bare CERTIFICATE
#: or PUBLIC KEY block is public material, never classified as a
#: credential artifact by this analyzer (stage 14 scope: private keys,
#: not certificates/public keys alone - those are Phase 6C's
#: gomemforensics.analyzers.crypto scope, sharing this same boundary
#: detector via gomemforensics.analyzers.pem rather than a duplicate
#: parser).
_SSH_PEM_LABELS = frozenset({"OPENSSH PRIVATE KEY"})
_GENERIC_PRIVATE_KEY_LABELS_SUFFIX = "PRIVATE KEY"


def _classify_pem(value: str) -> "_Classification | None":
    block = find_pem_block(value)
    if block is None:
        return None
    if not block.label.endswith(_GENERIC_PRIVATE_KEY_LABELS_SUFFIX):
        return None  # e.g. a CERTIFICATE/PUBLIC KEY block - not secret-like on its own

    artifact_type = _CT.SSH_PRIVATE_KEY if block.label in _SSH_PEM_LABELS else _CT.PEM_PRIVATE_KEY

    if not block.complete:
        # Boundary found without its close - an incomplete fragment, still
        # forensically significant, never silently dropped (stage 14).
        return _Classification(
            _CT.PRIVATE_KEY_FRAGMENT,
            {"label": block.label, "complete": False},
            Confidence.LOW,
            CredentialValidationStatus.STRUCTURALLY_INCOMPLETE,
            f"PEM BEGIN boundary ({block.label}) found without a matching END boundary in this string.",
        )
    return _Classification(
        artifact_type,
        {"label": block.label, "complete": True, "body_length": block.body_length},
        Confidence.HIGH,
        CredentialValidationStatus.STRUCTURALLY_VALID,
        None,
    )


#: Database-style URI schemes - deliberately excludes http/https (Phase
#: 6A's network analyzer already owns those); only classified here when
#: userinfo (a username, optionally a password) is actually present.
_DB_SCHEMES = frozenset(
    {
        "postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis",
        "rediss", "mssql", "sqlserver", "oracle", "mariadb", "amqp", "amqps",
    }
)
_DB_URL_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://"
    r"(?P<user>[^:/@\s]+)(?::(?P<password>[^@/\s]+))?@"
    r"(?P<host>[^/\s]+)"
    r"(?:/(?P<database>\S*))?$"
)


def _classify_database_url(value: str) -> "_Classification | None":
    match = _DB_URL_RE.match(value)
    if not match:
        return None
    scheme = match.group("scheme").lower()
    if scheme not in _DB_SCHEMES:
        return None
    password = match.group("password")
    normalized = {
        "scheme": scheme,
        "username": match.group("user"),
        "has_password": password is not None,
        "host": match.group("host"),
        "database": match.group("database") or None,
    }
    confidence = Confidence.HIGH if password is not None else Confidence.MEDIUM
    return _Classification(_CT.DATABASE_CREDENTIAL, normalized, confidence, CredentialValidationStatus.STRUCTURALLY_VALID, None)


#: RFC 6750 token68-shaped charset (no whitespace) - used to reject
#: "Bearer <English prose>" false positives (stage 21 false-positive
#: control: the bare-word "Bearer"/"Basic" must be followed by an actual
#: token shape, not arbitrary text).
_TOKEN68_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")
_AUTH_HEADER_RE = re.compile(r"^Authorization\s*:\s*(?P<scheme>\S+)\s+(?P<value>.+)$", re.IGNORECASE)
_BARE_SCHEME_RE = re.compile(r"^(?P<scheme>Bearer|Basic)\s+(?P<value>.+)$")


def _decode_basic_auth(encoded: str) -> tuple[str, str] | None:
    """Mirror Go's own ``net/http`` ``parseBasicAuth`` exactly (see module
    docstring for the source citation): standard base64 decode, then split
    on the *first* ``:`` only. Returns ``None`` on any decode/shape
    failure - never forces a malformed value into a credential artifact
    (stage 9)."""
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def _classify_authorization_header(value: str) -> "_Classification | None":
    match = _AUTH_HEADER_RE.match(value) or _BARE_SCHEME_RE.match(value)
    if not match:
        return None
    scheme = match.group("scheme")
    rest = match.group("value").strip()
    if not rest:
        return None
    scheme_lower = scheme.lower()

    if scheme_lower == "bearer":
        if not _TOKEN68_RE.match(rest):
            return None  # "Bearer <English prose>" - not a token shape
        return _Classification(
            _CT.BEARER_TOKEN,
            {"scheme": "Bearer"},
            Confidence.HIGH,
            CredentialValidationStatus.STRUCTURALLY_VALID,
            None,
        )

    if scheme_lower == "basic":
        decoded = _decode_basic_auth(rest)
        if decoded is None:
            # Structurally an Authorization: Basic header, but the body
            # did not decode - report the weaker, still-accurate shape
            # rather than fabricating a username/password (stage 9).
            return _Classification(
                _CT.AUTHORIZATION_HEADER,
                {"scheme": "Basic", "decoded": False},
                Confidence.LOW,
                CredentialValidationStatus.STRUCTURALLY_VALID,
                "Authorization: Basic header observed, but the base64 payload did not decode to a username:password form.",
            )
        username, password = decoded
        return _Classification(
            _CT.BASIC_AUTH,
            {"scheme": "Basic", "decoded": True, "username": username},
            Confidence.HIGH,
            CredentialValidationStatus.STRUCTURALLY_VALID,
            None,
        )

    # Any other named scheme (Digest, AWS4-HMAC-SHA256, NTLM, Negotiate,
    # ...) - structurally an Authorization header, but this analyzer does
    # not further decode arbitrary schemes.
    return _Classification(
        _CT.AUTHORIZATION_HEADER,
        {"scheme": scheme},
        Confidence.MEDIUM,
        CredentialValidationStatus.STRUCTURALLY_VALID,
        None,
    )


_COOKIE_HEADER_RE = re.compile(r"^(?P<header>Cookie|Set-Cookie)\s*:\s*(?P<body>.+)$", re.IGNORECASE)
_SESSION_NAME_KEYWORDS = frozenset({"session", "sid", "sessionid", "jsessionid", "phpsessid", "connect.sid", "auth", "token"})


def _classify_cookie_header(value: str) -> "_Classification | None":
    match = _COOKIE_HEADER_RE.match(value)
    if not match:
        return None
    body = match.group("body")
    first_pair = body.split(";", 1)[0].strip()
    if "=" not in first_pair:
        return None
    name, _, _cookie_value = first_pair.partition("=")
    name = name.strip()
    if not name:
        return None

    is_session = any(keyword in name.lower() for keyword in _SESSION_NAME_KEYWORDS)
    artifact_type = _CT.SESSION_TOKEN if is_session else _CT.COOKIE
    return _Classification(
        artifact_type,
        {"header": match.group("header"), "cookie_name": name},
        Confidence.MEDIUM,
        CredentialValidationStatus.STRUCTURALLY_VALID,
        None,
    )


_JWT_RE = re.compile(r"^(?P<header>[A-Za-z0-9_-]{10,})\.(?P<payload>[A-Za-z0-9_-]{4,})\.(?P<signature>[A-Za-z0-9_-]{4,})$")


def _b64url_decode(segment: str) -> bytes | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return None


def _classify_jwt(value: str) -> "_Classification | None":
    match = _JWT_RE.match(value)
    if not match:
        return None
    header_raw = _b64url_decode(match.group("header"))
    header_json = None
    if header_raw is not None:
        try:
            header_json = json.loads(header_raw)
        except (ValueError, UnicodeDecodeError):
            header_json = None

    if isinstance(header_json, dict) and "alg" in header_json:
        return _Classification(
            _CT.JWT,
            {"structurally_recognized": True, "header_alg": header_json.get("alg"), "header_typ": header_json.get("typ")},
            Confidence.MEDIUM,
            CredentialValidationStatus.STRUCTURALLY_VALID,
            "JWT-LIKE: three-segment base64url structure with a decodable header containing 'alg'. "
            "Signature NOT verified - structural recognition only, never a claim of validity.",
        )
    return _Classification(
        _CT.JWT,
        {"structurally_recognized": True, "header_alg": None},
        Confidence.LOW,
        CredentialValidationStatus.STRUCTURALLY_VALID,
        "JWT-LIKE: three-segment base64url structure, but the first segment did not decode to a "
        "JSON object containing 'alg'. Weak structural match only.",
    )


#: Explicit username+password pairing observed within a single string
#: (stage 12: same-StringArtifact pairing only - cross-artifact pairing
#: via call-site evidence is documented as NOT_IMPLEMENTED, see the
#: architecture doc, rather than inferred from address proximity).
_USER_PASS_PAIR_RE = re.compile(
    r"(?i)\b(?:username|user)\s*[:=]\s*\"?(?P<username>[^\s\"&;,=]+)\"?"
    r"[\s,;&]+"
    r"(?:password|passwd|pwd|pass)\s*[:=]\s*\"?(?P<password>[^\s\"&;,=]+)\"?"
)


def _classify_username_password_pair(value: str) -> "_Classification | None":
    match = _USER_PASS_PAIR_RE.search(value)
    if not match:
        return None
    username = match.group("username")
    password = match.group("password")
    if len(username) < 2 or len(password) < 3:
        return None
    return _Classification(
        _CT.USERNAME_PASSWORD,
        {"username": username},
        Confidence.MEDIUM,
        CredentialValidationStatus.STRUCTURALLY_VALID,
        None,
    )


#: Ordered (type, confidence, keyword-alternatives) table for generic
#: "keyword <sep> value" contextual recognition (stage 6/11/15). Checked
#: in this exact order, first match wins - most specific/highest-
#: confidence keywords first, so e.g. "client_secret=" is never
#: mis-bucketed as the weaker generic "token=" pattern.
_CONTEXT_KEYWORD_TABLE: tuple[tuple[CredentialArtifactType, Confidence, tuple[str, ...]], ...] = (
    (_CT.PASSWORD, Confidence.MEDIUM, ("password", "passwd", "pwd")),
    (_CT.CLIENT_SECRET, Confidence.MEDIUM, ("client_secret",)),
    (_CT.ACCESS_TOKEN, Confidence.MEDIUM, ("access_token",)),
    (_CT.API_KEY, Confidence.MEDIUM, ("api_key", "apikey", "x-api-key")),
    (_CT.CLOUD_CREDENTIAL, Confidence.MEDIUM, ("aws_access_key_id", "aws_secret_access_key")),
    (_CT.AUTH_TOKEN, Confidence.MEDIUM, ("auth_token", "authtoken")),
    (_CT.AUTH_TOKEN, Confidence.LOW, ("token",)),
    (_CT.USERNAME, Confidence.LOW, ("username", "user")),
    (_CT.ENV_SECRET_LIKE, Confidence.MEDIUM, ("database_url", "db_password", "database_password")),
    (_CT.CONFIG_SECRET_LIKE, Confidence.LOW, ("secret_key", "secret", "private_key")),
)
_MIN_CONTEXT_VALUE_LENGTH = 3


def _build_context_keyword_regexes() -> list[tuple[CredentialArtifactType, Confidence, re.Pattern]]:
    compiled = []
    for artifact_type, confidence, keywords in _CONTEXT_KEYWORD_TABLE:
        alternatives = "|".join(re.escape(k) for k in keywords)
        # Value excludes "=" itself (rejects Go equality comparisons like
        # `password == "admin"` matching on the first "=") and common
        # trailing-context delimiters.
        pattern = re.compile(rf'(?i)"?\b(?:{alternatives})\b"?\s*[:=]\s*"?([^\s"&;,=]+)"?')
        compiled.append((artifact_type, confidence, pattern))
    return compiled


_CONTEXT_KEYWORD_REGEXES = _build_context_keyword_regexes()


def _classify_context_keyword(value: str) -> "_Classification | None":
    if "://" in value:
        # A URL's own userinfo syntax ("scheme://user:pass@host") can
        # coincidentally match the generic "user:"/"pass:" keyword
        # patterns below - URL-shaped strings are deliberately left to
        # the dedicated _classify_database_url detector (DB schemes) and
        # Phase 6A's network analyzer (http/https), never this weaker
        # generic heuristic, to avoid a misleading low-context match.
        return None
    for artifact_type, confidence, pattern in _CONTEXT_KEYWORD_REGEXES:
        match = pattern.search(value)
        if not match:
            continue
        matched_value = match.group(1)
        if len(matched_value) < _MIN_CONTEXT_VALUE_LENGTH:
            continue
        return _Classification(
            artifact_type,
            {"matched_keyword_value_length": len(matched_value)},
            confidence,
            CredentialValidationStatus.STRUCTURALLY_VALID,
            None,
        )
    return None


#: Small, deliberately curated set of publicly documented, stable
#: vendor token-format conventions (stage 7: "Do not create dozens of
#: provider-specific patterns") - see the architecture doc's
#: "VENDOR-DOCUMENTED STRING FORMAT" category. Checked as a whole-string
#: match only (a bare token, no surrounding context needed - the prefix
#: shape itself is the evidence).
_PREFIX_PATTERNS: tuple[tuple[re.Pattern, CredentialArtifactType, str], ...] = (
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), _CT.CLOUD_CREDENTIAL, "aws_access_key_id_shape"),
    (re.compile(r"^gh[oprsu]_[A-Za-z0-9]{36}$"), _CT.API_KEY, "github_token_shape"),
    (re.compile(r"^AIza[0-9A-Za-z_-]{35}$"), _CT.API_KEY, "google_api_key_shape"),
    (re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"), _CT.API_KEY, "slack_token_shape"),
)


def _classify_prefixed_token(value: str) -> "_Classification | None":
    for pattern, artifact_type, shape_name in _PREFIX_PATTERNS:
        if pattern.match(value):
            return _Classification(
                artifact_type,
                {"recognized_shape": shape_name},
                Confidence.MEDIUM,
                CredentialValidationStatus.STRUCTURALLY_VALID,
                f"Matches the publicly documented {shape_name} - shape recognition only, not confirmed live/valid.",
            )
    return None


@dataclass(frozen=True)
class _Classification:
    artifact_type: CredentialArtifactType
    normalized: dict
    confidence: Confidence
    validation_status: CredentialValidationStatus
    notes: str | None = None


def classify_credential_string(value: str) -> _Classification | None:
    """Classify one already-recovered Go string's value, or return
    ``None`` if it matches no supported secret-like shape.

    Ordering (most structurally-specific first): provider-prefix bare
    token -> PEM -> database URL -> Authorization/Cookie headers -> JWT ->
    explicit username+password pair -> generic contextual keyword match.
    A string matching none of these produces no artifact - there is no
    entropy-only fallback (stage 6/21).
    """
    if not value or len(value) > MAX_STRING_VALUE_LENGTH:
        return None
    return (
        _classify_prefixed_token(value)
        or _classify_pem(value)
        or _classify_database_url(value)
        or _classify_authorization_header(value)
        or _classify_cookie_header(value)
        or _classify_jwt(value)
        or _classify_username_password_pair(value)
        or _classify_context_keyword(value)
    )


# ---------------------------------------------------------------------------
# Association (stages 17/18/19) - explicit evidence chains only.
# ---------------------------------------------------------------------------


def _build_function_string_references(functions: list[FunctionArtifact]) -> dict[str, set[str]]:
    """Identical evidence chain to Phase 6A's
    :func:`gomemforensics.analyzers.network._build_function_string_references`
    - kept as a separate copy (not a shared import) so this analyzer never
    depends on network.py's internals changing underneath it."""
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
    """``StringArtifact.id -> NetworkArtifact.id`` for a network artifact
    that shares the *same source string* (stage 19: e.g. a database URL
    string that is itself also independently recognized as a network URL/
    host:port). Deterministic (lowest-sorted id) if more than one network
    artifact somehow shared a source id, though in practice Phase 6A
    produces at most one network artifact per source string."""
    refs: dict[str, list[str]] = {}
    for artifact in network_artifacts:
        refs.setdefault(artifact.source_artifact_id, []).append(artifact.id)
    return {string_id: min(ids) for string_id, ids in refs.items()}


@dataclass(frozen=True)
class CredentialAnalysisStats:
    """Per-process credential-analyzer counters (mirrors
    :class:`~gomemforensics.analyzers.network.NetworkAnalysisStats`)."""

    strings_scanned: int = 0
    artifacts_extracted: int = 0
    strings_skipped_length_bound: int = 0
    capped: bool = False
    artifacts_by_type: dict[str, int] = field(default_factory=dict)


def extract_credential_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
) -> tuple[list[CredentialArtifact], list[AnalysisError], CredentialAnalysisStats]:
    """Extract :class:`CredentialArtifact` records from one process's
    already-recovered Go strings (plus already-recovered functions/
    goroutines/network artifacts, consumed only for their explicit
    evidence-chain association - never re-derived from scratch, never an
    independent memory scan, CLAUDE.md section 24 applies exactly as in
    Phase 6A: one malformed/unexpected string never aborts the rest).
    """
    errors: list[AnalysisError] = []
    artifacts: list[CredentialArtifact] = []
    artifacts_by_type: dict[str, int] = {}
    strings_skipped_length_bound = 0
    capped = False

    function_refs = _build_function_string_references(functions)
    goroutine_refs = _build_goroutine_function_references(goroutines)
    network_refs = _build_network_artifact_references(network_artifacts)

    id_counter = count(1)
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
            classification = classify_credential_string(source.value)
        except Exception as exc:  # one malformed/unexpected string must not abort the rest
            errors.append(
                AnalysisError(
                    component="analyzers.credentials",
                    message=f"Credential classification failed unexpectedly for string {source.id}: {exc}",
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
        network_artifact_id = network_refs.get(source.id)

        artifact_id = f"CRED-{pid}-{next(id_counter):04d}"
        related_artifacts = [source.id] + sorted(function_ids) + sorted(goroutine_ids)
        if network_artifact_id:
            related_artifacts.append(network_artifact_id)
        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type=f"credential_{classification.artifact_type.value}",
            analyzer="analyzers.credentials.extract_credential_artifacts",
            extraction_method="go_string_credential_classification",
            confidence=classification.confidence,
            pid=pid,
            virtual_address=f"0x{source.data_address:x}",
            memory_region=source.region,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=related_artifacts,
        )
        redacted_value = (
            _redact_pem(classification.normalized.get("label", "PRIVATE KEY"), classification.normalized.get("body_length", 0))
            if classification.artifact_type in (CredentialArtifactType.PEM_PRIVATE_KEY, CredentialArtifactType.SSH_PRIVATE_KEY, CredentialArtifactType.PRIVATE_KEY_FRAGMENT)
            else redact_value(source.value)
        )
        artifact = CredentialArtifact(
            id=artifact_id,
            pid=pid,
            process_name=process_name,
            artifact_type=classification.artifact_type,
            raw_value=source.value,
            redacted_value=redacted_value,
            normalized_value=classification.normalized,
            address=source.data_address,
            length=len(source.value),
            memory_region=source.region,
            source_artifact_id=source.id,
            function_id=min(function_ids) if function_ids else None,
            goroutine_id=min(goroutine_ids) if goroutine_ids else None,
            network_artifact_id=network_artifact_id,
            extraction_method="go_string_credential_classification",
            confidence=classification.confidence,
            validation_status=classification.validation_status,
            go_version=go_version,
            architecture=architecture,
            provenance=provenance,
            notes=classification.notes,
        )
        artifacts.append(artifact)
        type_key = classification.artifact_type.value
        artifacts_by_type[type_key] = artifacts_by_type.get(type_key, 0) + 1

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.credentials",
                message=(
                    f"Credential artifact cap ({MAX_ARTIFACTS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining recovered strings were not classified (bounded analysis, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    stats = CredentialAnalysisStats(
        strings_scanned=strings_scanned,
        artifacts_extracted=len(artifacts),
        strings_skipped_length_bound=strings_skipped_length_bound,
        capped=capped,
        artifacts_by_type=artifacts_by_type,
    )
    return artifacts, errors, stats
