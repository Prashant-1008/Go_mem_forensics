"""Data models for Phase 6A network artifacts and Phase 6B credential/
secret artifacts.

This is artifact *extraction*, not malware classification (CLAUDE.md
section 20): neither :class:`NetworkArtifact` nor :class:`CredentialArtifact`
ever records a maliciousness verdict, threat score, "C2 confidence", or
credential-severity score - only what was observed, where, and how
confidently. See :mod:`gomemforensics.analyzers.network` and
:mod:`gomemforensics.analyzers.credentials` for the extraction logic and
its source-grounding.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum

from gomemforensics.common.models import ArtifactProvenance, Confidence
from gomemforensics.common.utils import format_address


def _addr(value: int | None) -> str | None:
    return format_address(value) if value is not None else None


class NetworkArtifactType(str, Enum):
    """A closed, deterministic classification of what was recognized in a
    recovered Go string's value.

    Deliberately does NOT include a standalone "port" type - a port is
    only ever extracted as part of a ``host:port`` or ``url`` artifact's
    ``normalized_value`` (Phase 6A stage 4: "Do not classify arbitrary
    integers as network ports"), never as its own bare artifact.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HOSTNAME = "hostname"
    URL = "url"
    HOST_PORT = "host_port"


class NetworkValidationStatus(str, Enum):
    """How the artifact's *extraction technique* is trusted for the
    situation encountered - distinct from :class:`Confidence`, which
    grades trust in the *result* (mirrors the existing
    ``ArgumentRecoveryStatus``/``UnwindStatus`` two-axis pattern used by
    Phase 4/5).
    """

    #: Passed every deterministic structural/syntactic check for its type
    #: (octet ranges, RFC-shaped IPv6 parse, TLD allowlist match, etc.) -
    #: the only status ever actually emitted by the Phase 6A string-based
    #: extractor, since a candidate that fails validation is simply never
    #: reported as an artifact at all (there is no "reject but keep" path
    #: here, unlike e.g. PclntabCandidate - a false structural match on
    #: arbitrary text has no forensic value worth preserving).
    STRUCTURALLY_VALID = "structurally_valid"
    #: Reserved for a future structured-object recovery path (Phase 6A
    #: stage 9: net.TCPAddr/netip.Addr/url.URL/tls.ConnectionState) that
    #: this phase documents but does not implement - never emitted today.
    UNSUPPORTED_STRUCTURE = "unsupported_structure"


@dataclass
class NetworkArtifact:
    """One network-related artifact recognized within an already-recovered
    Go string's value.

    ``raw_value`` is always the exact, unmodified source string value
    (CLAUDE.md section 4: "Never alter recovered strings") - never
    replaced by ``normalized_value``, which instead holds only the
    *parsed/decomposed* view (e.g. scheme/host/port for a URL) alongside
    it. ``function_id``/``goroutine_id`` are populated only when an
    explicit evidence chain connects this artifact's source string to a
    function's recovered call-site arguments (Phase 4) and, from there, to
    a goroutine's unwound frames (Phase 5) - never by address proximity
    alone (Phase 6A stage 7/8). When *more than one* function or goroutine
    is legitimately connected, the single ``function_id``/``goroutine_id``
    field holds the lowest-sorted id (deterministic) and the complete set
    is preserved in ``provenance.related_artifacts`` - evidence is never
    silently dropped to fit the singular field.
    """

    id: str
    pid: int
    process_name: str | None
    artifact_type: NetworkArtifactType
    raw_value: str
    normalized_value: dict | None
    address: int | None
    length: int
    memory_region: str | None
    source_artifact_id: str
    function_id: str | None
    goroutine_id: str | None
    extraction_method: str
    confidence: Confidence
    validation_status: NetworkValidationStatus
    go_version: str | None
    architecture: str
    provenance: ArtifactProvenance | None = None
    notes: str | None = None

    @property
    def address_hex(self) -> str | None:
        return _addr(self.address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process_name": self.process_name,
            "artifact_type": self.artifact_type.value,
            "raw_value": self.raw_value,
            "normalized_value": self.normalized_value,
            "address": self.address_hex,
            "length": self.length,
            "memory_region": self.memory_region,
            "source_artifact_id": self.source_artifact_id,
            "function_id": self.function_id,
            "goroutine_id": self.goroutine_id,
            "extraction_method": self.extraction_method,
            "confidence": self.confidence.value,
            "validation_status": self.validation_status.value,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "provenance": asdict(self.provenance) if self.provenance else None,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 6B - Go credential / secret artifact analyzer
# ---------------------------------------------------------------------------


class CredentialArtifactType(str, Enum):
    """A closed, deterministic classification of a secret-like shape
    recognized in a recovered Go string's value.

    Only types actually implemented by
    :mod:`gomemforensics.analyzers.credentials` appear here (Phase 6B
    stage 4: "Only add types actually supported by implementation") -
    there is deliberately no generic ``UNKNOWN_SECRET`` catch-all, since
    that would require classifying by entropy alone, which stage 6/21
    explicitly forbid ("A random high-entropy string with no context
    should NOT automatically be called a credential").
    """

    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    BEARER_TOKEN = "bearer_token"
    AUTH_TOKEN = "auth_token"
    PASSWORD = "password"
    USERNAME = "username"
    USERNAME_PASSWORD = "username_password"
    CLIENT_SECRET = "client_secret"
    SESSION_TOKEN = "session_token"
    COOKIE = "cookie"
    AUTHORIZATION_HEADER = "authorization_header"
    BASIC_AUTH = "basic_auth"
    JWT = "jwt"
    PEM_PRIVATE_KEY = "pem_private_key"
    SSH_PRIVATE_KEY = "ssh_private_key"
    PRIVATE_KEY_FRAGMENT = "private_key_fragment"
    CLOUD_CREDENTIAL = "cloud_credential"
    DATABASE_CREDENTIAL = "database_credential"
    ENV_SECRET_LIKE = "env_secret_like"
    CONFIG_SECRET_LIKE = "config_secret_like"


class CredentialValidationStatus(str, Enum):
    """Distinct from :class:`Confidence` - grades how far the extraction
    *technique* got, not how much the result is trusted (mirrors
    :class:`NetworkValidationStatus`'s two-axis pattern)."""

    #: Passed every deterministic structural/contextual check for its
    #: type - the artifact is exactly what its type claims to be,
    #: structurally (never a claim that the *value itself* is valid,
    #: live, or in active use - see CORE OBJECTIVE).
    STRUCTURALLY_VALID = "structurally_valid"
    #: A recognized boundary marker (e.g. a PEM "-----BEGIN ... PRIVATE
    #: KEY-----" header) was found without its matching closing boundary
    #: in the same string - reported as ``PRIVATE_KEY_FRAGMENT`` rather
    #: than silently dropped or overstated as a complete key (stage 14).
    STRUCTURALLY_INCOMPLETE = "structurally_incomplete"


@dataclass
class CredentialArtifact:
    """One secret-like artifact recognized within an already-recovered Go
    string's value.

    Distinguishes, per Phase 6B's CORE OBJECTIVE, four things that must
    never be collapsed into one verdict:

    1. OBSERVED SECRET-LIKE DATA - ``raw_value`` (never altered) and
       ``address``/``memory_region`` (where it was observed).
    2. STRUCTURALLY IDENTIFIED SECRET MATERIAL - ``artifact_type`` +
       ``validation_status`` (what shape was recognized, and how
       completely).
    3. ASSOCIATED CONTEXT - ``function_id``/``goroutine_id``/
       ``network_artifact_id``, populated only via an explicit evidence
       chain (Phase 4 call-site string references, Phase 5 unwound
       frames, Phase 6A shared-source-string linkage) - never address
       proximity.
    4. INTERPRETATION - ``notes`` and ``confidence``, which never assert
       validity, liveness, or actual use (CORE OBJECTIVE: find
       secret-LIKE artifacts, never prove a string is a valid credential,
       and never prove a process used it).

    ``raw_value`` is preserved exactly as recovered (CLAUDE.md section 4).
    ``redacted_value`` is a separate, deterministically-derived masked
    form for human-readable/log-safe contexts - it never replaces
    ``raw_value`` in the machine-readable record (Phase 6B stage 20).
    """

    id: str
    pid: int
    process_name: str | None
    artifact_type: CredentialArtifactType
    raw_value: str
    redacted_value: str
    normalized_value: dict | None
    address: int | None
    length: int
    memory_region: str | None
    source_artifact_id: str
    function_id: str | None
    goroutine_id: str | None
    network_artifact_id: str | None
    extraction_method: str
    confidence: Confidence
    validation_status: CredentialValidationStatus
    go_version: str | None
    architecture: str
    provenance: ArtifactProvenance | None = None
    notes: str | None = None

    @property
    def address_hex(self) -> str | None:
        return _addr(self.address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process_name": self.process_name,
            "artifact_type": self.artifact_type.value,
            "raw_value": self.raw_value,
            "redacted_value": self.redacted_value,
            "normalized_value": self.normalized_value,
            "address": self.address_hex,
            "length": self.length,
            "memory_region": self.memory_region,
            "source_artifact_id": self.source_artifact_id,
            "function_id": self.function_id,
            "goroutine_id": self.goroutine_id,
            "network_artifact_id": self.network_artifact_id,
            "extraction_method": self.extraction_method,
            "confidence": self.confidence.value,
            "validation_status": self.validation_status.value,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "provenance": asdict(self.provenance) if self.provenance else None,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 6C - Go cryptographic artifact analyzer
# ---------------------------------------------------------------------------


class CryptoArtifactType(str, Enum):
    """A closed, deterministic classification of a cryptographic artifact
    shape recognized in already-recovered Go evidence.

    Only types actually implemented by
    :mod:`gomemforensics.analyzers.crypto` appear here (same discipline as
    :class:`NetworkArtifactType`/:class:`CredentialArtifactType`) - no
    generic ``UNKNOWN_CRYPTO_ARTIFACT`` catch-all, since that would
    require classifying arbitrary bytes by length/entropy alone, which
    Phase 6C stages 4/8/9/21 explicitly forbid.
    """

    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    CERTIFICATE = "certificate"
    CERTIFICATE_CHAIN = "certificate_chain"
    AES_KEY = "aes_key"
    CRYPTO_CONTEXT = "crypto_context"


class CryptoValidationStatus(str, Enum):
    """Mirrors :class:`NetworkValidationStatus`/:class:`CredentialValidationStatus`'s
    two-axis pattern."""

    STRUCTURALLY_VALID = "structurally_valid"
    #: A PEM boundary was found without its matching close, in the same
    #: string - reported with the boundary's own type rather than
    #: silently dropped (mirrors CredentialArtifact's PRIVATE_KEY_FRAGMENT
    #: handling, generalized here via this status instead of a dedicated
    #: per-type "fragment" enum value, to avoid type-list explosion).
    STRUCTURALLY_INCOMPLETE = "structurally_incomplete"


@dataclass
class CryptoArtifact:
    """One cryptographic artifact recognized within already-recovered Go
    evidence (a string, or a Phase 6B credential artifact, or a Phase 4
    call-site argument) - never independently re-scanning memory.

    Distinguishes, per Phase 6C's CORE OBJECTIVE, four things that must
    never be collapsed into a verdict:

    1. OBSERVED CRYPTOGRAPHIC MATERIAL - ``raw_value``/``redacted_value``
       and ``address``/``memory_region``.
    2. STRUCTURALLY IDENTIFIED CRYPTOGRAPHIC OBJECTS - ``artifact_type``/
       ``algorithm``/``key_type``/``validation_status``.
    3. CRYPTOGRAPHIC CONTEXT - ``function_id``/``goroutine_id``/
       ``network_artifact_id``/``credential_artifact_id``, populated only
       via an explicit evidence chain - never address proximity.
    4. INTERPRETATION - ``notes``/``confidence``, which never assert that
       encryption/decryption/authentication occurred, or that a key was
       actually used - at most, when Phase 4 call-site evidence supports
       it, that key-shaped material was passed as an argument to a named
       crypto constructor (``notes`` uses the precise phrase
       "KEY_MATERIAL_PASSED_AS_ARGUMENT", never "KEY_USED" or "ENCRYPTION
       OCCURRED").

    ``credential_artifact_id`` cross-references a Phase 6B
    :class:`CredentialArtifact` when this artifact's private-key evidence
    was *reused* from that phase rather than re-parsed (Phase 6C stage
    7/18: "Phase 6B already recognizes PEM private-key material. Reuse
    that evidence rather than implementing a duplicate parser.").
    """

    id: str
    pid: int
    process_name: str | None
    artifact_type: CryptoArtifactType
    algorithm: str | None
    key_type: str | None
    raw_value: str | None
    redacted_value: str | None
    normalized_value: dict | None
    address: int | None
    length: int | None
    memory_region: str | None
    source_artifact_id: str | None
    function_id: str | None
    goroutine_id: str | None
    network_artifact_id: str | None
    credential_artifact_id: str | None
    extraction_method: str
    confidence: Confidence
    validation_status: CryptoValidationStatus
    go_version: str | None
    architecture: str
    provenance: ArtifactProvenance | None = None
    notes: str | None = None

    @property
    def address_hex(self) -> str | None:
        return _addr(self.address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process_name": self.process_name,
            "artifact_type": self.artifact_type.value,
            "algorithm": self.algorithm,
            "key_type": self.key_type,
            "raw_value": self.raw_value,
            "redacted_value": self.redacted_value,
            "normalized_value": self.normalized_value,
            "address": self.address_hex,
            "length": self.length,
            "memory_region": self.memory_region,
            "source_artifact_id": self.source_artifact_id,
            "function_id": self.function_id,
            "goroutine_id": self.goroutine_id,
            "network_artifact_id": self.network_artifact_id,
            "credential_artifact_id": self.credential_artifact_id,
            "extraction_method": self.extraction_method,
            "confidence": self.confidence.value,
            "validation_status": self.validation_status.value,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "provenance": asdict(self.provenance) if self.provenance else None,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 6D - Go malware persistence artifact analyzer
# ---------------------------------------------------------------------------


class PersistenceArtifactType(str, Enum):
    """A closed, deterministic, platform-prefixed classification of a
    persistence-related shape recognized in already-recovered Go
    evidence.

    Every value is explicitly prefixed ``WINDOWS_``/``LINUX_`` (Phase 6D
    stage 3: "Do not mix Windows and Linux semantics") - there is no
    cross-platform catch-all, and no generic
    ``UNKNOWN_PERSISTENCE_ARTIFACT`` (same discipline as
    :class:`NetworkArtifactType`/:class:`CredentialArtifactType`/
    :class:`CryptoArtifactType`: a candidate that does not match one of
    these specific, deterministic shapes is never emitted).
    """

    WINDOWS_REGISTRY_RUN = "windows_registry_run"
    WINDOWS_WINLOGON = "windows_winlogon"
    WINDOWS_STARTUP_FOLDER = "windows_startup_folder"
    WINDOWS_SCHEDULED_TASK_REFERENCE = "windows_scheduled_task_reference"
    WINDOWS_SERVICE_REFERENCE = "windows_service_reference"
    WINDOWS_WMI_PERSISTENCE = "windows_wmi_persistence"
    WINDOWS_APPINIT = "windows_appinit"
    WINDOWS_IFEO = "windows_ifeo"
    LINUX_SYSTEMD_UNIT = "linux_systemd_unit"
    LINUX_CRON = "linux_cron"
    LINUX_SHELL_PROFILE = "linux_shell_profile"
    LINUX_AUTOSTART = "linux_autostart"
    LINUX_INIT_SCRIPT = "linux_init_script"
    LINUX_AUTHORIZED_KEYS_PATH = "linux_authorized_keys_path"
    LINUX_AUTHORIZED_KEY_ENTRY = "linux_authorized_key_entry"
    LINUX_LOADER_PRELOAD = "linux_loader_preload"


class PersistenceValidationStatus(str, Enum):
    """Mirrors :class:`NetworkValidationStatus`/:class:`CredentialValidationStatus`/
    :class:`CryptoValidationStatus`'s two-axis pattern - only one value is
    ever actually emitted by this phase's string-based detectors (a
    candidate that does not fully match a recognized shape is never
    emitted at all); reserved for a future structured OS-artifact
    recovery path that might need to express partial/incomplete evidence
    the way :class:`CryptoValidationStatus.STRUCTURALLY_INCOMPLETE` does
    for a truncated PEM block."""

    STRUCTURALLY_VALID = "structurally_valid"


@dataclass
class PersistenceArtifact:
    """One persistence-related artifact recognized within already-
    recovered Go evidence - never independently re-scanning memory, and
    never a claim that persistence was actually established.

    Distinguishes, per Phase 6D's CORE OBJECTIVE, four things that must
    never be collapsed into a verdict:

    1. OBSERVED PERSISTENCE-RELATED DATA - ``raw_value``/``redacted_value``
       and ``address``/``memory_region``.
    2. STRUCTURALLY RECOVERED PERSISTENCE ARTIFACT - ``artifact_type``/
       ``platform``/``persistence_mechanism``/``validation_status``.
    3. ASSOCIATED FUNCTION/GOROUTINE EVIDENCE - ``function_id``/
       ``goroutine_id``/``network_artifact_id``/``credential_artifact_id``/
       ``crypto_artifact_id``, populated only via an explicit evidence
       chain - never address proximity.
    4. INTERPRETATION - ``notes``, which always uses one of the precise,
       non-overclaiming phrases this phase mandates
       (``PERSISTENCE_ARTIFACT_OBSERVED``, ``PERSISTENCE_PATH_OBSERVED``,
       ``PERSISTENCE_COMMAND_OBSERVED``,
       ``PERSISTENCE_CONFIGURATION_REFERENCED``,
       ``PERSISTENCE_FUNCTION_ASSOCIATED``) - never
       ``PERSISTENCE_CONFIRMED``, ``PERSISTENCE_ESTABLISHED``, or
       ``COMMAND_EXECUTED``, since a compiled Go binary's own recovered
       strings/functions can never, by themselves, establish that a
       registry key exists, a service was created, a task was
       registered, or a command actually ran.
    """

    id: str
    pid: int
    process_name: str | None
    platform: str
    artifact_type: PersistenceArtifactType
    persistence_mechanism: str
    raw_value: str
    redacted_value: str
    normalized_value: dict | None
    address: int | None
    length: int
    memory_region: str | None
    source_artifact_id: str
    function_id: str | None
    goroutine_id: str | None
    network_artifact_id: str | None
    credential_artifact_id: str | None
    crypto_artifact_id: str | None
    extraction_method: str
    confidence: Confidence
    validation_status: PersistenceValidationStatus
    go_version: str | None
    architecture: str
    provenance: ArtifactProvenance | None = None
    notes: str | None = None

    @property
    def address_hex(self) -> str | None:
        return _addr(self.address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process_name": self.process_name,
            "platform": self.platform,
            "artifact_type": self.artifact_type.value,
            "persistence_mechanism": self.persistence_mechanism,
            "raw_value": self.raw_value,
            "redacted_value": self.redacted_value,
            "normalized_value": self.normalized_value,
            "address": self.address_hex,
            "length": self.length,
            "memory_region": self.memory_region,
            "source_artifact_id": self.source_artifact_id,
            "function_id": self.function_id,
            "goroutine_id": self.goroutine_id,
            "network_artifact_id": self.network_artifact_id,
            "credential_artifact_id": self.credential_artifact_id,
            "crypto_artifact_id": self.crypto_artifact_id,
            "extraction_method": self.extraction_method,
            "confidence": self.confidence.value,
            "validation_status": self.validation_status.value,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "provenance": asdict(self.provenance) if self.provenance else None,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 6E - IOC extraction and cross-artifact correlation
# ---------------------------------------------------------------------------


class IOCType(str, Enum):
    """A closed set of Indicator-of-Compromise types this phase promotes
    from already-recovered Phase 6A-6D artifacts.

    Every value's string is deliberately identical to the corresponding
    source artifact type's own value (:class:`NetworkArtifactType`/
    :class:`CredentialArtifactType`/:class:`CryptoArtifactType`/
    :class:`PersistenceArtifactType`) - this is a genuine reuse of
    already-verified taxonomy, never a parallel/invented type system
    (CLAUDE.md section 36: no duplicated logic). Only artifact types
    explicitly listed in the Phase 6E task's closed taxonomy are promoted
    - see :mod:`gomemforensics.analyzers.correlation` for the exact
    inclusion table and, for every excluded type, why it was excluded.
    There is no ``UNKNOWN_IOC`` catch-all.
    """

    # Network (identical values to NetworkArtifactType)
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HOSTNAME = "hostname"
    URL = "url"
    HOST_PORT = "host_port"
    # Credential/auth (identical values to CredentialArtifactType)
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    COOKIE = "cookie"
    SESSION_TOKEN = "session_token"
    JWT = "jwt"
    DATABASE_CREDENTIAL = "database_credential"
    API_KEY = "api_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    # Crypto (identical values to CryptoArtifactType)
    PUBLIC_KEY = "public_key"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    CERTIFICATE_CHAIN = "certificate_chain"
    CRYPTO_CONTEXT = "crypto_context"
    AES_KEY = "aes_key"
    # Persistence (identical values to PersistenceArtifactType)
    WINDOWS_REGISTRY_RUN = "windows_registry_run"
    WINDOWS_WINLOGON = "windows_winlogon"
    WINDOWS_STARTUP_FOLDER = "windows_startup_folder"
    WINDOWS_SCHEDULED_TASK_REFERENCE = "windows_scheduled_task_reference"
    WINDOWS_SERVICE_REFERENCE = "windows_service_reference"
    WINDOWS_WMI_PERSISTENCE = "windows_wmi_persistence"
    WINDOWS_APPINIT = "windows_appinit"
    WINDOWS_IFEO = "windows_ifeo"
    LINUX_SYSTEMD_UNIT = "linux_systemd_unit"
    LINUX_CRON = "linux_cron"
    LINUX_SHELL_PROFILE = "linux_shell_profile"
    LINUX_AUTOSTART = "linux_autostart"
    LINUX_INIT_SCRIPT = "linux_init_script"
    LINUX_AUTHORIZED_KEYS_PATH = "linux_authorized_keys_path"
    LINUX_AUTHORIZED_KEY_ENTRY = "linux_authorized_key_entry"
    LINUX_LOADER_PRELOAD = "linux_loader_preload"


class IOCCategory(str, Enum):
    """The coarse origin category of an IOC - which Phase 6A-6D analyzer
    produced the artifact this IOC was promoted from."""

    NETWORK = "network"
    CREDENTIAL = "credential"
    CRYPTO = "crypto"
    PERSISTENCE = "persistence"


class IOCValidationStatus(str, Enum):
    """Describes artifact *validity*, never threat reputation (Phase 6E
    stage 15: no fake "verified malicious" status exists or will ever
    exist here)."""

    #: Every source artifact contributing to this IOC (see ``dedup_key``)
    #: was itself STRUCTURALLY_VALID.
    STRUCTURALLY_VALID = "structurally_valid"
    #: At least one contributing source was STRUCTURALLY_VALID and at
    #: least one was incomplete (e.g. a PEM fragment) - never silently
    #: collapsed into one or the other.
    PARTIALLY_VALID = "partially_valid"
    #: Every contributing source was itself incomplete.
    STRUCTURALLY_INCOMPLETE = "structurally_incomplete"


@dataclass
class IOCArtifact:
    """One normalized Indicator of Compromise, promoted 1:1 from a single
    already-recovered Phase 6A-6D artifact (never merged with other
    source artifacts at the record level - CLAUDE.md's "never destroy
    distinct evidence locations" principle, upheld identically to every
    prior phase). Records that normalize to the same real-world indicator
    share the same ``dedup_key`` so they can be grouped for reporting
    (Phase 6E stage 7) without any evidence being discarded.

    ``raw_value``/``redacted_value`` are copied verbatim from the source
    artifact - this layer never re-derives or alters them.
    ``normalized_value`` is likewise copied from the source artifact's own
    already-computed normalization (Phase 6A-6D already normalize
    deterministically; this phase does not re-normalize or perform any
    network/DNS/reputation lookup - CLAUDE.md sections 16/32/33).
    """

    id: str
    pid: int
    process_name: str | None
    ioc_type: IOCType
    ioc_category: IOCCategory
    raw_value: str | None
    normalized_value: dict | None
    redacted_value: str | None
    address: int | None
    length: int | None
    memory_region: str | None
    source_artifact_id: str
    source_artifact_type: str
    dedup_key: str
    function_id: str | None
    goroutine_id: str | None
    related_network_artifact_id: str | None
    related_credential_artifact_id: str | None
    related_crypto_artifact_id: str | None
    related_persistence_artifact_id: str | None
    confidence: Confidence
    validation_status: IOCValidationStatus
    extraction_method: str
    go_version: str | None
    architecture: str
    provenance: ArtifactProvenance | None = None
    notes: str | None = None

    @property
    def address_hex(self) -> str | None:
        return _addr(self.address)

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "process_name": self.process_name,
            "ioc_type": self.ioc_type.value,
            "ioc_category": self.ioc_category.value,
            "raw_value": self.raw_value,
            "normalized_value": self.normalized_value,
            "redacted_value": self.redacted_value,
            "address": self.address_hex,
            "length": self.length,
            "memory_region": self.memory_region,
            "source_artifact_id": self.source_artifact_id,
            "source_artifact_type": self.source_artifact_type,
            "dedup_key": self.dedup_key,
            "function_id": self.function_id,
            "goroutine_id": self.goroutine_id,
            "related_network_artifact_id": self.related_network_artifact_id,
            "related_credential_artifact_id": self.related_credential_artifact_id,
            "related_crypto_artifact_id": self.related_crypto_artifact_id,
            "related_persistence_artifact_id": self.related_persistence_artifact_id,
            "confidence": self.confidence.value,
            "validation_status": self.validation_status.value,
            "extraction_method": self.extraction_method,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "provenance": asdict(self.provenance) if self.provenance else None,
            "notes": self.notes,
        }


class CorrelationType(str, Enum):
    """A closed, documented set of typed evidence relationships (Phase 6E
    stage 8) - every value emitted by
    :mod:`gomemforensics.analyzers.correlation` traces to an already-
    existing field on an already-recovered artifact (a shared
    ``source_artifact_id``, or an already-populated ``function_id``/
    ``goroutine_id``/``network_artifact_id``/``credential_artifact_id``/
    ``crypto_artifact_id`` cross-reference) - never memory proximity,
    never "same process", never "same goroutine" alone.
    """

    SAME_SOURCE_STRING = "same_source_string"
    STRING_TO_NETWORK = "string_to_network"
    STRING_TO_CREDENTIAL = "string_to_credential"
    STRING_TO_CRYPTO = "string_to_crypto"
    STRING_TO_PERSISTENCE = "string_to_persistence"
    NETWORK_TO_CREDENTIAL = "network_to_credential"
    NETWORK_TO_CRYPTO = "network_to_crypto"
    NETWORK_TO_PERSISTENCE = "network_to_persistence"
    CREDENTIAL_TO_CRYPTO = "credential_to_crypto"
    CREDENTIAL_TO_PERSISTENCE = "credential_to_persistence"
    CRYPTO_TO_PERSISTENCE = "crypto_to_persistence"
    FUNCTION_REFERENCES_ARTIFACT = "function_references_artifact"
    GOROUTINE_FRAME_REFERENCES_ARTIFACT = "goroutine_frame_references_artifact"


@dataclass
class CorrelationRecord:
    """One typed, deterministic edge between two already-recovered
    artifacts/entities - a *restatement* of an already-recorded evidence
    field as an explicit, queryable graph edge, never a new inference.

    Deliberately has no ``confidence`` field: unlike an artifact (whose
    confidence reflects uncertainty in what was *recognized*), a
    correlation record reflects a fact already recorded verbatim
    elsewhere (equal ``source_artifact_id`` values, or an already-
    populated ``function_id``/``goroutine_id``/``*_artifact_id`` field) -
    there is no independent uncertainty to grade (Phase 6E stage 8: "Only
    emit a relationship when the existing artifact models provide a real
    evidence chain"). ``evidence_basis`` names exactly which existing
    field justified the edge, so every record is independently
    auditable.
    """

    id: str
    pid: int
    relationship_type: CorrelationType
    source_id: str
    source_type: str
    target_id: str
    target_type: str
    evidence_basis: str
    notes: str | None = None

    def to_json_dict(self) -> dict:
        return {
            "id": self.id,
            "pid": self.pid,
            "relationship_type": self.relationship_type.value,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "evidence_basis": self.evidence_basis,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Phase 6F - Findings and evidence assessment
# ---------------------------------------------------------------------------


class FindingType(str, Enum):
    """A closed, evidence-backed finding taxonomy (Phase 6F stage 5).

    Findings deliberately summarize at a *coarser* grain than the
    :class:`IOCType`/:class:`CorrelationType` layers beneath them - that
    coarsening is what makes a Finding a reporting-level summary rather
    than a restated IOC. Every value below was derived by inspecting the
    actual Phase 6A-6E artifact taxonomy (never invented in advance) -
    see :mod:`gomemforensics.analyzers.findings` for the exact
    ``IOCType``/``CorrelationType`` -> ``FindingType`` evidence rule for
    each value. There is no ``UNKNOWN_FINDING`` catch-all: a
    non-qualifying IOC or correlation record simply produces no finding.
    """

    NETWORK_IP_OBSERVED = "network_ip_observed"
    NETWORK_HOSTNAME_OBSERVED = "network_hostname_observed"
    NETWORK_URL_OBSERVED = "network_url_observed"
    NETWORK_ENDPOINT_OBSERVED = "network_endpoint_observed"
    AUTHORIZATION_MATERIAL_OBSERVED = "authorization_material_observed"
    SESSION_MATERIAL_OBSERVED = "session_material_observed"
    DATABASE_CREDENTIAL_OBSERVED = "database_credential_observed"
    TOKEN_OBSERVED = "token_observed"
    CRYPTO_PUBLIC_KEY_OBSERVED = "crypto_public_key_observed"
    CRYPTO_PRIVATE_KEY_OBSERVED = "crypto_private_key_observed"
    CERTIFICATE_OBSERVED = "certificate_observed"
    CRYPTO_CONTEXT_OBSERVED = "crypto_context_observed"
    AES_KEY_OBSERVED = "aes_key_observed"
    WINDOWS_PERSISTENCE_REFERENCE = "windows_persistence_reference"
    LINUX_PERSISTENCE_REFERENCE = "linux_persistence_reference"
    MULTI_ARTIFACT_EVIDENCE = "multi_artifact_evidence"
    SHARED_SOURCE_EVIDENCE = "shared_source_evidence"


class FindingValidationStatus(str, Enum):
    """Mirrors :class:`IOCValidationStatus`'s evidence-oriented (never
    reputation-oriented) two/three-state pattern exactly - reused, not
    redefined. There is no ``MALICIOUS``/``VERIFIED_MALICIOUS``/
    ``THREAT_CONFIRMED`` state and never will be (stage 15)."""

    STRUCTURALLY_VALID = "structurally_valid"
    PARTIALLY_VALID = "partially_valid"
    STRUCTURALLY_INCOMPLETE = "structurally_incomplete"


class FindingSeverity(str, Enum):
    """Forensic/reporting importance only - **never** a maliciousness
    probability (stage 16's explicit distinction, restated on every
    :class:`Finding` record via a fixed, documented, per-``FindingType``
    lookup table in :mod:`gomemforensics.analyzers.findings` - never
    computed from "this looks like malware", never aggregated into an
    overall per-process score)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    """A structured evidence assessment summarizing already-recovered
    IOCs/correlations - never a malware verdict, malware score, threat
    score, reputation result, automatic attribution, or a claim that an
    artifact was actually used/transmitted/persisted (CORE OBJECTIVE).

    Every Finding keeps ``observed_evidence`` (what was directly
    recovered) and ``interpretation`` (the bounded, evidence-accurate
    reading of it) as two separate string fields - never collapsed into
    one sentence that could be misread as a behavioral claim. See
    ``docs/architecture/go-findings.md`` for the full per-type wording
    rules and prohibited-inference examples.

    Deduplication (stage 18): one Finding per
    ``(finding_type, pid, dedup_key)`` - multiple IOCs/correlation
    records supporting the same finding are all listed in
    ``supporting_ioc_ids``/``supporting_correlation_ids``/
    ``supporting_artifact_ids`` rather than producing repeated Finding
    records.
    """

    finding_id: str
    pid: int
    process_name: str | None
    finding_type: FindingType
    title: str
    description: str
    observed_evidence: str
    interpretation: str
    confidence: Confidence
    validation_status: FindingValidationStatus
    severity: FindingSeverity
    supporting_artifact_ids: list[str]
    supporting_ioc_ids: list[str]
    supporting_correlation_ids: list[str]
    function_ids: list[str]
    goroutine_ids: list[str]
    platform: str | None
    go_version: str | None
    architecture: str
    extraction_method: str
    provenance: ArtifactProvenance | None = None
    notes: str | None = None

    def to_json_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "finding_type": self.finding_type.value,
            "title": self.title,
            "description": self.description,
            "observed_evidence": self.observed_evidence,
            "interpretation": self.interpretation,
            "confidence": self.confidence.value,
            "validation_status": self.validation_status.value,
            "severity": self.severity.value,
            "supporting_artifact_ids": list(self.supporting_artifact_ids),
            "supporting_ioc_ids": list(self.supporting_ioc_ids),
            "supporting_correlation_ids": list(self.supporting_correlation_ids),
            "function_ids": list(self.function_ids),
            "goroutine_ids": list(self.goroutine_ids),
            "platform": self.platform,
            "go_version": self.go_version,
            "architecture": self.architecture,
            "extraction_method": self.extraction_method,
            "provenance": asdict(self.provenance) if self.provenance else None,
            "notes": self.notes,
        }
