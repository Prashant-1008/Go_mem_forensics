"""Phase 6E — IOC extraction and cross-artifact correlation.

Transforms already-recovered Phase 6A-6D artifacts into (1) normalized
:class:`~gomemforensics.analyzers.models.IOCArtifact` records and (2)
explicit, typed :class:`~gomemforensics.analyzers.models.CorrelationRecord`
graph edges. This module implements **no new detection** - it consumes
artifacts `network.py`/`credentials.py`/`crypto.py`/`persistence.py`
already produced, and never independently re-scans a
:class:`~gomemforensics.go_runtime.models.StringArtifact` or touches a
:class:`~gomemforensics.common.memory.MemoryReader`.

Think: artifact -> evidence -> normalized IOC -> relationship. Never:
artifact -> malware verdict. Nothing in this module ever assigns a
malware/threat/suspiciousness score, claims an IOC was actually used/
contacted/executed/downloaded/installed/authenticated/encrypted/
decrypted/persisted, or performs any DNS/WHOIS/reputation/network lookup
(CLAUDE.md sections 16/20/32/33).

## IOC promotion allowlist (stage 4)

Only artifact types the Phase 6E task explicitly names are promoted to
IOCs - every other Phase 6A-6D type remains an artifact only (never an
``UNKNOWN_IOC`` catch-all):

- Network: all 5 ``NetworkArtifactType`` values (IPv4/IPv6/hostname/URL/
  host:port) - the task's own NETWORK list matches exactly.
- Credential: ``BEARER_TOKEN``, ``BASIC_AUTH``, ``COOKIE``,
  ``SESSION_TOKEN``, ``JWT``, ``DATABASE_CREDENTIAL``, ``API_KEY``,
  ``CLOUD_CREDENTIAL`` (the task's "vendor-specific token formats where
  already supported"). Excluded: ``ACCESS_TOKEN``, ``AUTH_TOKEN``,
  ``PASSWORD``, ``USERNAME``, ``USERNAME_PASSWORD``, ``CLIENT_SECRET``,
  ``AUTHORIZATION_HEADER`` (generic, non-Bearer/Basic scheme),
  ``ENV_SECRET_LIKE``, ``CONFIG_SECRET_LIKE`` - these are raw per-
  instance secret material, not the kind of shareable/correlatable
  indicator the task's closed IOC taxonomy names; they remain
  ``CredentialArtifact``-only. ``PEM_PRIVATE_KEY``/``SSH_PRIVATE_KEY``/
  ``PRIVATE_KEY_FRAGMENT`` are also excluded *here* specifically because
  Phase 6C already reuses this exact evidence as
  ``CryptoArtifactType.PRIVATE_KEY`` - promoting both would duplicate one
  piece of evidence into two IOC records (CLAUDE.md section 36).
- Crypto: all 6 ``CryptoArtifactType`` values.
- Persistence: all 16 ``PersistenceArtifactType`` values (the task's own
  list of 14 mechanisms plus ``WINDOWS_WINLOGON``, which the task's
  illustrative list did not separately name but which is an already-
  verified Phase 6D type - included for 1:1, information-preserving
  coverage rather than an arbitrary omission).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count

from gomemforensics.analyzers.models import (
    CorrelationRecord,
    CorrelationType,
    CredentialArtifact,
    CredentialArtifactType,
    CryptoArtifact,
    IOCArtifact,
    IOCCategory,
    IOCType,
    IOCValidationStatus,
    NetworkArtifact,
    PersistenceArtifact,
)
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence
from gomemforensics.go_runtime.models import FunctionArtifact, GoroutineArtifact, StringArtifact

ANALYZER_VERSION = "analyzers.correlation/1"

#: Safety bounds (mirrors the Phase 6A-6D analyzers exactly).
MAX_IOCS_PER_PROCESS = 5000
MAX_CORRELATIONS_PER_PROCESS = 20000
#: A single source string producing more distinct derived-artifact types
#: than this is not pairwise-expanded into SAME_SOURCE_STRING edges (an
#: explicit, documented bound - stage 21 - rather than an unbounded
#: cross-product; in practice a string produces at most 4 derived
#: artifacts, one per analyzer, so this is a generous safety margin, not
#: a limit expected to ever bind in real data).
MAX_SAME_SOURCE_GROUP_SIZE = 8

_CREDENTIAL_IOC_TYPES = frozenset(
    {
        CredentialArtifactType.BEARER_TOKEN,
        CredentialArtifactType.BASIC_AUTH,
        CredentialArtifactType.COOKIE,
        CredentialArtifactType.SESSION_TOKEN,
        CredentialArtifactType.JWT,
        CredentialArtifactType.DATABASE_CREDENTIAL,
        CredentialArtifactType.API_KEY,
        CredentialArtifactType.CLOUD_CREDENTIAL,
    }
)

_CONFIDENCE_RANK = {Confidence.UNKNOWN: 0, Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}


def _dedup_key(ioc_type: IOCType, raw_value: str, normalized_value: dict | None) -> str:
    """Deterministic grouping key for "the same real-world indicator
    observed via different evidence" (stage 6/7) - built only from each
    IOC type's own already-computed ``normalized_value`` fields, never a
    new normalization invented here.
    """
    normalized_value = normalized_value or {}
    if ioc_type == IOCType.IPV4 or ioc_type == IOCType.IPV6:
        return f"{ioc_type.value}:{normalized_value.get('ip', raw_value)}"
    if ioc_type == IOCType.HOSTNAME:
        return f"hostname:{normalized_value.get('hostname', raw_value.lower())}"
    if ioc_type == IOCType.URL:
        scheme = normalized_value.get("scheme", "")
        hostname = normalized_value.get("hostname", "")
        port = normalized_value.get("port")
        path = normalized_value.get("path", "")
        return f"url:{scheme}://{hostname}:{port}{path}"
    if ioc_type == IOCType.HOST_PORT:
        host = normalized_value.get("host", "")
        port = normalized_value.get("port")
        return f"host_port:{host}:{port}"
    # Every other IOC type (credential/crypto/persistence) has no further
    # normalization beyond the source analyzer's own raw value - dedup on
    # the exact recovered value, never invented path/case normalization.
    return f"{ioc_type.value}:{raw_value}"


def _combine_confidence(confidences: list[Confidence]) -> Confidence:
    """Stage 14's deterministic rule: the highest-ranked confidence among
    all contributing sources wins - never averaged, never silently
    redefining what a given :class:`Confidence` value means."""
    if not confidences:
        return Confidence.UNKNOWN
    return max(confidences, key=lambda c: _CONFIDENCE_RANK[c])


@dataclass(frozen=True)
class _IOCCandidate:
    ioc_type: IOCType
    ioc_category: IOCCategory
    raw_value: str
    normalized_value: dict | None
    redacted_value: str | None
    address: int | None
    length: int | None
    memory_region: str | None
    source_artifact_id: str
    source_artifact_type: str
    function_id: str | None
    goroutine_id: str | None
    network_artifact_id: str | None
    credential_artifact_id: str | None
    crypto_artifact_id: str | None
    persistence_artifact_id: str | None
    confidence: Confidence
    validation_status: str
    extraction_method: str
    go_version: str | None
    architecture: str


def _network_candidate(artifact: NetworkArtifact) -> _IOCCandidate | None:
    try:
        ioc_type = IOCType(artifact.artifact_type.value)
    except ValueError:
        return None
    return _IOCCandidate(
        ioc_type, IOCCategory.NETWORK, artifact.raw_value, artifact.normalized_value, None,
        artifact.address, artifact.length, artifact.memory_region, artifact.source_artifact_id,
        "network_artifact", artifact.function_id, artifact.goroutine_id, artifact.id, None, None, None,
        artifact.confidence, artifact.validation_status.value, artifact.extraction_method,
        artifact.go_version, artifact.architecture,
    )


def _credential_candidate(artifact: CredentialArtifact) -> _IOCCandidate | None:
    if artifact.artifact_type not in _CREDENTIAL_IOC_TYPES:
        return None
    try:
        ioc_type = IOCType(artifact.artifact_type.value)
    except ValueError:
        return None
    return _IOCCandidate(
        ioc_type, IOCCategory.CREDENTIAL, artifact.raw_value, artifact.normalized_value, artifact.redacted_value,
        artifact.address, artifact.length, artifact.memory_region, artifact.source_artifact_id,
        "credential_artifact", artifact.function_id, artifact.goroutine_id, artifact.network_artifact_id,
        artifact.id, None, None,
        artifact.confidence, artifact.validation_status.value, artifact.extraction_method,
        artifact.go_version, artifact.architecture,
    )


def _crypto_candidate(artifact: CryptoArtifact) -> _IOCCandidate | None:
    try:
        ioc_type = IOCType(artifact.artifact_type.value)
    except ValueError:
        return None
    return _IOCCandidate(
        ioc_type, IOCCategory.CRYPTO, artifact.raw_value or "", artifact.normalized_value, artifact.redacted_value,
        artifact.address, artifact.length, artifact.memory_region, artifact.source_artifact_id or "",
        "crypto_artifact", artifact.function_id, artifact.goroutine_id, artifact.network_artifact_id,
        artifact.credential_artifact_id, artifact.id, None,
        artifact.confidence, artifact.validation_status.value, artifact.extraction_method,
        artifact.go_version, artifact.architecture,
    )


def _persistence_candidate(artifact: PersistenceArtifact) -> _IOCCandidate | None:
    try:
        ioc_type = IOCType(artifact.artifact_type.value)
    except ValueError:
        return None
    return _IOCCandidate(
        ioc_type, IOCCategory.PERSISTENCE, artifact.raw_value, artifact.normalized_value, artifact.redacted_value,
        artifact.address, artifact.length, artifact.memory_region, artifact.source_artifact_id,
        "persistence_artifact", artifact.function_id, artifact.goroutine_id, artifact.network_artifact_id,
        artifact.credential_artifact_id, artifact.crypto_artifact_id, artifact.id,
        artifact.confidence, artifact.validation_status.value, artifact.extraction_method,
        artifact.go_version, artifact.architecture,
    )


@dataclass(frozen=True)
class IOCExtractionStats:
    """Per-process IOC-extraction counters (mirrors the Phase 6A-6D
    ``*AnalysisStats`` pattern)."""

    candidates_evaluated: int = 0
    iocs_extracted: int = 0
    unique_iocs: int = 0
    capped: bool = False
    iocs_by_type: dict[str, int] = field(default_factory=dict)


def extract_iocs(
    pid: int,
    process_name: str | None,
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
    crypto_artifacts: list[CryptoArtifact],
    persistence_artifacts: list[PersistenceArtifact],
) -> tuple[list[IOCArtifact], list[AnalysisError], IOCExtractionStats]:
    """Promote qualifying Phase 6A-6D artifacts into normalized
    :class:`IOCArtifact` records - 1:1 per source artifact, never merged
    (CLAUDE.md: never destroy distinct evidence locations). Records
    sharing the same real-world indicator share a ``dedup_key`` for
    reporting/grouping - see module docstring.
    """
    errors: list[AnalysisError] = []
    iocs: list[IOCArtifact] = []
    iocs_by_type: dict[str, int] = {}
    capped = False
    id_counter = count(1)

    candidates: list[_IOCCandidate] = []
    for builder, source_list in (
        (_network_candidate, network_artifacts),
        (_credential_candidate, credential_artifacts),
        (_crypto_candidate, crypto_artifacts),
        (_persistence_candidate, persistence_artifacts),
    ):
        for artifact in source_list:
            try:
                candidate = builder(artifact)
            except Exception as exc:  # one malformed artifact must not abort the rest
                errors.append(
                    AnalysisError(
                        component="analyzers.correlation",
                        message=f"IOC candidate construction failed unexpectedly: {exc}",
                        pid=pid,
                    )
                )
                continue
            if candidate is not None:
                candidates.append(candidate)

    dedup_keys: dict[str, list[Confidence]] = {}
    for candidate in candidates:
        key = _dedup_key(candidate.ioc_type, candidate.raw_value, candidate.normalized_value)
        dedup_keys.setdefault(key, []).append(candidate.confidence)

    for candidate in candidates:
        if len(iocs) >= MAX_IOCS_PER_PROCESS:
            capped = True
            break

        dedup_key = _dedup_key(candidate.ioc_type, candidate.raw_value, candidate.normalized_value)
        group_confidence = _combine_confidence(dedup_keys[dedup_key])
        artifact_id = f"IOC-{pid}-{next(id_counter):04d}"

        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type=f"ioc_{candidate.ioc_type.value}",
            analyzer="analyzers.correlation.extract_iocs",
            extraction_method="ioc_promotion",
            confidence=candidate.confidence,
            pid=pid,
            virtual_address=f"0x{candidate.address:x}" if candidate.address is not None else None,
            memory_region=candidate.memory_region,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=[candidate.source_artifact_id] if candidate.source_artifact_id else [],
        )
        iocs.append(
            IOCArtifact(
                id=artifact_id,
                pid=pid,
                process_name=process_name,
                ioc_type=candidate.ioc_type,
                ioc_category=candidate.ioc_category,
                raw_value=candidate.raw_value,
                normalized_value=candidate.normalized_value,
                redacted_value=candidate.redacted_value,
                address=candidate.address,
                length=candidate.length,
                memory_region=candidate.memory_region,
                source_artifact_id=candidate.source_artifact_id,
                source_artifact_type=candidate.source_artifact_type,
                dedup_key=dedup_key,
                function_id=candidate.function_id,
                goroutine_id=candidate.goroutine_id,
                related_network_artifact_id=candidate.network_artifact_id,
                related_credential_artifact_id=candidate.credential_artifact_id,
                related_crypto_artifact_id=candidate.crypto_artifact_id,
                related_persistence_artifact_id=candidate.persistence_artifact_id,
                confidence=candidate.confidence,
                validation_status=(
                    IOCValidationStatus.STRUCTURALLY_VALID
                    if candidate.validation_status == "structurally_valid"
                    else IOCValidationStatus.STRUCTURALLY_INCOMPLETE
                ),
                extraction_method=candidate.extraction_method,
                go_version=candidate.go_version,
                architecture=candidate.architecture,
                provenance=provenance,
                notes=(
                    f"Promoted from {candidate.source_artifact_type} (source_artifact_id="
                    f"{candidate.source_artifact_id!r}). This is an observed indicator, not a "
                    "malware verdict - see docs/architecture/go-ioc-correlation.md."
                ),
            )
        )
        type_key = candidate.ioc_type.value
        iocs_by_type[type_key] = iocs_by_type.get(type_key, 0) + 1

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.correlation",
                message=(
                    f"IOC cap ({MAX_IOCS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining candidates were not promoted (bounded analysis, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    # PARTIALLY_VALID upgrade: a dedup group containing both valid and
    # incomplete members is recorded as such on every member of that
    # group, without merging the members themselves.
    incomplete_keys = set()
    valid_keys = set()
    for ioc in iocs:
        if ioc.validation_status == IOCValidationStatus.STRUCTURALLY_INCOMPLETE:
            incomplete_keys.add(ioc.dedup_key)
        else:
            valid_keys.add(ioc.dedup_key)
    mixed_keys = incomplete_keys & valid_keys
    for ioc in iocs:
        if ioc.dedup_key in mixed_keys:
            ioc.validation_status = IOCValidationStatus.PARTIALLY_VALID

    stats = IOCExtractionStats(
        candidates_evaluated=len(candidates),
        iocs_extracted=len(iocs),
        unique_iocs=len({ioc.dedup_key for ioc in iocs}),
        capped=capped,
        iocs_by_type=iocs_by_type,
    )
    return iocs, errors, stats


# ---------------------------------------------------------------------------
# Correlation (stages 8-13) - operates on the original artifact graph,
# never on IOCs specifically, so it covers every recovered artifact
# whether or not it qualified for IOC promotion.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationStats:
    relationships_emitted: int = 0
    capped: bool = False
    relationships_by_type: dict[str, int] = field(default_factory=dict)


def correlate_artifacts(
    pid: int,
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
    crypto_artifacts: list[CryptoArtifact],
    persistence_artifacts: list[PersistenceArtifact],
) -> tuple[list[CorrelationRecord], list[AnalysisError], CorrelationStats]:
    """Emit explicit :class:`CorrelationRecord` edges for every already-
    existing evidence-chain field on the given artifacts - never a new
    inference, never memory-proximity or same-process/same-goroutine-
    alone correlation (stage 8's explicit prohibition).
    """
    errors: list[AnalysisError] = []
    records: list[CorrelationRecord] = []
    relationships_by_type: dict[str, int] = {}
    capped = False
    id_counter = count(1)

    #: (artifact, python_type_label, string_to_type, function_id, goroutine_id)
    derived = (
        (network_artifacts, "network_artifact", CorrelationType.STRING_TO_NETWORK),
        (credential_artifacts, "credential_artifact", CorrelationType.STRING_TO_CREDENTIAL),
        (crypto_artifacts, "crypto_artifact", CorrelationType.STRING_TO_CRYPTO),
        (persistence_artifacts, "persistence_artifact", CorrelationType.STRING_TO_PERSISTENCE),
    )

    def _emit(relationship_type: CorrelationType, source_id, source_type, target_id, target_type, evidence_basis) -> bool:
        nonlocal capped
        if len(records) >= MAX_CORRELATIONS_PER_PROCESS:
            capped = True
            return False
        record_id = f"CORR-{pid}-{next(id_counter):04d}"
        records.append(
            CorrelationRecord(
                id=record_id,
                pid=pid,
                relationship_type=relationship_type,
                source_id=str(source_id),
                source_type=source_type,
                target_id=str(target_id),
                target_type=target_type,
                evidence_basis=evidence_basis,
            )
        )
        relationships_by_type[relationship_type.value] = relationships_by_type.get(relationship_type.value, 0) + 1
        return True

    try:
        # STRING_TO_* and FUNCTION/GOROUTINE_REFERENCES_ARTIFACT: one pass
        # per already-recovered derived artifact, reading only its own
        # existing fields - O(N) total.
        source_groups: dict[str, list[tuple[str, str]]] = {}
        for artifact_list, type_label, string_edge_type in derived:
            for artifact in artifact_list:
                if not _emit(
                    string_edge_type, artifact.source_artifact_id, "string_artifact", artifact.id, type_label,
                    "shared source_artifact_id (StringArtifact -> derived artifact)",
                ):
                    break
                source_groups.setdefault(artifact.source_artifact_id, []).append((artifact.id, type_label))

                if artifact.function_id:
                    _emit(
                        CorrelationType.FUNCTION_REFERENCES_ARTIFACT, artifact.function_id, "function",
                        artifact.id, type_label, "artifact.function_id (Phase 4 call-site string_ref evidence)",
                    )
                if artifact.goroutine_id:
                    _emit(
                        CorrelationType.GOROUTINE_FRAME_REFERENCES_ARTIFACT, artifact.goroutine_id, "goroutine",
                        artifact.id, type_label, "artifact.goroutine_id (Phase 5 unwound-frame function_id evidence)",
                    )

        # NETWORK_TO_* / CREDENTIAL_TO_* / CRYPTO_TO_*: direct cross-
        # reference fields Phase 6B/6C/6D already populate - restated as
        # explicit edges, never re-derived from scratch.
        for artifact in credential_artifacts:
            if artifact.network_artifact_id:
                _emit(
                    CorrelationType.NETWORK_TO_CREDENTIAL, artifact.network_artifact_id, "network_artifact",
                    artifact.id, "credential_artifact", "credential_artifact.network_artifact_id (shared source string)",
                )
        for artifact in crypto_artifacts:
            if artifact.network_artifact_id:
                _emit(
                    CorrelationType.NETWORK_TO_CRYPTO, artifact.network_artifact_id, "network_artifact",
                    artifact.id, "crypto_artifact", "crypto_artifact.network_artifact_id (shared source string)",
                )
            if artifact.credential_artifact_id:
                _emit(
                    CorrelationType.CREDENTIAL_TO_CRYPTO, artifact.credential_artifact_id, "credential_artifact",
                    artifact.id, "crypto_artifact",
                    "crypto_artifact.credential_artifact_id (reused Phase 6B private-key evidence)",
                )
        for artifact in persistence_artifacts:
            if artifact.network_artifact_id:
                _emit(
                    CorrelationType.NETWORK_TO_PERSISTENCE, artifact.network_artifact_id, "network_artifact",
                    artifact.id, "persistence_artifact", "persistence_artifact.network_artifact_id (shared source string)",
                )
            if artifact.credential_artifact_id:
                _emit(
                    CorrelationType.CREDENTIAL_TO_PERSISTENCE, artifact.credential_artifact_id, "credential_artifact",
                    artifact.id, "persistence_artifact", "persistence_artifact.credential_artifact_id (shared source string)",
                )
            if artifact.crypto_artifact_id:
                _emit(
                    CorrelationType.CRYPTO_TO_PERSISTENCE, artifact.crypto_artifact_id, "crypto_artifact",
                    artifact.id, "persistence_artifact", "persistence_artifact.crypto_artifact_id (shared source string)",
                )

        # SAME_SOURCE_STRING: within each small group of derived artifacts
        # sharing one source string, emit pairwise edges - bounded per
        # group (MAX_SAME_SOURCE_GROUP_SIZE), never a cross-product across
        # the whole process's artifact population.
        for source_id, members in source_groups.items():
            if len(members) < 2:
                continue
            if len(members) > MAX_SAME_SOURCE_GROUP_SIZE:
                errors.append(
                    AnalysisError(
                        component="analyzers.correlation",
                        message=(
                            f"Source string {source_id} produced {len(members)} derived artifacts, "
                            f"exceeding the SAME_SOURCE_STRING pairwise-expansion bound "
                            f"({MAX_SAME_SOURCE_GROUP_SIZE}); pairwise edges skipped for this group "
                            "(bounded analysis, not a failure)"
                        ),
                        pid=pid,
                        recoverable=True,
                    )
                )
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    if not _emit(
                        CorrelationType.SAME_SOURCE_STRING, members[i][0], members[i][1], members[j][0], members[j][1],
                        "shared source_artifact_id across two derived artifacts",
                    ):
                        break
    except Exception as exc:  # a single process must never abort the whole run
        errors.append(
            AnalysisError(
                component="analyzers.correlation",
                message=f"Correlation failed unexpectedly: {exc}",
                pid=pid,
            )
        )

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.correlation",
                message=(
                    f"Correlation cap ({MAX_CORRELATIONS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining relationships were not emitted (bounded analysis, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    stats = CorrelationStats(
        relationships_emitted=len(records),
        capped=capped,
        relationships_by_type=relationships_by_type,
    )
    return records, errors, stats
