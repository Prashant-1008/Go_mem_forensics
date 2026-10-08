"""Phase 6F — Findings and evidence assessment.

Transforms already-recovered Phase 6E :class:`~gomemforensics.analyzers.models.IOCArtifact`
and :class:`~gomemforensics.analyzers.models.CorrelationRecord` objects
into structured :class:`~gomemforensics.analyzers.models.Finding` records.
This module implements **no new detection and no independent memory
scan** - it never imports :class:`~gomemforensics.common.memory.MemoryReader`,
never reads a raw :class:`~gomemforensics.go_runtime.models.StringArtifact`,
and consumes only IOCs and correlation records Phase 6E already produced
(stage 24: "If a required artifact does not exist: do not scan memory
again. Document the limitation.").

A Finding is an **evidence assessment**, never a malware verdict, malware
score, threat score, reputation result, automatic attribution, or a
claim that an artifact was actually used, contacted, executed,
downloaded, installed, authenticated, or that credentials were stolen
(CORE OBJECTIVE). Every Finding keeps ``observed_evidence`` (what was
directly recovered) and ``interpretation`` (the bounded reading of it)
as two separate fields - see the module-level rule tables below for the
exact, deterministic, inspectable wording each ``FindingType`` uses.

## Evidence rules (stage 7)

Each rule maps a specific, already-verified :class:`IOCType` (or
:class:`CorrelationType`) to exactly one :class:`FindingType` - no
finding is ever produced from an arbitrary string, address proximity,
process name, executable name, Go package name, or function name alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count

from gomemforensics.analyzers.models import (
    ArtifactProvenance,
    CorrelationRecord,
    CorrelationType,
    Finding,
    FindingSeverity,
    FindingType,
    FindingValidationStatus,
    IOCArtifact,
    IOCCategory,
    IOCType,
    IOCValidationStatus,
)
from gomemforensics.common.models import AnalysisError, Confidence

ANALYZER_VERSION = "analyzers.findings/1"

#: Safety bounds (mirrors Phase 6A-6E exactly - not a new invariant).
MAX_FINDINGS_PER_PROCESS = 5000

_CONFIDENCE_RANK = {Confidence.UNKNOWN: 0, Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}


def _combine_confidence(confidences: list[Confidence]) -> Confidence:
    """Identical rule to Phase 6E's own ``_combine_confidence`` (highest-
    ranked source wins, never averaged) - kept as a separate copy per
    module, matching the established Phase 6A-6E convention."""
    if not confidences:
        return Confidence.UNKNOWN
    return max(confidences, key=lambda c: _CONFIDENCE_RANK[c])


def _combine_validation(statuses: list[IOCValidationStatus]) -> FindingValidationStatus:
    values = {s.value for s in statuses}
    if values <= {"structurally_valid"}:
        return FindingValidationStatus.STRUCTURALLY_VALID
    if values <= {"structurally_incomplete"}:
        return FindingValidationStatus.STRUCTURALLY_INCOMPLETE
    return FindingValidationStatus.PARTIALLY_VALID


#: IOCType -> FindingType, evidence-rule tables (stage 7). Every IOCType
#: not listed here produces no finding - there is no fallback/default.
_NETWORK_RULES: dict[IOCType, FindingType] = {
    IOCType.IPV4: FindingType.NETWORK_IP_OBSERVED,
    IOCType.IPV6: FindingType.NETWORK_IP_OBSERVED,
    IOCType.HOSTNAME: FindingType.NETWORK_HOSTNAME_OBSERVED,
    IOCType.URL: FindingType.NETWORK_URL_OBSERVED,
    IOCType.HOST_PORT: FindingType.NETWORK_ENDPOINT_OBSERVED,
}
_CREDENTIAL_RULES: dict[IOCType, FindingType] = {
    IOCType.BEARER_TOKEN: FindingType.AUTHORIZATION_MATERIAL_OBSERVED,
    IOCType.BASIC_AUTH: FindingType.AUTHORIZATION_MATERIAL_OBSERVED,
    IOCType.COOKIE: FindingType.SESSION_MATERIAL_OBSERVED,
    IOCType.SESSION_TOKEN: FindingType.SESSION_MATERIAL_OBSERVED,
    IOCType.DATABASE_CREDENTIAL: FindingType.DATABASE_CREDENTIAL_OBSERVED,
    IOCType.JWT: FindingType.TOKEN_OBSERVED,
    IOCType.API_KEY: FindingType.TOKEN_OBSERVED,
    IOCType.CLOUD_CREDENTIAL: FindingType.TOKEN_OBSERVED,
}
_CRYPTO_RULES: dict[IOCType, FindingType] = {
    IOCType.PUBLIC_KEY: FindingType.CRYPTO_PUBLIC_KEY_OBSERVED,
    IOCType.PRIVATE_KEY: FindingType.CRYPTO_PRIVATE_KEY_OBSERVED,
    IOCType.CERTIFICATE: FindingType.CERTIFICATE_OBSERVED,
    IOCType.CERTIFICATE_CHAIN: FindingType.CERTIFICATE_OBSERVED,
    IOCType.CRYPTO_CONTEXT: FindingType.CRYPTO_CONTEXT_OBSERVED,
    IOCType.AES_KEY: FindingType.AES_KEY_OBSERVED,
}
_PERSISTENCE_TYPES = frozenset(
    {
        IOCType.WINDOWS_REGISTRY_RUN, IOCType.WINDOWS_WINLOGON, IOCType.WINDOWS_STARTUP_FOLDER,
        IOCType.WINDOWS_SCHEDULED_TASK_REFERENCE, IOCType.WINDOWS_SERVICE_REFERENCE,
        IOCType.WINDOWS_WMI_PERSISTENCE, IOCType.WINDOWS_APPINIT, IOCType.WINDOWS_IFEO,
        IOCType.LINUX_SYSTEMD_UNIT, IOCType.LINUX_CRON, IOCType.LINUX_SHELL_PROFILE,
        IOCType.LINUX_AUTOSTART, IOCType.LINUX_INIT_SCRIPT, IOCType.LINUX_AUTHORIZED_KEYS_PATH,
        IOCType.LINUX_AUTHORIZED_KEY_ENTRY, IOCType.LINUX_LOADER_PRELOAD,
    }
)

#: FindingType -> fixed severity (stage 16: forensic/reporting importance
#: only, never a maliciousness probability, never aggregated into an
#: overall process score). Documented per-type, not computed from any
#: "looks like malware" heuristic.
_SEVERITY_TABLE: dict[FindingType, FindingSeverity] = {
    FindingType.NETWORK_IP_OBSERVED: FindingSeverity.INFORMATIONAL,
    FindingType.NETWORK_HOSTNAME_OBSERVED: FindingSeverity.INFORMATIONAL,
    FindingType.NETWORK_URL_OBSERVED: FindingSeverity.INFORMATIONAL,
    FindingType.NETWORK_ENDPOINT_OBSERVED: FindingSeverity.INFORMATIONAL,
    FindingType.AUTHORIZATION_MATERIAL_OBSERVED: FindingSeverity.MEDIUM,
    FindingType.SESSION_MATERIAL_OBSERVED: FindingSeverity.MEDIUM,
    FindingType.DATABASE_CREDENTIAL_OBSERVED: FindingSeverity.MEDIUM,
    FindingType.TOKEN_OBSERVED: FindingSeverity.MEDIUM,
    FindingType.CRYPTO_PUBLIC_KEY_OBSERVED: FindingSeverity.LOW,
    FindingType.CERTIFICATE_OBSERVED: FindingSeverity.LOW,
    FindingType.CRYPTO_CONTEXT_OBSERVED: FindingSeverity.LOW,
    FindingType.CRYPTO_PRIVATE_KEY_OBSERVED: FindingSeverity.HIGH,
    FindingType.AES_KEY_OBSERVED: FindingSeverity.HIGH,
    FindingType.WINDOWS_PERSISTENCE_REFERENCE: FindingSeverity.MEDIUM,
    FindingType.LINUX_PERSISTENCE_REFERENCE: FindingSeverity.MEDIUM,
    FindingType.MULTI_ARTIFACT_EVIDENCE: FindingSeverity.MEDIUM,
    FindingType.SHARED_SOURCE_EVIDENCE: FindingSeverity.MEDIUM,
}

#: FindingType -> (title, observed_evidence template, interpretation) -
#: every description is evidence-accurate wording (stage 22), never a
#: behavioral claim.
_WORDING: dict[FindingType, tuple[str, str, str]] = {
    FindingType.NETWORK_IP_OBSERVED: (
        "Network IP address observed",
        "One or more IPv4/IPv6 address strings were recovered from process memory and classified as network artifacts.",
        "The process memory contains an observable IP address. This is not evidence that a network connection to it occurred.",
    ),
    FindingType.NETWORK_HOSTNAME_OBSERVED: (
        "Network hostname observed",
        "One or more hostname/domain strings were recovered from process memory and classified as network artifacts.",
        "The process memory contains an observable hostname. This is not evidence that DNS resolution or a connection occurred.",
    ),
    FindingType.NETWORK_URL_OBSERVED: (
        "Network URL observed",
        "One or more URL strings were recovered from process memory and classified as network artifacts.",
        "The process memory contains an observable URL. This is not evidence that an HTTP request was made.",
    ),
    FindingType.NETWORK_ENDPOINT_OBSERVED: (
        "Network endpoint (host:port) observed",
        "One or more host:port strings were recovered from process memory and classified as network artifacts.",
        "The process memory contains an observable network endpoint reference. This is not evidence of an established connection.",
    ),
    FindingType.AUTHORIZATION_MATERIAL_OBSERVED: (
        "Authorization material observed",
        "A Bearer-token or Basic-Auth-shaped string was recovered from process memory and classified as a credential artifact.",
        "The process memory contains observable authorization material. This is not evidence that authentication succeeded or that the material was transmitted.",
    ),
    FindingType.SESSION_MATERIAL_OBSERVED: (
        "Session material observed",
        "A cookie or session-token-shaped string was recovered from process memory and classified as a credential artifact.",
        "The process memory contains observable session material. This is not evidence of an active session.",
    ),
    FindingType.DATABASE_CREDENTIAL_OBSERVED: (
        "Database connection credential observed",
        "A database connection string containing embedded credential material was recovered and classified as a credential artifact.",
        "The process memory contains an observable database credential reference. This is not evidence that a database connection was made.",
    ),
    FindingType.TOKEN_OBSERVED: (
        "Token-shaped material observed",
        "A JWT-shaped, API-key-shaped, or cloud-credential-shaped string was recovered and classified as a credential artifact.",
        "The process memory contains observable token-shaped material. This is not evidence that the token is valid, live, or was used.",
    ),
    FindingType.CRYPTO_PUBLIC_KEY_OBSERVED: (
        "Public key material observed",
        "A PEM public-key boundary was recovered from process memory and classified as a crypto artifact.",
        "The process memory contains observable public-key material.",
    ),
    FindingType.CRYPTO_PRIVATE_KEY_OBSERVED: (
        "Private key material observed",
        "A PEM/SSH private-key boundary was recovered from process memory and classified as a crypto artifact (reused from Phase 6B credential evidence).",
        "The process memory contains observable private-key material. This is not evidence that the key was used to sign, decrypt, or authenticate anything.",
    ),
    FindingType.CERTIFICATE_OBSERVED: (
        "Certificate material observed",
        "A PEM certificate (or certificate chain) boundary was recovered from process memory and classified as a crypto artifact.",
        "The process memory contains observable certificate material. Certificate content (subject/issuer/validity) was not parsed.",
    ),
    FindingType.CRYPTO_CONTEXT_OBSERVED: (
        "Cryptographic algorithm/cipher-suite identifier observed",
        "A recognized algorithm or cipher-suite identifier string was recovered from process memory.",
        "The process memory references a cryptographic algorithm/cipher-suite name. This is not evidence that the algorithm was actually used.",
    ),
    FindingType.AES_KEY_OBSERVED: (
        "Evidence-backed AES key material observed",
        "A call-site argument matching crypto/aes.NewCipher's source-verified key-length requirement (16/24/32 bytes) was recovered.",
        "Key-shaped material was passed as an argument to a named AES constructor. This is not evidence that encryption actually occurred.",
    ),
    FindingType.WINDOWS_PERSISTENCE_REFERENCE: (
        "Windows persistence-related reference observed",
        "A string matching a Windows persistence-related registry path, startup path, service/scheduled-task/WMI reference, AppInit, or IFEO pattern was recovered.",
        "Persistence-related configuration reference observed in process memory. This is not proof that the registry key/service/task exists on the operating system or that persistence was established.",
    ),
    FindingType.LINUX_PERSISTENCE_REFERENCE: (
        "Linux persistence-related reference observed",
        "A string matching a Linux persistence-related systemd/cron/shell-profile/autostart/init-script/authorized_keys/LD_PRELOAD pattern was recovered.",
        "Persistence-related configuration reference observed in process memory. This is not proof that the unit/cron entry/autostart file exists on the operating system or that persistence was established.",
    ),
    FindingType.MULTI_ARTIFACT_EVIDENCE: (
        "Multiple artifact types share explicit evidence linkage",
        "Two artifacts of different categories (network/credential/crypto/persistence) are connected by an already-recorded cross-reference field.",
        "The linked artifacts share explicit evidence, not merely process membership. This is not evidence of a behavioral relationship (e.g. not evidence a credential was sent to a URL).",
    ),
    FindingType.SHARED_SOURCE_EVIDENCE: (
        "Multiple artifacts share the same source string",
        "Two or more derived artifacts were classified from the identical recovered Go string.",
        "The artifacts originate from the same evidence location. This is not evidence of a behavioral relationship between them.",
    ),
}


def _ioc_finding_type(ioc: IOCArtifact) -> FindingType | None:
    if ioc.ioc_category == IOCCategory.NETWORK:
        return _NETWORK_RULES.get(ioc.ioc_type)
    if ioc.ioc_category == IOCCategory.CREDENTIAL:
        return _CREDENTIAL_RULES.get(ioc.ioc_type)
    if ioc.ioc_category == IOCCategory.CRYPTO:
        return _CRYPTO_RULES.get(ioc.ioc_type)
    if ioc.ioc_category == IOCCategory.PERSISTENCE and ioc.ioc_type in _PERSISTENCE_TYPES:
        return FindingType.WINDOWS_PERSISTENCE_REFERENCE if ioc.ioc_type.value.startswith("windows_") else FindingType.LINUX_PERSISTENCE_REFERENCE
    return None


def _origin_artifact_id(ioc: IOCArtifact) -> str | None:
    """The id of the specific Phase 6A-6D artifact this IOC was promoted
    from (each analyzer's candidate builder self-references its own
    origin id into the matching ``related_*_artifact_id`` slot - see
    :mod:`gomemforensics.analyzers.correlation`)."""
    if ioc.ioc_category == IOCCategory.NETWORK:
        return ioc.related_network_artifact_id
    if ioc.ioc_category == IOCCategory.CREDENTIAL:
        return ioc.related_credential_artifact_id
    if ioc.ioc_category == IOCCategory.CRYPTO:
        return ioc.related_crypto_artifact_id
    if ioc.ioc_category == IOCCategory.PERSISTENCE:
        return ioc.related_persistence_artifact_id
    return None


@dataclass(frozen=True)
class FindingStats:
    """Per-process finding-generation counters (mirrors the Phase 6A-6E
    ``*AnalysisStats``/``*Stats`` pattern)."""

    iocs_evaluated: int = 0
    correlations_evaluated: int = 0
    findings_generated: int = 0
    capped: bool = False
    findings_by_type: dict[str, int] = field(default_factory=dict)


def generate_findings(
    pid: int,
    process_name: str | None,
    iocs: list[IOCArtifact],
    correlations: list[CorrelationRecord],
) -> tuple[list[Finding], list[AnalysisError], FindingStats]:
    """Generate deterministic :class:`Finding` records for one process
    from its already-recovered IOCs and correlation records.

    Two independent rule families (stage 17's "deterministic rule
    engine", never ML, never an opaque heuristic):

    1. **IOC-based findings**: every IOC whose type is in the stage-7
       evidence-rule tables above contributes to exactly one Finding per
       ``(finding_type, dedup_key)`` group - deduplicated by reusing
       Phase 6E's own ``dedup_key`` (stage 18), never a new grouping
       mechanism.
    2. **Correlation-based findings**: every ``CorrelationRecord`` of
       type ``SAME_SOURCE_STRING`` or one of the six ``*_TO_*`` types
       whose *both* endpoints correspond to an already-promoted IOC
       contributes one Finding (an edge touching a non-IOC-eligible
       artifact, e.g. a raw ``PASSWORD`` credential, produces no
       finding - the underlying ``CorrelationRecord`` remains available
       in the JSON output regardless, stage 12).
    """
    errors: list[AnalysisError] = []
    findings: list[Finding] = []
    findings_by_type: dict[str, int] = {}
    capped = False
    id_counter = count(1)

    def _next_id() -> str:
        return f"FINDING-{pid}-{next(id_counter):04d}"

    def _record(
        finding_type: FindingType,
        confidence: Confidence,
        validation_status: FindingValidationStatus,
        supporting_artifact_ids: list[str],
        supporting_ioc_ids: list[str],
        supporting_correlation_ids: list[str],
        function_ids: list[str],
        goroutine_ids: list[str],
        platform: str | None,
        go_version: str | None,
        architecture: str,
    ) -> bool:
        nonlocal capped
        if len(findings) >= MAX_FINDINGS_PER_PROCESS:
            capped = True
            return False
        title, observed_evidence, interpretation = _WORDING[finding_type]
        # ``description`` is the human-facing summary combining both
        # parts; ``observed_evidence``/``interpretation`` remain the
        # separate, independently-inspectable fields stage 6 requires -
        # never collapsed into one sentence that could be misread as a
        # single behavioral claim.
        description = f"{observed_evidence} {interpretation}"
        finding_id = _next_id()
        related = sorted(set(supporting_artifact_ids)) + sorted(set(supporting_ioc_ids)) + sorted(set(supporting_correlation_ids))
        provenance = ArtifactProvenance(
            artifact_id=finding_id,
            artifact_type=f"finding_{finding_type.value}",
            analyzer="analyzers.findings.generate_findings",
            extraction_method="finding_rule_evaluation",
            confidence=confidence,
            pid=pid,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=related,
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                pid=pid,
                process_name=process_name,
                finding_type=finding_type,
                title=title,
                description=description,
                observed_evidence=observed_evidence,
                interpretation=interpretation,
                confidence=confidence,
                validation_status=validation_status,
                severity=_SEVERITY_TABLE[finding_type],
                supporting_artifact_ids=sorted(set(supporting_artifact_ids)),
                supporting_ioc_ids=sorted(set(supporting_ioc_ids)),
                supporting_correlation_ids=sorted(set(supporting_correlation_ids)),
                function_ids=sorted({f for f in function_ids if f}),
                goroutine_ids=sorted({g for g in goroutine_ids if g}),
                platform=platform,
                go_version=go_version,
                architecture=architecture,
                extraction_method="finding_rule_evaluation",
                provenance=provenance,
                notes=(
                    f"{interpretation} See docs/architecture/go-findings.md for the full evidence "
                    "rule and prohibited-inference list for this finding type."
                ),
            )
        )
        findings_by_type[finding_type.value] = findings_by_type.get(finding_type.value, 0) + 1
        return True

    try:
        # --- IOC-based findings: group by (finding_type, dedup_key) ---
        groups: dict[tuple[FindingType, str], list[IOCArtifact]] = {}
        for ioc in iocs:
            finding_type = _ioc_finding_type(ioc)
            if finding_type is None:
                continue
            groups.setdefault((finding_type, ioc.dedup_key), []).append(ioc)

        for (finding_type, _dedup_key), members in groups.items():
            platform = "windows" if finding_type == FindingType.WINDOWS_PERSISTENCE_REFERENCE else (
                "linux" if finding_type == FindingType.LINUX_PERSISTENCE_REFERENCE else None
            )
            if not _record(
                finding_type,
                _combine_confidence([m.confidence for m in members]),
                _combine_validation([m.validation_status for m in members]),
                [m.source_artifact_id for m in members],
                [m.id for m in members],
                [],
                [m.function_id for m in members if m.function_id],
                [m.goroutine_id for m in members if m.goroutine_id],
                platform,
                members[0].go_version,
                members[0].architecture,
            ):
                break

        # --- Correlation-based findings: both endpoints must be IOCs ---
        iocs_by_origin_artifact_id = {aid: ioc for ioc in iocs if (aid := _origin_artifact_id(ioc)) is not None}
        _CORRELATION_FINDING_TYPES = {
            CorrelationType.SAME_SOURCE_STRING: FindingType.SHARED_SOURCE_EVIDENCE,
            CorrelationType.NETWORK_TO_CREDENTIAL: FindingType.MULTI_ARTIFACT_EVIDENCE,
            CorrelationType.NETWORK_TO_CRYPTO: FindingType.MULTI_ARTIFACT_EVIDENCE,
            CorrelationType.NETWORK_TO_PERSISTENCE: FindingType.MULTI_ARTIFACT_EVIDENCE,
            CorrelationType.CREDENTIAL_TO_CRYPTO: FindingType.MULTI_ARTIFACT_EVIDENCE,
            CorrelationType.CREDENTIAL_TO_PERSISTENCE: FindingType.MULTI_ARTIFACT_EVIDENCE,
            CorrelationType.CRYPTO_TO_PERSISTENCE: FindingType.MULTI_ARTIFACT_EVIDENCE,
        }
        for record in correlations:
            finding_type = _CORRELATION_FINDING_TYPES.get(record.relationship_type)
            if finding_type is None:
                continue
            source_ioc = iocs_by_origin_artifact_id.get(record.source_id)
            target_ioc = iocs_by_origin_artifact_id.get(record.target_id)
            if source_ioc is None or target_ioc is None:
                continue  # an endpoint is not IOC-eligible - no finding, per module docstring
            if not _record(
                finding_type,
                _combine_confidence([source_ioc.confidence, target_ioc.confidence]),
                _combine_validation([source_ioc.validation_status, target_ioc.validation_status]),
                [source_ioc.source_artifact_id, target_ioc.source_artifact_id],
                [source_ioc.id, target_ioc.id],
                [record.id],
                [f for f in (source_ioc.function_id, target_ioc.function_id) if f],
                [g for g in (source_ioc.goroutine_id, target_ioc.goroutine_id) if g],
                None,
                source_ioc.go_version,
                source_ioc.architecture,
            ):
                break
    except Exception as exc:  # a single process must never abort the whole run
        errors.append(
            AnalysisError(
                component="analyzers.findings",
                message=f"Finding generation failed unexpectedly: {exc}",
                pid=pid,
            )
        )

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.findings",
                message=(
                    f"Finding cap ({MAX_FINDINGS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining candidates were not recorded (bounded analysis, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    stats = FindingStats(
        iocs_evaluated=len(iocs),
        correlations_evaluated=len(correlations),
        findings_generated=len(findings),
        capped=capped,
        findings_by_type=findings_by_type,
    )
    return findings, errors, stats
