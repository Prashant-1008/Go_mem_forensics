"""Analysis pipeline orchestration.

Wires together evidence validation, Volatility initialization, OS/
architecture detection, process enumeration, and (as of Phase 2) per-process
Go runtime detection into the behavior behind ``gomemforensics analyze``.
This module still contains no string/function/goroutine recovery, IOC
extraction, correlation, or reporting beyond plain JSON - all later-phase
work per the approved plan.
"""

from __future__ import annotations

import json
import platform as platform_module
from dataclasses import asdict, dataclass, field
from itertools import count
from pathlib import Path

from gomemforensics import __version__
from gomemforensics.acquisition.evidence import EvidenceMetadata, EvidenceValidator
from gomemforensics.analyzers.correlation import (
    CorrelationStats,
    IOCExtractionStats,
    correlate_artifacts,
    extract_iocs,
)
from gomemforensics.analyzers.credentials import CredentialAnalysisStats, extract_credential_artifacts
from gomemforensics.analyzers.crypto import CryptoAnalysisStats, extract_crypto_artifacts
from gomemforensics.analyzers.findings import FindingStats, generate_findings
from gomemforensics.analyzers.models import (
    CorrelationRecord,
    CredentialArtifact,
    CryptoArtifact,
    Finding,
    IOCArtifact,
    NetworkArtifact,
    PersistenceArtifact,
)
from gomemforensics.analyzers.network import NetworkAnalysisStats, extract_network_artifacts
from gomemforensics.analyzers.persistence import PersistenceAnalysisStats, extract_persistence_artifacts
from gomemforensics.architecture.x86_64 import is_register_based_abi
from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisError, AnalysisStatistics, Confidence, FailureReason, ProcessInfo
from gomemforensics.common.utils import utc_now_iso
from gomemforensics.go_runtime import backward_analysis
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.functab import FunctionIndex, FunctionTableParser
from gomemforensics.go_runtime.goroutines import GoroutineRecoveryEngine
from gomemforensics.go_runtime.models import (
    FunctionArtifact,
    GoroutineArtifact,
    GoroutineRecoveryStats,
    GoRuntime,
    PclntabCandidate,
    StringArtifact,
)
from gomemforensics.go_runtime.stack_unwind import unwind_goroutine
from gomemforensics.go_runtime.strings import StringRecoveryEngine
from gomemforensics.volatility.integration import VolatilityIntegration, probe_dependencies
from gomemforensics.volatility.runner import VolatilityInitializationError

logger = get_logger("pipeline")


@dataclass
class AnalysisResult:
    """Full analysis result: evidence + environment + system + processes +
    Go runtimes/candidates + errors."""

    case_id: str | None
    evidence: EvidenceMetadata
    environment: dict
    os: str
    architecture: str
    processes: list[ProcessInfo]
    errors: list[AnalysisError]
    statistics: AnalysisStatistics
    go_runtimes: list[GoRuntime] = field(default_factory=list)
    go_candidates: list[PclntabCandidate] = field(default_factory=list)
    strings: list[StringArtifact] = field(default_factory=list)
    functions: list[FunctionArtifact] = field(default_factory=list)
    goroutines: list[GoroutineArtifact] = field(default_factory=list)
    network_artifacts: list[NetworkArtifact] = field(default_factory=list)
    credential_artifacts: list[CredentialArtifact] = field(default_factory=list)
    crypto_artifacts: list[CryptoArtifact] = field(default_factory=list)
    persistence_artifacts: list[PersistenceArtifact] = field(default_factory=list)
    iocs: list[IOCArtifact] = field(default_factory=list)
    correlations: list[CorrelationRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_json_dict(self) -> dict:
        """Build the stable JSON structure.

        Top-level shape matches the approved plan:
        ``{case, evidence, environment, system, processes, go_runtimes,
        go_candidates, strings, functions, goroutines, errors,
        statistics}``.
        """
        evidence = self.evidence
        return {
            "case": {"case_id": self.case_id},
            "evidence": {
                "input_path": str(evidence.input_path),
                "file_name": evidence.file_name,
                "file_size": evidence.file_size,
                "sha256": evidence.sha256,
                "hash_algorithm": evidence.hash_algorithm,
                "analysis_timestamp": evidence.analysis_timestamp,
                "read_only": evidence.read_only,
            },
            "environment": self.environment,
            "system": {"os": self.os, "architecture": self.architecture},
            "processes": [asdict(process) for process in self.processes],
            "go_runtimes": [runtime.to_json_dict() for runtime in self.go_runtimes],
            "go_candidates": [candidate.to_json_dict() for candidate in self.go_candidates],
            "strings": [artifact.to_json_dict() for artifact in self.strings],
            "functions": [artifact.to_json_dict() for artifact in self.functions],
            "goroutines": [artifact.to_json_dict() for artifact in self.goroutines],
            "network_artifacts": [artifact.to_json_dict() for artifact in self.network_artifacts],
            "credential_artifacts": [artifact.to_json_dict() for artifact in self.credential_artifacts],
            "crypto_artifacts": [artifact.to_json_dict() for artifact in self.crypto_artifacts],
            "persistence_artifacts": [artifact.to_json_dict() for artifact in self.persistence_artifacts],
            "iocs": [artifact.to_json_dict() for artifact in self.iocs],
            "correlations": [record.to_json_dict() for record in self.correlations],
            "findings": [finding.to_json_dict() for finding in self.findings],
            "errors": [asdict(error) for error in self.errors],
            "statistics": asdict(self.statistics),
        }

    def write_json(self, output_path: Path) -> None:
        """Serialize this result to ``output_path`` as indented, deterministic JSON.

        Creates parent directories as needed. Never writes into the
        evidence file's own directory automatically - callers are
        responsible for choosing an output path outside of it (the CLI
        defaults to ``reports/analysis.json``).
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_json_dict(), handle, indent=2, default=str)
            handle.write("\n")


def _build_environment_info() -> dict:
    deps = probe_dependencies()
    return {
        "tool_version": __version__,
        "python_version": platform_module.python_version(),
        "platform": f"{platform_module.system()} {platform_module.release()}",
        "volatility_version": deps.volatility3.version,
        "capstone_version": deps.capstone.version,
        "analysis_timestamp": utc_now_iso(),
    }


#: Pointer size fallback used only when architecture detection itself came
#: back "unknown" - Go runtime detection is skipped entirely in that case
#: (see run_analysis), so this value is never actually used to interpret
#: memory; it exists only to satisfy GoProcessDetector's type signature.
_ARCHITECTURE_POINTER_SIZES = {"x86_64": 8, "x86": 4, "arm64": 8}


def run_analysis(image_path: Path, case_id: str | None = None) -> AnalysisResult:
    """Run the full pipeline: evidence -> Volatility -> OS/arch -> processes -> Go runtimes.

    Evidence validation failures (missing file, not a regular file, I/O
    error) propagate to the caller as
    :class:`gomemforensics.acquisition.evidence.EvidenceValidationError` -
    there is no meaningful partial result without valid evidence.

    Volatility initialization failure (image unsupported/corrupted, or not
    a currently-targeted OS) does NOT raise: it is recorded as a
    non-recoverable :class:`AnalysisError` so a forensically complete report
    is still produced (evidence hash, environment, the failure itself), with
    ``os``/``architecture`` left ``"unknown"`` and no processes. Callers
    (the CLI) must inspect the returned result's errors to decide whether to
    report the run as failed.

    Go runtime detection (Phase 2) is attempted for every enumerated
    process that has an accessible memory layer; one process's detection
    failing never aborts detection for the rest (CLAUDE.md section 24).
    """
    evidence = EvidenceValidator().validate(image_path, case_id=case_id)
    environment = _build_environment_info()

    errors: list[AnalysisError] = []
    processes: list[ProcessInfo] = []
    go_runtimes: list[GoRuntime] = []
    go_candidates: list[PclntabCandidate] = []
    strings: list[StringArtifact] = []
    functions: list[FunctionArtifact] = []
    goroutines: list[GoroutineArtifact] = []
    network_artifacts: list[NetworkArtifact] = []
    credential_artifacts: list[CredentialArtifact] = []
    crypto_artifacts: list[CryptoArtifact] = []
    persistence_artifacts: list[PersistenceArtifact] = []
    iocs: list[IOCArtifact] = []
    correlations: list[CorrelationRecord] = []
    findings: list[Finding] = []
    goroutine_stats_totals: list[GoroutineRecoveryStats] = []
    network_stats_totals: list[NetworkAnalysisStats] = []
    credential_stats_totals: list[CredentialAnalysisStats] = []
    crypto_stats_totals: list[CryptoAnalysisStats] = []
    persistence_stats_totals: list[PersistenceAnalysisStats] = []
    ioc_stats_totals: list[IOCExtractionStats] = []
    correlation_stats_totals: list[CorrelationStats] = []
    finding_stats_totals: list[FindingStats] = []
    os_name = "unknown"
    architecture = "unknown"

    integration = VolatilityIntegration()
    try:
        integration.initialize(image_path)
    except VolatilityInitializationError as exc:
        logger.error("Volatility initialization failed: %s", exc)
        errors.append(
            AnalysisError(
                component="volatility.integration.initialize",
                message=str(exc),
                recoverable=False,
                reason=FailureReason.VOLATILITY_UNSUPPORTED,
            )
        )
    else:
        os_name = integration.detect_os()
        architecture = integration.detect_architecture()
        processes, process_errors = integration.enumerate_processes()
        errors.extend(process_errors)

        pointer_size = _ARCHITECTURE_POINTER_SIZES.get(architecture)
        if pointer_size is not None:
            detector = GoProcessDetector()
            for process in processes:
                if not process.memory_layer_available:
                    continue
                reader = integration.get_process_memory(process.pid)
                if reader is None:
                    continue
                regions = integration.get_process_regions(process.pid)

                result = detector.detect(process.pid, architecture, pointer_size, reader, regions)
                errors.extend(result.errors)
                go_candidates.extend(result.pclntab_candidates)

                if result.runtime is not None:
                    go_runtimes.append(result.runtime)
                    process.go_confidence = result.runtime.confidence
                    process.go_version = result.runtime.go_version
                    process.go_runtime_id = result.runtime.runtime_id
                    process.is_go_candidate = result.runtime.confidence in (
                        Confidence.HIGH,
                        Confidence.MEDIUM,
                    )

                    # String recovery (Phase 3) only runs for a process
                    # that at least has a recovered runtime - a failure to
                    # recover heap strings never blocks static recovery,
                    # and neither ever blocks the rest of the pipeline.
                    string_engine = StringRecoveryEngine(reader, pointer_size)
                    heap_strings, heap_errors = string_engine.recover_heap_strings(result.runtime, regions)
                    static_strings, static_errors = string_engine.recover_static_strings(result.runtime, regions)
                    strings.extend(heap_strings)
                    strings.extend(static_strings)
                    errors.extend(heap_errors)
                    errors.extend(static_errors)

                    # Function recovery (Phase 4) - a failure here never
                    # blocks analysis of any other process (CLAUDE.md
                    # section 24); everything is caught inside
                    # _recover_functions.
                    process_strings = heap_strings + static_strings
                    function_artifacts, function_errors = _recover_functions(
                        reader, pointer_size, result.runtime, process_strings, process.pid
                    )
                    functions.extend(function_artifacts)
                    errors.extend(function_errors)

                    # Goroutine recovery (Phase 5) - reuses the just-recovered
                    # function metadata; a failure here never blocks any
                    # other process (CLAUDE.md section 24), everything is
                    # caught inside _recover_goroutines.
                    goroutine_artifacts, goroutine_errors, goroutine_stats = _recover_goroutines(
                        reader, pointer_size, result.runtime, function_artifacts, regions, process.pid
                    )
                    goroutines.extend(goroutine_artifacts)
                    errors.extend(goroutine_errors)
                    goroutine_stats_totals.append(goroutine_stats)

                    # Network artifact extraction (Phase 6A) - reuses the
                    # just-recovered strings/functions/goroutines only;
                    # never an independent memory scan. A failure here
                    # never blocks any other process (CLAUDE.md section
                    # 24), everything is caught inside
                    # _recover_network_artifacts.
                    net_artifacts, net_errors, net_stats = _recover_network_artifacts(
                        process.pid,
                        process.name,
                        result.runtime.go_version,
                        architecture,
                        process_strings,
                        function_artifacts,
                        goroutine_artifacts,
                    )
                    network_artifacts.extend(net_artifacts)
                    errors.extend(net_errors)
                    network_stats_totals.append(net_stats)

                    # Credential/secret artifact extraction (Phase 6B) -
                    # reuses strings/functions/goroutines/network
                    # artifacts just recovered for this process only;
                    # never an independent memory scan. A failure here
                    # never blocks any other process (CLAUDE.md section
                    # 24), everything is caught inside
                    # _recover_credential_artifacts.
                    cred_artifacts, cred_errors, cred_stats = _recover_credential_artifacts(
                        process.pid,
                        process.name,
                        result.runtime.go_version,
                        architecture,
                        process_strings,
                        function_artifacts,
                        goroutine_artifacts,
                        net_artifacts,
                    )
                    credential_artifacts.extend(cred_artifacts)
                    errors.extend(cred_errors)
                    credential_stats_totals.append(cred_stats)

                    # Cryptographic artifact extraction (Phase 6C) -
                    # reuses strings/functions/goroutines/network/
                    # credential artifacts just recovered for this
                    # process only; never an independent memory scan. A
                    # failure here never blocks any other process
                    # (CLAUDE.md section 24), everything is caught inside
                    # _recover_crypto_artifacts.
                    crypto_artifact_list, crypto_errors, crypto_stats = _recover_crypto_artifacts(
                        process.pid,
                        process.name,
                        result.runtime.go_version,
                        architecture,
                        process_strings,
                        function_artifacts,
                        goroutine_artifacts,
                        net_artifacts,
                        cred_artifacts,
                    )
                    crypto_artifacts.extend(crypto_artifact_list)
                    errors.extend(crypto_errors)
                    crypto_stats_totals.append(crypto_stats)

                    # Persistence artifact extraction (Phase 6D) - reuses
                    # strings/functions/goroutines/network/credential/
                    # crypto artifacts just recovered for this process
                    # only; never an independent memory scan, never a
                    # filesystem/registry/SCM/task-scheduler access. A
                    # failure here never blocks any other process
                    # (CLAUDE.md section 24), everything is caught inside
                    # _recover_persistence_artifacts.
                    persist_artifact_list, persist_errors, persist_stats = _recover_persistence_artifacts(
                        process.pid,
                        process.name,
                        result.runtime.go_version,
                        architecture,
                        process_strings,
                        function_artifacts,
                        goroutine_artifacts,
                        net_artifacts,
                        cred_artifacts,
                        crypto_artifact_list,
                    )
                    persistence_artifacts.extend(persist_artifact_list)
                    errors.extend(persist_errors)
                    persistence_stats_totals.append(persist_stats)

                    # IOC extraction + cross-artifact correlation
                    # (Phase 6E) - reuses network/credential/crypto/
                    # persistence artifacts just recovered for this
                    # process only; never an independent memory scan,
                    # never a new detector. A failure here never blocks
                    # any other process (CLAUDE.md section 24).
                    process_iocs, ioc_errors, ioc_stats = _recover_iocs(
                        process.pid, process.name, net_artifacts, cred_artifacts, crypto_artifact_list, persist_artifact_list
                    )
                    iocs.extend(process_iocs)
                    errors.extend(ioc_errors)
                    ioc_stats_totals.append(ioc_stats)

                    process_correlations, corr_errors, corr_stats = _recover_correlations(
                        process.pid,
                        function_artifacts,
                        goroutine_artifacts,
                        net_artifacts,
                        cred_artifacts,
                        crypto_artifact_list,
                        persist_artifact_list,
                    )
                    correlations.extend(process_correlations)
                    errors.extend(corr_errors)
                    correlation_stats_totals.append(corr_stats)

                    # Finding generation (Phase 6F) - reuses the IOCs and
                    # correlations just recovered for this process only;
                    # never an independent memory scan, never a new
                    # detector. A failure here never blocks any other
                    # process (CLAUDE.md section 24).
                    process_findings, finding_errors, finding_stats = _recover_findings(
                        process.pid, process.name, process_iocs, process_correlations
                    )
                    findings.extend(process_findings)
                    errors.extend(finding_errors)
                    finding_stats_totals.append(finding_stats)
        else:
            logger.debug("Skipping Go runtime detection: unknown architecture %r", architecture)

    _link_shared_backing_strings(strings)

    functions_by_classification: dict[str, int] = {}
    for func in functions:
        key = f"functions_{func.classification.value}"
        functions_by_classification[key] = functions_by_classification.get(key, 0) + 1
    call_sites_analyzed = sum(len(f.recovered_call_sites) for f in functions)
    arguments_recovered = sum(
        len(cs.recovered_arguments) for f in functions for cs in f.recovered_call_sites
    )

    goroutines_by_status: dict[str, int] = {}
    for g in goroutines:
        key = f"goroutines_status_{g.status_name or 'unknown'}"
        goroutines_by_status[key] = goroutines_by_status.get(key, 0) + 1
    frames_recovered = sum(len(g.frames) for g in goroutines)
    unwind_complete = sum(1 for g in goroutines if g.unwind_status.value == "complete")
    unwind_failures = sum(1 for g in goroutines if g.unwind_status.value not in ("complete", "not_attempted"))
    unwind_unsupported = sum(1 for g in goroutines if g.unwind_status.value == "unsupported_frame")
    candidates_scanned = sum(s.candidates_scanned for s in goroutine_stats_totals)
    invalid_candidates = sum(s.invalid_candidates for s in goroutine_stats_totals)

    network_artifacts_by_type: dict[str, int] = {}
    for stats_entry in network_stats_totals:
        for type_key, type_count in stats_entry.artifacts_by_type.items():
            key = f"network_artifacts_{type_key}"
            network_artifacts_by_type[key] = network_artifacts_by_type.get(key, 0) + type_count
    network_strings_scanned = sum(s.strings_scanned for s in network_stats_totals)
    network_strings_skipped_length_bound = sum(s.strings_skipped_length_bound for s in network_stats_totals)
    network_capped_processes = sum(1 for s in network_stats_totals if s.capped)

    credential_artifacts_by_type: dict[str, int] = {}
    for stats_entry in credential_stats_totals:
        for type_key, type_count in stats_entry.artifacts_by_type.items():
            key = f"credential_artifacts_{type_key}"
            credential_artifacts_by_type[key] = credential_artifacts_by_type.get(key, 0) + type_count
    credential_strings_scanned = sum(s.strings_scanned for s in credential_stats_totals)
    credential_strings_skipped_length_bound = sum(s.strings_skipped_length_bound for s in credential_stats_totals)
    credential_capped_processes = sum(1 for s in credential_stats_totals if s.capped)

    crypto_artifacts_by_type: dict[str, int] = {}
    for stats_entry in crypto_stats_totals:
        for type_key, type_count in stats_entry.artifacts_by_type.items():
            key = f"crypto_artifacts_{type_key}"
            crypto_artifacts_by_type[key] = crypto_artifacts_by_type.get(key, 0) + type_count
    crypto_strings_scanned = sum(s.strings_scanned for s in crypto_stats_totals)
    crypto_credential_artifacts_reused = sum(s.credential_artifacts_reused for s in crypto_stats_totals)
    crypto_call_sites_evaluated = sum(s.call_sites_evaluated for s in crypto_stats_totals)
    crypto_capped_processes = sum(1 for s in crypto_stats_totals if s.capped)

    persistence_artifacts_by_type: dict[str, int] = {}
    for stats_entry in persistence_stats_totals:
        for type_key, type_count in stats_entry.artifacts_by_type.items():
            key = f"persistence_artifacts_{type_key}"
            persistence_artifacts_by_type[key] = persistence_artifacts_by_type.get(key, 0) + type_count
    persistence_strings_scanned = sum(s.strings_scanned for s in persistence_stats_totals)
    persistence_capped_processes = sum(1 for s in persistence_stats_totals if s.capped)

    ioc_iocs_by_type: dict[str, int] = {}
    for stats_entry in ioc_stats_totals:
        for type_key, type_count in stats_entry.iocs_by_type.items():
            key = f"iocs_{type_key}"
            ioc_iocs_by_type[key] = ioc_iocs_by_type.get(key, 0) + type_count
    ioc_candidates_evaluated = sum(s.candidates_evaluated for s in ioc_stats_totals)
    ioc_unique_iocs = sum(s.unique_iocs for s in ioc_stats_totals)
    ioc_capped_processes = sum(1 for s in ioc_stats_totals if s.capped)

    correlation_relationships_by_type: dict[str, int] = {}
    for stats_entry in correlation_stats_totals:
        for type_key, type_count in stats_entry.relationships_by_type.items():
            key = f"correlations_{type_key}"
            correlation_relationships_by_type[key] = correlation_relationships_by_type.get(key, 0) + type_count
    correlation_capped_processes = sum(1 for s in correlation_stats_totals if s.capped)

    finding_findings_by_type: dict[str, int] = {}
    for stats_entry in finding_stats_totals:
        for type_key, type_count in stats_entry.findings_by_type.items():
            key = f"findings_{type_key}"
            finding_findings_by_type[key] = finding_findings_by_type.get(key, 0) + type_count
    finding_capped_processes = sum(1 for s in finding_stats_totals if s.capped)

    statistics = AnalysisStatistics(
        processes_discovered=len(processes),
        processes_with_memory_access=sum(1 for p in processes if p.memory_layer_available),
        processes_failed=sum(
            1 for e in errors if e.component == "volatility.integration.enumerate_processes"
        ),
        errors_count=len(errors),
        go_candidate_processes=sum(1 for p in processes if p.is_go_candidate),
        go_runtimes_reconstructed=len(go_runtimes),
        strings_recovered=len(strings),
        strings_recovered_heap=sum(1 for s in strings if s.region == "heap"),
        strings_recovered_static=sum(1 for s in strings if s.region == "static"),
        extra={
            "functions_recovered": len(functions),
            "call_sites_analyzed": call_sites_analyzed,
            "arguments_recovered": arguments_recovered,
            **functions_by_classification,
            "goroutines_discovered": len(goroutines),
            "goroutine_candidates_scanned": candidates_scanned,
            "goroutine_invalid_candidates": invalid_candidates,
            "goroutine_frames_recovered": frames_recovered,
            "goroutine_unwind_complete": unwind_complete,
            "goroutine_unwind_failures": unwind_failures,
            "goroutine_unwind_unsupported": unwind_unsupported,
            **goroutines_by_status,
            "network_artifacts_extracted": len(network_artifacts),
            "network_strings_scanned": network_strings_scanned,
            "network_strings_skipped_length_bound": network_strings_skipped_length_bound,
            "network_capped_processes": network_capped_processes,
            **network_artifacts_by_type,
            "credential_artifacts_extracted": len(credential_artifacts),
            "credential_strings_scanned": credential_strings_scanned,
            "credential_strings_skipped_length_bound": credential_strings_skipped_length_bound,
            "credential_capped_processes": credential_capped_processes,
            **credential_artifacts_by_type,
            "crypto_artifacts_extracted": len(crypto_artifacts),
            "crypto_strings_scanned": crypto_strings_scanned,
            "crypto_credential_artifacts_reused": crypto_credential_artifacts_reused,
            "crypto_call_sites_evaluated": crypto_call_sites_evaluated,
            "crypto_capped_processes": crypto_capped_processes,
            **crypto_artifacts_by_type,
            "persistence_artifacts_extracted": len(persistence_artifacts),
            "persistence_strings_scanned": persistence_strings_scanned,
            "persistence_capped_processes": persistence_capped_processes,
            **persistence_artifacts_by_type,
            "iocs_extracted": len(iocs),
            "iocs_unique": ioc_unique_iocs,
            "ioc_candidates_evaluated": ioc_candidates_evaluated,
            "ioc_capped_processes": ioc_capped_processes,
            **ioc_iocs_by_type,
            "correlations_emitted": len(correlations),
            "correlation_capped_processes": correlation_capped_processes,
            **correlation_relationships_by_type,
            "findings_generated": len(findings),
            "finding_capped_processes": finding_capped_processes,
            **finding_findings_by_type,
        },
    )

    return AnalysisResult(
        case_id=case_id,
        evidence=evidence,
        environment=environment,
        os=os_name,
        architecture=architecture,
        processes=processes,
        errors=errors,
        statistics=statistics,
        go_runtimes=go_runtimes,
        go_candidates=go_candidates,
        strings=strings,
        functions=functions,
        goroutines=goroutines,
        network_artifacts=network_artifacts,
        credential_artifacts=credential_artifacts,
        crypto_artifacts=crypto_artifacts,
        persistence_artifacts=persistence_artifacts,
        iocs=iocs,
        correlations=correlations,
        findings=findings,
    )


def _recover_functions(
    reader: MemoryReader,
    pointer_size: int,
    runtime: GoRuntime,
    process_strings: list[StringArtifact],
    pid: int,
) -> tuple[list[FunctionArtifact], list[AnalysisError]]:
    """Recover function metadata and, where the ABI is determinable, call-site
    argument evidence for one process's Go runtime.

    Function-table parsing failures never abort other processes - any
    unexpected exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    Call-site backward analysis (x86-64 only, and only when the Go
    version confidently resolves to one ABI era - see
    :func:`gomemforensics.architecture.x86_64.is_register_based_abi`) is
    skipped cleanly, not guessed, when either precondition fails.
    """
    errors: list[AnalysisError] = []
    try:
        functions, parse_errors = FunctionTableParser(reader, pointer_size).parse(runtime)
        errors.extend(parse_errors)
    except Exception as exc:  # a single process must never abort the whole run
        errors.append(
            AnalysisError(
                component="go_runtime.functab",
                message=f"Function table recovery failed unexpectedly: {exc}",
                pid=pid,
                reason=FailureReason.INTERNAL_ERROR,
            )
        )
        return [], errors

    if not functions or runtime.architecture != "x86_64":
        return functions, errors

    register_abi = is_register_based_abi(runtime.go_version)
    if register_abi is None:
        errors.append(
            AnalysisError(
                component="go_runtime.backward_analysis",
                message=(
                    f"ABI era not confidently determined for go_version={runtime.go_version!r}; "
                    "call-site argument analysis skipped"
                ),
                pid=pid,
                reason=FailureReason.UNSUPPORTED_GO_VERSION,
            )
        )
        return functions, errors

    known_function_addresses = {f.entry_address: f.name for f in functions if f.name}
    known_string_data_addresses = {s.data_address: s.id for s in process_strings}
    # Phase 4.1: only a function whose ArgInfo shape was actually
    # ABI-mapped (functab.FunctionArtifact.argument_locations is not
    # None) is included - backward_analysis must never guess an argument
    # count/index for a callee it has no resolved shape for (approved
    # Phase 4.1 correction).
    known_function_argument_locations = {
        f.entry_address: f.argument_locations for f in functions if f.argument_locations is not None
    }

    sorted_functions = sorted(functions, key=lambda f: f.entry_address)
    id_counter = count(1)
    for index, func in enumerate(sorted_functions):
        end_pc = sorted_functions[index + 1].entry_address if index + 1 < len(sorted_functions) else None
        try:
            func.recovered_call_sites = backward_analysis.analyze_function_call_sites(
                reader,
                pid,
                func.entry_address,
                func.name,
                end_pc=end_pc,
                known_function_addresses=known_function_addresses,
                known_function_argument_locations=known_function_argument_locations,
                known_string_data_addresses=known_string_data_addresses,
                id_counter=id_counter,
            )
        except Exception as exc:  # one malformed function must not abort the rest
            errors.append(
                AnalysisError(
                    component="go_runtime.backward_analysis",
                    message=f"Call-site analysis failed for function {func.name!r} at 0x{func.entry_address:x}: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            )
            continue

    return functions, errors


def _recover_goroutines(
    reader: MemoryReader,
    pointer_size: int,
    runtime: GoRuntime,
    functions: list[FunctionArtifact],
    regions: list[MemoryRegion],
    pid: int,
) -> tuple[list[GoroutineArtifact], list[AnalysisError], GoroutineRecoveryStats]:
    """Recover goroutine metadata and, on x86-64 only, unwind each valid
    goroutine's call stack (Phase 5, paper Section 3.4).

    Goroutine discovery/validation failures never abort other processes -
    any unexpected exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    Stack unwinding (x86-64 only - the verified return-address formula in
    :mod:`gomemforensics.go_runtime.stack_unwind` is specific to x86's
    "call pushes return PC" convention, never extended to another
    architecture without independent verification) is skipped cleanly,
    leaving every goroutine's ``unwind_status`` at its
    :attr:`~gomemforensics.go_runtime.models.UnwindStatus.NOT_ATTEMPTED`
    default, when the architecture or ``pctab`` address is unavailable.
    """
    try:
        goroutines, errors, stats = GoroutineRecoveryEngine(reader, pointer_size).recover_goroutines(
            runtime, regions, functions
        )
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="go_runtime.goroutines",
                    message=f"Goroutine recovery failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            GoroutineRecoveryStats(),
        )

    if not goroutines:
        return goroutines, errors, stats

    if runtime.architecture != "x86_64" or runtime.pctab_address is None:
        errors.append(
            AnalysisError(
                component="go_runtime.stack_unwind",
                message=(
                    f"Stack unwinding skipped for {len(goroutines)} recovered goroutine(s): "
                    f"architecture={runtime.architecture!r} pctab_address="
                    f"{'available' if runtime.pctab_address is not None else 'unavailable'} "
                    "(x86-64 with a recovered pctab address is required)"
                ),
                pid=pid,
                reason=(
                    FailureReason.UNSUPPORTED_ARCHITECTURE
                    if runtime.architecture != "x86_64"
                    else FailureReason.STACK_UNAVAILABLE
                ),
            )
        )
        return goroutines, errors, stats

    function_index = FunctionIndex(functions)
    for g in goroutines:
        if g.sched_pc is None or g.sched_sp is None or g.stack_lo is None or g.stack_hi is None:
            continue
        try:
            frames, unwind_status = unwind_goroutine(
                reader,
                pointer_size,
                runtime.pctab_address,
                function_index,
                initial_pc=g.sched_pc,
                initial_sp=g.sched_sp,
                stack_lo=g.stack_lo,
                stack_hi=g.stack_hi,
            )
        except Exception as exc:  # one malformed goroutine must not abort the rest
            errors.append(
                AnalysisError(
                    component="go_runtime.stack_unwind",
                    message=f"Unwind failed unexpectedly for goroutine at 0x{g.goroutine_address:x}: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            )
            continue
        g.frames = frames
        g.unwind_status = unwind_status

    return goroutines, errors, stats


def _recover_network_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    process_strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
) -> tuple[list[NetworkArtifact], list[AnalysisError], NetworkAnalysisStats]:
    """Recover network artifacts (Phase 6A) from one process's already-
    recovered strings/functions/goroutines.

    Never re-scans process memory - purely a classification pass over
    :class:`~gomemforensics.go_runtime.models.StringArtifact` objects the
    string/function/goroutine analyzers already produced. An unexpected
    exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    """
    try:
        return extract_network_artifacts(
            pid, process_name, go_version, architecture, process_strings, functions, goroutines
        )
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.network",
                    message=f"Network artifact extraction failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            NetworkAnalysisStats(),
        )


def _recover_credential_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    process_strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
) -> tuple[list[CredentialArtifact], list[AnalysisError], CredentialAnalysisStats]:
    """Recover credential/secret artifacts (Phase 6B) from one process's
    already-recovered strings/functions/goroutines/network artifacts.

    Never re-scans process memory - purely a classification pass over
    :class:`~gomemforensics.go_runtime.models.StringArtifact` objects the
    string analyzer already produced, reusing Phase 4/5/6A's existing
    association evidence. An unexpected exception here is caught and
    recorded as a recoverable :class:`AnalysisError` rather than
    propagating (CLAUDE.md section 24).
    """
    try:
        return extract_credential_artifacts(
            pid, process_name, go_version, architecture, process_strings, functions, goroutines, network_artifacts
        )
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.credentials",
                    message=f"Credential artifact extraction failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            CredentialAnalysisStats(),
        )


def _recover_crypto_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    process_strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
) -> tuple[list[CryptoArtifact], list[AnalysisError], CryptoAnalysisStats]:
    """Recover cryptographic artifacts (Phase 6C) from one process's
    already-recovered strings/functions/goroutines/network/credential
    artifacts.

    Never re-scans process memory - purely a classification/reuse pass
    over evidence the earlier analyzers already produced. An unexpected
    exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    """
    try:
        return extract_crypto_artifacts(
            pid,
            process_name,
            go_version,
            architecture,
            process_strings,
            functions,
            goroutines,
            network_artifacts,
            credential_artifacts,
        )
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.crypto",
                    message=f"Crypto artifact extraction failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            CryptoAnalysisStats(),
        )


def _recover_persistence_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    process_strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
    crypto_artifacts: list[CryptoArtifact],
) -> tuple[list[PersistenceArtifact], list[AnalysisError], PersistenceAnalysisStats]:
    """Recover persistence-related artifacts (Phase 6D) from one
    process's already-recovered strings/functions/goroutines/network/
    credential/crypto artifacts.

    Never re-scans process memory, never touches the filesystem/registry/
    service-control-manager/task scheduler, never executes anything. An
    unexpected exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    """
    try:
        return extract_persistence_artifacts(
            pid,
            process_name,
            go_version,
            architecture,
            process_strings,
            functions,
            goroutines,
            network_artifacts,
            credential_artifacts,
            crypto_artifacts,
        )
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.persistence",
                    message=f"Persistence artifact extraction failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            PersistenceAnalysisStats(),
        )


def _recover_iocs(
    pid: int,
    process_name: str | None,
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
    crypto_artifacts: list[CryptoArtifact],
    persistence_artifacts: list[PersistenceArtifact],
) -> tuple[list[IOCArtifact], list[AnalysisError], IOCExtractionStats]:
    """Recover normalized IOCs (Phase 6E) from one process's already-
    recovered network/credential/crypto/persistence artifacts.

    Never re-scans process memory, never adds a new detector - purely a
    promotion pass. An unexpected exception here is caught and recorded
    as a recoverable :class:`AnalysisError` rather than propagating
    (CLAUDE.md section 24).
    """
    try:
        return extract_iocs(pid, process_name, network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts)
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.correlation",
                    message=f"IOC extraction failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            IOCExtractionStats(),
        )


def _recover_correlations(
    pid: int,
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
    crypto_artifacts: list[CryptoArtifact],
    persistence_artifacts: list[PersistenceArtifact],
) -> tuple[list[CorrelationRecord], list[AnalysisError], CorrelationStats]:
    """Recover cross-artifact correlation records (Phase 6E) from one
    process's already-recovered evidence. Never re-derives new
    relationships beyond already-existing evidence-chain fields. An
    unexpected exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    """
    try:
        return correlate_artifacts(
            pid, functions, goroutines, network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
        )
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.correlation",
                    message=f"Correlation failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            CorrelationStats(),
        )


def _recover_findings(
    pid: int,
    process_name: str | None,
    iocs: list[IOCArtifact],
    correlations: list[CorrelationRecord],
) -> tuple[list[Finding], list[AnalysisError], FindingStats]:
    """Recover structured findings (Phase 6F) from one process's already-
    recovered IOCs and correlation records.

    Never re-scans process memory, never adds a new detector - purely a
    deterministic rule-evaluation pass over Phase 6E output. An
    unexpected exception here is caught and recorded as a recoverable
    :class:`AnalysisError` rather than propagating (CLAUDE.md section 24).
    """
    try:
        return generate_findings(pid, process_name, iocs, correlations)
    except Exception as exc:  # a single process must never abort the whole run
        return (
            [],
            [
                AnalysisError(
                    component="analyzers.findings",
                    message=f"Finding generation failed unexpectedly: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            ],
            FindingStats(),
        )


def _link_shared_backing_strings(strings: list[StringArtifact]) -> None:
    """Cross-populate provenance.related_artifacts for strings sharing backing bytes.

    Deterministic grouping/dedup metadata (approved plan Section J):
    ``data_address`` is the grouping key, never the recovered ``value``
    alone - two artifacts with identical values but different backing
    addresses are NOT linked here (they are independent evidence, even if
    coincidentally equal in content).
    """
    by_data_address: dict[int, list[StringArtifact]] = {}
    for artifact in strings:
        by_data_address.setdefault(artifact.data_address, []).append(artifact)

    for group in by_data_address.values():
        if len(group) < 2:
            continue
        ids = [a.id for a in group]
        for artifact in group:
            if artifact.provenance is not None:
                siblings = [i for i in ids if i != artifact.id]
                artifact.provenance.related_artifacts = list(artifact.provenance.related_artifacts) + siblings


def has_fatal_error(result: AnalysisResult) -> bool:
    """Whether ``result`` contains a non-recoverable error (e.g. init failure).

    Used by the CLI to decide the process exit code without duplicating
    knowledge of which error component names are fatal.
    """
    return any(not error.recoverable for error in result.errors)
