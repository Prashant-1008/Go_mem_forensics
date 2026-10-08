"""Phase 6G — ``ReportModel`` construction.

Consumes an already-produced analysis JSON dict (matching
:meth:`gomemforensics.pipeline.AnalysisResult.to_json_dict`'s exact
schema) and builds a :class:`ReportModel`: the original analysis data
plus a small set of *new, presentation-only* computed sections
(executive summary, per-process summary, methodology, limitations,
evidence traceability, errors/warnings split).

**This module performs no new forensic discovery** (Phase 6G stage 2/39):
it never imports :class:`~gomemforensics.common.memory.MemoryReader`,
never calls a Volatility plugin, and never creates a new artifact/IOC/
finding - every count, chain, and summary is derived purely by reading
fields that already exist in the supplied analysis dict. All "forensic
calculation" happens here, not in the renderers
(:mod:`gomemforensics.reporting.json_renderer`/
:mod:`gomemforensics.reporting.html_renderer`), which only format
already-computed data (stage 27).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gomemforensics import REAL_MEMORY_VALIDATED
from gomemforensics import __version__ as TOOL_VERSION
from gomemforensics.common.utils import utc_now_iso

#: Independent of ``gomemforensics.__version__`` - this versions the
#: *report schema/structure* itself (stage 31), so a future change to the
#: report's own shape (not the analyzer pipeline) can be distinguished.
REPORT_SCHEMA_VERSION = "6G.1"

#: Bounds (stage 34) - the JSON report never truncates (it is the
#: canonical, complete machine-readable form); these bounds apply only to
#: the HTML renderer's human-readable tables, always with an explicit,
#: recorded truncation notice - never a silent evidence drop.
MAX_TABLE_ROWS_HTML = 2000
MAX_STRING_DISPLAY_LENGTH_HTML = 500

#: Top-level keys that have existed since Phase 1/2 - their absence means
#: the input is not a recognizable GoMemForensics analysis JSON at all.
_REQUIRED_TOP_LEVEL_KEYS = ("case", "evidence", "environment", "system", "processes")
#: Keys added by later phases - always optional for backward
#: compatibility with an analysis JSON produced by an earlier phase
#: (stage 33: "missing optional field" must not crash report generation).
_OPTIONAL_LIST_KEYS = (
    "go_runtimes", "go_candidates", "strings", "functions", "goroutines",
    "network_artifacts", "credential_artifacts", "crypto_artifacts",
    "persistence_artifacts", "iocs", "correlations", "findings", "errors",
)


class ReportGenerationError(Exception):
    """Raised when the supplied analysis data is malformed/unusable for
    report generation - report generation fails loudly rather than
    silently fabricating a placeholder report (stage 33)."""


def _require_keys(data: dict, keys: tuple[str, ...]) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        raise ReportGenerationError(
            f"Analysis data is missing required top-level key(s): {missing} - "
            "this does not look like a GoMemForensics analysis JSON."
        )


def _index_by_pid(items: list[dict]) -> dict[Any, list[dict]]:
    index: dict[Any, list[dict]] = {}
    for item in items:
        index.setdefault(item.get("pid"), []).append(item)
    return index


def _index_by_id(items: list[dict], key: str = "id") -> dict[str, dict]:
    return {item[key]: item for item in items if key in item}


# ---------------------------------------------------------------------------
# Methodology (stage 23) - fixed, deterministic prose, never per-run.
# ---------------------------------------------------------------------------

METHODOLOGY_STATEMENTS: tuple[str, ...] = (
    "Evidence acquisition is performed externally, by the investigator, using an approved "
    "acquisition method - this tool never acquires memory itself (see docs/validation/memory-acquisition.md).",
    "The supplied evidence file is treated as read-only throughout analysis; it is never modified.",
    "Evidence identity is established via a chunked SHA-256 hash computed directly from the evidence file.",
    "Volatility 3 provides operating-system and process context (process enumeration, memory layer access) "
    "on top of the raw evidence.",
    "Go runtime analysis (pclntab/pcHeader/moduledata recovery) is version- and layout-aware - every struct "
    "offset used is traced to real Go source for the specific detected version range, never guessed.",
    "String, function, goroutine, network, credential, cryptographic, and persistence analyzers each consume "
    "already-recovered Go runtime evidence - none of them independently re-scans process memory.",
    "IOC extraction and cross-artifact correlation are evidence-derived: every IOC/correlation record traces "
    "to an already-existing artifact field, never a new inference or memory-proximity guess.",
    "Findings are evidence assessments that separate observed evidence from interpretation - never a malware "
    "verdict, malware score, threat score, or automatic attribution.",
    "No automatic malware verdict, malware/threat/risk score, machine-learning classification, or external "
    "threat-intelligence/reputation lookup is produced by this tool at any stage.",
)

_ALWAYS_APPLICABLE_LIMITATIONS: tuple[str, ...] = (
    "No real-memory validation has been performed for this project - see 'validation' below and "
    "docs/validation/validation-plan.md.",
    "Structured OS persistence artifacts (Windows registry hive, service-control-manager records, Task "
    "Scheduler database) are not recovered - only string/command references within process memory "
    "(see docs/architecture/go-persistence-artifacts.md).",
    "Structured cryptographic key objects (RSA/ECDSA/Ed25519/X25519 keys, TLS connection state) are not "
    "recovered - only PEM boundaries, crypto-context identifiers, and evidence-backed AES key material "
    "(see docs/architecture/go-crypto-artifacts.md).",
    "No external threat intelligence, IOC reputation lookup, DNS resolution, WHOIS, or geolocation enrichment "
    "is performed - all analysis is offline.",
    "No malware verdict, malware score, threat score, or automatic attribution is produced - Findings are "
    "evidence assessments only (see docs/architecture/go-findings.md).",
)

#: FailureReason value -> human-readable limitation sentence - only
#: included in a given report if that reason actually appears in the
#: report's own errors list (stage 22: "Only include limitations that
#: actually apply").
_REASON_TO_LIMITATION: dict[str, str] = {
    "unsupported_architecture": "One or more processes had an architecture outside this project's current "
    "full-analysis target (x86-64) - see docs/supported-platforms/platforms.md.",
    "unsupported_go_version": "One or more processes used a Go runtime version/layout that has not been "
    "source-verified for structured recovery.",
    "address_space_unavailable": "One or more processes' memory address space could not be fully accessed.",
    "volatility_unsupported": "The supplied evidence could not be fully processed by the installed Volatility 3 version.",
    "allgs_not_found": "Goroutine discovery could not locate a structurally valid runtime.allgs candidate for "
    "one or more processes.",
    "g_validation_failed": "One or more candidate goroutine structures failed structural validation and were excluded.",
    "pclntab_invalid": "A candidate pclntab/pcHeader structure failed validation for one or more processes.",
    "moduledata_invalid": "A candidate moduledata structure failed validation for one or more processes.",
    "go_runtime_not_found": "No Go runtime could be recovered for one or more candidate processes.",
    "stack_unavailable": "Stack unwinding was skipped for one or more goroutines (architecture or pctab unavailable).",
    "insufficient_evidence": "One or more candidate structures were malformed/incomplete and were excluded from results.",
    "os_process_discovery_failed": "Process enumeration failed entirely for one or more operating systems in this evidence.",
}


def _build_executive_summary(data: dict) -> dict:
    processes = data.get("processes", [])
    go_runtimes = data.get("go_runtimes", [])
    findings = data.get("findings", [])
    iocs = data.get("iocs", [])
    errors_list = data.get("errors", [])

    findings_by_severity: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

    unique_ioc_keys = {ioc["dedup_key"] for ioc in iocs if ioc.get("dedup_key")}
    has_fatal_error = any(not e.get("recoverable", True) for e in errors_list)

    return {
        "analysis_status": "COMPLETE_WITH_ERRORS" if has_fatal_error else "COMPLETE",
        "evidence_file_name": data.get("evidence", {}).get("file_name"),
        "evidence_sha256": data.get("evidence", {}).get("sha256"),
        "platform": data.get("system", {}).get("os"),
        "architecture": data.get("system", {}).get("architecture"),
        "process_count": len(processes),
        "go_candidate_process_count": sum(1 for p in processes if p.get("is_go_candidate")),
        "go_runtime_recovered_count": len(go_runtimes),
        "strings_recovered": len(data.get("strings", [])),
        "functions_recovered": len(data.get("functions", [])),
        "goroutines_recovered": len(data.get("goroutines", [])),
        "network_artifacts": len(data.get("network_artifacts", [])),
        "credential_artifacts": len(data.get("credential_artifacts", [])),
        "crypto_artifacts": len(data.get("crypto_artifacts", [])),
        "persistence_artifacts": len(data.get("persistence_artifacts", [])),
        "ioc_count": len(iocs),
        "unique_ioc_count": len(unique_ioc_keys),
        "correlation_count": len(data.get("correlations", [])),
        "finding_count": len(findings),
        "findings_by_severity": findings_by_severity,
        "errors_count": sum(1 for e in errors_list if not e.get("recoverable", True)),
        "warnings_count": sum(1 for e in errors_list if e.get("recoverable", True)),
        "real_memory_validated": REAL_MEMORY_VALIDATED,
        "note": (
            "This summary contains observed evidence counts only - it is never a malware verdict, "
            "overall risk score, or process ranking by suspiciousness."
        ),
    }


def _build_process_summaries(data: dict) -> list[dict]:
    processes = data.get("processes", [])
    go_runtimes_by_pid = _index_by_pid(data.get("go_runtimes", []))
    strings_by_pid = _index_by_pid(data.get("strings", []))
    functions_by_pid = _index_by_pid(data.get("functions", []))
    goroutines_by_pid = _index_by_pid(data.get("goroutines", []))
    network_by_pid = _index_by_pid(data.get("network_artifacts", []))
    credential_by_pid = _index_by_pid(data.get("credential_artifacts", []))
    crypto_by_pid = _index_by_pid(data.get("crypto_artifacts", []))
    persistence_by_pid = _index_by_pid(data.get("persistence_artifacts", []))
    iocs_by_pid = _index_by_pid(data.get("iocs", []))
    correlations_by_pid = _index_by_pid(data.get("correlations", []))
    findings_by_pid = _index_by_pid(data.get("findings", []))
    errors_by_pid = _index_by_pid([e for e in data.get("errors", []) if e.get("pid") is not None])

    # Deliberately the SAME order as the source `processes` list (already
    # deterministic - Volatility's own enumeration order, preserved
    # unchanged through every prior phase) - never sorted by any
    # "suspiciousness" heuristic (stage 10's explicit prohibition).
    summaries = []
    for process in processes:
        pid = process.get("pid")
        runtimes = go_runtimes_by_pid.get(pid, [])
        runtime = runtimes[0] if runtimes else None
        summaries.append(
            {
                "pid": pid,
                "process_name": process.get("name"),
                "os": process.get("os"),
                "architecture": process.get("architecture"),
                "is_go_candidate": process.get("is_go_candidate", False),
                "go_version": process.get("go_version"),
                "go_confidence": process.get("go_confidence"),
                "runtime_recovered": runtime is not None,
                "runtime_confidence": runtime.get("confidence") if runtime else None,
                "strings_count": len(strings_by_pid.get(pid, [])),
                "functions_count": len(functions_by_pid.get(pid, [])),
                "goroutines_count": len(goroutines_by_pid.get(pid, [])),
                "network_artifacts_count": len(network_by_pid.get(pid, [])),
                "credential_artifacts_count": len(credential_by_pid.get(pid, [])),
                "crypto_artifacts_count": len(crypto_by_pid.get(pid, [])),
                "persistence_artifacts_count": len(persistence_by_pid.get(pid, [])),
                "ioc_count": len(iocs_by_pid.get(pid, [])),
                "correlation_count": len(correlations_by_pid.get(pid, [])),
                "finding_count": len(findings_by_pid.get(pid, [])),
                "error_count": len(errors_by_pid.get(pid, [])),
            }
        )
    return summaries


def _build_go_runtime_section(data: dict) -> list[dict]:
    processes_by_pid = {p.get("pid"): p for p in data.get("processes", [])}
    entries = []
    for runtime in data.get("go_runtimes", []):
        entry = dict(runtime)  # shallow copy - never mutate the source data
        process = processes_by_pid.get(runtime.get("pid"))
        entry["process_name"] = process.get("name") if process else None
        entries.append(entry)
    return entries


def _build_limitations(data: dict) -> list[str]:
    limitations = list(_ALWAYS_APPLICABLE_LIMITATIONS)
    reasons_present = {e.get("reason") for e in data.get("errors", []) if e.get("reason")}
    for reason, text in _REASON_TO_LIMITATION.items():
        if reason in reasons_present:
            limitations.append(text)
    return limitations


_ORIGIN_ID_FIELD_BY_CATEGORY = {
    "network": "related_network_artifact_id",
    "credential": "related_credential_artifact_id",
    "crypto": "related_crypto_artifact_id",
    "persistence": "related_persistence_artifact_id",
}


def _build_evidence_traceability(data: dict) -> list[dict]:
    """Finding -> IOC -> derived artifact -> string -> function/goroutine
    -> process -> evidence SHA-256 (stage 24). Every link is an actual,
    already-existing id lookup - a missing link is simply omitted, never
    invented."""
    strings_by_id = _index_by_id(data.get("strings", []))
    iocs_by_id = _index_by_id(data.get("iocs", []))
    derived_by_id: dict[str, dict] = {}
    derived_by_id.update(_index_by_id(data.get("network_artifacts", [])))
    derived_by_id.update(_index_by_id(data.get("credential_artifacts", [])))
    derived_by_id.update(_index_by_id(data.get("crypto_artifacts", [])))
    derived_by_id.update(_index_by_id(data.get("persistence_artifacts", [])))
    evidence_sha256 = data.get("evidence", {}).get("sha256")

    chains = []
    for finding in data.get("findings", []):
        chain: list[dict] = [{"type": "finding", "id": finding.get("finding_id")}]
        seen_ids: set[str] = set()
        for ioc_id in finding.get("supporting_ioc_ids", []):
            ioc = iocs_by_id.get(ioc_id)
            if ioc is None or ioc_id in seen_ids:
                continue
            seen_ids.add(ioc_id)
            chain.append({"type": "ioc", "id": ioc_id})

            origin_field = _ORIGIN_ID_FIELD_BY_CATEGORY.get(ioc.get("ioc_category"))
            origin_id = ioc.get(origin_field) if origin_field else None
            if origin_id and origin_id in derived_by_id and origin_id not in seen_ids:
                seen_ids.add(origin_id)
                chain.append({"type": ioc.get("source_artifact_type"), "id": origin_id})

            string_id = ioc.get("source_artifact_id")
            if string_id in strings_by_id and string_id not in seen_ids:
                seen_ids.add(string_id)
                chain.append({"type": "string_artifact", "id": string_id})

            if ioc.get("function_id") and ioc["function_id"] not in seen_ids:
                seen_ids.add(ioc["function_id"])
                chain.append({"type": "function", "id": ioc["function_id"]})
            if ioc.get("goroutine_id") and ioc["goroutine_id"] not in seen_ids:
                seen_ids.add(ioc["goroutine_id"])
                chain.append({"type": "goroutine", "id": ioc["goroutine_id"]})

        chain.append({"type": "process", "id": finding.get("pid")})
        if evidence_sha256:
            chain.append({"type": "evidence_sha256", "id": evidence_sha256})
        chains.append({"finding_id": finding.get("finding_id"), "chain": chain})
    return chains


@dataclass
class ReportModel:
    """The full, presentation-ready report - original analysis data plus
    the Phase 6G computed sections. Every list field below preserves the
    exact objects/order from the source analysis JSON (never re-sorted,
    never merged, never partially duplicated) except where explicitly
    noted (``processes``/``go_runtimes`` gain a read-only summary
    enrichment, never mutating the originals)."""

    report_metadata: dict
    case: dict
    evidence: dict
    environment: dict
    validation: dict
    executive_summary: dict
    processes: list[dict]
    process_summaries: list[dict]
    go_runtimes: list[dict]
    strings: list[dict]
    functions: list[dict]
    goroutines: list[dict]
    network_artifacts: list[dict]
    credential_artifacts: list[dict]
    crypto_artifacts: list[dict]
    persistence_artifacts: list[dict]
    iocs: list[dict]
    correlations: list[dict]
    findings: list[dict]
    errors: list[dict]
    warnings: list[dict]
    methodology: list[str]
    limitations: list[str]
    evidence_traceability: list[dict]
    statistics: dict

    @classmethod
    def from_analysis_dict(cls, data: dict, *, report_timestamp: str | None = None) -> "ReportModel":
        """Build a :class:`ReportModel` from an already-produced analysis
        JSON dict. Raises :class:`ReportGenerationError` if ``data`` does
        not look like a GoMemForensics analysis result at all - never
        silently fabricates missing sections."""
        if not isinstance(data, dict):
            raise ReportGenerationError(f"Analysis data must be a JSON object, got {type(data).__name__}")
        _require_keys(data, _REQUIRED_TOP_LEVEL_KEYS)
        for key in _OPTIONAL_LIST_KEYS:
            data.setdefault(key, [])

        all_errors = data.get("errors", [])
        errors = [e for e in all_errors if not e.get("recoverable", True)]
        warnings = [e for e in all_errors if e.get("recoverable", True)]

        return cls(
            report_metadata={
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "tool_version": TOOL_VERSION,
                "report_generated_at": report_timestamp or utc_now_iso(),
                "note": "report_generated_at is when this REPORT was rendered, distinct from evidence/analysis timestamps below.",
            },
            case=data.get("case", {}),
            evidence=data.get("evidence", {}),
            environment=data.get("environment", {}),
            validation={
                "real_memory_validated": REAL_MEMORY_VALIDATED,
                "note": (
                    "REAL_MEMORY_VALIDATED describes this PROJECT's current validation state, not this "
                    "specific evidence file. COMPILED_BINARY_VALIDATED (real compiled Go binary file bytes) "
                    "and SYNTHETIC_VALIDATED (unit-test buffers) are validation tiers below real-memory "
                    "validation and are never presented as equivalent to it - see "
                    "docs/validation/validation-plan.md."
                ),
            },
            executive_summary=_build_executive_summary(data),
            processes=data.get("processes", []),
            process_summaries=_build_process_summaries(data),
            go_runtimes=_build_go_runtime_section(data),
            strings=data.get("strings", []),
            functions=data.get("functions", []),
            goroutines=data.get("goroutines", []),
            network_artifacts=data.get("network_artifacts", []),
            credential_artifacts=data.get("credential_artifacts", []),
            crypto_artifacts=data.get("crypto_artifacts", []),
            persistence_artifacts=data.get("persistence_artifacts", []),
            iocs=data.get("iocs", []),
            correlations=data.get("correlations", []),
            findings=data.get("findings", []),
            errors=errors,
            warnings=warnings,
            methodology=list(METHODOLOGY_STATEMENTS),
            limitations=_build_limitations(data),
            evidence_traceability=_build_evidence_traceability(data),
            statistics=data.get("statistics", {}),
        )
