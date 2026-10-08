"""Phase 6G — deterministic JSON report rendering.

Purely a formatting pass over an already-built
:class:`~gomemforensics.reporting.models.ReportModel` - no forensic
calculation happens here (that is entirely done in
:mod:`gomemforensics.reporting.models`). The JSON report never truncates
- it is the canonical, complete machine-readable form (stage 34).
"""

from __future__ import annotations

import json
from pathlib import Path

from gomemforensics.reporting.models import ReportModel


def render_json_dict(report: ReportModel) -> dict:
    """Build the full report JSON structure. Field order is fixed and
    deterministic (a plain Python dict literal, matching
    :meth:`~gomemforensics.pipeline.AnalysisResult.to_json_dict`'s own
    established convention) - every original analysis field is present,
    plus the new Phase 6G sections."""
    return {
        "report_metadata": report.report_metadata,
        "case": report.case,
        "evidence": report.evidence,
        "environment": report.environment,
        "validation": report.validation,
        "executive_summary": report.executive_summary,
        "processes": report.processes,
        "process_summaries": report.process_summaries,
        "go_runtimes": report.go_runtimes,
        "strings": report.strings,
        "functions": report.functions,
        "goroutines": report.goroutines,
        "network_artifacts": report.network_artifacts,
        "credential_artifacts": report.credential_artifacts,
        "crypto_artifacts": report.crypto_artifacts,
        "persistence_artifacts": report.persistence_artifacts,
        "iocs": report.iocs,
        "correlations": report.correlations,
        "findings": report.findings,
        "errors": report.errors,
        "warnings": report.warnings,
        "methodology": report.methodology,
        "limitations": report.limitations,
        "evidence_traceability": report.evidence_traceability,
        "statistics": report.statistics,
    }


def render_json_text(report: ReportModel) -> str:
    """Deterministic, indented JSON text (never key-sorted - field order
    is already fixed by :func:`render_json_dict`'s own literal
    construction, matching the rest of the project's JSON output style)."""
    return json.dumps(render_json_dict(report), indent=2, default=str) + "\n"


def write_json_report(report: ReportModel, output_path: Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_json_text(report), encoding="utf-8")
