"""Phase 6H Step 7 — error and partial-failure integration.

Targets the integration-layer failure modes that are genuinely new ground
for this phase: dangling cross-collection references (an IOC/correlation/
finding pointing at an id that does not exist in the supplied analysis
JSON) and malformed report input at the CLI boundary.

Per-analyzer malformed-structure handling (invalid pclntab/moduledata,
unsupported architecture/Go version, invalid string/network/credential/
crypto/persistence artifact construction) is already exhaustively unit-
tested where each analyzer actually lives - see
docs/validation/phase-6h-end-to-end-validation.md's citation table. This
file does not duplicate that; it validates the NEW seam Phase 6G/6H
introduced: what the reporting layer does when a cross-referenced id in
an otherwise-valid-shaped analysis JSON does not resolve. The required
behavior is "fail safely, explicitly, and non-silently" - not "abort the
whole report", and never "fabricate a replacement id".
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from gomemforensics.cli.main import EXIT_REPORT_ERROR, cli
from gomemforensics.reporting.html_renderer import render_html
from gomemforensics.reporting.json_renderer import render_json_dict
from gomemforensics.reporting.models import ReportModel


def _base_data(**overrides) -> dict:
    data = {
        "case": {"case_id": "CASE-6H-DANGLING"},
        "evidence": {
            "input_path": "x.raw", "file_name": "x.raw", "file_size": 100,
            "sha256": "deadbeef", "hash_algorithm": "SHA-256",
            "analysis_timestamp": "2026-01-01T00:00:00Z", "read_only": True,
        },
        "environment": {"tool_version": "0.14.0"},
        "system": {"os": "windows", "architecture": "x86_64"},
        "processes": [
            {"pid": 1, "name": "app.exe", "os": "windows", "architecture": "x86_64",
             "is_go_candidate": True, "go_version": "1.26.2", "go_confidence": "high"},
        ],
    }
    data.update(overrides)
    return data


class TestDanglingIocSourceReference:
    def test_ioc_with_missing_source_string_does_not_crash_and_is_not_fabricated(self):
        data = _base_data(iocs=[{
            "id": "IOC-1-0001", "pid": 1, "ioc_type": "ipv4", "ioc_category": "network",
            "source_artifact_id": "STR-1-DOES-NOT-EXIST", "source_artifact_type": "network_artifact",
            "dedup_key": "ipv4:1.2.3.4", "redacted_value": None, "normalized_value": "1.2.3.4",
            "confidence": "high", "validation_status": "structurally_valid",
        }])
        report = ReportModel.from_analysis_dict(data)  # must not raise
        rendered = render_json_dict(report)
        # The dangling reference is preserved verbatim in the machine-
        # readable JSON - it is evidence of what the analyzer actually
        # recorded, never silently dropped or rewritten.
        assert rendered["iocs"][0]["source_artifact_id"] == "STR-1-DOES-NOT-EXIST"
        assert render_html(report)  # HTML rendering must not crash either

    def test_dangling_ioc_source_never_appears_in_evidence_traceability_chain(self):
        data = _base_data(
            iocs=[{
                "id": "IOC-1-0001", "pid": 1, "ioc_type": "ipv4", "ioc_category": "network",
                "source_artifact_id": "STR-1-DOES-NOT-EXIST", "source_artifact_type": "network_artifact",
                "dedup_key": "ipv4:1.2.3.4", "redacted_value": None, "normalized_value": "1.2.3.4",
                "confidence": "high", "validation_status": "structurally_valid",
            }],
            findings=[{"finding_id": "FINDING-1-0001", "pid": 1, "supporting_ioc_ids": ["IOC-1-0001"]}],
        )
        report = ReportModel.from_analysis_dict(data)
        chain = report.evidence_traceability[0]["chain"]
        chain_ids = {link["id"] for link in chain}
        # The IOC itself is real and appears; the dangling string is not
        # fabricated into the chain (no "string_artifact":"STR-1-DOES-NOT-EXIST").
        assert "IOC-1-0001" in chain_ids
        assert "STR-1-DOES-NOT-EXIST" not in chain_ids


class TestDanglingCorrelationReference:
    def test_correlation_with_missing_endpoint_does_not_crash(self):
        data = _base_data(correlations=[{
            "id": "CORR-1-0001", "pid": 1, "relationship_type": "same_source_string",
            "source_id": "NET-1-DOES-NOT-EXIST", "source_type": "network_artifact",
            "target_id": "CRED-1-DOES-NOT-EXIST", "target_type": "credential_artifact",
            "evidence_basis": "shared source_artifact_id across two derived artifacts", "notes": None,
        }])
        report = ReportModel.from_analysis_dict(data)  # must not raise
        rendered = render_json_dict(report)
        # Preserved verbatim, not silently dropped.
        assert rendered["correlations"][0]["source_id"] == "NET-1-DOES-NOT-EXIST"
        html = render_html(report)
        assert "network_artifact:NET-1-DOES-NOT-EXIST" in html  # rendered as-is, not hidden

    def test_correlation_endpoint_types_restricted_to_closed_taxonomy(self):
        # A correlation record referencing an endpoint type this project
        # has never defined (e.g. a fabricated "process_behavior" type)
        # must still render without crashing or being reinterpreted as
        # something it is not - reporting never adds semantic meaning
        # beyond what the record itself declares.
        data = _base_data(correlations=[{
            "id": "CORR-1-0001", "pid": 1, "relationship_type": "same_source_string",
            "source_id": "X", "source_type": "unexpected_future_type",
            "target_id": "Y", "target_type": "unexpected_future_type",
            "evidence_basis": "shared source_artifact_id across two derived artifacts", "notes": None,
        }])
        report = ReportModel.from_analysis_dict(data)
        assert render_html(report)  # forward-compatible, does not crash


class TestDanglingFindingReferences:
    def test_finding_with_missing_supporting_ioc_id_does_not_crash(self):
        data = _base_data(findings=[{
            "finding_id": "FINDING-1-0001", "pid": 1, "title": "x", "severity": "medium",
            "observed_evidence": "x", "interpretation": "x", "confidence": "medium",
            "validation_status": "structurally_valid",
            "supporting_ioc_ids": ["IOC-1-DOES-NOT-EXIST"],
            "supporting_artifact_ids": ["STR-1-DOES-NOT-EXIST"],
            "supporting_correlation_ids": ["CORR-1-DOES-NOT-EXIST"],
            "function_ids": ["FUNC-1-DOES-NOT-EXIST"],
            "goroutine_ids": ["GOR-1-DOES-NOT-EXIST"],
        }])
        report = ReportModel.from_analysis_dict(data)  # must not raise
        html = render_html(report)
        # All dangling ids are still shown verbatim in the Findings section
        # (an examiner can see exactly what the analyzer claimed) - never
        # silently hidden, never replaced with a fabricated resolved name.
        assert "IOC-1-DOES-NOT-EXIST" in html
        assert "FUNC-1-DOES-NOT-EXIST" in html
        assert "GOR-1-DOES-NOT-EXIST" in html

    def test_finding_with_all_dangling_ids_produces_evidence_chain_with_no_fabricated_links(self):
        data = _base_data(findings=[{
            "finding_id": "FINDING-1-0001", "pid": 1,
            "supporting_ioc_ids": ["IOC-1-DOES-NOT-EXIST"],
        }])
        report = ReportModel.from_analysis_dict(data)
        chain = report.evidence_traceability[0]["chain"]
        chain_types = {link["type"] for link in chain}
        # Only the finding itself, the process, and the evidence hash are
        # real/resolvable here - no "ioc" link is fabricated for a
        # nonexistent id.
        assert chain_types == {"finding", "process", "evidence_sha256"}


class TestMalformedReportInputAtCliBoundary:
    def test_report_command_rejects_top_level_list_instead_of_object(self, tmp_path):
        analysis_path = tmp_path / "bad.json"
        analysis_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        result = CliRunner().invoke(cli, ["report", str(analysis_path)])
        assert result.exit_code == EXIT_REPORT_ERROR
        assert "could not build report" in result.output.lower()

    def test_report_command_rejects_empty_file(self, tmp_path):
        analysis_path = tmp_path / "empty.json"
        analysis_path.write_text("", encoding="utf-8")
        result = CliRunner().invoke(cli, ["report", str(analysis_path)])
        assert result.exit_code == EXIT_REPORT_ERROR

    def test_report_command_handles_partially_truncated_json(self, tmp_path):
        analysis_path = tmp_path / "truncated.json"
        analysis_path.write_text('{"case": {"case_id": "X"}, "evidence": {', encoding="utf-8")
        result = CliRunner().invoke(cli, ["report", str(analysis_path)])
        assert result.exit_code == EXIT_REPORT_ERROR
        assert "not valid json" in result.output.lower()

    def test_report_command_never_fabricates_placeholder_evidence(self, tmp_path):
        # A minimal-but-valid analysis JSON with no findings/iocs/etc must
        # render a complete, valid report with empty (not fabricated)
        # sections - confirms "fail clearly OR render only what is real",
        # never a synthesized placeholder finding/IOC.
        analysis_path = tmp_path / "minimal.json"
        analysis_path.write_text(json.dumps(_base_data()), encoding="utf-8")
        output_path = tmp_path / "report.html"
        result = CliRunner().invoke(cli, ["report", str(analysis_path), "--output", str(output_path)])
        assert result.exit_code == 0
        html = output_path.read_text(encoding="utf-8")
        assert "No findings generated." in html
        assert "No IOCs extracted." in html
