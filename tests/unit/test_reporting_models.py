"""Tests for :mod:`gomemforensics.reporting.models`.

All fixtures are hand-built plain dicts matching
:meth:`gomemforensics.pipeline.AnalysisResult.to_json_dict`'s exact
schema (SYNTHETIC) - report-model construction performs no memory
access, no new detection, and no network activity.
"""

from __future__ import annotations

import pytest

from gomemforensics.reporting.models import ReportGenerationError, ReportModel


def _minimal_data(**overrides):
    data = {
        "case": {"case_id": "CASE-1"},
        "evidence": {
            "input_path": "x.raw", "file_name": "x.raw", "file_size": 100,
            "sha256": "deadbeef", "hash_algorithm": "SHA-256",
            "analysis_timestamp": "2026-01-01T00:00:00Z", "read_only": True,
        },
        "environment": {"tool_version": "0.13.0"},
        "system": {"os": "windows", "architecture": "x86_64"},
        "processes": [
            {"pid": 1, "name": "app.exe", "os": "windows", "architecture": "x86_64",
             "is_go_candidate": True, "go_version": "1.26.2", "go_confidence": "high"},
        ],
    }
    data.update(overrides)
    return data


class TestConstruction:
    def test_minimal_data_builds_successfully(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        assert report.case["case_id"] == "CASE-1"
        assert report.evidence["sha256"] == "deadbeef"

    def test_missing_required_key_raises(self):
        data = _minimal_data()
        del data["evidence"]
        with pytest.raises(ReportGenerationError):
            ReportModel.from_analysis_dict(data)

    def test_non_dict_input_raises(self):
        with pytest.raises(ReportGenerationError):
            ReportModel.from_analysis_dict(["not", "a", "dict"])

    def test_missing_optional_keys_default_to_empty(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        assert report.strings == []
        assert report.findings == []
        assert report.iocs == []

    def test_original_analysis_data_not_mutated(self):
        data = _minimal_data()
        original_processes = list(data["processes"])
        ReportModel.from_analysis_dict(data)
        assert data["processes"] == original_processes


class TestExecutiveSummary:
    def test_counts_match_input(self):
        data = _minimal_data(
            strings=[{"id": "STR-1-0001", "pid": 1}],
            network_artifacts=[{"id": "NET-1-0001", "pid": 1}],
            iocs=[{"id": "IOC-1-0001", "pid": 1, "dedup_key": "ipv4:1.1.1.1"}, {"id": "IOC-1-0002", "pid": 1, "dedup_key": "ipv4:1.1.1.1"}],
            findings=[{"finding_id": "FINDING-1-0001", "pid": 1, "severity": "medium"}],
        )
        report = ReportModel.from_analysis_dict(data)
        summary = report.executive_summary
        assert summary["strings_recovered"] == 1
        assert summary["network_artifacts"] == 1
        assert summary["ioc_count"] == 2
        assert summary["unique_ioc_count"] == 1  # deduped by dedup_key
        assert summary["finding_count"] == 1
        assert summary["findings_by_severity"] == {"medium": 1}

    def test_real_memory_validated_is_false(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        assert report.executive_summary["real_memory_validated"] is False

    def test_no_malware_score_or_verdict_field(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        for forbidden in ("malware_score", "threat_score", "risk_score", "verdict", "malicious", "suspiciousness_score"):
            assert forbidden not in report.executive_summary

    def test_analysis_status_complete_without_fatal_errors(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        assert report.executive_summary["analysis_status"] == "COMPLETE"

    def test_analysis_status_reflects_fatal_error(self):
        data = _minimal_data(errors=[{"component": "x", "message": "boom", "recoverable": False}])
        report = ReportModel.from_analysis_dict(data)
        assert report.executive_summary["analysis_status"] == "COMPLETE_WITH_ERRORS"


class TestErrorsWarningsSplit:
    def test_recoverable_errors_are_warnings(self):
        data = _minimal_data(errors=[{"component": "x", "message": "minor", "recoverable": True, "pid": 1}])
        report = ReportModel.from_analysis_dict(data)
        assert len(report.warnings) == 1
        assert report.errors == []

    def test_non_recoverable_errors_are_errors(self):
        data = _minimal_data(errors=[{"component": "x", "message": "fatal", "recoverable": False}])
        report = ReportModel.from_analysis_dict(data)
        assert len(report.errors) == 1
        assert report.warnings == []


class TestProcessSummaries:
    def test_one_summary_per_process(self):
        data = _minimal_data(
            processes=[
                {"pid": 1, "name": "a.exe", "os": "windows", "architecture": "x86_64", "is_go_candidate": True},
                {"pid": 2, "name": "b.exe", "os": "windows", "architecture": "x86_64", "is_go_candidate": False},
            ],
            strings=[{"id": "STR-1-0001", "pid": 1}, {"id": "STR-2-0001", "pid": 2}, {"id": "STR-2-0002", "pid": 2}],
        )
        report = ReportModel.from_analysis_dict(data)
        assert len(report.process_summaries) == 2
        by_pid = {p["pid"]: p for p in report.process_summaries}
        assert by_pid[1]["strings_count"] == 1
        assert by_pid[2]["strings_count"] == 2

    def test_order_matches_source_never_resorted(self):
        data = _minimal_data(
            processes=[
                {"pid": 99, "name": "z.exe", "os": "windows", "architecture": "x86_64", "is_go_candidate": False},
                {"pid": 1, "name": "a.exe", "os": "windows", "architecture": "x86_64", "is_go_candidate": True},
            ],
        )
        report = ReportModel.from_analysis_dict(data)
        assert [p["pid"] for p in report.process_summaries] == [99, 1]

    def test_no_suspiciousness_field_exists(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        for key in report.process_summaries[0]:
            assert "suspicio" not in key.lower()
            assert "risk" not in key.lower()
            assert "malicious" not in key.lower()


class TestLimitations:
    def test_always_applicable_limitations_present(self):
        report = ReportModel.from_analysis_dict(_minimal_data())
        joined = " ".join(report.limitations)
        assert "real-memory validation" in joined.lower()
        assert "threat intelligence" in joined.lower()

    def test_conditional_limitation_only_when_reason_present(self):
        data_without = _minimal_data()
        report_without = ReportModel.from_analysis_dict(data_without)
        assert not any("unsupported Go runtime version" in lim or "unsupported_go_version" in lim for lim in report_without.limitations)

        data_with = _minimal_data(errors=[{"component": "x", "message": "m", "reason": "unsupported_go_version", "recoverable": True}])
        report_with = ReportModel.from_analysis_dict(data_with)
        assert any("Go runtime version/layout" in lim for lim in report_with.limitations)


class TestEvidenceTraceability:
    def test_chain_built_from_real_ids(self):
        data = _minimal_data(
            strings=[{"id": "STR-1-0001", "pid": 1, "value": "8.8.8.8"}],
            network_artifacts=[{"id": "NET-1-0001", "pid": 1, "source_artifact_id": "STR-1-0001"}],
            iocs=[{
                "id": "IOC-1-0001", "pid": 1, "ioc_category": "network", "source_artifact_id": "STR-1-0001",
                "source_artifact_type": "network_artifact", "related_network_artifact_id": "NET-1-0001",
                "dedup_key": "ipv4:8.8.8.8", "function_id": None, "goroutine_id": None,
            }],
            findings=[{"finding_id": "FINDING-1-0001", "pid": 1, "supporting_ioc_ids": ["IOC-1-0001"]}],
        )
        report = ReportModel.from_analysis_dict(data)
        assert len(report.evidence_traceability) == 1
        chain = report.evidence_traceability[0]["chain"]
        chain_ids = [(link["type"], link["id"]) for link in chain]
        assert ("finding", "FINDING-1-0001") in chain_ids
        assert ("ioc", "IOC-1-0001") in chain_ids
        assert ("network_artifact", "NET-1-0001") in chain_ids
        assert ("string_artifact", "STR-1-0001") in chain_ids
        assert ("process", 1) in chain_ids
        assert ("evidence_sha256", "deadbeef") in chain_ids

    def test_never_invents_missing_links(self):
        data = _minimal_data(
            findings=[{"finding_id": "FINDING-1-0001", "pid": 1, "supporting_ioc_ids": ["IOC-1-nonexistent"]}],
        )
        report = ReportModel.from_analysis_dict(data)
        chain = report.evidence_traceability[0]["chain"]
        chain_ids = {link["id"] for link in chain}
        assert "IOC-1-nonexistent" not in chain_ids
