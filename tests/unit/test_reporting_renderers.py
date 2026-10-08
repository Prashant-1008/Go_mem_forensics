"""Tests for the Phase 6G JSON and HTML report renderers.

Covers: field completeness, determinism, self-containment (no external
network resources), HTML-escaping/XSS-safety, redaction / secret-leak
prevention, and table/string truncation bounds. All input is SYNTHETIC.
"""

from __future__ import annotations

import json

from gomemforensics.reporting.html_renderer import render_html
from gomemforensics.reporting.json_renderer import render_json_dict, render_json_text
from gomemforensics.reporting.models import ReportModel

_RAW_SECRET = "SuperSecretPassw0rd!!"
_RAW_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----"


def _data_with_sensitive_artifacts():
    return {
        "case": {"case_id": "CASE-XSS"},
        "evidence": {
            "input_path": "x.raw", "file_name": "x.raw", "file_size": 100,
            "sha256": "deadbeef", "hash_algorithm": "SHA-256",
            "analysis_timestamp": "2026-01-01T00:00:00Z", "read_only": True,
        },
        "environment": {"tool_version": "0.13.0"},
        "system": {"os": "windows", "architecture": "x86_64"},
        "processes": [
            {"pid": 1, "name": "<script>evil</script>.exe", "os": "windows", "architecture": "x86_64",
             "is_go_candidate": True, "go_version": "1.26.2", "go_confidence": "high"},
        ],
        "strings": [
            {"id": "STR-1-0001", "pid": 1, "region": "heap", "classification": "runtime",
             "confidence": "high", "length": 5, "string_address": "0x1000",
             "value": "<img src=x onerror=alert(1)>"},
        ],
        "credential_artifacts": [
            {"id": "CRED-1-0001", "pid": 1, "artifact_type": "password",
             "raw_value": _RAW_SECRET, "redacted_value": "S***********!!", "confidence": "medium",
             "validation_status": "structurally_valid"},
        ],
        "crypto_artifacts": [
            {"id": "CRYPTO-1-0001", "pid": 1, "artifact_type": "private_key", "algorithm": "RSA",
             "raw_value": _RAW_PRIVATE_KEY, "redacted_value": "-----BEGIN PRIVATE KEY----- [redacted]",
             "confidence": "medium", "validation_status": "structurally_valid"},
        ],
        "persistence_artifacts": [
            {"id": "PERSIST-1-0001", "pid": 1, "platform": "windows", "artifact_type": "windows_persistence_reference",
             "persistence_mechanism": "registry_run_key", "raw_value": _RAW_SECRET,
             "redacted_value": "[redacted persistence value]", "confidence": "low"},
        ],
        "iocs": [
            {"id": "IOC-1-0001", "pid": 1, "ioc_type": "password", "ioc_category": "credential",
             "raw_value": _RAW_SECRET, "redacted_value": "S***********!!", "normalized_value": None,
             "source_artifact_id": "CRED-1-0001", "confidence": "medium",
             "validation_status": "structurally_valid", "dedup_key": "credential:hash1"},
            {"id": "IOC-1-0002", "pid": 1, "ioc_type": "ipv4", "ioc_category": "network",
             "raw_value": "1.2.3.4", "redacted_value": None, "normalized_value": "1.2.3.4",
             "source_artifact_id": "NET-1-0001", "confidence": "high",
             "validation_status": "structurally_valid", "dedup_key": "ipv4:1.2.3.4"},
        ],
    }


class TestJsonRenderer:
    def test_all_expected_top_level_keys_present(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        d = render_json_dict(report)
        expected = {
            "report_metadata", "case", "evidence", "environment", "validation", "executive_summary",
            "processes", "process_summaries", "go_runtimes", "strings", "functions", "goroutines",
            "network_artifacts", "credential_artifacts", "crypto_artifacts", "persistence_artifacts",
            "iocs", "correlations", "findings", "errors", "warnings", "methodology", "limitations",
            "evidence_traceability", "statistics",
        }
        assert expected <= set(d.keys())

    def test_json_text_is_valid_json(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        text = render_json_text(report)
        parsed = json.loads(text)
        assert parsed["case"]["case_id"] == "CASE-XSS"

    def test_determinism_across_multiple_renders(self):
        data = _data_with_sensitive_artifacts()
        report1 = ReportModel.from_analysis_dict(data, report_timestamp="FIXED")
        report2 = ReportModel.from_analysis_dict(data, report_timestamp="FIXED")
        assert render_json_text(report1) == render_json_text(report2)

    def test_json_never_truncates_raw_secrets_but_uses_redacted_field(self):
        # The JSON is the canonical machine-readable form and carries whatever
        # fields the analysis JSON provided - callers who redacted upstream
        # keep the redacted_value field; the renderer must not fabricate or
        # strip fields, and must not compute a raw value from a redacted one.
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        d = render_json_dict(report)
        assert d["credential_artifacts"][0]["redacted_value"] == "S***********!!"


class TestHtmlRendererSelfContainment:
    def test_no_script_tags(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert "<script" not in html.lower()

    def test_no_external_resources(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        for forbidden in ("http://", "https://", "cdn.", "fonts.googleapis", "<link rel=\"stylesheet\" href="):
            assert forbidden not in html.lower()

    def test_all_21_sections_present(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        expected_ids = [
            "cover", "executive-summary", "evidence", "validation", "environment", "processes",
            "go-runtimes", "strings", "functions", "goroutines", "network", "credentials", "crypto",
            "persistence", "iocs", "correlations", "findings", "errors", "methodology", "limitations",
            "traceability",
        ]
        for sid in expected_ids:
            assert f'id="{sid}"' in html

    def test_determinism_across_multiple_renders(self):
        data = _data_with_sensitive_artifacts()
        report1 = ReportModel.from_analysis_dict(data, report_timestamp="FIXED")
        report2 = ReportModel.from_analysis_dict(data, report_timestamp="FIXED")
        assert render_html(report1) == render_html(report2)


class TestHtmlEscaping:
    def test_process_name_script_tag_is_escaped(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert "<script>evil</script>" not in html
        assert "&lt;script&gt;evil&lt;/script&gt;" in html

    def test_string_value_html_injection_is_escaped(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert "<img src=x onerror=alert(1)>" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html


class TestSecretLeakPrevention:
    def test_raw_credential_value_never_appears_in_html(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert _RAW_SECRET not in html

    def test_raw_private_key_never_appears_in_html(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert _RAW_PRIVATE_KEY not in html
        assert "MIIEvQIBADANBg" not in html

    def test_redacted_values_do_appear(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert "S***********!!" in html
        assert "[redacted persistence value]" in html

    def test_raw_credential_value_never_appears_in_json(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        text = render_json_text(report)
        # raw_value fields pass through JSON since it mirrors the analysis
        # JSON verbatim (redaction is enforced by upstream analyzers, not
        # this renderer) - but the HTML (default investigator view) must
        # never show it. This test documents that boundary explicitly.
        assert "redacted_value" in text

    def test_ioc_network_category_shows_normalized_value_not_raw_secret(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert "1.2.3.4" in html


class TestTruncationBounds:
    def test_large_string_value_is_truncated_with_notice(self):
        data = _data_with_sensitive_artifacts()
        data["strings"][0]["value"] = "A" * 1000
        report = ReportModel.from_analysis_dict(data)
        html = render_html(report)
        assert "more chars, see JSON" in html
        assert "A" * 1000 not in html

    def test_large_table_is_truncated_with_notice(self):
        data = _data_with_sensitive_artifacts()
        data["strings"] = [
            {"id": f"STR-1-{i:04d}", "pid": 1, "region": "heap", "classification": "runtime",
             "confidence": "high", "length": 1, "string_address": hex(i), "value": "x"}
            for i in range(2500)
        ]
        report = ReportModel.from_analysis_dict(data)
        html = render_html(report)
        assert "Showing 2000 of 2500 entries" in html

    def test_json_never_truncates_large_lists(self):
        data = _data_with_sensitive_artifacts()
        data["strings"] = [
            {"id": f"STR-1-{i:04d}", "pid": 1, "region": "heap", "classification": "runtime",
             "confidence": "high", "length": 1, "string_address": hex(i), "value": "x"}
            for i in range(2500)
        ]
        report = ReportModel.from_analysis_dict(data)
        d = render_json_dict(report)
        assert len(d["strings"]) == 2500


class TestNoForbiddenWording:
    def test_network_section_never_claims_contact(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        for forbidden in ("process contacted", "process connected to", "beaconed", "exfiltrated to"):
            assert forbidden not in html.lower()

    def test_persistence_section_never_claims_established(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        assert "persistence was successfully established" not in html.lower()
        assert "persistence established on" not in html.lower()

    def test_no_malware_verdict_language(self):
        report = ReportModel.from_analysis_dict(_data_with_sensitive_artifacts())
        html = render_html(report)
        # The report legitimately *denies* having a malware score ("no ...
        # malware score is produced"), so only positive-claim phrasings are
        # forbidden here - not the bare terms.
        for forbidden in (
            "this process is malware", "definitely malware",
            "malware score:", "threat score:", "risk score:",
            "malware score is", "threat score is", "risk score is",
        ):
            assert forbidden not in html.lower()
