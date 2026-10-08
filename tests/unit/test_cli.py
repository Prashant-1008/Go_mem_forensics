"""CLI behavior tests using Click's in-process test runner.

None of these tests touch a real memory image; ``validate``/``analyze`` are
exercised against small synthetic files created in ``tmp_path``. ``report``
is exercised against small synthetic analysis JSON files - it never
re-scans memory.
"""

import hashlib
import json

from click.testing import CliRunner

from gomemforensics.cli.main import EXIT_OK, EXIT_REPORT_ERROR, EXIT_VALIDATION_ERROR, cli

_MINIMAL_ANALYSIS_JSON = {
    "case": {"case_id": "CASE-CLI"},
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


def test_cli_help_exits_zero():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "GoMemForensics" in result.output


def test_cli_version_command():
    result = CliRunner().invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "GoMemForensics" in result.output
    assert "Phase 6" in result.output


def test_cli_info_command():
    result = CliRunner().invoke(cli, ["info"])
    assert result.exit_code == 0
    assert "Python version" in result.output
    assert "volatility3" in result.output
    assert "capstone" in result.output
    assert "ARM64" in result.output


def test_cli_validate_success(tmp_path):
    evidence = tmp_path / "sample.raw"
    evidence.write_bytes(b"synthetic evidence bytes")
    expected_hash = hashlib.sha256(b"synthetic evidence bytes").hexdigest()

    result = CliRunner().invoke(cli, ["validate", str(evidence)])

    assert result.exit_code == EXIT_OK
    assert expected_hash in result.output
    assert "Evidence validated" in result.output


def test_cli_validate_nonexistent_file():
    result = CliRunner().invoke(cli, ["validate", "does-not-exist.raw"])
    assert result.exit_code == EXIT_VALIDATION_ERROR
    assert "validation failed" in result.output.lower()


def test_cli_validate_directory(tmp_path):
    result = CliRunner().invoke(cli, ["validate", str(tmp_path)])
    assert result.exit_code == EXIT_VALIDATION_ERROR


def test_cli_analyze_requires_image_path_argument():
    # IMAGE_PATH became a required argument in Phase 1 now that `analyze`
    # performs a real pipeline run; Click should reject a missing argument
    # before any evidence/Volatility code runs.
    result = CliRunner().invoke(cli, ["analyze"])
    assert result.exit_code != 0
    assert "Missing argument" in result.output


def test_cli_analyze_nonexistent_file_fails_at_evidence_validation():
    # Evidence validation happens before Volatility is ever touched, so
    # this stays fast and does not require a real memory image.
    result = CliRunner().invoke(cli, ["analyze", "does-not-exist.raw"])
    assert result.exit_code == EXIT_VALIDATION_ERROR
    assert "validation failed" in result.output.lower()


def test_cli_analyze_directory_fails_at_evidence_validation(tmp_path):
    result = CliRunner().invoke(cli, ["analyze", str(tmp_path)])
    assert result.exit_code == EXIT_VALIDATION_ERROR


def test_cli_debug_flag_accepted():
    result = CliRunner().invoke(cli, ["--debug", "info"])
    assert result.exit_code == 0


def test_cli_info_mentions_phase_6g_reporting():
    result = CliRunner().invoke(cli, ["info"])
    assert result.exit_code == 0
    assert "gomemforensics report" in result.output
    assert "go-reporting.md" in result.output


def test_cli_report_html_success(tmp_path):
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(_MINIMAL_ANALYSIS_JSON), encoding="utf-8")
    output_path = tmp_path / "report.html"

    result = CliRunner().invoke(cli, ["report", str(analysis_path), "--format", "html", "--output", str(output_path)])

    assert result.exit_code == EXIT_OK
    assert output_path.exists()
    assert "REAL_MEMORY_VALIDATED = False" in result.output
    assert "<!DOCTYPE html>" in output_path.read_text(encoding="utf-8")


def test_cli_report_json_success(tmp_path):
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(_MINIMAL_ANALYSIS_JSON), encoding="utf-8")
    output_path = tmp_path / "report.json"

    result = CliRunner().invoke(cli, ["report", str(analysis_path), "--format", "json", "--output", str(output_path)])

    assert result.exit_code == EXIT_OK
    parsed = json.loads(output_path.read_text(encoding="utf-8"))
    assert parsed["case"]["case_id"] == "CASE-CLI"


def test_cli_report_defaults_to_html_and_default_output_dir(tmp_path, monkeypatch):
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(_MINIMAL_ANALYSIS_JSON), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli, ["report", str(analysis_path)])

    assert result.exit_code == EXIT_OK
    assert (tmp_path / "reports" / "report.html").exists()


def test_cli_report_missing_file_fails():
    result = CliRunner().invoke(cli, ["report", "does-not-exist.json"])
    assert result.exit_code == 2  # Click's own exists=True path validation


def test_cli_report_malformed_json_fails(tmp_path):
    analysis_path = tmp_path / "bad.json"
    analysis_path.write_text("{not valid json", encoding="utf-8")

    result = CliRunner().invoke(cli, ["report", str(analysis_path)])

    assert result.exit_code == EXIT_REPORT_ERROR
    assert "not valid json" in result.output.lower()


def test_cli_report_missing_required_keys_fails(tmp_path):
    analysis_path = tmp_path / "incomplete.json"
    analysis_path.write_text(json.dumps({"case": {}}), encoding="utf-8")

    result = CliRunner().invoke(cli, ["report", str(analysis_path)])

    assert result.exit_code == EXIT_REPORT_ERROR
    assert "could not build report" in result.output.lower()


def test_cli_report_unsupported_format_rejected_by_click(tmp_path):
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(_MINIMAL_ANALYSIS_JSON), encoding="utf-8")

    result = CliRunner().invoke(cli, ["report", str(analysis_path), "--format", "pdf"])

    assert result.exit_code != 0
    assert "invalid value" in result.output.lower()


def test_cli_report_never_reruns_analysis(tmp_path):
    # The report command must only read the supplied JSON file - it must
    # not accept an --format option that implies a live memory image path,
    # and it must not touch anything named like a raw memory image.
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(_MINIMAL_ANALYSIS_JSON), encoding="utf-8")
    output_path = tmp_path / "report.html"

    result = CliRunner().invoke(cli, ["report", str(analysis_path), "--output", str(output_path)])

    assert result.exit_code == EXIT_OK
    assert "Validating evidence" not in result.output
    assert "Volatility" not in result.output
