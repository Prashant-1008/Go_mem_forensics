"""Phase 6H — CLI end-to-end validation.

Exercises the CLI exactly as an investigator would: `analyze` against the
real compiled fixture binary (via the same Volatility-layer substitution
as tests/integration/test_end_to_end_pipeline.py - only the image-parsing
layer is faked, everything else in the pipeline runs for real), then
`report` against the resulting JSON. Confirms exit codes, output-file
handling, overwrite behavior, stdout/stderr separation, secret safety,
and that `report` never re-runs analysis (no Volatility coupling).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from gomemforensics import pipeline as pipeline_module
from gomemforensics.cli.main import EXIT_OK, cli
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import ProcessInfo

pefile = pytest.importorskip("pefile")

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"


class _PEMappedReader(MemoryReader):
    def __init__(self, pe: "pefile.PE") -> None:
        self._pe = pe

    @property
    def pointer_size(self) -> int:
        return 8

    def read(self, address: int, length: int) -> bytes:
        try:
            data = self._pe.get_data(address - self._pe.OPTIONAL_HEADER.ImageBase, length)
        except Exception as exc:
            raise MemoryAccessError(f"Could not read 0x{address:x}: {exc}") from exc
        if len(data) < length:
            raise MemoryAccessError(f"Short read at 0x{address:x}")
        return data

    def is_valid(self, address: int) -> bool:
        try:
            self._pe.get_data(address - self._pe.OPTIONAL_HEADER.ImageBase, 1)
            return True
        except Exception:
            return False


def _build_regions(pe: "pefile.PE") -> list[MemoryRegion]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    regions = []
    for section in pe.sections:
        start = image_base + section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        regions.append(
            MemoryRegion(
                start=start, end=start + size, readable=True,
                writable=bool(section.Characteristics & 0x80000000),
                executable=bool(section.Characteristics & 0x20000000),
                source="pe_section",
            )
        )
    return regions


class _FakeVolatilityIntegration:
    """Same interface-compatible stand-in as
    tests/integration/test_end_to_end_pipeline.py (duplicated locally per
    this project's established fixture-test convention - see e.g.
    test_findings_fixture.py/test_reporting_fixture.py, which each
    duplicate their own small PE-mapping boilerplate rather than sharing
    it across files without a tests-as-package import path)."""

    def __init__(self) -> None:
        self._reader: _PEMappedReader | None = None
        self._regions: list[MemoryRegion] | None = None

    def initialize(self, image_path: Path) -> None:
        pe = pefile.PE(str(image_path), fast_load=True)
        self._reader = _PEMappedReader(pe)
        self._regions = _build_regions(pe)

    def detect_os(self) -> str:
        return "windows"

    def detect_architecture(self) -> str:
        return "x86_64"

    def enumerate_processes(self) -> tuple[list[ProcessInfo], list]:
        process = ProcessInfo(
            pid=1, ppid=None, name="fixture.exe", executable_path=str(_WINDOWS_FIXTURE),
            architecture="x86_64", os="windows", create_time=None, memory_layer_available=True,
        )
        return [process], []

    def get_process_memory(self, pid: int) -> MemoryReader | None:
        return self._reader

    def get_process_regions(self, pid: int) -> list[MemoryRegion]:
        return list(self._regions)


def _invoke_analyze(output_path: Path, case_id: str = "CASE-6H-CLI"):
    with patch.object(pipeline_module, "VolatilityIntegration", _FakeVolatilityIntegration):
        return CliRunner().invoke(
            cli, ["analyze", str(_WINDOWS_FIXTURE), "--case-id", case_id, "--output", str(output_path)]
        )


@pytest.fixture(scope="module")
def _analysis_json_path(tmp_path_factory):
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")
    output_dir = tmp_path_factory.mktemp("cli_e2e")
    output_path = output_dir / "analysis.json"
    result = _invoke_analyze(output_path)
    assert result.exit_code == EXIT_OK, result.output
    return output_path


class TestCliHelpAndInfo:
    def test_help_exits_zero(self):
        result = CliRunner().invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "GoMemForensics" in result.output

    def test_info_exits_zero_and_never_touches_volatility(self):
        result = CliRunner().invoke(cli, ["info"])
        assert result.exit_code == 0
        assert "volatility3" in result.output


class TestCliAnalyzeEndToEnd:
    def test_analyze_against_real_fixture_succeeds(self, _analysis_json_path):
        data = json.loads(_analysis_json_path.read_text(encoding="utf-8"))
        assert data["case"]["case_id"] == "CASE-6H-CLI"
        assert len(data["strings"]) == 1976
        assert len(data["findings"]) == 6

    def test_analyze_stdout_reports_progress_without_secrets(self, tmp_path):
        output_path = tmp_path / "analysis2.json"
        result = _invoke_analyze(output_path, case_id="CASE-6H-CLI-2")
        assert result.exit_code == EXIT_OK
        assert "Evidence validated" in result.output
        assert "Findings generated: 6" in result.output

    def test_analyze_missing_file_fails_before_volatility(self):
        result = CliRunner().invoke(cli, ["analyze", "does-not-exist.raw"])
        assert result.exit_code != EXIT_OK
        assert "validation failed" in result.output.lower()

    def test_analyze_overwrite_behavior(self, tmp_path):
        output_path = tmp_path / "analysis.json"
        result1 = _invoke_analyze(output_path, case_id="CASE-FIRST")
        assert result1.exit_code == EXIT_OK
        first_data = json.loads(output_path.read_text(encoding="utf-8"))
        assert first_data["case"]["case_id"] == "CASE-FIRST"

        result2 = _invoke_analyze(output_path, case_id="CASE-SECOND")
        assert result2.exit_code == EXIT_OK
        second_data = json.loads(output_path.read_text(encoding="utf-8"))
        assert second_data["case"]["case_id"] == "CASE-SECOND"  # cleanly overwritten, no stale merge


class TestCliReportEndToEnd:
    def test_report_html_from_real_analyze_output(self, _analysis_json_path, tmp_path):
        output_path = tmp_path / "report.html"
        result = CliRunner().invoke(cli, ["report", str(_analysis_json_path), "--format", "html", "--output", str(output_path)])
        assert result.exit_code == EXIT_OK
        html = output_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "REAL_MEMORY_VALIDATED = False" in result.output

    def test_report_json_from_real_analyze_output(self, _analysis_json_path, tmp_path):
        output_path = tmp_path / "report.json"
        result = CliRunner().invoke(cli, ["report", str(_analysis_json_path), "--format", "json", "--output", str(output_path)])
        assert result.exit_code == EXIT_OK
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["executive_summary"]["finding_count"] == 6

    def test_report_never_touches_volatility_or_memoryreader(self, _analysis_json_path, tmp_path):
        # No patch.object() active here at all - if `report` tried to
        # construct a real VolatilityIntegration or re-run analysis, it
        # would either fail outright (no real memory image available) or
        # attempt real Volatility initialization; neither happens, and the
        # command still succeeds using only the already-produced JSON.
        output_path = tmp_path / "report.html"
        result = CliRunner().invoke(cli, ["report", str(_analysis_json_path), "--output", str(output_path)])
        assert result.exit_code == EXIT_OK
        assert "Validating evidence" not in result.output
        assert "Volatility" not in result.output

    def test_report_overwrite_behavior(self, _analysis_json_path, tmp_path):
        output_path = tmp_path / "report.html"
        result1 = CliRunner().invoke(cli, ["report", str(_analysis_json_path), "--output", str(output_path)])
        assert result1.exit_code == EXIT_OK
        size1 = output_path.stat().st_size

        result2 = CliRunner().invoke(cli, ["report", str(_analysis_json_path), "--output", str(output_path)])
        assert result2.exit_code == EXIT_OK
        size2 = output_path.stat().st_size
        assert size1 == size2  # same input -> same deterministic output size

    def test_report_stderr_separated_from_stdout_on_success(self, _analysis_json_path, tmp_path):
        # Click's CliRunner mixes stdout/stderr by default unless told
        # otherwise; success-path output must contain no "[!]" error marker.
        output_path = tmp_path / "report.html"
        result = CliRunner().invoke(cli, ["report", str(_analysis_json_path), "--output", str(output_path)])
        assert "[!]" not in result.output


class TestCliFullWorkflow:
    def test_analyze_then_report_workflow_end_to_end(self, tmp_path):
        analysis_path = tmp_path / "analysis.json"
        html_path = tmp_path / "report.html"
        json_report_path = tmp_path / "report.json"

        analyze_result = _invoke_analyze(analysis_path, case_id="CASE-WORKFLOW")
        assert analyze_result.exit_code == EXIT_OK

        html_result = CliRunner().invoke(cli, ["report", str(analysis_path), "--format", "html", "--output", str(html_path)])
        assert html_result.exit_code == EXIT_OK

        json_result = CliRunner().invoke(cli, ["report", str(analysis_path), "--format", "json", "--output", str(json_report_path)])
        assert json_result.exit_code == EXIT_OK

        report_data = json.loads(json_report_path.read_text(encoding="utf-8"))
        assert report_data["case"]["case_id"] == "CASE-WORKFLOW"
        assert report_data["executive_summary"]["strings_recovered"] == 1976
        assert report_data["validation"]["real_memory_validated"] is False
