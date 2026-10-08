"""COMPILED_BINARY_VALIDATED coverage for the Phase 6G reporting layer.

Runs the full Phase 2-6F chain against the real compiled Go 1.26.2 fixture
binary (same PE-section-mapped-reader boundary as every other Phase 6A-6F
real-fixture test), assembles a genuine :class:`~gomemforensics.pipeline.AnalysisResult`
from the recovered artifacts, and verifies that :mod:`gomemforensics.reporting`
correctly represents the known real counts through both the JSON and HTML
renderers - and that report generation is deterministic across repeated
renders of the same data.

Explicitly NOT real-memory validation - see CLAUDE.md and
docs/validation/validation-plan.md. ``REAL_MEMORY_VALIDATED`` must remain
``False`` throughout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics import REAL_MEMORY_VALIDATED
from gomemforensics.acquisition.evidence import EvidenceValidator
from gomemforensics.analyzers.correlation import correlate_artifacts, extract_iocs
from gomemforensics.analyzers.credentials import extract_credential_artifacts
from gomemforensics.analyzers.crypto import extract_crypto_artifacts
from gomemforensics.analyzers.findings import generate_findings
from gomemforensics.analyzers.network import extract_network_artifacts
from gomemforensics.analyzers.persistence import extract_persistence_artifacts
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisStatistics, Confidence, ProcessInfo
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.functab import FunctionTableParser
from gomemforensics.go_runtime.strings import StringRecoveryEngine
from gomemforensics.pipeline import AnalysisResult
from gomemforensics.reporting.html_renderer import render_html
from gomemforensics.reporting.json_renderer import render_json_dict
from gomemforensics.reporting.models import ReportModel

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


@pytest.fixture(scope="module")
def _analysis_result():
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")

    evidence = EvidenceValidator().validate(_WINDOWS_FIXTURE, case_id="CASE-6G-FIXTURE")

    pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
    reader = _PEMappedReader(pe)
    regions = _build_regions(pe)

    detection = GoProcessDetector().detect(pid=1, architecture="x86_64", pointer_size=8, reader=reader, regions=regions)
    assert detection.runtime is not None, f"Go runtime not recovered from real fixture: {detection.errors}"
    runtime = detection.runtime

    static_strings, string_errors = StringRecoveryEngine(reader, pointer_size=8).recover_static_strings(runtime, regions)
    functions, function_errors = FunctionTableParser(reader, pointer_size=8).parse(runtime)

    network_artifacts, net_errors, _stats = extract_network_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, []
    )
    credential_artifacts, cred_errors, _stats = extract_credential_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, [], network_artifacts
    )
    crypto_artifacts, crypto_errors, _stats = extract_crypto_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, [], network_artifacts, credential_artifacts
    )
    persistence_artifacts, persist_errors, _stats = extract_persistence_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, [],
        network_artifacts, credential_artifacts, crypto_artifacts,
    )
    iocs, ioc_errors, _ioc_stats = extract_iocs(
        1, "fixture.exe", network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
    )
    correlations, corr_errors, _corr_stats = correlate_artifacts(
        1, functions, [], network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
    )
    findings, finding_errors, _finding_stats = generate_findings(1, "fixture.exe", iocs, correlations)

    process = ProcessInfo(
        pid=1, ppid=None, name="fixture.exe", executable_path=str(_WINDOWS_FIXTURE),
        architecture="x86_64", os="windows", create_time=None, memory_layer_available=True,
        is_go_candidate=True, go_confidence=Confidence.HIGH, go_version=runtime.go_version,
    )
    all_errors = [
        *string_errors, *function_errors, *net_errors, *cred_errors, *crypto_errors,
        *persist_errors, *ioc_errors, *corr_errors, *finding_errors,
    ]
    statistics = AnalysisStatistics(
        processes_discovered=1, processes_with_memory_access=1, go_candidate_processes=1,
        go_runtimes_reconstructed=1, strings_recovered=len(static_strings),
        strings_recovered_static=len(static_strings), errors_count=len(all_errors),
    )

    result = AnalysisResult(
        case_id="CASE-6G-FIXTURE", evidence=evidence, environment={"tool_version": "0.13.0"},
        os="windows", architecture="x86_64", processes=[process], errors=all_errors,
        statistics=statistics, go_runtimes=[runtime], strings=static_strings, functions=functions,
        network_artifacts=network_artifacts, credential_artifacts=credential_artifacts,
        crypto_artifacts=crypto_artifacts, persistence_artifacts=persistence_artifacts,
        iocs=iocs, correlations=correlations, findings=findings,
    )
    return result


def test_real_memory_validated_remains_false():
    # A COMPILED_BINARY_VALIDATED fixture run must never flip this project-
    # wide constant - see CLAUDE.md section 51 and the Phase 6G prompt.
    assert REAL_MEMORY_VALIDATED is False


def test_fixture_produces_expected_baseline_counts(_analysis_result):
    # These specific numbers (1,976 static strings; 6 IOCs; 6 correlations;
    # 6 findings) are the currently-verified real output of the compiled
    # fixture as of Phase 6D/6E/6F - recorded here only as a fixture-
    # validation expectation, never hardcoded into production logic.
    assert len(_analysis_result.strings) == 1976
    assert len(_analysis_result.iocs) == 6
    assert len(_analysis_result.correlations) == 6
    assert len(_analysis_result.findings) == 6


def test_report_model_reflects_fixture_counts(_analysis_result):
    data = _analysis_result.to_json_dict()
    report = ReportModel.from_analysis_dict(data)
    summary = report.executive_summary
    assert summary["strings_recovered"] == 1976
    assert summary["ioc_count"] == 6
    assert summary["correlation_count"] == 6
    assert summary["finding_count"] == 6
    assert summary["real_memory_validated"] is False


def test_json_render_preserves_fixture_counts(_analysis_result):
    data = _analysis_result.to_json_dict()
    report = ReportModel.from_analysis_dict(data)
    rendered = render_json_dict(report)
    assert len(rendered["strings"]) == 1976
    assert len(rendered["iocs"]) == 6
    assert len(rendered["correlations"]) == 6
    assert len(rendered["findings"]) == 6


def test_html_render_succeeds_and_is_self_contained(_analysis_result):
    data = _analysis_result.to_json_dict()
    report = ReportModel.from_analysis_dict(data)
    html = render_html(report)
    assert "<!DOCTYPE html>" in html
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html
    # Some fixture tables (e.g. functions, at 2193 rows) legitimately exceed
    # the 2000-row HTML display bound - when that happens the truncation
    # must be explicit, never silent (stage 33/44), never a JSON truncation.
    if "truncation-notice" in html:
        assert "the complete, untruncated set is in the JSON report" in html


def test_html_render_uses_redacted_values_in_sensitive_artifact_tables(_analysis_result):
    # The fixture's persistence "secrets" are inert fake registry/scheduled-
    # task/systemd path strings, not real credentials - and by the Phase 6G
    # design (see html_renderer module docstring), the Strings section
    # intentionally shows full raw evidence, so those same benign path
    # strings legitimately reappear there. The actual redaction contract
    # under test is narrower: each sensitive artifact's OWN table renders
    # its redacted_value, and never leaves it blank when one was supplied.
    data = _analysis_result.to_json_dict()
    report = ReportModel.from_analysis_dict(data)
    html = render_html(report)
    for artifact in report.credential_artifacts + report.crypto_artifacts + report.persistence_artifacts:
        redacted = artifact.get("redacted_value")
        if redacted:
            assert redacted in html


def test_synthetic_true_secret_never_leaks_in_fixture_report(_analysis_result):
    # Confirms the redaction *mechanism itself* against a genuinely
    # secret-shaped value, by injecting one synthetic credential artifact
    # alongside the real fixture data (the fixture binary contains no real
    # passwords/private keys to test against).
    data = _analysis_result.to_json_dict()
    raw_secret = "TrulySecretFixturePassw0rd!!"
    data["credential_artifacts"] = data.get("credential_artifacts", []) + [{
        "id": "CRED-1-9999", "pid": 1, "artifact_type": "password",
        "raw_value": raw_secret, "redacted_value": "T***************!!",
        "confidence": "medium", "validation_status": "structurally_valid",
    }]
    report = ReportModel.from_analysis_dict(data)
    html = render_html(report)
    assert raw_secret not in html
    assert "T***************!!" in html


def test_report_determinism_across_repeated_renders(_analysis_result):
    data = _analysis_result.to_json_dict()
    report1 = ReportModel.from_analysis_dict(data, report_timestamp="FIXED")
    report2 = ReportModel.from_analysis_dict(data, report_timestamp="FIXED")
    assert render_html(report1) == render_html(report2)
    assert render_json_dict(report1) == render_json_dict(report2)


def test_findings_traceable_through_evidence_chain(_analysis_result):
    data = _analysis_result.to_json_dict()
    report = ReportModel.from_analysis_dict(data)
    assert len(report.evidence_traceability) == 6
    evidence_sha = data["evidence"]["sha256"]
    for entry in report.evidence_traceability:
        chain_ids = {(link["type"], link["id"]) for link in entry["chain"]}
        assert ("evidence_sha256", evidence_sha) in chain_ids
        assert ("process", 1) in chain_ids
