"""Phase 6H — end-to-end integration validation.

Exercises the REAL, unmodified ``gomemforensics.pipeline.run_analysis()``
top-level function against the real compiled Go 1.26.2 fixture binary, by
substituting a fake, interface-compatible stand-in for
``VolatilityIntegration`` (the only piece of the pipeline that genuinely
requires a captured memory image, which remains unavailable - Phase 5.5).
Every other stage - evidence hashing, OS/architecture propagation, process
enumeration, Go runtime detection, string/function/goroutine recovery,
network/credential/crypto/persistence extraction, IOC extraction,
correlation, finding generation, statistics aggregation, JSON
serialization, and Phase 6G reporting - runs unmodified, through the
actual production code path (``pipeline._recover_*`` wrappers included),
not a hand-assembled shortcut.

This is COMPILED_BINARY_VALIDATED, not REAL_MEMORY_VALIDATED - the fake
integration stands in only for Volatility's own image-parsing layer; the
underlying bytes it reads are a real, on-disk Go binary, not a captured
process memory image. ``REAL_MEMORY_VALIDATED`` remains ``False``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from gomemforensics import REAL_MEMORY_VALIDATED
from gomemforensics import pipeline as pipeline_module
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import ProcessInfo
from gomemforensics.reporting.html_renderer import render_html
from gomemforensics.reporting.json_renderer import render_json_dict, render_json_text
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


class _FakeVolatilityIntegration:
    """Interface-compatible stand-in for
    :class:`gomemforensics.volatility.integration.VolatilityIntegration`.

    Implements exactly the methods ``run_analysis`` actually calls
    (``initialize``/``detect_os``/``detect_architecture``/
    ``enumerate_processes``/``get_process_memory``/``get_process_regions``),
    backed by a PE-section-mapped reader over the real fixture binary
    file - the same real-file-bytes boundary every other Phase 6A-6G
    fixture test uses. No Volatility 3 code runs; no real memory image is
    read or required.
    """

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


def _run_real_pipeline(case_id: str = "CASE-6H-E2E"):
    """Run the real, unmodified ``run_analysis()`` against the fixture,
    with only the Volatility image-parsing layer substituted."""
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")
    with patch.object(pipeline_module, "VolatilityIntegration", _FakeVolatilityIntegration):
        return pipeline_module.run_analysis(_WINDOWS_FIXTURE, case_id=case_id)


@pytest.fixture(scope="module")
def _result():
    return _run_real_pipeline()


@pytest.fixture(scope="module")
def _data(_result):
    return _result.to_json_dict()


# ---------------------------------------------------------------------------
# Step 3 - end-to-end fixture test
# ---------------------------------------------------------------------------


class TestPipelineExecution:
    def test_real_memory_validated_remains_false(self):
        assert REAL_MEMORY_VALIDATED is False

    def test_evidence_hashed_from_real_file(self, _result):
        import hashlib

        expected = hashlib.sha256(_WINDOWS_FIXTURE.read_bytes()).hexdigest()
        assert _result.evidence.sha256 == expected
        assert _result.evidence.read_only is True

    def test_os_and_architecture_detected(self, _result):
        assert _result.os == "windows"
        assert _result.architecture == "x86_64"

    def test_process_discovered_and_flagged_go_candidate(self, _result):
        assert len(_result.processes) == 1
        process = _result.processes[0]
        assert process.pid == 1
        assert process.is_go_candidate is True
        assert process.go_version is not None

    def test_go_runtime_recovered(self, _result):
        assert len(_result.go_runtimes) == 1
        runtime = _result.go_runtimes[0]
        assert runtime.pid == 1
        assert runtime.pclntab_address is not None
        assert runtime.moduledata_address is not None

    def test_fixture_baseline_counts_preserved_through_full_pipeline(self, _result):
        # Same verified real counts as every prior Phase 6D-6G fixture
        # test - recorded here only as a fixture-validation expectation,
        # never hardcoded into production logic.
        assert len(_result.strings) == 1976
        assert len(_result.iocs) == 6
        assert len(_result.correlations) == 6
        assert len(_result.findings) == 6

    def test_no_fatal_errors(self, _result):
        assert not any(not e.recoverable for e in _result.errors)


# ---------------------------------------------------------------------------
# Steps 4/5 - provenance and cross-artifact reference validation
# ---------------------------------------------------------------------------


class TestCrossArtifactConsistency:
    def test_every_ioc_source_artifact_resolves(self, _data):
        # IOCArtifact.source_artifact_id is copied verbatim from its
        # derived (network/credential/crypto/persistence) artifact's OWN
        # source_artifact_id, which points to the originating StringArtifact
        # - not to the derived artifact itself (see
        # gomemforensics.analyzers.correlation._network_candidate et al.,
        # and reporting/models.py's _build_evidence_traceability, which
        # relies on exactly this).
        string_ids = {s["id"] for s in _data["strings"]}
        for ioc in _data["iocs"]:
            assert ioc["source_artifact_id"] in string_ids, (
                f"IOC {ioc['id']} references missing source string artifact {ioc['source_artifact_id']}"
            )

    def test_ioc_related_artifact_matches_its_own_category(self, _data):
        # The derived artifact this IOC was actually promoted FROM is
        # referenced via the category-specific related_*_artifact_id field
        # (source_artifact_type is a descriptive label, e.g.
        # "persistence_artifact", not an id).
        category_to_key = {
            "network": ("network_artifacts", "related_network_artifact_id"),
            "credential": ("credential_artifacts", "related_credential_artifact_id"),
            "crypto": ("crypto_artifacts", "related_crypto_artifact_id"),
            "persistence": ("persistence_artifacts", "related_persistence_artifact_id"),
        }
        for ioc in _data["iocs"]:
            key, related_field = category_to_key[ioc["ioc_category"]]
            related_id = ioc.get(related_field)
            assert related_id is not None, f"IOC {ioc['id']} missing its own {related_field}"
            ids_in_collection = {a["id"] for a in _data[key]}
            assert related_id in ids_in_collection, (
                f"IOC {ioc['id']} category {ioc['ioc_category']!r} {related_field}={related_id!r} "
                f"does not resolve within {key}"
            )

    def test_every_correlation_endpoint_resolves(self, _data):
        all_ids_by_type: dict[str, set] = {
            "network_artifact": {a["id"] for a in _data["network_artifacts"]},
            "credential_artifact": {a["id"] for a in _data["credential_artifacts"]},
            "crypto_artifact": {a["id"] for a in _data["crypto_artifacts"]},
            "persistence_artifact": {a["id"] for a in _data["persistence_artifacts"]},
            "string_artifact": {a["id"] for a in _data["strings"]},
            "function": {a["id"] for a in _data["functions"]},
            "goroutine": {a["id"] for a in _data["goroutines"]},
        }
        for corr in _data["correlations"]:
            for role in ("source", "target"):
                obj_type = corr[f"{role}_type"]
                obj_id = corr[f"{role}_id"]
                if obj_type in all_ids_by_type:
                    assert obj_id in all_ids_by_type[obj_type], (
                        f"Correlation {corr['id']} {role} {obj_type}:{obj_id} does not resolve"
                    )

    def test_every_finding_supporting_ioc_resolves(self, _data):
        ioc_ids = {ioc["id"] for ioc in _data["iocs"]}
        for finding in _data["findings"]:
            for ioc_id in finding["supporting_ioc_ids"]:
                assert ioc_id in ioc_ids, f"Finding {finding['finding_id']} references missing IOC {ioc_id}"

    def test_every_finding_supporting_artifact_resolves(self, _data):
        string_ids = {s["id"] for s in _data["strings"]}
        for finding in _data["findings"]:
            for artifact_id in finding["supporting_artifact_ids"]:
                assert artifact_id in string_ids, (
                    f"Finding {finding['finding_id']} references missing artifact {artifact_id}"
                )

    def test_every_finding_supporting_correlation_resolves(self, _data):
        correlation_ids = {c["id"] for c in _data["correlations"]}
        for finding in _data["findings"]:
            for corr_id in finding["supporting_correlation_ids"]:
                assert corr_id in correlation_ids, (
                    f"Finding {finding['finding_id']} references missing correlation {corr_id}"
                )

    def test_finding_function_and_goroutine_ids_resolve_if_present(self, _data):
        function_ids = {f["id"] for f in _data["functions"]}
        goroutine_ids = {g["id"] for g in _data["goroutines"]}
        for finding in _data["findings"]:
            for fid in finding["function_ids"]:
                assert fid in function_ids
            for gid in finding["goroutine_ids"]:
                assert gid in goroutine_ids

    def test_ioc_function_and_goroutine_ids_resolve_if_present(self, _data):
        function_ids = {f["id"] for f in _data["functions"]}
        goroutine_ids = {g["id"] for g in _data["goroutines"]}
        for ioc in _data["iocs"]:
            if ioc.get("function_id"):
                assert ioc["function_id"] in function_ids
            if ioc.get("goroutine_id"):
                assert ioc["goroutine_id"] in goroutine_ids

    def test_no_correlation_claims_relationship_analyzers_do_not_support(self, _data):
        # Only the 13 closed CorrelationType values may appear - never an
        # invented "SAME_FUNCTION_MEANS_BEHAVIOR"/"SAME_GOROUTINE_MEANS_NETWORK"
        # style relationship (stage 5's explicit prohibition).
        forbidden_types = {"same_function_behavior", "same_goroutine_network", "proximity", "adjacent_memory"}
        for corr in _data["correlations"]:
            assert corr["relationship_type"] not in forbidden_types

    def test_all_process_ids_consistent_across_every_collection(self, _data):
        valid_pids = {p["pid"] for p in _data["processes"]}
        for key in (
            "go_runtimes", "strings", "functions", "goroutines", "network_artifacts",
            "credential_artifacts", "crypto_artifacts", "persistence_artifacts",
            "iocs", "correlations", "findings",
        ):
            for item in _data[key]:
                assert item["pid"] in valid_pids, f"{key} item {item.get('id', item.get('finding_id'))} has unknown pid {item['pid']}"


# ---------------------------------------------------------------------------
# Step 6 - determinism / repeatability
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_full_pipeline_runs_produce_identical_ids_and_ordering(self):
        result_a = _run_real_pipeline(case_id="CASE-DETERMINISM")
        result_b = _run_real_pipeline(case_id="CASE-DETERMINISM")

        assert [s.id for s in result_a.strings] == [s.id for s in result_b.strings]
        assert [f.id for f in result_a.functions] == [f.id for f in result_b.functions]
        assert [g.id for g in result_a.goroutines] == [g.id for g in result_b.goroutines]
        assert [i.id for i in result_a.iocs] == [i.id for i in result_b.iocs]
        assert [c.id for c in result_a.correlations] == [c.id for c in result_b.correlations]
        assert [f.finding_id for f in result_a.findings] == [f.finding_id for f in result_b.findings]

    @staticmethod
    def _strip_run_timestamps(data: dict) -> dict:
        # Each call to run_analysis() performs its own fresh evidence
        # validation/environment snapshot and constructs fresh
        # AnalysisError records (each with its own event `timestamp`,
        # default_factory=utc_now_iso) - these are legitimately
        # time-varying per run (like two separate `analyze` invocations
        # against the same file), exactly as Phase 6G already isolates
        # report_generated_at from evidence/analysis timestamps. Every
        # OTHER field - every id, ordering, value, and error
        # component/message/pid/reason/recoverable - must be identical;
        # this strips ONLY the clock reading, never anything that would
        # hide a real nondeterminism bug.
        data = json.loads(json.dumps(data, default=str))
        for key in ("environment", "evidence"):
            data[key] = {k: v for k, v in data[key].items() if k != "analysis_timestamp"}
        data["errors"] = [{k: v for k, v in e.items() if k != "timestamp"} for e in data["errors"]]
        return data

    def test_repeated_runs_produce_structurally_identical_json(self):
        result_a = _run_real_pipeline(case_id="CASE-DETERMINISM-JSON")
        result_b = _run_real_pipeline(case_id="CASE-DETERMINISM-JSON")
        data_a = self._strip_run_timestamps(result_a.to_json_dict())
        data_b = self._strip_run_timestamps(result_b.to_json_dict())
        assert data_a == data_b

    def test_report_rendering_deterministic_across_repeated_pipeline_runs(self):
        result_a = _run_real_pipeline(case_id="CASE-DETERMINISM-REPORT")
        result_b = _run_real_pipeline(case_id="CASE-DETERMINISM-REPORT")
        data_a = self._strip_run_timestamps(result_a.to_json_dict())
        data_b = self._strip_run_timestamps(result_b.to_json_dict())
        report_a = ReportModel.from_analysis_dict(data_a, report_timestamp="FIXED")
        report_b = ReportModel.from_analysis_dict(data_b, report_timestamp="FIXED")
        assert render_html(report_a) == render_html(report_b)
        assert render_json_text(report_a) == render_json_text(report_b)


# ---------------------------------------------------------------------------
# Step 8 - partial-analysis validation
# ---------------------------------------------------------------------------


class TestPartialAnalysis:
    def test_empty_categories_are_distinct_from_analyzer_failure(self, _result, _data):
        # Whichever categories the fixture legitimately produces zero
        # artifacts for (e.g. this benign fixture may have zero real
        # credential/crypto artifacts) must not be accompanied by a
        # non-recoverable error for that category - "nothing found" must
        # never be conflated with "analysis failed".
        empty_categories = [
            key for key in ("network_artifacts", "credential_artifacts", "crypto_artifacts")
            if len(_data[key]) == 0
        ]
        fatal_errors = [e for e in _result.errors if not e.recoverable]
        assert fatal_errors == [], "an empty category coincided with a fatal error"

    def test_report_renders_empty_sections_with_explicit_empty_message_not_error(self, _data):
        report = ReportModel.from_analysis_dict(dict(_data))
        html = render_html(report)
        # Every possible artifact section either has real rows or the
        # explicit "No X recovered." empty-state message - never silently
        # missing, never mislabeled as an error/unavailable state.
        if not report.credential_artifacts:
            assert "No credential artifacts recovered." in html
        if not report.crypto_artifacts:
            assert "No crypto artifacts recovered." in html


# ---------------------------------------------------------------------------
# Step 9 - secret-safety end-to-end
# ---------------------------------------------------------------------------


class TestSecretSafetyEndToEnd:
    _RAW_PASSWORD = "E2ESecretPassw0rd!!"
    _RAW_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCE2Efakekeydata-----END RSA PRIVATE KEY-----"
    _RAW_BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.e2e.fakebearer"
    _RAW_BASIC = "Basic dXNlcjpFMkVTZWNyZXRQYXNzdzByZCEh"
    _RAW_COOKIE = "session=E2ESessionTokenSecretValue12345"
    _RAW_DB_CRED = "postgres://admin:E2EDbPassw0rd!!@10.0.0.5:5432/prod"

    def _inject_synthetic_secrets(self, data: dict) -> dict:
        data = json.loads(json.dumps(data))  # deep copy via round-trip
        synthetic = [
            {"id": "CRED-E2E-0001", "pid": 1, "artifact_type": "password",
             "raw_value": self._RAW_PASSWORD, "redacted_value": "E******************!!",
             "confidence": "medium", "validation_status": "structurally_valid"},
            {"id": "CRED-E2E-0002", "pid": 1, "artifact_type": "basic_auth",
             "raw_value": self._RAW_BASIC, "redacted_value": "Basic [redacted]",
             "confidence": "medium", "validation_status": "structurally_valid"},
            {"id": "CRED-E2E-0003", "pid": 1, "artifact_type": "bearer_token",
             "raw_value": self._RAW_BEARER, "redacted_value": "Bearer [redacted]",
             "confidence": "medium", "validation_status": "structurally_valid"},
            {"id": "CRED-E2E-0004", "pid": 1, "artifact_type": "cookie",
             "raw_value": self._RAW_COOKIE, "redacted_value": "session=[redacted]",
             "confidence": "medium", "validation_status": "structurally_valid"},
            {"id": "CRED-E2E-0005", "pid": 1, "artifact_type": "database_credential",
             "raw_value": self._RAW_DB_CRED, "redacted_value": "postgres://admin:[redacted]@10.0.0.5:5432/prod",
             "confidence": "medium", "validation_status": "structurally_valid"},
        ]
        data.setdefault("credential_artifacts", []).extend(synthetic)
        data.setdefault("crypto_artifacts", []).append({
            "id": "CRYPTO-E2E-0001", "pid": 1, "artifact_type": "private_key", "algorithm": "RSA",
            "raw_value": self._RAW_PRIVATE_KEY, "redacted_value": "-----BEGIN RSA PRIVATE KEY----- [redacted]",
            "confidence": "medium", "validation_status": "structurally_valid",
        })
        return data

    def test_html_report_never_leaks_any_injected_raw_secret(self, _data):
        data = self._inject_synthetic_secrets(_data)
        report = ReportModel.from_analysis_dict(data)
        html = render_html(report)
        for raw in (self._RAW_PASSWORD, self._RAW_PRIVATE_KEY, self._RAW_BEARER, self._RAW_BASIC, self._RAW_COOKIE, self._RAW_DB_CRED):
            assert raw not in html

    def test_html_report_shows_redacted_forms(self, _data):
        data = self._inject_synthetic_secrets(_data)
        report = ReportModel.from_analysis_dict(data)
        html = render_html(report)
        assert "E******************!!" in html
        assert "Basic [redacted]" in html
        assert "Bearer [redacted]" in html

    def test_cli_report_stdout_never_leaks_raw_secret(self, _data, tmp_path):
        from click.testing import CliRunner

        from gomemforensics.cli.main import cli

        data = self._inject_synthetic_secrets(_data)
        analysis_path = tmp_path / "analysis.json"
        analysis_path.write_text(json.dumps(data), encoding="utf-8")
        output_path = tmp_path / "report.html"

        result = CliRunner().invoke(cli, ["report", str(analysis_path), "--output", str(output_path)])

        assert result.exit_code == 0
        for raw in (self._RAW_PASSWORD, self._RAW_PRIVATE_KEY, self._RAW_BEARER):
            assert raw not in result.output


# ---------------------------------------------------------------------------
# Step 11 - JSON schema / serialization round-trip
# ---------------------------------------------------------------------------


class TestJsonRoundTrip:
    def test_analysis_result_json_is_fully_serializable(self, _result):
        text = json.dumps(_result.to_json_dict(), indent=2, default=str)
        parsed = json.loads(text)
        assert parsed["case"]["case_id"] == "CASE-6H-E2E"
        assert len(parsed["strings"]) == 1976

    def test_report_round_trip_preserves_special_characters(self, _data):
        data = json.loads(json.dumps(_data))
        injected_value = 'Ünïcödé 中文 "quoted" \\backslash\\ \nnewline\ttab <script>alert(1)</script>'
        data.setdefault("strings", []).append({
            "id": "STR-E2E-SPECIAL", "pid": 1, "region": "static", "classification": "unknown",
            "confidence": "low", "length": len(injected_value), "string_address": "0xdeadbeef",
            "value": injected_value,
        })

        report = ReportModel.from_analysis_dict(data)
        json_text = render_json_text(report)
        round_tripped = json.loads(json_text)
        found = [s for s in round_tripped["strings"] if s["id"] == "STR-E2E-SPECIAL"]
        assert found and found[0]["value"] == injected_value  # no silent data loss/mangling

        html = render_html(report)
        assert "<script>alert(1)</script>" not in html  # escaped, not executable
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_empty_optional_collections_round_trip_without_crash(self, _data):
        data = json.loads(json.dumps(_data))
        for key in ("network_artifacts", "credential_artifacts", "crypto_artifacts", "persistence_artifacts"):
            data[key] = []
        report = ReportModel.from_analysis_dict(data)
        assert render_json_dict(report)["network_artifacts"] == []
        assert render_html(report)  # does not raise

    def test_null_optional_fields_do_not_crash_rendering(self, _data):
        data = json.loads(json.dumps(_data))
        if data["go_runtimes"]:
            data["go_runtimes"][0]["go_version"] = None
        report = ReportModel.from_analysis_dict(data)
        assert render_html(report)


# ---------------------------------------------------------------------------
# Step 13 - resource-bound / large-result validation
# ---------------------------------------------------------------------------


class TestResourceBounds:
    def test_html_truncates_large_table_with_explicit_notice(self, _data):
        # The real fixture's Functions table (2,193 rows) already exceeds
        # MAX_TABLE_ROWS_HTML=2000 - this must be disclosed, never silent.
        report = ReportModel.from_analysis_dict(dict(_data))
        html = render_html(report)
        if len(report.functions) > 2000:
            assert "the complete, untruncated set is in the JSON report" in html

    def test_json_report_never_truncates_regardless_of_html_bound(self, _data):
        report = ReportModel.from_analysis_dict(dict(_data))
        rendered = render_json_dict(report)
        assert len(rendered["functions"]) == len(_data["functions"])
        assert len(rendered["strings"]) == len(_data["strings"])
