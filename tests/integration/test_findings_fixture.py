"""COMPILED_BINARY_VALIDATED coverage for the Phase 6F findings layer.

Runs the full Phase 2-6F chain (Go runtime detection -> strings ->
functions -> network -> credential -> crypto -> persistence -> IOC
extraction -> correlation -> finding generation) against the real
compiled Go 1.26.2 fixture binary, via the same PE-section-mapped-reader
real-file boundary as every other Phase 6A-6E real-fixture test.

Explicitly NOT runtime-memory validation and NOT proof of any real-world
detection effectiveness - the fixture contains only benign application
logic plus the small number of inert, obviously-fake persistence/crypto-
context marker constants added during Phase 6C/6D testing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.analyzers.correlation import correlate_artifacts, extract_iocs
from gomemforensics.analyzers.credentials import extract_credential_artifacts
from gomemforensics.analyzers.crypto import extract_crypto_artifacts
from gomemforensics.analyzers.findings import generate_findings
from gomemforensics.analyzers.models import FindingType
from gomemforensics.analyzers.network import extract_network_artifacts
from gomemforensics.analyzers.persistence import extract_persistence_artifacts
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.functab import FunctionTableParser
from gomemforensics.go_runtime.strings import StringRecoveryEngine

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
def _full_chain_findings():
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")

    pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
    reader = _PEMappedReader(pe)
    regions = _build_regions(pe)

    result = GoProcessDetector().detect(pid=1, architecture="x86_64", pointer_size=8, reader=reader, regions=regions)
    assert result.runtime is not None, f"Go runtime not recovered from real fixture: {result.errors}"
    runtime = result.runtime

    static_strings, _errors = StringRecoveryEngine(reader, pointer_size=8).recover_static_strings(runtime, regions)
    functions, _errors = FunctionTableParser(reader, pointer_size=8).parse(runtime)

    network_artifacts, _errors, _stats = extract_network_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, []
    )
    credential_artifacts, _errors, _stats = extract_credential_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, [], network_artifacts
    )
    crypto_artifacts, _errors, _stats = extract_crypto_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, [], network_artifacts, credential_artifacts
    )
    persistence_artifacts, _errors, _stats = extract_persistence_artifacts(
        1, "fixture.exe", runtime.go_version, "x86_64", static_strings, functions, [],
        network_artifacts, credential_artifacts, crypto_artifacts,
    )
    iocs, _ioc_errors, ioc_stats = extract_iocs(
        1, "fixture.exe", network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
    )
    correlations, _corr_errors, corr_stats = correlate_artifacts(
        1, functions, [], network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
    )
    findings, finding_errors, finding_stats = generate_findings(1, "fixture.exe", iocs, correlations)

    return {
        "static_strings": static_strings,
        "iocs": iocs,
        "correlations": correlations,
        "findings": findings,
        "finding_errors": finding_errors,
        "finding_stats": finding_stats,
    }


def test_expected_persistence_findings_generated(_full_chain_findings):
    findings = _full_chain_findings["findings"]
    windows_findings = [f for f in findings if f.finding_type == FindingType.WINDOWS_PERSISTENCE_REFERENCE]
    linux_findings = [f for f in findings if f.finding_type == FindingType.LINUX_PERSISTENCE_REFERENCE]
    # Deduplication groups by (finding_type, dedup_key) - since each of
    # the fixture's fake markers (plus the one documented incidental real
    # stdlib match, "OpenSCManagerW" - see Phase 6D's report) has a
    # distinct ioc_type/raw_value pair, each produces its OWN dedup_key
    # and therefore its own Finding record, even though they share the
    # same coarser finding_type - this is the actually-observed, correct
    # behavior (distinct evidence is never merged just because it maps to
    # the same finding_type, per stage 18: "do NOT merge semantically
    # different findings").
    assert len(windows_findings) == 3
    assert len(linux_findings) == 3
    for finding in windows_findings + linux_findings:
        assert len(finding.supporting_ioc_ids) >= 1


def test_findings_reference_real_ioc_ids(_full_chain_findings):
    ioc_ids = {ioc.id for ioc in _full_chain_findings["iocs"]}
    for finding in _full_chain_findings["findings"]:
        for ioc_id in finding.supporting_ioc_ids:
            assert ioc_id in ioc_ids


def test_findings_reference_real_string_artifact_ids(_full_chain_findings):
    string_ids = {s.id for s in _full_chain_findings["static_strings"]}
    for finding in _full_chain_findings["findings"]:
        for artifact_id in finding.supporting_artifact_ids:
            assert artifact_id in string_ids


def test_no_prohibited_inference_language_anywhere(_full_chain_findings):
    forbidden_phrases = (
        "malware established", "c2 established", "confirmed c2", "credential theft",
        "credentials were stolen", "data exfiltrat", "key usage confirmed", "the malware",
        "the attacker", "is malicious", "confirmed malware",
    )
    for finding in _full_chain_findings["findings"]:
        combined = " ".join(
            [finding.title, finding.description, finding.observed_evidence, finding.interpretation, finding.notes or ""]
        ).lower()
        for phrase in forbidden_phrases:
            assert phrase not in combined, f"prohibited phrase {phrase!r} found in finding {finding.finding_id}"


def test_no_score_or_verdict_field_on_any_finding(_full_chain_findings):
    for finding in _full_chain_findings["findings"]:
        json_dict = finding.to_json_dict()
        for forbidden_key in ("score", "threat_score", "malware_score", "malware_probability", "risk_score", "verdict"):
            assert forbidden_key not in json_dict


def test_deterministic_across_runs(_full_chain_findings):
    findings_a = _full_chain_findings["findings"]
    iocs = _full_chain_findings["iocs"]
    correlations = _full_chain_findings["correlations"]
    findings_b, _errors, _stats = generate_findings(1, "fixture.exe", iocs, correlations)
    assert [f.finding_id for f in findings_a] == [f.finding_id for f in findings_b]
    assert [f.finding_type for f in findings_a] == [f.finding_type for f in findings_b]


def test_summary_counts_reported(_full_chain_findings):
    findings = _full_chain_findings["findings"]
    iocs = _full_chain_findings["iocs"]
    correlations = _full_chain_findings["correlations"]
    findings_by_type = {}
    for f in findings:
        findings_by_type[f.finding_type.value] = findings_by_type.get(f.finding_type.value, 0) + 1
    print(
        "recovered_strings=", len(_full_chain_findings["static_strings"]),
        "iocs=", len(iocs), "correlations=", len(correlations),
        "findings=", len(findings), "findings_by_type=", findings_by_type,
    )
    assert _full_chain_findings["finding_errors"] == [] or all(e.recoverable for e in _full_chain_findings["finding_errors"])
    assert _full_chain_findings["finding_stats"].capped is False
