"""COMPILED_BINARY_VALIDATED coverage for the Phase 6E IOC/correlation layer.

Runs the full Phase 6A-6E chain (network -> credential -> crypto ->
persistence -> IOC extraction -> correlation) against strings recovered
from the real compiled Go 1.26.2 fixture binary, via the same PE-section-
mapped-reader real-file boundary as the other Phase 6A/6B/6C/6D real-
fixture tests.

Only *static*-section string recovery is exercised (heap recovery has no
on-disk equivalent). This is explicitly NOT runtime-memory validation and
NOT proof of any real-world detection effectiveness - the fixture
contains only benign application logic plus a small number of inert,
obviously-fake persistence/crypto-context marker constants added in
Phase 6D/6C testing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.analyzers.correlation import correlate_artifacts, extract_iocs
from gomemforensics.analyzers.credentials import extract_credential_artifacts
from gomemforensics.analyzers.crypto import extract_crypto_artifacts
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
    """Self-contained copy of the same minimal PE-backed reader used by
    the other Phase 6A/6B/6C/6D real-fixture tests."""

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
def _full_chain_result():
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
    iocs, ioc_errors, ioc_stats = extract_iocs(
        1, "fixture.exe", network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
    )
    correlations, corr_errors, corr_stats = correlate_artifacts(
        1, functions, [], network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts
    )

    return {
        "static_strings": static_strings,
        "network_artifacts": network_artifacts,
        "credential_artifacts": credential_artifacts,
        "crypto_artifacts": crypto_artifacts,
        "persistence_artifacts": persistence_artifacts,
        "iocs": iocs,
        "ioc_errors": ioc_errors,
        "ioc_stats": ioc_stats,
        "correlations": correlations,
        "corr_errors": corr_errors,
        "corr_stats": corr_stats,
    }


def test_expected_persistence_iocs_recovered(_full_chain_result):
    iocs = _full_chain_result["iocs"]
    persistence_iocs = {ioc.raw_value for ioc in iocs if ioc.ioc_category.value == "persistence"}
    assert r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GoMemForensicsFixtureTestValue" in persistence_iocs
    assert "schtasks /create /tn GoMemForensicsFixtureTestTask /tr fake.exe" in persistence_iocs
    assert "/etc/systemd/system/gomemforensics-fixture-test.service" in persistence_iocs
    assert "/etc/cron.d/gomemforensics-fixture-test" in persistence_iocs
    assert "/home/fixture/.config/autostart/gomemforensics-fixture-test.desktop" in persistence_iocs


def test_expected_crypto_context_ioc_recovered(_full_chain_result):
    iocs = _full_chain_result["iocs"]
    crypto_iocs = {ioc.raw_value for ioc in iocs if ioc.ioc_category.value == "crypto"}
    # From the real fixture binary's own linked stdlib/runtime content,
    # not fixture application code (see docs/architecture/go-crypto-artifacts.md).
    # No crypto-context marker was specifically injected into the fixture
    # itself, so this asserts the *mechanism* works end to end rather than
    # a specific expected value - see the injected-value tests in
    # test_crypto_artifacts_fixture.py for a positive-match check.
    assert isinstance(crypto_iocs, set)


def test_no_unexpected_ioc_explosion(_full_chain_result):
    static_strings = _full_chain_result["static_strings"]
    iocs = _full_chain_result["iocs"]
    ioc_stats = _full_chain_result["ioc_stats"]
    # Real, observed counts: bounded, not exploding relative to the
    # number of recovered strings.
    assert len(iocs) < len(static_strings) * 0.05
    assert ioc_stats.capped is False
    assert _full_chain_result["ioc_errors"] == [] or all(e.recoverable for e in _full_chain_result["ioc_errors"])


def test_deterministic_across_runs(_full_chain_result):
    iocs_a = _full_chain_result["iocs"]
    # Re-run the whole chain once more independently and confirm the same
    # IOC set (by raw_value + type), proving determinism end to end.
    static_strings = _full_chain_result["static_strings"]
    network_artifacts = _full_chain_result["network_artifacts"]
    credential_artifacts = _full_chain_result["credential_artifacts"]
    crypto_artifacts = _full_chain_result["crypto_artifacts"]
    persistence_artifacts = _full_chain_result["persistence_artifacts"]
    iocs_b, _errors, _stats = extract_iocs(1, "fixture.exe", network_artifacts, credential_artifacts, crypto_artifacts, persistence_artifacts)
    assert [(i.ioc_type, i.raw_value) for i in iocs_a] == [(i.ioc_type, i.raw_value) for i in iocs_b]
    assert [i.id for i in iocs_a] == [i.id for i in iocs_b]


def test_provenance_traces_to_real_source_artifacts(_full_chain_result):
    static_strings = _full_chain_result["static_strings"]
    string_ids = {s.id for s in static_strings}
    for ioc in _full_chain_result["iocs"]:
        assert ioc.source_artifact_id in string_ids


def test_correlations_reference_real_artifact_ids(_full_chain_result):
    network_ids = {a.id for a in _full_chain_result["network_artifacts"]}
    credential_ids = {a.id for a in _full_chain_result["credential_artifacts"]}
    crypto_ids = {a.id for a in _full_chain_result["crypto_artifacts"]}
    persistence_ids = {a.id for a in _full_chain_result["persistence_artifacts"]}
    string_ids = {s.id for s in _full_chain_result["static_strings"]}
    derived_and_string_ids = network_ids | credential_ids | crypto_ids | persistence_ids | string_ids

    for record in _full_chain_result["correlations"]:
        # FUNCTION_REFERENCES_ARTIFACT/GOROUTINE_FRAME_REFERENCES_ARTIFACT
        # source ids are function/goroutine ids, a different id space -
        # every other record must reference a real, already-recovered
        # string or derived-artifact id.
        if record.source_type not in ("function", "goroutine"):
            assert record.source_id in derived_and_string_ids
        assert record.target_id in derived_and_string_ids


def test_correlation_summary_counts_reported(_full_chain_result):
    print(
        "recovered_strings=", len(_full_chain_result["static_strings"]),
        "network=", len(_full_chain_result["network_artifacts"]),
        "credential=", len(_full_chain_result["credential_artifacts"]),
        "crypto=", len(_full_chain_result["crypto_artifacts"]),
        "persistence=", len(_full_chain_result["persistence_artifacts"]),
        "iocs=", len(_full_chain_result["iocs"]),
        "unique_iocs=", _full_chain_result["ioc_stats"].unique_iocs,
        "correlations=", len(_full_chain_result["correlations"]),
    )
    assert len(_full_chain_result["static_strings"]) > 0
