"""COMPILED_BINARY_VALIDATED coverage for the Phase 6B credential analyzer.

Runs :func:`~gomemforensics.analyzers.credentials.extract_credential_artifacts`
against strings recovered from the real compiled Go 1.26.2 fixture binary
(``tests/fixtures/go/fixture.go``) via a PE-section-mapped reader - the
same real-file boundary as ``tests/integration/test_network_artifacts_fixture.py``.

Only *static*-section string recovery is exercised (heap recovery has no
on-disk equivalent - see that file's own docstring for the scope note).

This validates one thing specifically: that the credential classifier
does NOT flood a real, large (2000+ function) compiled Go binary's real
recovered strings with false-positive secret-like artifacts. It is
explicitly NOT runtime-memory validation and NOT proof that the fixture
process ever held or used any credential - the fixture program contains
no credential-handling code at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.analyzers.credentials import extract_credential_artifacts
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.models import StringArtifact
from gomemforensics.go_runtime.strings import StringRecoveryEngine

pefile = pytest.importorskip("pefile")

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"


class _PEMappedReader(MemoryReader):
    """Self-contained copy of the same minimal PE-backed reader used by
    test_network_artifacts_fixture.py and test_go_runtime_function_fixture.py
    (not imported from either, to keep this file's real-fixture boundary
    independently auditable)."""

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
                start=start,
                end=start + size,
                readable=True,
                writable=bool(section.Characteristics & 0x80000000),
                executable=bool(section.Characteristics & 0x20000000),
                source="pe_section",
            )
        )
    return regions


@pytest.fixture(scope="module")
def _recovered_static_strings():
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")

    pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
    reader = _PEMappedReader(pe)
    regions = _build_regions(pe)

    result = GoProcessDetector().detect(pid=1, architecture="x86_64", pointer_size=8, reader=reader, regions=regions)
    assert result.runtime is not None, f"Go runtime not recovered from real fixture: {result.errors}"

    static_strings, errors = StringRecoveryEngine(reader, pointer_size=8).recover_static_strings(
        result.runtime, regions
    )
    return static_strings, errors, result.runtime


def test_no_crash_and_no_false_positive_flood_against_real_binary_strings(_recovered_static_strings):
    static_strings, _errors, runtime = _recovered_static_strings

    artifacts, errors, stats = extract_credential_artifacts(
        1, "gomemforensics_fixture_windows_amd64.exe", runtime.go_version, "x86_64", static_strings, [], [], []
    )

    assert errors == []
    assert stats.strings_scanned == len(static_strings)
    # The benign fixture contains no credential-handling code at all (see
    # tests/fixtures/go/fixture.go) - its ~1,976 real static strings are
    # Go package/source paths, runtime-internal strings, and the
    # fixture's own non-secret marker constants. This is the actually-
    # observed result (independently confirmed, not assumed): zero of
    # those 1,976 real strings coincidentally matches a supported
    # secret-like shape. A single real-binary data point, not proof of
    # zero false positives in general (see the Phase 6B report's
    # Limitations).
    assert len(artifacts) == 0

    for artifact in artifacts:
        matching = [s for s in static_strings if s.id == artifact.source_artifact_id]
        assert len(matching) == 1
        assert artifact.raw_value == matching[0].value
        assert artifact.address == matching[0].data_address
        # No artifact's redacted form should ever equal its raw form when
        # the raw form is long enough to redact meaningfully.
        if len(artifact.raw_value) > 8:
            assert artifact.redacted_value != artifact.raw_value


def test_a_genuine_secret_shaped_string_is_still_recognized_amid_real_binary_noise(_recovered_static_strings):
    """Confirms a positive match is still found correctly when a
    genuine secret-shaped string is present alongside real compiled-binary
    strings, mirroring test_network_artifacts_fixture.py's equivalent
    positive-case check."""
    static_strings, _errors, runtime = _recovered_static_strings
    injected = StringArtifact(
        id="STR-1-INJECTED",
        pid=1,
        string_address=0xDEAD0000,
        data_address=0xDEAD0000,
        length=len("password=Sup3rSecretInjectedValue"),
        value="password=Sup3rSecretInjectedValue",
        region="static",
        extraction_method="static_section_scan",
        confidence=Confidence.HIGH,
        is_utf8=True,
        printable_ratio=1.0,
    )
    mixed = list(static_strings) + [injected]

    artifacts, _errors, _stats = extract_credential_artifacts(1, None, runtime.go_version, "x86_64", mixed, [], [], [])

    matches = [a for a in artifacts if a.source_artifact_id == "STR-1-INJECTED"]
    assert len(matches) == 1
    assert matches[0].raw_value == "password=Sup3rSecretInjectedValue"
    assert "Sup3rSecretInjectedValue" not in matches[0].redacted_value
