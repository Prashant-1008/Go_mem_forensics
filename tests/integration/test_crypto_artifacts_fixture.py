"""COMPILED_BINARY_VALIDATED coverage for the Phase 6C crypto analyzer.

Runs :func:`~gomemforensics.analyzers.crypto.extract_crypto_artifacts`
against strings recovered from the real compiled Go 1.26.2 fixture binary
(``tests/fixtures/go/fixture.go``) via a PE-section-mapped reader - the
same real-file boundary as ``tests/integration/test_network_artifacts_fixture.py``
and ``tests/integration/test_credential_artifacts_fixture.py``.

Only *static*-section string recovery is exercised (heap recovery has no
on-disk equivalent - see those files' own docstrings for the scope note).

This validates one thing specifically: that the crypto classifier does
NOT flood a real, large (2000+ function) compiled Go binary's real
recovered strings with false-positive cryptographic artifacts. It is
explicitly NOT runtime-memory validation and NOT proof that the fixture
process ever held or used any cryptographic material - the fixture
program contains no crypto-handling code at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.analyzers.crypto import extract_crypto_artifacts
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
    the other Phase 6A/6B real-fixture tests (not imported from them, to
    keep this file's real-fixture boundary independently auditable)."""

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

    artifacts, errors, stats = extract_crypto_artifacts(
        1, "gomemforensics_fixture_windows_amd64.exe", runtime.go_version, "x86_64", static_strings, [], [], [], []
    )

    assert errors == []
    assert stats.strings_scanned == len(static_strings)
    # The benign fixture contains no crypto-handling code at all (see
    # tests/fixtures/go/fixture.go) - its ~1,976 real static strings are
    # Go package/source paths, runtime-internal strings, and the
    # fixture's own non-crypto marker constants. This is the actually-
    # observed result (independently confirmed, not assumed): zero of
    # those 1,976 real strings coincidentally matches a supported
    # crypto-artifact shape. A single real-binary data point, not proof
    # of zero false positives in general (see the Phase 6C report's
    # Limitations).
    assert len(artifacts) == 0


def test_a_genuine_crypto_shaped_string_is_still_recognized_amid_real_binary_noise(_recovered_static_strings):
    """Confirms a positive match is still found correctly when a
    genuine crypto-context-shaped string is present alongside real
    compiled-binary strings, mirroring the equivalent Phase 6A/6B checks.
    """
    static_strings, _errors, runtime = _recovered_static_strings
    injected = StringArtifact(
        id="STR-1-INJECTED",
        pid=1,
        string_address=0xDEAD0000,
        data_address=0xDEAD0000,
        length=len("TLS_AES_128_GCM_SHA256"),
        value="TLS_AES_128_GCM_SHA256",
        region="static",
        extraction_method="static_section_scan",
        confidence=Confidence.HIGH,
        is_utf8=True,
        printable_ratio=1.0,
    )
    mixed = list(static_strings) + [injected]

    artifacts, _errors, _stats = extract_crypto_artifacts(1, None, runtime.go_version, "x86_64", mixed, [], [], [], [])

    matches = [a for a in artifacts if a.source_artifact_id == "STR-1-INJECTED"]
    assert len(matches) == 1
    assert matches[0].raw_value == "TLS_AES_128_GCM_SHA256"


def test_no_aes_key_false_positives_from_real_function_call_sites(_recovered_static_strings):
    """The fixture never calls crypto/aes.NewCipher, so the evidence-
    backed AES-key detector (which requires an exact target-function-name
    match) must never fire against the real fixture's own recovered
    functions - confirmed by re-running full function recovery against
    the same real binary and checking for zero AES_KEY artifacts."""
    static_strings, _errors, runtime = _recovered_static_strings
    from gomemforensics.go_runtime.functab import FunctionTableParser

    pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
    reader = _PEMappedReader(pe)
    functions, _func_errors = FunctionTableParser(reader, pointer_size=8).parse(runtime)

    artifacts, _errors, _stats = extract_crypto_artifacts(
        1, None, runtime.go_version, "x86_64", static_strings, functions, [], [], []
    )
    assert not any(a.artifact_type.value == "aes_key" for a in artifacts)
