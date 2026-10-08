"""COMPILED_BINARY_VALIDATED coverage for the Phase 6D persistence analyzer.

Runs :func:`~gomemforensics.analyzers.persistence.extract_persistence_artifacts`
against strings recovered from the real compiled Go 1.26.2 fixture binary
(``tests/fixtures/go/fixture.go``) via a PE-section-mapped reader - the
same real-file boundary as the other Phase 6A/6B/6C real-fixture tests.

Only *static*-section string recovery is exercised (heap recovery has no
on-disk equivalent - see those files' own docstrings for the scope note).

The fixture was extended (Phase 6D) with five inert, obviously-fake
persistence-marker string constants (``markerFakeRegistryRun``,
``markerFakeSchtasks``, ``markerFakeSystemdUnit``, ``markerFakeCronPath``,
``markerFakeAutostart``) - never written to the registry/filesystem/
service manager/cron/systemd, never executed. This validates two things:
(1) that the classifier does NOT flood the ~1,966 other real recovered
strings with false-positive persistence artifacts, and (2) that the five
genuinely fake-but-shaped markers ARE correctly recognized amid that real
noise. It is explicitly NOT runtime-memory validation and NOT proof that
the fixture process (or any process) ever actually established
persistence - the fixture never performs any persistence action.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.analyzers.models import PersistenceArtifactType
from gomemforensics.analyzers.persistence import extract_persistence_artifacts
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.strings import StringRecoveryEngine

pefile = pytest.importorskip("pefile")

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"

_EXPECTED_FAKE_MARKERS = {
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GoMemForensicsFixtureTestValue": PersistenceArtifactType.WINDOWS_REGISTRY_RUN,
    "schtasks /create /tn GoMemForensicsFixtureTestTask /tr fake.exe": PersistenceArtifactType.WINDOWS_SCHEDULED_TASK_REFERENCE,
    "/etc/systemd/system/gomemforensics-fixture-test.service": PersistenceArtifactType.LINUX_SYSTEMD_UNIT,
    "/etc/cron.d/gomemforensics-fixture-test": PersistenceArtifactType.LINUX_CRON,
    "/home/fixture/.config/autostart/gomemforensics-fixture-test.desktop": PersistenceArtifactType.LINUX_AUTOSTART,
}

#: The real fixture binary's own linked Go stdlib/runtime code
#: incidentally embeds a small number of genuine Windows API name strings
#: unrelated to the fixture's own (persistence-free) application code -
#: e.g. "OpenSCManagerW", referenced somewhere inside the standard
#: library's own Windows support code. These are real, independently-
#: confirmed low-confidence WINDOWS_SERVICE_REFERENCE matches (bare API
#: name only - never a configured service, correctly scored LOW, never
#: overclaimed) - documented here explicitly rather than asserted away,
#: since pretending they do not exist would be less honest than recording
#: them as an actually-observed real-binary finding.
_KNOWN_INCIDENTAL_STDLIB_MATCHES = {"OpenSCManagerW"}


class _PEMappedReader(MemoryReader):
    """Self-contained copy of the same minimal PE-backed reader used by
    the other Phase 6A/6B/6C real-fixture tests."""

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


def test_fake_persistence_markers_are_recognized_in_real_binary(_recovered_static_strings):
    static_strings, _errors, runtime = _recovered_static_strings

    artifacts, errors, stats = extract_persistence_artifacts(
        1, "gomemforensics_fixture_windows_amd64.exe", runtime.go_version, "x86_64", static_strings, [], [], [], [], []
    )

    assert errors == []
    assert stats.strings_scanned == len(static_strings)

    found_values = {a.raw_value: a.artifact_type for a in artifacts}
    for expected_value, expected_type in _EXPECTED_FAKE_MARKERS.items():
        assert expected_value in found_values, f"fake marker not recognized: {expected_value!r}"
        assert found_values[expected_value] == expected_type

    # No false-positive flood from the ~1,966 other real recovered
    # strings (Go package/source paths, runtime-internal strings, other
    # fixture markers): only the five injected fake markers plus any
    # explicitly-documented, independently-confirmed incidental stdlib
    # matches (see _KNOWN_INCIDENTAL_STDLIB_MATCHES) are permitted - any
    # other match is unexpected and fails this test rather than being
    # silently tolerated.
    unexpected = set(found_values) - set(_EXPECTED_FAKE_MARKERS) - _KNOWN_INCIDENTAL_STDLIB_MATCHES
    assert unexpected == set(), f"unexpected persistence matches in real fixture strings: {unexpected}"
    for incidental_value in _KNOWN_INCIDENTAL_STDLIB_MATCHES & set(found_values):
        incidental_artifact = next(a for a in artifacts if a.raw_value == incidental_value)
        assert incidental_artifact.confidence.value == "low"


def test_no_crash_and_provenance_traces_to_real_strings(_recovered_static_strings):
    static_strings, _errors, runtime = _recovered_static_strings
    artifacts, _errors, _stats = extract_persistence_artifacts(
        1, None, runtime.go_version, "x86_64", static_strings, [], [], [], [], []
    )
    for artifact in artifacts:
        matching = [s for s in static_strings if s.id == artifact.source_artifact_id]
        assert len(matching) == 1
        assert artifact.raw_value == matching[0].value
        assert artifact.address == matching[0].data_address


def test_notes_never_overclaim_for_real_fixture_markers(_recovered_static_strings):
    static_strings, _errors, runtime = _recovered_static_strings
    artifacts, _errors, _stats = extract_persistence_artifacts(
        1, None, runtime.go_version, "x86_64", static_strings, [], [], [], [], []
    )
    for artifact in artifacts:
        notes_upper = (artifact.notes or "").upper()
        assert "PERSISTENCE_CONFIRMED" not in notes_upper
        assert "PERSISTENCE_ESTABLISHED" not in notes_upper
        assert "COMMAND_EXECUTED" not in notes_upper
