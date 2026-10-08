"""Fixture *content* validation for Go string recovery (Phase 3).

IMPORTANT SCOPE NOTE (approved plan Section N): a compiled Go executable
file is NOT a process memory image. Heap state (allspans, mspan, live
heap objects) does not exist at all in an on-disk binary - it is
allocated by the Go runtime only after the process starts. This test
therefore does **not** exercise ``StringRecoveryEngine`` or any ptr+len
header-scanning logic at all; it only confirms the benign fixture
(tests/fixtures/go/fixture.go) was built with the expected marker string
content, as a basic sanity check on the fixture build itself. This is
explicitly NOT a substitute for real memory-image validation of the
heap/static string recovery pipeline, which remains pending (see
docs/validation/validation-plan.md).

Contrast with tests/integration/test_go_runtime_real_fixture.py, which
*does* exercise real analyzer logic (``PclntabParser``) against real
compiled bytes - pclntab is present on disk (linker-emitted static
metadata), unlike heap state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"

#: Marker substrings expected verbatim in the compiled binary's static
#: data, matching tests/fixtures/go/fixture.go's const block. Encoded as
#: UTF-8 bytes, matching how Go stores string literals.
_EXPECTED_STATIC_MARKERS = [
    "GOMEMFORENSICS_FIXTURE_STATIC_MARKER_39f1",
    "gomemforensics benign go runtime fixture",
    "GOMEMFORENSICS_REPEAT_MARKER",
    "GOMEMFORENSICS_UNICODE_MARKER_héllo_wörld_日本語_🔍",
    "GOMEMFORENSICS_LONG_MARKER_",
    "_END_OF_LONG_MARKER",
]


@pytest.mark.skipif(
    not _WINDOWS_FIXTURE.exists(),
    reason="Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.",
)
def test_fixture_binary_contains_expected_marker_strings():
    data = _WINDOWS_FIXTURE.read_bytes()
    for marker in _EXPECTED_STATIC_MARKERS:
        assert marker.encode("utf-8") in data, f"marker not found in compiled fixture: {marker!r}"


@pytest.mark.skipif(
    not _WINDOWS_FIXTURE.exists(),
    reason="Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.",
)
def test_fixture_binary_does_not_contain_malware_indicators():
    """Sanity check that the fixture remains benign (approved plan Section T)."""
    data = _WINDOWS_FIXTURE.read_bytes().lower()
    for forbidden in (b"cmd.exe /c", b"powershell -enc", b"reverse shell"):
        assert forbidden not in data
