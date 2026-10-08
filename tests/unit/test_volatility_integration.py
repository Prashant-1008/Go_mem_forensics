"""Unit tests for the Volatility integration facade.

These tests avoid constructing a real Volatility Context (that requires an
actual memory image and is covered by tests/integration/); they test the
dependency probe, the pure OS/architecture normalization functions, the
VolatilityMemoryReader adapter (against a lightweight fake layer object,
using Volatility's real exception types), and that every accessor refuses
to run before initialize() has succeeded.
"""

from __future__ import annotations

import pytest
from volatility3.framework import exceptions as vol_exceptions

from gomemforensics.common.memory import MemoryAccessError
from gomemforensics.volatility.integration import (
    VolatilityIntegration,
    VolatilityIntegrationError,
    VolatilityMemoryReader,
    _normalize_architecture,
    _normalize_os,
    _resolve_os,
    probe_dependencies,
)


def test_probe_dependencies_returns_status_for_both_packages():
    availability = probe_dependencies()

    assert availability.volatility3.name == "volatility3"
    assert availability.capstone.name == "capstone"
    assert isinstance(availability.volatility3.installed, bool)
    assert isinstance(availability.capstone.installed, bool)


class TestNormalizeArchitecture:
    def test_intel64_is_x86_64(self):
        assert _normalize_architecture("Intel64") == "x86_64"

    def test_intel32_is_x86(self):
        assert _normalize_architecture("Intel32") == "x86"

    def test_arm64_is_identified_but_not_claimed_as_supported_elsewhere(self):
        # Never actually produced by volatility3==2.28.2 (no ARM layer
        # exists in this version - see docs/architecture/volatility3-integration.md),
        # but the mapping exists so an unexpected future value is at least
        # identified rather than silently reported "unknown".
        assert _normalize_architecture("ARM64") == "arm64"
        assert _normalize_architecture("AArch64") == "arm64"

    def test_unknown_value_normalizes_to_unknown(self):
        assert _normalize_architecture("SomethingElse") == "unknown"

    def test_none_normalizes_to_unknown(self):
        assert _normalize_architecture(None) == "unknown"


class TestNormalizeOS:
    def test_windows(self):
        assert _normalize_os("Windows") == "windows"

    def test_linux(self):
        assert _normalize_os("Linux") == "linux"

    def test_unrecognized_value_is_unknown(self):
        assert _normalize_os("Mac") == "unknown"

    def test_none_is_unknown(self):
        assert _normalize_os(None) == "unknown"


class TestResolveOs:
    """Reproducer for the Phase 7B real-memory finding: a genuine Windows
    crash-dump image (WindowsCrashDump64Layer) leaves the kernel layer's
    own ``"os"`` metadata key as ``"Unknown"`` even though Windows-specific
    plugin construction and kernel-symbol resolution both genuinely
    succeeded (real process enumeration worked). Before this fix,
    VolatilityIntegration.detect_os() incorrectly returned "unknown" for
    such an image; docs/validation/phase-7b-first-real-memory-validation.md
    Section 17 documents the real evidence this was reproduced against."""

    def test_metadata_os_windows_is_used_directly(self):
        assert _resolve_os("Windows", "windows") == "windows"

    def test_metadata_os_linux_is_used_directly(self):
        assert _resolve_os("Linux", "linux") == "linux"

    def test_metadata_os_preferred_over_conflicting_os_kind(self):
        # The metadata value is the primary signal and is never overridden
        # by os_kind when it already resolved to something usable.
        assert _resolve_os("Windows", "linux") == "windows"

    def test_falls_back_to_os_kind_when_metadata_unknown_windows(self):
        # Reproduces the real Phase 7B finding: metadata "Unknown" + a
        # successfully-constructed Windows plugin.
        assert _resolve_os("Unknown", "windows") == "windows"

    def test_falls_back_to_os_kind_when_metadata_unknown_linux(self):
        assert _resolve_os("Unknown", "linux") == "linux"

    def test_falls_back_to_os_kind_when_metadata_none(self):
        assert _resolve_os(None, "windows") == "windows"

    def test_remains_unknown_when_both_signals_absent(self):
        assert _resolve_os(None, None) == "unknown"
        assert _resolve_os("Mac", None) == "unknown"

    def test_remains_unknown_when_os_kind_is_an_unrecognized_value(self):
        # os_kind is only ever "windows"/"linux" in production
        # (VolatilityIntegration.initialize's own attempts tuple) - this
        # guards against silently accepting an unexpected value rather
        # than reporting "unknown".
        assert _resolve_os(None, "mac") == "unknown"


class _FakeLayer:
    """Minimal stand-in for a Volatility TranslationLayerInterface.

    Only implements what VolatilityMemoryReader actually calls
    (read/is_valid), using real Volatility exception types so the reader's
    exception-translation logic is exercised against real classes.
    """

    def __init__(self, data: bytes, base: int = 0x1000) -> None:
        self._data = data
        self._base = base

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self._base <= offset < self._base + len(self._data)

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        start = offset - self._base
        end = start + length
        if start < 0 or end > len(self._data):
            raise vol_exceptions.InvalidAddressException(
                "fake_layer", offset, f"Layer fake_layer cannot map offset: {offset:#x}"
            )
        return self._data[start:end]


class TestVolatilityMemoryReader:
    def test_read_within_bounds(self):
        reader = VolatilityMemoryReader(_FakeLayer(b"ABCDEFGH"), pointer_size=8)
        assert reader.read(0x1000, 4) == b"ABCD"

    def test_is_valid(self):
        reader = VolatilityMemoryReader(_FakeLayer(b"ABCD"), pointer_size=8)
        assert reader.is_valid(0x1000) is True
        assert reader.is_valid(0x2000) is False

    def test_invalid_address_raises_memory_access_error_not_volatility_exception(self):
        reader = VolatilityMemoryReader(_FakeLayer(b"AB"), pointer_size=8)
        with pytest.raises(MemoryAccessError):
            reader.read(0x1000, 100)

    def test_pointer_size_exposed(self):
        reader = VolatilityMemoryReader(_FakeLayer(b"AB"), pointer_size=4)
        assert reader.pointer_size == 4

    def test_has_no_write_method(self):
        reader = VolatilityMemoryReader(_FakeLayer(b"AB"), pointer_size=8)
        assert not hasattr(reader, "write")


class TestVolatilityIntegrationBeforeInitialize:
    def test_detect_os_raises_before_initialize(self):
        with pytest.raises(VolatilityIntegrationError):
            VolatilityIntegration().detect_os()

    def test_detect_architecture_raises_before_initialize(self):
        with pytest.raises(VolatilityIntegrationError):
            VolatilityIntegration().detect_architecture()

    def test_enumerate_processes_raises_before_initialize(self):
        with pytest.raises(VolatilityIntegrationError):
            VolatilityIntegration().enumerate_processes()

    def test_get_process_memory_raises_before_initialize(self):
        with pytest.raises(VolatilityIntegrationError):
            VolatilityIntegration().get_process_memory(1234)
