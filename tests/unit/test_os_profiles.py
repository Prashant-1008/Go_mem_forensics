"""Tests for the OS abstraction layer."""

import pytest

from gomemforensics.os.base import OperatingSystemProfile
from gomemforensics.os.linux import LINUX, LinuxProfile
from gomemforensics.os.windows import WINDOWS, WindowsProfile


def test_operating_system_profile_is_abstract():
    with pytest.raises(TypeError):
        OperatingSystemProfile()  # type: ignore[abstract]


def test_windows_profile():
    profile = WindowsProfile()
    assert profile.name == "Windows"
    assert profile.supported is True
    assert profile.supported_architectures == ("x86_64",)
    assert WINDOWS.name == "Windows"


def test_linux_profile():
    profile = LinuxProfile()
    assert profile.name == "Linux"
    assert profile.supported is True
    assert profile.supported_architectures == ("x86_64",)
    assert LINUX.name == "Linux"


def test_neither_profile_claims_arm64_support():
    assert "arm64" not in WINDOWS.supported_architectures
    assert "arm64" not in LINUX.supported_architectures
