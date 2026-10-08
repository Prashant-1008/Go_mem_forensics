"""Tests for typed run configuration defaults."""

from pathlib import Path

from gomemforensics.common.logging import LogLevel
from gomemforensics.config.settings import ConfidenceMode, GoMemForensicsConfig


def test_default_configuration():
    config = GoMemForensicsConfig()

    assert config.log_level == LogLevel.NORMAL
    assert config.output_directory == Path("reports")
    assert config.report_directory == Path("reports")
    assert config.max_workers == 1
    assert config.confidence_mode == ConfidenceMode.STANDARD


def test_configuration_is_overridable():
    config = GoMemForensicsConfig(
        log_level=LogLevel.DEBUG,
        output_directory=Path("/tmp/out"),
        max_workers=4,
        confidence_mode=ConfidenceMode.STRICT,
    )

    assert config.log_level == LogLevel.DEBUG
    assert config.output_directory == Path("/tmp/out")
    assert config.max_workers == 4
    assert config.confidence_mode == ConfidenceMode.STRICT


def test_default_configuration_instances_do_not_share_mutable_state():
    a = GoMemForensicsConfig()
    b = GoMemForensicsConfig()
    assert a.output_directory == b.output_directory
    assert a is not b
