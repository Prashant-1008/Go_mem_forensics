"""Integration tests that exercise real Volatility 3 machinery.

Two tiers, per CLAUDE.md section 26/27 and the Phase 1 plan:

1. Tests using a small synthetic ("garbage") file: these perform a REAL
   Volatility Context/automagic/plugin-construction attempt (not mocked),
   verifying the graceful-failure path when an image is not a supported,
   recognizable memory image. No real memory image is required, so these
   always run.
2. Tests marked ``@pytest.mark.memory_image``: these require an actual
   captured memory image and are automatically skipped (via the
   ``real_memory_image_path`` fixture in tests/conftest.py) when none is
   configured. As of Phase 1 completion, no real image was available in
   the development environment, so this tier is expected to skip - see
   docs/validation/validation-plan.md for what remains pending.

Do NOT make CI depend on a local memory image: nothing here fails if
``real_memory_image_path`` is unavailable, it skips.
"""

from __future__ import annotations

import json
import os

import pytest
from click.testing import CliRunner

from gomemforensics.cli.main import EXIT_ANALYSIS_ERROR, cli
from gomemforensics.volatility.integration import VolatilityIntegration
from gomemforensics.volatility.runner import VolatilityInitializationError, VolatilityRunner


@pytest.fixture
def garbage_image(tmp_path):
    """A small file that is definitely not a valid Windows or Linux memory image."""
    path = tmp_path / "not_a_memory_image.raw"
    path.write_bytes(os.urandom(64 * 1024))
    return path


class TestRunnerAgainstUnsupportedImage:
    def test_construct_plugin_raises_for_garbage_file(self, garbage_image):
        from volatility3.plugins.windows import pslist as windows_pslist

        runner = VolatilityRunner(garbage_image)
        with pytest.raises(VolatilityInitializationError):
            runner.construct_plugin(windows_pslist.PsList)


class TestIntegrationAgainstUnsupportedImage:
    def test_initialize_raises_when_neither_os_matches(self, garbage_image):
        integration = VolatilityIntegration()
        with pytest.raises(VolatilityInitializationError):
            integration.initialize(garbage_image)


class TestCliAnalyzeAgainstUnsupportedImage:
    def test_analyze_writes_partial_report_and_exits_nonzero(self, garbage_image, tmp_path):
        output_path = tmp_path / "out.json"

        result = CliRunner().invoke(
            cli, ["analyze", str(garbage_image), "--output", str(output_path)]
        )

        assert result.exit_code == EXIT_ANALYSIS_ERROR
        assert output_path.exists()

        with output_path.open(encoding="utf-8") as handle:
            data = json.load(handle)

        assert data["system"]["os"] == "unknown"
        assert data["system"]["architecture"] == "unknown"
        assert data["processes"] == []
        assert data["evidence"]["sha256"]  # evidence hashing still happened
        assert any(not_recoverable_error(e) for e in data["errors"])
        assert any(e.get("reason") == "volatility_unsupported" for e in data["errors"])


def not_recoverable_error(error: dict) -> bool:
    return error.get("recoverable") is False and "initialize" in error.get("component", "")


# ---------------------------------------------------------------------------
# Real-image tests (skipped automatically without a configured fixture)
# ---------------------------------------------------------------------------


@pytest.mark.memory_image
class TestRealMemoryImage:
    def test_full_pipeline_against_real_image(self, real_memory_image_path):
        from gomemforensics.pipeline import has_fatal_error, run_analysis

        result = run_analysis(real_memory_image_path)

        assert not has_fatal_error(result)
        assert result.os in ("windows", "linux")
        assert result.architecture != "unknown"
        assert result.statistics.processes_discovered > 0
