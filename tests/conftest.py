"""Shared pytest fixtures.

Provides the ``real_memory_image_path`` fixture used by tests marked
``@pytest.mark.memory_image``. Those tests require an actual captured
memory image (a real Windows or Linux memory dump) and are automatically
skipped when none is configured - CI must never depend on a local memory
image being present (see docs/validation/validation-plan.md).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EVIDENCE_DIR = _REPO_ROOT / "evidence"
_CANDIDATE_SUFFIXES = {".raw", ".mem", ".dmp", ".lime", ".vmem"}


def _discover_real_memory_image() -> Path | None:
    env_path = os.environ.get("GOMEMFORENSICS_TEST_IMAGE")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return candidate

    if _EVIDENCE_DIR.is_dir():
        for candidate in sorted(_EVIDENCE_DIR.iterdir()):
            if candidate.is_file() and candidate.suffix.lower() in _CANDIDATE_SUFFIXES:
                return candidate

    return None


@pytest.fixture(scope="session")
def real_memory_image_path() -> Path:
    """A real memory image fixture path, or skip the requesting test.

    Resolution order: the ``GOMEMFORENSICS_TEST_IMAGE`` environment
    variable, then the first recognized image file under ``evidence/``.
    """
    image = _discover_real_memory_image()
    if image is None:
        pytest.skip(
            "No real memory image fixture available. Set GOMEMFORENSICS_TEST_IMAGE "
            "or place a memory image under evidence/ (gitignored) to run this test."
        )
    return image
