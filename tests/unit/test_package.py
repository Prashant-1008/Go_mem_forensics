"""Sanity checks that the package is importable and exposes basic metadata."""

import gomemforensics


def test_package_imports():
    assert gomemforensics is not None


def test_package_has_version():
    assert isinstance(gomemforensics.__version__, str)
    assert gomemforensics.__version__


def test_package_has_phase_marker():
    assert "Phase 6" in gomemforensics.PROJECT_PHASE
