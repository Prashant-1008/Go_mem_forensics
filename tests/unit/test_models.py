"""Tests for shared, minimal data models."""

from gomemforensics.common.models import AnalysisError, AnalysisStatistics, ArtifactProvenance, Confidence


def test_confidence_levels():
    assert {c.value for c in Confidence} == {"high", "medium", "low", "unknown"}


def test_artifact_provenance_defaults():
    provenance = ArtifactProvenance(
        artifact_id="STR-0001",
        artifact_type="go_string",
        analyzer="strings",
        extraction_method="heap_span_walk",
        confidence=Confidence.HIGH,
    )

    assert provenance.related_artifacts == []
    assert provenance.case_id is None
    assert provenance.pid is None


def test_analysis_error_has_timestamp():
    error = AnalysisError(component="go_runtime.detector", message="pclntab not found")
    assert error.recoverable is True
    assert error.timestamp.endswith("Z")


def test_analysis_statistics_defaults_and_extra():
    stats = AnalysisStatistics()
    assert stats.processes_discovered == 0
    stats.extra["strings_recovered"] = 42
    assert stats.extra["strings_recovered"] == 42
