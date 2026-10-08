"""Tests for the :class:`FailureReason` taxonomy (Phase 5.5, CLAUDE.md
section 24 / Phase 5.5 stage M: failure causes must never be collapsed
into a single generic "error" bucket).

This module only tests the taxonomy's own shape and its default wiring
into :class:`AnalysisError`. Coverage of *which* reason a given call site
attaches lives alongside that call site's own existing tests (e.g.
``tests/unit/test_functab.py``, ``tests/unit/test_go_runtime_goroutines.py``,
``tests/unit/test_pipeline.py``), extended with a ``reason=`` assertion
rather than duplicated here.
"""

from __future__ import annotations

from gomemforensics.common.models import AnalysisError, FailureReason

_EXPECTED_VALUES = {
    "evidence_unavailable",
    "evidence_invalid",
    "evidence_truncated",
    "volatility_unsupported",
    "os_process_discovery_failed",
    "address_space_unavailable",
    "go_runtime_not_found",
    "pclntab_invalid",
    "moduledata_invalid",
    "unsupported_go_version",
    "unsupported_architecture",
    "allgs_not_found",
    "g_validation_failed",
    "stack_unavailable",
    "pcsp_invalid",
    "unwind_stopped",
    "insufficient_evidence",
    "internal_error",
}


def test_taxonomy_has_exactly_the_specified_values():
    actual = {member.value for member in FailureReason}
    assert actual == _EXPECTED_VALUES


def test_is_a_str_subclass_for_transparent_json_serialization():
    # AnalysisResult.to_json_dict() serializes errors via dataclasses.asdict()
    # + json.dumps() with no custom enum handling - this only produces a
    # plain JSON string if FailureReason values are themselves str
    # instances (mirrors gomemforensics.common.models.Confidence).
    assert isinstance(FailureReason.INTERNAL_ERROR, str)
    assert FailureReason.INTERNAL_ERROR == "internal_error"


def test_analysis_error_reason_defaults_to_none_for_backward_compatibility():
    error = AnalysisError(component="x", message="y")
    assert error.reason is None


def test_analysis_error_accepts_an_explicit_reason():
    error = AnalysisError(component="x", message="y", reason=FailureReason.EVIDENCE_TRUNCATED)
    assert error.reason == FailureReason.EVIDENCE_TRUNCATED
