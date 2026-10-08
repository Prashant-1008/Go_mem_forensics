"""Tests for Go version detection from pclntab magic bytes."""

from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.version import (
    GO_1_2_MAGIC,
    GO_1_16_MAGIC,
    GO_1_18_MAGIC,
    GO_1_20_MAGIC,
    GoVersionDetector,
    magic_bytes_le,
)


class TestMagicBytesEncoding:
    def test_go120_magic_little_endian_bytes(self):
        # Verified against internal/abi/symtab.go: Go120PCLnTabMagic =
        # 0xfffffff1, matching the paper's documented \xf1\xff\xff\xff.
        assert magic_bytes_le(GO_1_20_MAGIC) == b"\xf1\xff\xff\xff"

    def test_go118_magic_bytes(self):
        assert magic_bytes_le(GO_1_18_MAGIC) == b"\xf0\xff\xff\xff"

    def test_go116_magic_bytes(self):
        assert magic_bytes_le(GO_1_16_MAGIC) == b"\xfa\xff\xff\xff"

    def test_go12_magic_bytes(self):
        assert magic_bytes_le(GO_1_2_MAGIC) == b"\xfb\xff\xff\xff"


class TestGoVersionDetector:
    def test_known_version_marker_go120_family(self):
        estimate = GoVersionDetector().detect_from_magic(GO_1_20_MAGIC)
        assert estimate.version_range == "1.20+"
        assert estimate.confidence == Confidence.HIGH
        assert estimate.version is None  # never invents exact precision

    def test_known_version_marker_go116_family(self):
        estimate = GoVersionDetector().detect_from_magic(GO_1_16_MAGIC)
        assert estimate.version_range == "1.16-1.17"
        assert estimate.confidence == Confidence.HIGH

    def test_unknown_magic_is_unknown_confidence(self):
        estimate = GoVersionDetector().detect_from_magic(0xDEADBEEF)
        assert estimate.version_range == "unknown"
        assert estimate.confidence == Confidence.UNKNOWN
        assert estimate.evidence  # always explains why

    def test_refine_narrows_1_20_plus_to_1_22_plus(self):
        detector = GoVersionDetector()
        estimate = detector.detect_from_magic(GO_1_20_MAGIC)
        refined = detector.refine_with_moduledata_layout(estimate, "moduledata@go1.22+")
        assert refined.version_range == "1.22+"
        assert refined.confidence == estimate.confidence  # unchanged, only range narrows

    def test_refine_narrows_1_20_plus_to_1_20_1_21(self):
        detector = GoVersionDetector()
        estimate = detector.detect_from_magic(GO_1_20_MAGIC)
        refined = detector.refine_with_moduledata_layout(estimate, "moduledata@go1.20-1.21")
        assert refined.version_range == "1.20-1.21"

    def test_refine_does_not_affect_other_magic_families(self):
        detector = GoVersionDetector()
        estimate = detector.detect_from_magic(GO_1_16_MAGIC)
        refined = detector.refine_with_moduledata_layout(estimate, "moduledata@go1.22+")
        assert refined.version_range == "1.16-1.17"  # unchanged - refinement is 1.20+ only

    def test_refine_with_unrecognized_layout_id_is_a_no_op(self):
        detector = GoVersionDetector()
        estimate = detector.detect_from_magic(GO_1_20_MAGIC)
        refined = detector.refine_with_moduledata_layout(estimate, "some-unknown-layout")
        assert refined.version_range == "1.20+"
