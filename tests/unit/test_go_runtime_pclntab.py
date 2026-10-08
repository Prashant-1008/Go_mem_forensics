"""Unit tests for pclntab/pcHeader discovery and validation.

Every test uses synthetic buffers built via tests/unit/go_runtime_helpers.py
against a MockMemoryReader - no real memory image or Go binary is needed
(real-fixture-binary validation lives in
tests/integration/test_go_runtime_real_fixture.py).
"""

from gomemforensics.common.memory import MockMemoryReader
from gomemforensics.common.memory import MemoryRegion
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.layouts import PCHEADER_1_18_PLUS, PCHEADER_PRE_1_18
from gomemforensics.go_runtime.models import PclntabDetectionStatus
from gomemforensics.go_runtime.pclntab import PclntabParser, validate_pc_header, _RawPcHeader
from gomemforensics.go_runtime.version import GO_1_16_MAGIC, GO_1_18_MAGIC, GO_1_20_MAGIC

from tests.unit.go_runtime_helpers import build_pc_header_bytes

REGION_START = 0x400000
REGION_END = 0x500000


def _region(**overrides) -> MemoryRegion:
    defaults = dict(start=REGION_START, end=REGION_END, readable=True, writable=False, executable=True)
    defaults.update(overrides)
    return MemoryRegion(**defaults)


class TestValidatePcHeaderInvariants:
    def _raw(self, **overrides) -> _RawPcHeader:
        defaults = dict(
            magic=GO_1_20_MAGIC, pad1=0, pad2=0, min_lc=1, ptr_size=8,
            nfunc=100, nfiles=10, funcname_offset=1, cu_offset=2,
            filetab_offset=3, pctab_offset=4, pcln_offset=5,
        )
        defaults.update(overrides)
        return _RawPcHeader(**defaults)

    def test_valid_header_has_no_errors(self):
        assert validate_pc_header(self._raw(), expected_pointer_size=8) == []

    def test_nonzero_pad1_rejected(self):
        errors = validate_pc_header(self._raw(pad1=1), expected_pointer_size=8)
        assert any("pad1" in e for e in errors)

    def test_nonzero_pad2_rejected(self):
        errors = validate_pc_header(self._raw(pad2=7), expected_pointer_size=8)
        assert any("pad2" in e for e in errors)

    def test_invalid_min_lc_rejected(self):
        errors = validate_pc_header(self._raw(min_lc=3), expected_pointer_size=8)
        assert any("minLC" in e for e in errors)

    def test_invalid_ptr_size_rejected(self):
        errors = validate_pc_header(self._raw(ptr_size=16), expected_pointer_size=8)
        assert any("ptrSize" in e for e in errors)

    def test_ptr_size_mismatch_with_process_architecture_rejected(self):
        # Header internally consistent (ptrSize=4 is a valid *value*), but
        # does not match the process's actual (amd64) pointer size.
        errors = validate_pc_header(self._raw(ptr_size=4), expected_pointer_size=8)
        assert any("does not match" in e for e in errors)

    def test_impossible_nfunc_rejected(self):
        errors = validate_pc_header(self._raw(nfunc=10_000_000), expected_pointer_size=8)
        assert any("nfunc" in e for e in errors)

    def test_negative_nfunc_rejected(self):
        errors = validate_pc_header(self._raw(nfunc=-1), expected_pointer_size=8)
        assert any("nfunc" in e for e in errors)

    def test_impossible_nfiles_rejected(self):
        errors = validate_pc_header(self._raw(nfiles=50_000_000), expected_pointer_size=8)
        assert any("nfiles" in e for e in errors)


class TestPclntabParserMagicDetection:
    def test_valid_go120_magic_is_high_confidence(self):
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)

        matches = [c for c in candidates if not c.rejected]
        assert len(matches) == 1
        assert matches[0].confidence == Confidence.HIGH
        assert matches[0].detection_status == PclntabDetectionStatus.MAGIC_DETECTED
        assert matches[0].magic == GO_1_20_MAGIC
        assert matches[0].address == REGION_START

    def test_valid_go118_magic_family(self):
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_18_MAGIC)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)
        matches = [c for c in candidates if not c.rejected]
        assert len(matches) == 1
        assert matches[0].magic == GO_1_18_MAGIC

    def test_valid_go116_magic_family(self):
        header = build_pc_header_bytes(PCHEADER_PRE_1_18, 8, magic=GO_1_16_MAGIC)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)
        matches = [c for c in candidates if not c.rejected]
        assert len(matches) == 1
        assert matches[0].magic == GO_1_16_MAGIC

    def test_unrecognized_magic_is_not_matched_by_magic_scan(self):
        # An unrecognized 4-byte value is simply not one of the needles the
        # magic scan searches for, so no MAGIC_DETECTED candidate appears;
        # the structural fallback may or may not find something separately
        # depending on the surrounding bytes (covered by its own tests).
        reader = MockMemoryReader(REGION_START, b"\x99\x99\x99\x99" + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)
        assert not any(c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED and not c.rejected for c in candidates)

    def test_invalid_ptr_size_in_otherwise_valid_magic_header_is_rejected(self):
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC, ptr_size=4)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)
        magic_candidates = [c for c in candidates if c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED]
        assert len(magic_candidates) == 1
        assert magic_candidates[0].rejected is True
        assert any("ptrSize" in e or "does not match" in e for e in magic_candidates[0].validation_errors)

    def test_impossible_nfunc_in_otherwise_valid_magic_header_is_rejected(self):
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC, nfunc=99_999_999)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)
        magic_candidates = [c for c in candidates if c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED]
        assert magic_candidates[0].rejected is True

    def test_corrupted_padding_is_rejected(self):
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC, pad1=0xFF)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)
        magic_candidates = [c for c in candidates if c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED]
        assert magic_candidates[0].rejected is True

    def test_truncated_pcheader_is_rejected_as_unreadable(self):
        # Magic sits 2 bytes before the end of the backing buffer; the full
        # 72-byte pcHeader cannot be read from there.
        data = b"\x00" * 60 + build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC)[:4]
        reader = MockMemoryReader(REGION_START, data)
        region = _region(end=REGION_START + len(data))
        candidates = PclntabParser(reader, 8).scan_regions([region], pid=1)
        magic_candidates = [c for c in candidates if c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED]
        assert len(magic_candidates) == 1
        assert magic_candidates[0].rejected is True
        assert magic_candidates[0].rejection_reason == "unreadable"

    def test_never_returns_more_than_max_candidates_per_process(self):
        from gomemforensics.go_runtime.pclntab import MAX_CANDIDATES_PER_PROCESS

        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC, pad1=1)  # always rejected
        data = header * 400  # far more repeats than the safety cap
        reader = MockMemoryReader(REGION_START, data)
        region = _region(end=REGION_START + len(data))
        candidates = PclntabParser(reader, 8).scan_regions([region], pid=1)
        assert len(candidates) <= MAX_CANDIDATES_PER_PROCESS


class TestPclntabParserStructuralFallback:
    def test_structural_candidate_found_when_no_magic_present(self):
        # Build a header whose magic field holds an unrecognized value but
        # whose remaining fields fully satisfy the pcHeader invariants.
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=0xAABBCCDD)
        reader = MockMemoryReader(REGION_START, header + b"\x00" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region()], pid=1)

        structural = [
            c for c in candidates
            if c.detection_status == PclntabDetectionStatus.MAGIC_NOT_DETECTED_STRUCTURAL_CANDIDATE and not c.rejected
        ]
        assert len(structural) >= 1
        assert structural[0].confidence == Confidence.LOW

    def test_pure_garbage_yields_no_candidates(self):
        reader = MockMemoryReader(REGION_START, b"\x41" * 4096)
        candidates = PclntabParser(reader, 8).scan_regions([_region(end=REGION_START + 4096)], pid=1)
        assert all(c.rejected for c in candidates) or candidates == []


class TestSelectPclntabRegions:
    def test_read_only_region_included(self):
        from gomemforensics.go_runtime.pclntab import _select_pclntab_regions

        ro = _region(readable=True, writable=False, executable=False)
        selected = _select_pclntab_regions([ro])
        assert ro in selected

    def test_executable_region_included_even_if_writable(self):
        from gomemforensics.go_runtime.pclntab import _select_pclntab_regions

        rwx = _region(readable=True, writable=True, executable=True)
        selected = _select_pclntab_regions([rwx])
        assert rwx in selected

    def test_writable_non_executable_region_excluded(self):
        from gomemforensics.go_runtime.pclntab import _select_pclntab_regions

        rw = _region(readable=True, writable=True, executable=False)
        selected = _select_pclntab_regions([rw])
        assert rw not in selected

    def test_unreadable_region_excluded(self):
        from gomemforensics.go_runtime.pclntab import _select_pclntab_regions

        none_region = _region(readable=False, writable=False, executable=False)
        selected = _select_pclntab_regions([none_region])
        assert none_region not in selected
