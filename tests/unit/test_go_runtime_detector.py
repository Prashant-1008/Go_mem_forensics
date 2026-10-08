"""End-to-end (still fully synthetic) tests for GoProcessDetector.

Combines a pclntab candidate in one region with a moduledata candidate in
another, exactly as a real process's executable-vs-writable mapping split
would look, all via MockMemoryReader - no real memory image involved.
"""

from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.layouts import MODULEDATA_1_22_PLUS, PCHEADER_1_18_PLUS
from gomemforensics.go_runtime.version import GO_1_20_MAGIC

from tests.unit.go_runtime_helpers import build_moduledata_bytes, build_pc_header_bytes

TEXT_START = 0x140000000
DATA_START = 0x180000000
PC_HEADER_ADDR = TEXT_START + 0x1000


def _text_region():
    return MemoryRegion(start=TEXT_START, end=TEXT_START + 0x100000, readable=True, writable=False, executable=True)


def _data_region(size=0x10000):
    return MemoryRegion(start=DATA_START, end=DATA_START + size, readable=True, writable=True, executable=False)


def _confirmed_go_process_reader() -> MockMemoryReader:
    header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC)
    text_data = b"\x00" * 0x1000 + header + b"\x00" * 4096

    moduledata = build_moduledata_bytes(
        MODULEDATA_1_22_PLUS,
        8,
        pc_header_pointer=PC_HEADER_ADDR,
        text=TEXT_START,
        etext=TEXT_START + 0x50000,
        data=DATA_START,
        edata=DATA_START + 0x2000,
        bss=DATA_START + 0x2000,
        ebss=DATA_START + 0x3000,
        types=TEXT_START + 0x60000,
        etypes=TEXT_START + 0x70000,
        rodata=TEXT_START + 0x55000,
        typelinks_ptr=TEXT_START + 0x60100,
        typelinks_len=3,
        typelinks_cap=3,
        itablinks_ptr=TEXT_START + 0x60200,
        itablinks_len=1,
        itablinks_cap=1,
    )

    return MockMemoryReader(
        TEXT_START,
        text_data,
        extra_regions={DATA_START: moduledata + b"\x00" * 4096},
    )


class TestConfirmedGoProcess:
    def test_high_confidence_runtime_recovered(self):
        reader = _confirmed_go_process_reader()
        result = GoProcessDetector().detect(1234, "x86_64", 8, reader, [_text_region(), _data_region()])

        assert result.runtime is not None
        assert result.runtime.confidence == Confidence.HIGH
        assert result.runtime.pc_header_address == PC_HEADER_ADDR
        assert result.runtime.moduledata_address == DATA_START
        assert result.runtime.text_start == TEXT_START
        assert result.runtime.text_end == TEXT_START + 0x50000
        assert result.runtime.typelinks_end == TEXT_START + 0x60100 + 3 * 4  # int32 elements
        assert result.runtime.itablinks_end == TEXT_START + 0x60200 + 1 * 8  # pointer elements, amd64
        assert result.runtime.go_version_confidence == Confidence.HIGH
        assert result.runtime.go_version_confidence != Confidence.UNKNOWN

    def test_provenance_recorded_for_both_artifacts(self):
        reader = _confirmed_go_process_reader()
        result = GoProcessDetector().detect(1234, "x86_64", 8, reader, [_text_region(), _data_region()])

        artifact_types = {p.artifact_type for p in result.runtime.provenance}
        assert artifact_types == {"pclntab", "moduledata"}
        for p in result.runtime.provenance:
            assert p.pid == 1234

    def test_version_range_narrowed_by_moduledata_era(self):
        reader = _confirmed_go_process_reader()
        result = GoProcessDetector().detect(1234, "x86_64", 8, reader, [_text_region(), _data_region()])
        # moduledata built with MODULEDATA_1_22_PLUS -> narrows "1.20+" to "1.22+".
        assert result.runtime.go_version == "1.22+"


class TestNonGoProcess:
    def test_no_magic_no_structural_candidate_yields_no_runtime(self):
        reader = MockMemoryReader(TEXT_START, b"\x41" * 8192)
        result = GoProcessDetector().detect(999, "x86_64", 8, reader, [_text_region()])

        assert result.runtime is None
        assert result.errors == []


class TestMagicOnlyFalsePositive:
    def test_magic_present_but_pc_header_invalid_never_becomes_a_runtime(self):
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=GO_1_20_MAGIC, pad1=0xFF)  # corrupt padding
        reader = MockMemoryReader(TEXT_START, header + b"\x00" * 4096)
        result = GoProcessDetector().detect(1, "x86_64", 8, reader, [_text_region()])

        assert result.runtime is None
        assert len(result.pclntab_candidates) >= 1
        assert all(c.rejected for c in result.pclntab_candidates)


class TestStructuralOnlyCandidate:
    def test_structural_candidate_yields_low_confidence_runtime_without_moduledata(self):
        # Valid pcHeader shape but with an unrecognized magic value.
        header = build_pc_header_bytes(PCHEADER_1_18_PLUS, 8, magic=0x11223344)
        reader = MockMemoryReader(TEXT_START, header + b"\x00" * 4096)
        result = GoProcessDetector().detect(1, "x86_64", 8, reader, [_text_region()])

        assert result.runtime is not None
        assert result.runtime.confidence == Confidence.LOW
        assert result.runtime.moduledata_address is None


class TestInaccessibleProcess:
    def test_reader_that_raises_everywhere_does_not_crash(self):
        class _AlwaysFailingReader(MockMemoryReader):
            def read(self, address, length):
                from gomemforensics.common.memory import MemoryAccessError

                raise MemoryAccessError("simulated inaccessible memory")

        reader = _AlwaysFailingReader(TEXT_START, b"\x00" * 16)
        result = GoProcessDetector().detect(1, "x86_64", 8, reader, [_text_region()])

        assert result.runtime is None
        assert result.errors == []  # resilient scanning degrades gracefully, not an AnalysisError

    def test_no_regions_yields_no_runtime_without_crashing(self):
        reader = MockMemoryReader(TEXT_START, b"\x00" * 16)
        result = GoProcessDetector().detect(1, "x86_64", 8, reader, [])
        assert result.runtime is None
        assert result.pclntab_candidates == []
