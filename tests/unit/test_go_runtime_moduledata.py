"""Unit tests for moduledata discovery and validation.

All synthetic - no real memory image needed.
"""

from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.go_runtime.layouts import MODULEDATA_1_16_17, MODULEDATA_1_18_19, MODULEDATA_1_22_PLUS
from gomemforensics.go_runtime.moduledata import ModuledataParser
from gomemforensics.go_runtime.version import GO_1_16_MAGIC, GO_1_18_MAGIC, GO_1_20_MAGIC

from tests.unit.go_runtime_helpers import build_moduledata_bytes

PC_HEADER_ADDR = 0x7FF600000000
MODULE_START = 0x180000000
MODULE_END = 0x180010000


def _region(**overrides) -> MemoryRegion:
    defaults = dict(start=MODULE_START, end=MODULE_END, readable=True, writable=True, executable=False)
    defaults.update(overrides)
    return MemoryRegion(**defaults)


def _valid_fields(pc_header_pointer=PC_HEADER_ADDR):
    return dict(
        pc_header_pointer=pc_header_pointer,
        text=0x140001000,
        etext=0x140050000,
        data=0x180001000,
        edata=0x180002000,
        bss=0x180002000,
        ebss=0x180003000,
        types=0x140060000,
        etypes=0x140070000,
        rodata=0x140055000,
        typelinks_ptr=0x140060100,
        typelinks_len=5,
        typelinks_cap=5,
        itablinks_ptr=0x140060200,
        itablinks_len=2,
        itablinks_cap=2,
    )


class TestValidModuledataCandidate:
    def test_valid_candidate_is_accepted(self):
        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **_valid_fields())
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_20_MAGIC)

        accepted = [c for c in candidates if not c.rejected]
        assert len(accepted) == 1
        assert accepted[0].fields.text == 0x140001000
        assert accepted[0].fields.typelinks_len == 5

    def test_valid_candidate_go116_layout(self):
        fields = _valid_fields()
        fields.pop("rodata")  # go1.16-1.17 moduledata has no rodata field
        body = build_moduledata_bytes(MODULEDATA_1_16_17, 8, **fields)
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_16_MAGIC)

        assert any(not c.rejected for c in candidates)

    def test_valid_candidate_go118_layout(self):
        body = build_moduledata_bytes(MODULEDATA_1_18_19, 8, **_valid_fields())
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_18_MAGIC)

        assert any(not c.rejected for c in candidates)


class TestModuledataRejection:
    def test_wrong_pc_header_pointer_rejected(self):
        # The scan only ever finds candidates by matching the anchor
        # pointer value in memory, so to exercise the "value mismatch"
        # validation path directly we bypass the scan and call the
        # validator with a deliberately different anchor.
        from gomemforensics.go_runtime.moduledata import ModuledataValidator, _decode_moduledata

        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **_valid_fields(pc_header_pointer=0x999999))
        raw = _decode_moduledata(body, MODULEDATA_1_22_PLUS, 8)
        errors = ModuledataValidator().validate(raw, anchor_pc_header_address=PC_HEADER_ADDR)
        assert any("does not match the anchor" in e for e in errors)

    def test_invalid_slice_length_greater_than_capacity_rejected(self):
        fields = _valid_fields()
        fields["typelinks_len"] = 100
        fields["typelinks_cap"] = 5
        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **fields)
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_20_MAGIC)

        assert all(c.rejected for c in candidates)
        assert any("typelinks len" in e for c in candidates for e in c.validation_errors)

    def test_invalid_region_ordering_rejected(self):
        fields = _valid_fields()
        fields["text"], fields["etext"] = fields["etext"], fields["text"]  # text > etext
        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **fields)
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_20_MAGIC)

        assert all(c.rejected for c in candidates)
        assert any("expected text <= etext" in e for c in candidates for e in c.validation_errors)

    def test_implausibly_large_span_rejected(self):
        fields = _valid_fields()
        fields["etext"] = fields["text"] + (8 * 1024 * 1024 * 1024)  # 8 GiB span
        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **fields)
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_20_MAGIC)

        assert all(c.rejected for c in candidates)

    def test_no_candidates_when_anchor_pointer_absent(self):
        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **_valid_fields())
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates(
            [_region()], pid=1, pc_header_address=0xDEADBEEF00, pc_header_magic=GO_1_20_MAGIC
        )
        assert candidates == []

    def test_unknown_magic_family_yields_no_candidates(self):
        body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **_valid_fields())
        reader = MockMemoryReader(MODULE_START, body + b"\x00" * 4096)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates(
            [_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=0xDEADBEEF
        )
        assert candidates == []


class TestMultipleModuledataCandidates:
    def test_one_valid_and_one_invalid_pointer_match_both_reported(self):
        valid_body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **_valid_fields())
        # A second, coincidental pointer-aligned match to the same anchor
        # value, but with an otherwise-corrupt moduledata body.
        bad_fields = _valid_fields()
        bad_fields["typelinks_len"] = 999
        bad_fields["typelinks_cap"] = 1
        bad_body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **bad_fields)

        combined = valid_body + bad_body + b"\x00" * 4096
        reader = MockMemoryReader(MODULE_START, combined)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates([_region()], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_20_MAGIC)

        assert len(candidates) == 2
        accepted = [c for c in candidates if not c.rejected]
        rejected = [c for c in candidates if c.rejected]
        assert len(accepted) == 1
        assert len(rejected) == 1

    def test_moduledata_candidates_respect_max_cap(self):
        from gomemforensics.go_runtime.moduledata import MAX_CANDIDATES_PER_PROCESS

        # Many repeats of a body that fails validation, to prove the scan
        # is bounded rather than growing without limit.
        bad_fields = _valid_fields()
        bad_fields["typelinks_len"] = 999
        bad_fields["typelinks_cap"] = 1
        bad_body = build_moduledata_bytes(MODULEDATA_1_22_PLUS, 8, **bad_fields)
        combined = bad_body * 200
        reader = MockMemoryReader(MODULE_START, combined)
        parser = ModuledataParser(reader, 8)

        candidates = parser.find_candidates(
            [_region(end=MODULE_START + len(combined))], pid=1, pc_header_address=PC_HEADER_ADDR, pc_header_magic=GO_1_20_MAGIC
        )
        assert len(candidates) <= MAX_CANDIDATES_PER_PROCESS


class TestSelectModuledataRegions:
    def test_writable_readable_region_included(self):
        from gomemforensics.go_runtime.moduledata import _select_moduledata_regions

        rw = _region(readable=True, writable=True)
        assert rw in _select_moduledata_regions([rw])

    def test_read_only_region_excluded(self):
        from gomemforensics.go_runtime.moduledata import _select_moduledata_regions

        ro = _region(readable=True, writable=False)
        assert ro not in _select_moduledata_regions([ro])
