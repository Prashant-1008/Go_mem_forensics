"""Tests for the declarative struct layout / offset computation system.

Offsets are cross-checked against manual hand-computation for a couple of
representative fields, to catch any arithmetic drift in StructLayout itself
independent of the higher-level parser tests.
"""

from gomemforensics.go_runtime.layouts import (
    G_GO1_26,
    MODULEDATA_1_16_17,
    MODULEDATA_1_18_19,
    MODULEDATA_1_20_EARLY,
    MODULEDATA_1_22_PLUS,
    PCHEADER_1_18_PLUS,
    PCHEADER_PRE_1_18,
)


class TestPcHeaderLayouts:
    def test_pre_1_18_size_amd64(self):
        # magic(4)+pad1(1)+pad2(1)+minLC(1)+ptrSize(1) = 8, then 7 word
        # fields (nfunc, nfiles, funcnameOffset, cuOffset, filetabOffset,
        # pctabOffset, pclnOffset) * 8 bytes = 64 total.
        assert PCHEADER_PRE_1_18.size(8) == 8 + 7 * 8

    def test_1_18_plus_size_amd64(self):
        # one extra word field (textStartOrUnused) vs pre-1.18
        assert PCHEADER_1_18_PLUS.size(8) == 8 + 8 * 8

    def test_1_18_plus_is_larger_than_pre_1_18(self):
        assert PCHEADER_1_18_PLUS.size(8) == PCHEADER_PRE_1_18.size(8) + 8

    def test_funcname_offset_shifted_by_inserted_field(self):
        pre = PCHEADER_PRE_1_18.field_offset("funcnameOffset", 8)
        plus = PCHEADER_1_18_PLUS.field_offset("funcnameOffset", 8)
        assert plus == pre + 8

    def test_386_pointer_size_halves_word_fields(self):
        size_386 = PCHEADER_PRE_1_18.size(4)
        # header prefix (8 bytes) is pointer-size-independent; only the
        # 7 word-sized fields shrink from 8 to 4 bytes each.
        assert size_386 == 8 + 7 * 4


class TestModuledataLayouts:
    def test_1_16_17_has_no_rodata_field(self):
        assert "rodata" not in MODULEDATA_1_16_17.offsets(8)

    def test_1_18_19_has_rodata_but_no_covctrs(self):
        offsets = MODULEDATA_1_18_19.offsets(8)
        assert "rodata" in offsets
        assert "covctrs" not in offsets

    def test_1_20_early_has_covctrs_but_no_epclntab(self):
        offsets = MODULEDATA_1_20_EARLY.offsets(8)
        assert "covctrs" in offsets
        assert "epclntab" not in offsets

    def test_1_22_plus_has_epclntab(self):
        assert "epclntab" in MODULEDATA_1_22_PLUS.offsets(8)

    def test_sizes_strictly_increase_across_eras(self):
        sizes = [
            MODULEDATA_1_16_17.size(8),
            MODULEDATA_1_18_19.size(8),
            MODULEDATA_1_20_EARLY.size(8),
            MODULEDATA_1_22_PLUS.size(8),
        ]
        assert sizes == sorted(sizes)
        assert len(set(sizes)) == len(sizes)  # strictly increasing, no ties

    def test_pc_header_field_is_always_first(self):
        for layout in (MODULEDATA_1_16_17, MODULEDATA_1_18_19, MODULEDATA_1_20_EARLY, MODULEDATA_1_22_PLUS):
            assert layout.field_offset("pcHeader", 8) == 0

    def test_typelinks_offset_shifts_with_rodata_insertion(self):
        without_rodata = MODULEDATA_1_16_17.field_offset("typelinks", 8)
        with_rodata = MODULEDATA_1_18_19.field_offset("typelinks", 8)
        # textsectmap(24) + typelinks comes after types/etypes in both; 1.18
        # inserts rodata+gofunc (2 words = 16 bytes) before textsectmap.
        assert with_rodata == without_rodata + 16


class TestGLayout:
    """Phase 5A: offsets cross-checked against a real go1.26.2 compiler run.

    A throwaway Go program declaring a struct with the same field
    sizes/order as `runtime.g` (using local stand-in type names, since
    `runtime.g`'s real field types are unexported/internal to package
    runtime) was compiled and run with the local go1.26.2 toolchain;
    these are its `unsafe.Offsetof`/`unsafe.Sizeof` results, verbatim -
    not merely this project's own StructLayout computation checked
    against itself.
    """

    _EXPECTED_OFFSETS = {
        "stack_lo": 0, "stack_hi": 8, "stackguard0": 16, "stackguard1": 24,
        "_panic": 32, "_defer": 40, "m": 48,
        "sched_sp": 56, "sched_pc": 64, "sched_g": 72, "sched_ctxt": 80,
        "sched_lr": 88, "sched_bp": 96,
        "syscallsp": 104, "syscallpc": 112, "syscallbp": 120, "stktopsp": 128,
        "param": 136, "atomicstatus": 144, "stackLock": 148, "goid": 152,
        "schedlink": 160, "waitsince": 168, "waitreason": 176, "preempt": 177,
        "trackingStamp": 192, "runnableTime": 200, "lockedm": 208,
        "fipsIndicator": 216, "sig": 224, "secret": 228, "writebuf_ptr": 232,
        "sigcode0": 256, "sigcode1": 264, "sigpc": 272, "parentGoid": 280,
        "gopc": 288, "ancestors": 296, "startpc": 304,
    }

    def test_offsets_match_real_compiler_output(self):
        offsets = G_GO1_26.offsets(8)
        for name, expected in self._EXPECTED_OFFSETS.items():
            assert offsets[name] == expected, f"{name}: expected {expected}, got {offsets[name]}"

    def test_size_matches_real_compiler_output(self):
        assert G_GO1_26.size(8) == 312

    def test_gobuf_fields_are_contiguous_48_bytes(self):
        offsets = G_GO1_26.offsets(8)
        assert offsets["sched_sp"] == offsets["m"] + 8
        assert offsets["syscallsp"] == offsets["sched_sp"] + 48  # sizeof(gobuf) == 48
