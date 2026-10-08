"""Unit tests for the pctab (PC-value table) decoder.

Every expected value below was independently hand-calculated from the
verified encoding (zigzag value-delta + unsigned varint pc-delta,
PCQuantum=1 for amd64) before being asserted - see module docstrings in
gomemforensics.go_runtime.pctab for the exact source citations.
"""

import pytest

from gomemforensics.go_runtime.pctab import (
    MalformedPctabError,
    _zigzag_decode,
    pc_value,
    read_varint,
    step,
)


class TestReadVarint:
    def test_single_byte_varint(self):
        consumed, value = read_varint(bytes([0x2A]), 0)
        assert consumed == 1
        assert value == 42

    def test_multi_byte_varint(self):
        # 300 = 0b1_0010_1100 -> low 7 bits = 0101100 (0x2C) with continuation,
        # remaining bits = 10 (0x02) -> bytes: 0xAC, 0x02
        consumed, value = read_varint(bytes([0xAC, 0x02]), 0)
        assert consumed == 2
        assert value == 300

    def test_zero_varint(self):
        consumed, value = read_varint(bytes([0x00]), 0)
        assert consumed == 1
        assert value == 0

    def test_varint_at_nonzero_offset(self):
        consumed, value = read_varint(bytes([0xFF, 0x2A]), 1)
        assert consumed == 1
        assert value == 42

    def test_truncated_varint_raises(self):
        with pytest.raises(MalformedPctabError):
            read_varint(bytes([0x80]), 0)  # continuation bit set, no more bytes

    def test_runaway_varint_raises(self):
        with pytest.raises(MalformedPctabError):
            read_varint(bytes([0x80] * 20), 0)


class TestZigzagDecode:
    def test_zero(self):
        assert _zigzag_decode(0) == 0

    def test_positive_one(self):
        assert _zigzag_decode(2) == 1

    def test_negative_one(self):
        assert _zigzag_decode(1) == -1

    def test_positive_large(self):
        assert _zigzag_decode(12) == 6

    def test_negative_large(self):
        assert _zigzag_decode(5) == -3


class TestStep:
    def test_first_step_from_minus_one(self):
        # delta = 6 (val -1 -> 5), zigzag(6) = 12 (0x0C); pcdelta = 10 (0x0A)
        result = step(bytes([0x0C, 0x0A]), 0, 0x1000, -1, True)
        assert result is not None
        assert result.val == 5
        assert result.pc == 0x100A
        assert result.consumed == 2

    def test_terminator_on_non_first_step(self):
        assert step(bytes([0x00]), 0, 0x1000, 5, False) is None

    def test_zero_uvdelta_on_first_step_is_not_a_terminator(self):
        # first=True: a zero value-delta byte is a legitimate (val stays
        # the same) step, not end-of-stream - only non-first zero bytes
        # terminate (verified: `if uvdelta == 0 && !first`).
        result = step(bytes([0x00, 0x0A]), 0, 0x1000, -1, True)
        assert result is not None
        assert result.val == -1  # delta 0 applied to -1

    def test_truncated_pc_delta_raises(self):
        with pytest.raises(MalformedPctabError):
            step(bytes([0x0C]), 0, 0x1000, -1, True)  # value byte present, pc byte missing


class TestPcValue:
    #: val=5 for pc in [entry, entry+10), val=7 for pc in [entry+10, entry+20).
    #: Byte 0 is a deliberate leading pad so table_offset != 0 (0 means
    #: "no table" per the verified convention).
    _STREAM = bytes([0xAA, 0x0C, 0x0A, 0x04, 0x0A, 0x00])
    _ENTRY = 0x1000

    def test_value_at_range_start(self):
        assert pc_value(self._STREAM, 1, self._ENTRY, self._ENTRY) == 5

    def test_value_within_first_range(self):
        assert pc_value(self._STREAM, 1, self._ENTRY, self._ENTRY + 9) == 5

    def test_value_at_second_range_start(self):
        assert pc_value(self._STREAM, 1, self._ENTRY, self._ENTRY + 10) == 7

    def test_value_within_second_range(self):
        assert pc_value(self._STREAM, 1, self._ENTRY, self._ENTRY + 19) == 7

    def test_target_beyond_table_is_none(self):
        assert pc_value(self._STREAM, 1, self._ENTRY, self._ENTRY + 20) is None

    def test_table_offset_zero_means_no_table(self):
        assert pc_value(self._STREAM, 0, self._ENTRY, self._ENTRY) is None

    def test_target_before_entry_raises(self):
        with pytest.raises(ValueError):
            pc_value(self._STREAM, 1, self._ENTRY, self._ENTRY - 1)

    def test_negative_value_delta_decoded_correctly(self):
        # val=5 for [entry, entry+10), then val=2 for [entry+10, entry+20)
        # (delta -3, zigzag(−3) = 5 = 0x05).
        stream = bytes([0xAA, 0x0C, 0x0A, 0x05, 0x0A, 0x00])
        assert pc_value(stream, 1, self._ENTRY, self._ENTRY + 15) == 2

    def test_multi_byte_pc_delta(self):
        # A single step with a large pc-delta (300, requiring a 2-byte
        # varint: 0xAC, 0x02) covering [entry, entry+300).
        stream = bytes([0xAA, 0x0C, 0xAC, 0x02, 0x00])
        assert pc_value(stream, 1, self._ENTRY, self._ENTRY + 250) == 5

    def test_malformed_stream_raises_not_silently_wrong_value(self):
        # A continuation-bit-set value byte with nothing after it.
        stream = bytes([0xAA, 0x80])
        with pytest.raises(MalformedPctabError):
            pc_value(stream, 1, self._ENTRY, self._ENTRY)


class TestPcValueFirstStepSemantics:
    """Regression coverage for Phase 4.1 Correction 1.

    Verified: ``runtime/symtab.go``'s real ``pcvalue`` passes
    ``first = (pc == f.entry())`` to ``step()`` on *every* loop
    iteration - a value-based check, recomputed fresh each time - not a
    one-time flag consumed after the first call. This only differs from
    an iteration-count-based approximation when a step's pc-delta is 0
    (``pc`` stays at ``entry_pc``), making the *next* step "first" again
    too.

    This edge case was constructed by hand from the verified encoding to
    prove the divergence exists - it has NOT been observed in the
    project's real compiled fixture binary or in any other real Go
    output, and no claim is made that it occurs there.
    """

    _ENTRY = 0x1000

    #: Step 1: val -1 -> 5 (zigzag(6) = 0x0C), pc-delta = 0 (pc stays at
    #: entry). Step 2: value-delta byte is 0x00 (delta 0, val stays 5) -
    #: under the *correct* value-based `first` check this is step 2's
    #: legitimate zero-delta, not a terminator, because pc is still
    #: entry_pc; pc-delta = 10 then advances pc to entry+10.
    #: Byte 0 is the deliberate leading pad (table_offset=1, matching the
    #: rest of this file's convention).
    _ZERO_PC_DELTA_FIRST_STEP_STREAM = bytes([0xAA, 0x0C, 0x00, 0x00, 0x0A])

    def test_zero_pc_delta_first_step_keeps_first_true_for_next_step(self):
        # Correct (value-based) behavior: value 5 is active for
        # [entry, entry+10) even though it took two encoded steps to get
        # there (the first of which does not advance pc at all).
        assert pc_value(self._ZERO_PC_DELTA_FIRST_STEP_STREAM, 1, self._ENTRY, self._ENTRY) == 5

    def test_value_still_active_just_before_second_step_advances_pc(self):
        assert pc_value(self._ZERO_PC_DELTA_FIRST_STEP_STREAM, 1, self._ENTRY, self._ENTRY + 9) == 5

    def test_iteration_based_first_flag_would_misread_this_stream(self):
        """Demonstrates the actual divergence: a local re-implementation of
        the *old*, iteration-based approximation (`first` true only for the
        literal first loop pass, never recomputed) on this exact stream
        silently loses the answer, returning ``None`` for a query that is
        genuinely in range - whereas the corrected, value-based
        implementation (asserted above) returns ``5``.
        """

        def _old_iteration_based_pc_value(pctab, table_offset, entry_pc, target_pc):
            offset = table_offset
            pc = entry_pc
            val = -1
            first = True  # BUG: never recomputed after the first pass
            while True:
                result = step(pctab, offset, pc, val, first)
                if result is None:
                    return None
                if target_pc < result.pc:
                    return result.val
                offset += result.consumed
                pc = result.pc
                val = result.val
                first = False

        old_result = _old_iteration_based_pc_value(
            self._ZERO_PC_DELTA_FIRST_STEP_STREAM, 1, self._ENTRY, self._ENTRY
        )
        new_result = pc_value(self._ZERO_PC_DELTA_FIRST_STEP_STREAM, 1, self._ENTRY, self._ENTRY)

        assert old_result is None  # the bug: silently treats step 2's 0x00 as a terminator
        assert new_result == 5  # the fix: step 2 is still "first" since pc never advanced
        assert old_result != new_result
