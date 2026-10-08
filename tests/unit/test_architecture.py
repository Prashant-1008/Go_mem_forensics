"""Tests for the architecture abstraction layer."""

import pytest

from gomemforensics.architecture.arm64 import ARM64Layout
from gomemforensics.architecture.base import ArchitectureLayout, InstructionDecoderConfig
from gomemforensics.architecture.x86_64 import (
    GO_ABI_INTERNAL_AMD64_INT_REGISTERS,
    X86_64Layout,
    assign_integer_argument_locations,
    is_register_based_abi,
)


def test_architecture_layout_is_abstract():
    with pytest.raises(TypeError):
        ArchitectureLayout()  # type: ignore[abstract]


class TestX86_64Layout:
    def test_basic_facts(self):
        layout = X86_64Layout()

        assert layout.architecture_name == "x86_64"
        assert layout.is_supported is True
        assert layout.pointer_size == 8
        assert layout.word_size == 8
        assert layout.endianness == "little"

    def test_registers_include_general_purpose_set(self):
        layout = X86_64Layout()

        assert "rax" in layout.registers
        assert "rsp" in layout.registers
        assert "r15" in layout.registers
        assert len(layout.registers) == 16

    def test_instruction_decoder_config(self):
        layout = X86_64Layout()
        config = layout.instruction_decoder_config

        assert isinstance(config, InstructionDecoderConfig)
        assert config.engine == "capstone"
        assert config.arch == "x86"
        assert config.mode == "64"

    def test_calling_convention_name_is_descriptive_only(self):
        layout = X86_64Layout()
        assert "ABI" in layout.calling_convention_name


class TestARM64Layout:
    def test_reports_unsupported(self):
        layout = ARM64Layout()

        assert layout.architecture_name == "arm64"
        assert layout.is_supported is False

    @pytest.mark.parametrize(
        "attribute",
        [
            "pointer_size",
            "word_size",
            "endianness",
            "registers",
            "calling_convention_name",
            "instruction_decoder_config",
        ],
    )
    def test_unimplemented_properties_raise_clearly(self, attribute):
        layout = ARM64Layout()
        with pytest.raises(NotImplementedError, match="not implemented"):
            getattr(layout, attribute)


class TestAssignIntegerArgumentLocations:
    """Go ABI register-assignment algorithm (cmd/compile/abi-internal.md)."""

    def test_single_scalar_argument_gets_first_register(self):
        result = assign_integer_argument_locations([[(0, 8)]], num_integer_registers=9)

        assert len(result) == 1
        assert len(result[0]) == 1
        loc = result[0][0]
        assert loc.kind == "register"
        assert loc.register == GO_ABI_INTERNAL_AMD64_INT_REGISTERS[0]
        assert loc.fp_offset == 0
        assert loc.size == 8

    def test_string_argument_two_leaves_get_consecutive_registers(self):
        # string = ptr (offset 0) + len (offset 8), both integer-class leaves.
        result = assign_integer_argument_locations([[(0, 8), (8, 8)]], num_integer_registers=9)

        assert len(result[0]) == 2
        assert [loc.register for loc in result[0]] == list(GO_ABI_INTERNAL_AMD64_INT_REGISTERS[:2])
        assert all(loc.kind == "register" for loc in result[0])

    def test_multiple_scalar_arguments_consume_registers_in_order(self):
        arguments = [[(0, 8)], [(8, 8)], [(16, 8)]]
        result = assign_integer_argument_locations(arguments, num_integer_registers=9)

        registers = [loc.register for arg in result for loc in arg]
        assert registers == list(GO_ABI_INTERNAL_AMD64_INT_REGISTERS[:3])

    def test_zero_registers_is_pure_stack_abi(self):
        # num_integer_registers=0 models Go's pre-1.17 ABI0 (stack-based).
        arguments = [[(0, 8)], [(8, 8)]]
        result = assign_integer_argument_locations(arguments, num_integer_registers=0)

        for arg in result:
            for loc in arg:
                assert loc.kind == "stack"
                assert loc.register is None

    def test_stack_location_preserves_arginfo_offset_and_size(self):
        result = assign_integer_argument_locations([[(24, 4)]], num_integer_registers=0)

        loc = result[0][0]
        assert loc.kind == "stack"
        assert loc.fp_offset == 24
        assert loc.size == 4

    def test_argument_that_does_not_fit_spills_to_stack_without_wasting_registers(self):
        # Verified rule: an argument assigned entirely to registers or
        # entirely to the stack, and a spilled argument does NOT consume
        # registers a later, smaller argument could still use.
        # 8-leaf arg fills all 8 of the first 8 registers; a 3-leaf arg
        # cannot fit in the remaining 1 register and spills to the stack
        # (register_index stays at 8); a later 1-leaf arg then claims the
        # still-available 9th register.
        eight_leaf_arg = [(i * 8, 8) for i in range(8)]
        three_leaf_arg = [(64, 8), (72, 8), (80, 8)]
        one_leaf_arg = [(88, 8)]

        result = assign_integer_argument_locations(
            [eight_leaf_arg, three_leaf_arg, one_leaf_arg], num_integer_registers=9
        )

        assert all(loc.kind == "register" for loc in result[0])
        assert [loc.register for loc in result[0]] == list(GO_ABI_INTERNAL_AMD64_INT_REGISTERS[:8])

        assert all(loc.kind == "stack" for loc in result[1])

        assert len(result[2]) == 1
        assert result[2][0].kind == "register"
        assert result[2][0].register == GO_ABI_INTERNAL_AMD64_INT_REGISTERS[8]

    def test_empty_arguments_list_returns_empty(self):
        assert assign_integer_argument_locations([], num_integer_registers=9) == []

    def test_argument_with_no_leaves_returns_empty_location_list(self):
        result = assign_integer_argument_locations([[]], num_integer_registers=9)
        assert result == [[]]

    def test_negative_register_budget_raises(self):
        with pytest.raises(ValueError):
            assign_integer_argument_locations([[(0, 8)]], num_integer_registers=-1)


class TestIsRegisterBasedAbi:
    @pytest.mark.parametrize("version_range", ["1.18-1.19", "1.20+", "1.22+"])
    def test_post_1_17_ranges_are_register_based(self, version_range):
        assert is_register_based_abi(version_range) is True

    def test_pre_1_17_range_is_stack_based(self):
        assert is_register_based_abi("1.2-1.15") is False

    def test_straddling_range_is_unknown_not_guessed(self):
        assert is_register_based_abi("1.16-1.17") is None

    def test_none_version_is_unknown(self):
        assert is_register_based_abi(None) is None

    def test_unrecognized_string_is_unknown(self):
        assert is_register_based_abi("not-a-real-range") is None
