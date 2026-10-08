"""Validates Go function recovery (Phase 4) against real Go 1.26.2 compiler output.

Unlike tests/integration/test_go_runtime_real_fixture.py (which reads the
compiled binary's raw file bytes directly as a flat, offset-addressed
buffer - valid only for pclntab's own magic-byte scan, since pclntab
fields are relative offsets), function/moduledata recovery requires
resolving *absolute virtual addresses* embedded in moduledata (ftab,
funcnametab, text, ...). This module builds a small PE-section-aware
:class:`~gomemforensics.common.memory.MemoryReader` (using ``pefile``,
already present transitively via volatility3) that maps a virtual address
to its backing file bytes via the real PE section table - genuine
compiled-binary validation of the full pclntab -> moduledata -> ftab ->
_func -> name/classification recovery path, still against on-disk static
layout, NOT a captured process memory image.

SCOPE NOTE (CLAUDE.md section 51 / approved plan Section N, same caveat as
the string-fixture test): a compiled executable file is not a process
memory image. This validates static metadata recovery (function tables,
names, source paths, classification) faithfully, since pclntab/moduledata/
ftab are all linker-emitted, on-disk structures - but it says nothing
about runtime-only state (goroutines, live heap objects, or Capstone
call-site *argument value* recovery against a real running process's
register/stack state at capture time), which remains genuinely
unvalidated until a real memory image is available (see
docs/validation/validation-plan.md).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.go_runtime import backward_analysis as ba
from gomemforensics.go_runtime.detector import GoProcessDetector
from gomemforensics.go_runtime.functab import FunctionTableParser
from gomemforensics.go_runtime.models import FunctionClassification

pefile = pytest.importorskip("pefile", reason="pefile not available - PE-mapped function-fixture test skipped")

_FIXTURE_BIN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "go" / "bin"
_WINDOWS_FIXTURE = _FIXTURE_BIN_DIR / "gomemforensics_fixture_windows_amd64.exe"


class _PEMappedReader(MemoryReader):
    """Maps virtual addresses to file bytes via the PE section table.

    Test-only. Real analysis always goes through a Volatility-backed
    MemoryReader over actual process virtual memory; this exists solely to
    validate the function-recovery parsers against real compiled bytes at
    their real, resolvable virtual addresses (unlike the pclntab-only
    scan in test_go_runtime_real_fixture.py, moduledata/ftab parsing
    dereferences absolute pointers and cannot work against raw file
    offsets directly).
    """

    def __init__(self, pe: "pefile.PE") -> None:
        self._pe = pe
        self._image_base = pe.OPTIONAL_HEADER.ImageBase

    @property
    def pointer_size(self) -> int:
        return 8

    def is_valid(self, address: int) -> bool:
        rva = address - self._image_base
        if rva < 0:
            return False
        return self._pe.get_section_by_rva(rva) is not None

    def read(self, address: int, length: int) -> bytes:
        rva = address - self._image_base
        if rva < 0 or length < 0:
            raise MemoryAccessError(f"address 0x{address:x} outside image base 0x{self._image_base:x}")
        try:
            data = self._pe.get_data(rva, length)
        except Exception as exc:  # pefile raises plain Exception/PEFormatError
            raise MemoryAccessError(f"unreadable at rva=0x{rva:x} length={length}: {exc}") from exc
        if len(data) < length:
            raise MemoryAccessError(f"short read at rva=0x{rva:x}: got {len(data)} of {length} bytes")
        return data


def _build_regions(pe: "pefile.PE") -> list[MemoryRegion]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    regions = []
    for section in pe.sections:
        start = image_base + section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        regions.append(
            MemoryRegion(
                start=start,
                end=start + size,
                readable=True,
                writable=bool(section.Characteristics & 0x80000000),
                executable=bool(section.Characteristics & 0x20000000),
                source="pe_section",
            )
        )
    return regions


@pytest.fixture(scope="module")
def _recovered_functions():
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")

    pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
    reader = _PEMappedReader(pe)
    regions = _build_regions(pe)

    result = GoProcessDetector().detect(pid=1, architecture="x86_64", pointer_size=8, reader=reader, regions=regions)
    assert result.runtime is not None, f"Go runtime not recovered from real fixture: {result.errors}"

    functions, errors = FunctionTableParser(reader, pointer_size=8).parse(result.runtime)
    return functions, errors, result.runtime


def test_go_runtime_recovered_from_real_pe(_recovered_functions):
    functions, errors, runtime = _recovered_functions
    assert runtime.go_version is not None
    assert len(functions) > 100  # nfunc was independently observed as 2184 for this build


def test_application_function_names_and_classification_recovered(_recovered_functions):
    functions, _errors, _runtime = _recovered_functions
    by_name = {f.name: f for f in functions if f.name}

    for expected_name in (
        "main.fixtureArgInt",
        "main.fixtureArgString",
        "main.fixtureArgMulti",
        "main.fixtureArgPointer",
        "main.fixtureArgZero",
        "main.fixtureArgConstant",
        "main.fixtureArgGlobalAddress",
        "main.fixtureOuter",
        "main.fixtureInner",
        "main.fixtureInnermost",
        "main.fixtureStdlibCall",
        "main.fixtureHelperA",
        "main.fixtureHelperB",
        "main.main",
    ):
        assert expected_name in by_name, f"expected function not recovered: {expected_name}"
        assert by_name[expected_name].classification == FunctionClassification.APPLICATION


def test_stdlib_and_runtime_functions_classified_correctly(_recovered_functions):
    functions, _errors, _runtime = _recovered_functions
    by_name = {f.name: f for f in functions if f.name}

    assert "strings.ToUpper" in by_name
    assert by_name["strings.ToUpper"].classification == FunctionClassification.STDLIB

    # Genuinely runtime-package-sourced functions (source path under
    # .../src/runtime/) must classify as RUNTIME.
    for name in ("runtime.main", "runtime.gopanic", "runtime.newobject"):
        assert by_name[name].classification == FunctionClassification.RUNTIME, name

    # NOTE: classification is evidence-based on recovered *source path*,
    # never the function's linker-visible name (CLAUDE.md section 7). Go's
    # real toolchain gives some functions a "runtime."-prefixed exported
    # name while their actual source lives elsewhere (e.g. Go 1.24+ moved
    # the swiss-table map implementation to internal/runtime/maps, and
    # internal/bytealg backs runtime.memequal/runtime.cmpstring) - those
    # correctly classify as RUNTIME_INTERNAL by path, confirmed here as a
    # real, path-driven distinction rather than a naming assumption.
    linkname_examples = ("runtime.mapaccess1_fast32", "runtime.memequal", "runtime.cmpstring")
    for name in linkname_examples:
        assert by_name[name].classification == FunctionClassification.RUNTIME_INTERNAL, name
        assert "internal/" in by_name[name].source_file


def test_backward_analysis_recovers_real_arguments_using_callee_arginfo_shape(_recovered_functions):
    """Phase 4.1 correction, validated against real compiled output (not
    just synthetic bytes): backward analysis, driven by each callee's own
    recovered :class:`~gomemforensics.go_runtime.models.ArgumentLocation`
    shape - the exact same production wiring
    ``pipeline._recover_functions`` uses - correctly recovers several
    real, independently-verifiable argument values from
    ``main.runFixtureFunctionCatalog``'s real calls into the controlled
    fixture functions (tests/fixtures/go/fixture.go). Still file-based
    static-layout validation, NOT a captured process memory image (see
    module docstring) - argument *value* recovery against a real running
    process's live register/stack state at capture time remains
    genuinely UNVALIDATED.
    """
    functions, _errors, runtime = _recovered_functions
    reader = _PEMappedReader(pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True))
    by_name = {f.name: f for f in functions if f.name}

    known_function_addresses = {f.entry_address: f.name for f in functions if f.name}
    known_function_argument_locations = {
        f.entry_address: f.argument_locations for f in functions if f.argument_locations is not None
    }

    caller = by_name["main.runFixtureFunctionCatalog"]
    sorted_functions = sorted(functions, key=lambda f: f.entry_address)
    caller_index = sorted_functions.index(caller)
    end_pc = (
        sorted_functions[caller_index + 1].entry_address
        if caller_index + 1 < len(sorted_functions)
        else None
    )

    call_sites = ba.analyze_function_call_sites(
        reader, pid=1, entry_pc=caller.entry_address, caller_function=caller.name,
        end_pc=end_pc,
        known_function_addresses=known_function_addresses,
        known_function_argument_locations=known_function_argument_locations,
    )
    calls_by_target = {cs.target_function: cs for cs in call_sites if cs.target_function}

    def arg_value(target_function: str, location: str) -> str | None:
        call = calls_by_target.get(target_function)
        if call is None:
            return None
        for arg in call.recovered_arguments:
            if arg.location == location:
                return arg.value
        return None

    # Each value below is independently verifiable against fixture.go's
    # real source: an exact integer literal, or the true character count
    # of a real string literal (the string leaf's length component).
    assert arg_value("main.fixtureArgInt", "register:rax") == "41"  # fixtureArgInt(41)
    assert arg_value("main.fixtureArgConstant", "register:rax") == "1"  # fixtureArgConstant(1)
    assert arg_value("main.fixtureOuter", "register:rax") == "5"  # fixtureOuter(5)

    # fixtureArgMulti(7, "seven", true): a=7 (rax), b.ptr/b.len (rbx/rcx,
    # len(“seven”)==5), c=true->1 (rdi) - a full 3-argument, 4-leaf
    # recovery, leaf-for-leaf against real optimized compiler output.
    assert arg_value("main.fixtureArgMulti", "register:rax") == "7"
    assert arg_value("main.fixtureArgMulti", "register:rcx") == "5"
    assert arg_value("main.fixtureArgMulti", "register:rdi") == "1"

    # String-argument leaf lengths, each independently verifiable against
    # the real literal in fixture.go.
    assert arg_value("main.fixtureStdlibCall", "register:rbx") == "14"  # len("gomemforensics")
    assert arg_value("main.fixtureHelperA", "register:rbx") == "7"  # len("fixture")

    # False-positive control (Phase 4.1's central correction), against
    # real compiled code: fixtureArgInt takes exactly ONE argument
    # (rax). Even if some other register happened to hold a live value
    # in the same backward window, it must never appear as a recovered
    # argument for this call, because the callee's own ArgInfo shape
    # declares only one leaf.
    fixture_arg_int_call = calls_by_target["main.fixtureArgInt"]
    assert len(fixture_arg_int_call.recovered_arguments) == 1
    assert fixture_arg_int_call.recovered_arguments[0].location == "register:rax"
    assert fixture_arg_int_call.argument_analysis_status.value == "supported"


def test_function_recovery_is_deterministic_across_runs():
    if not _WINDOWS_FIXTURE.exists():
        pytest.skip("Fixture binary not built - run scripts/fixtures/build_fixture.ps1 first.")

    names_per_run = []
    for _ in range(2):
        pe = pefile.PE(str(_WINDOWS_FIXTURE), fast_load=True)
        reader = _PEMappedReader(pe)
        regions = _build_regions(pe)
        result = GoProcessDetector().detect(pid=1, architecture="x86_64", pointer_size=8, reader=reader, regions=regions)
        functions, _errors = FunctionTableParser(reader, pointer_size=8).parse(result.runtime)
        names_per_run.append(sorted(f.name for f in functions if f.name))

    assert names_per_run[0] == names_per_run[1]
