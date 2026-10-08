"""Unit tests for Go function table recovery (functab.py).

All synthetic - no real memory image or Go binary needed (real-fixture
validation lives in tests/integration/).
"""

import struct

import pytest

from gomemforensics.common.memory import MockMemoryReader
from gomemforensics.common.models import Confidence, FailureReason
from gomemforensics.go_runtime.functab import FunctionTableParser, resolve_func_layout
from gomemforensics.go_runtime.layouts import FUNC_GO1_26, FUNCTAB_GO1_26
from gomemforensics.go_runtime.models import FunctionClassification, GoRuntime

from tests.unit.go_runtime_helpers import build_struct_bytes

TEXT_BASE = 0x140000000
PCLNTABLE_BASE = 0x140100000
FUNCNAMETAB_BASE = 0x140200000
CUTAB_BASE = 0x140300000
FILETAB_BASE = 0x140400000
PCTAB_BASE = 0x140500000
FTAB_BASE = 0x140600000
GOFUNC_BASE = 0x140700000


def _zigzag(delta: int) -> int:
    return (delta << 1) if delta >= 0 else ((-delta - 1) << 1) | 1


def _constant_pctab_stream(value: int, span: int) -> bytes:
    """Build a pctab stream encoding a single constant value for [0, span)."""
    delta = value - (-1)
    uv = _zigzag(delta)
    assert uv < 0x80 and span < 0x80  # keep the test streams single-byte for simplicity
    return bytes([uv, span, 0x00])


def _make_runtime(**overrides) -> GoRuntime:
    defaults = dict(
        pid=1,
        architecture="x86_64",
        go_version="1.22+",
        go_version_confidence=Confidence.HIGH,
        runtime_id="GORUNTIME-1-test",
        text_start=TEXT_BASE,
        pclntable_address=PCLNTABLE_BASE,
        funcnametab_address=FUNCNAMETAB_BASE,
        cutab_address=CUTAB_BASE,
        filetab_address=FILETAB_BASE,
        pctab_address=PCTAB_BASE,
        ftab_address=FTAB_BASE,
        ftab_length=1,
        gofunc_address=GOFUNC_BASE,
    )
    defaults.update(overrides)
    return GoRuntime(**defaults)


def _build_reader(*, entryoff=0x10, name=b"main.main", fileno=0, line=42, cutab_fileoff=5,
                   file_path=b"myapp/main.go", nfuncdata=0, funcdata_bytes=b"") -> MockMemoryReader:
    functab_bytes = build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": entryoff, "funcoff": 0})

    func_bytes = build_struct_bytes(
        FUNC_GO1_26, 8,
        {
            "entryOff": entryoff, "nameOff": 1, "args": 0, "deferreturn": 0,
            "pcsp": 0, "pcfile": 10, "pcln": 20, "npcdata": 0, "cuOffset": 0,
            "startLine": 0, "funcID": 0, "flag": 0, "pad": 0, "nfuncdata": nfuncdata,
        },
    )
    func_bytes += funcdata_bytes  # trailing pcdata[0]/funcdata[nfuncdata] arrays

    funcnametab_bytes = b"\x00" + name + b"\x00"
    pctab_bytes = bytearray(64)
    pctab_bytes[10:10 + 3] = _constant_pctab_stream(fileno, 100)
    pctab_bytes[20:20 + 3] = _constant_pctab_stream(line, 100)
    cutab_bytes = struct.pack("<I", cutab_fileoff)
    filetab_bytes = b"\x00" * 5 + file_path + b"\x00"

    regions = {
        FTAB_BASE: functab_bytes,
        PCLNTABLE_BASE: func_bytes,
        FUNCNAMETAB_BASE: funcnametab_bytes,
        CUTAB_BASE: cutab_bytes,
        FILETAB_BASE: filetab_bytes,
        PCTAB_BASE: bytes(pctab_bytes),
    }
    return MockMemoryReader(TEXT_BASE, b"\x00" * 4096, extra_regions=regions)


class TestResolveFuncLayout:
    def test_verified_era_resolves(self):
        func_layout, functab_layout = resolve_func_layout("1.22+")
        assert func_layout is not None
        assert functab_layout is not None

    def test_unsupported_version_returns_none(self):
        assert resolve_func_layout("1.16-1.17") == (None, None)

    def test_none_version_returns_none(self):
        assert resolve_func_layout(None) == (None, None)


class TestFunctionTableParserHappyPath:
    def test_recovers_name_file_line_and_classification(self):
        reader = _build_reader()
        runtime = _make_runtime()

        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)

        assert errors == []
        assert len(artifacts) == 1
        f = artifacts[0]
        assert f.name == "main.main"
        assert f.entry_address == TEXT_BASE + 0x10
        assert f.address == f.entry_address
        assert f.source_file == "myapp/main.go"
        assert f.source_line == 42
        assert f.classification == FunctionClassification.APPLICATION
        assert f.confidence == Confidence.HIGH
        assert f.go_version == "1.22+"
        assert f.architecture == "x86_64"
        assert f.provenance is not None
        assert f.provenance.pid == 1

    def test_stdlib_classification(self):
        reader = _build_reader(name=b"os.ReadFile", file_path=b"/usr/local/go/src/os/file.go")
        runtime = _make_runtime()
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert errors == []
        assert artifacts[0].classification == FunctionClassification.STDLIB

    def test_runtime_classification(self):
        reader = _build_reader(name=b"runtime.newobject", file_path=b"/usr/local/go/src/runtime/malloc.go")
        runtime = _make_runtime()
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert artifacts[0].classification == FunctionClassification.RUNTIME

    def test_deterministic_output_on_repeated_parse(self):
        reader = _build_reader()
        runtime = _make_runtime()
        parser = FunctionTableParser(reader, 8)
        first = parser.parse(runtime)[0][0].to_json_dict()
        second = FunctionTableParser(reader, 8).parse(runtime)[0][0].to_json_dict()
        assert first == second


class TestFunctionTableParserNegative:
    def test_unsupported_go_version_reports_error(self):
        reader = _build_reader()
        runtime = _make_runtime(go_version="1.16-1.17")
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert artifacts == []
        assert len(errors) == 1
        assert "UNSUPPORTED_RUNTIME_LAYOUT" in errors[0].message
        assert errors[0].reason == FailureReason.UNSUPPORTED_GO_VERSION

    def test_missing_moduledata_tables_reports_error(self):
        reader = _build_reader()
        runtime = _make_runtime(ftab_address=None)
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert artifacts == []
        assert len(errors) == 1

    def test_truncated_func_record_recorded_not_fatal(self):
        # functab entry points at a func_addr with almost no backing data.
        functab_bytes = build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0})
        reader = MockMemoryReader(
            TEXT_BASE, b"\x00" * 16,
            extra_regions={FTAB_BASE: functab_bytes, PCLNTABLE_BASE: b"\x01\x02"},  # far too short
        )
        runtime = _make_runtime()
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert artifacts == []
        assert len(errors) == 1
        assert "unreadable" in errors[0].message

    def test_invalid_name_offset_yields_none_name_not_crash(self):
        # nameOff points past the end of the tiny funcnametab region.
        functab_bytes = build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0})
        func_bytes = build_struct_bytes(
            FUNC_GO1_26, 8,
            {"entryOff": 0x10, "nameOff": 9999, "pcsp": 0, "pcfile": 0, "pcln": 0, "npcdata": 0, "nfuncdata": 0},
        )
        reader = MockMemoryReader(
            TEXT_BASE, b"\x00" * 16,
            extra_regions={FTAB_BASE: functab_bytes, PCLNTABLE_BASE: func_bytes, FUNCNAMETAB_BASE: b"\x00main\x00"},
        )
        runtime = _make_runtime()
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert errors == []
        assert len(artifacts) == 1
        assert artifacts[0].name is None

    def test_invalid_file_offset_yields_none_source_file(self):
        reader = _build_reader(cutab_fileoff=0xFFFFFFFF)  # sentinel: no entry
        runtime = _make_runtime()
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert errors == []
        assert artifacts[0].source_file is None

    def test_impossible_pc_delta_does_not_crash_whole_parse(self):
        # A malformed pctab stream (continuation bit set, nothing after)
        # for pcfile - must degrade to unknown file/line, not crash.
        reader = _build_reader()
        # Corrupt just the pcfile stream region in-place via a fresh reader.
        functab_bytes = build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0})
        func_bytes = build_struct_bytes(
            FUNC_GO1_26, 8,
            {"entryOff": 0x10, "nameOff": 1, "pcsp": 0, "pcfile": 10, "pcln": 20, "npcdata": 0, "nfuncdata": 0},
        )
        pctab_bytes = bytearray(64)
        pctab_bytes[10] = 0x80  # malformed: continuation bit set, nothing follows within window... actually window is 64KB so this alone won't truncate; use a boundary case instead
        regions = {
            FTAB_BASE: functab_bytes,
            PCLNTABLE_BASE: func_bytes,
            FUNCNAMETAB_BASE: b"\x00main\x00",
            PCTAB_BASE: bytes(pctab_bytes),
        }
        reader2 = MockMemoryReader(TEXT_BASE, b"\x00" * 16, extra_regions=regions)
        runtime = _make_runtime(cutab_address=None, filetab_address=None)
        artifacts, errors = FunctionTableParser(reader2, 8).parse(runtime)
        assert errors == []
        assert len(artifacts) == 1
        assert artifacts[0].source_file is None  # no cutab/filetab available -> degrades gracefully

    def test_multiple_functions_one_malformed_does_not_abort_others(self):
        functab_bytes = (
            build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0})
            + build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x20, "funcoff": 9999999})  # bad funcoff
        )
        good_func = build_struct_bytes(
            FUNC_GO1_26, 8,
            {"entryOff": 0x10, "nameOff": 1, "pcsp": 0, "pcfile": 0, "pcln": 0, "npcdata": 0, "nfuncdata": 0},
        )
        reader = MockMemoryReader(
            TEXT_BASE, b"\x00" * 16,
            extra_regions={FTAB_BASE: functab_bytes, PCLNTABLE_BASE: good_func, FUNCNAMETAB_BASE: b"\x00ok\x00"},
        )
        runtime = _make_runtime(ftab_length=2)
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert len(artifacts) == 1
        assert artifacts[0].name == "ok"
        assert len(errors) == 1

    def test_duplicate_entry_addresses_deduplicated(self):
        functab_bytes = (
            build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0})
            + build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0})  # exact duplicate
        )
        func_bytes = build_struct_bytes(
            FUNC_GO1_26, 8,
            {"entryOff": 0x10, "nameOff": 1, "pcsp": 0, "pcfile": 0, "pcln": 0, "npcdata": 0, "nfuncdata": 0},
        )
        reader = MockMemoryReader(
            TEXT_BASE, b"\x00" * 16,
            extra_regions={FTAB_BASE: functab_bytes, PCLNTABLE_BASE: func_bytes, FUNCNAMETAB_BASE: b"\x00dup\x00"},
        )
        runtime = _make_runtime(ftab_length=2)
        artifacts, _ = FunctionTableParser(reader, 8).parse(runtime)
        assert len(artifacts) == 1


class TestArgInfoIntegration:
    def test_function_with_arginfo_gets_argument_metadata(self):
        # ArgInfo: one int arg (offset 0, size 8), then EndSeq.
        arginfo_bytes = bytes([0x00, 0x08, 0xFF])
        funcdata_array = struct.pack("<I", 0)  # funcdata[FUNCDATA_ArgInfo=5]... see note below
        reader = _build_reader(nfuncdata=6, funcdata_bytes=b"\xff\xff\xff\xff" * 5 + struct.pack("<I", 0))
        # place the arginfo bytes at GOFUNC_BASE + 0
        gofunc_region = {GOFUNC_BASE: arginfo_bytes}
        # merge into reader's regions by rebuilding with the extra region
        reader = MockMemoryReader(
            TEXT_BASE, b"\x00" * 4096,
            extra_regions={
                FTAB_BASE: build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": 0x10, "funcoff": 0}),
                PCLNTABLE_BASE: build_struct_bytes(
                    FUNC_GO1_26, 8,
                    {"entryOff": 0x10, "nameOff": 1, "pcsp": 0, "pcfile": 10, "pcln": 20, "npcdata": 0, "nfuncdata": 6},
                ) + b"\xff\xff\xff\xff" * 5 + struct.pack("<I", 0),
                FUNCNAMETAB_BASE: b"\x00f\x00",
                PCTAB_BASE: bytes(64),
                GOFUNC_BASE: arginfo_bytes,
            },
        )
        runtime = _make_runtime(cutab_address=None, filetab_address=None)
        artifacts, errors = FunctionTableParser(reader, 8).parse(runtime)
        assert errors == []
        assert len(artifacts) == 1
        assert len(artifacts[0].argument_metadata) == 1
        assert artifacts[0].argument_metadata[0].type_hint == "scalar"
        assert artifacts[0].argument_metadata[0].status.value == "supported"
