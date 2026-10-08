"""Unit tests for AnalysisResult JSON assembly (no real Volatility calls)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from gomemforensics.acquisition.evidence import EvidenceMetadata
from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.common.models import AnalysisError, AnalysisStatistics, Confidence, FailureReason, ProcessInfo
from gomemforensics.analyzers.models import NetworkArtifact, NetworkArtifactType, NetworkValidationStatus
from gomemforensics.go_runtime.models import FunctionArtifact, FunctionClassification, GoRuntime, StringArtifact
from gomemforensics.pipeline import (
    AnalysisResult,
    _recover_correlations,
    _recover_credential_artifacts,
    _recover_crypto_artifacts,
    _recover_findings,
    _recover_functions,
    _recover_goroutines,
    _recover_iocs,
    _recover_network_artifacts,
    _recover_persistence_artifacts,
    has_fatal_error,
)
from tests.unit.go_runtime_helpers import build_struct_bytes
from gomemforensics.go_runtime.layouts import FUNC_FLAG_TOP_FRAME, FUNC_GO1_26, FUNCTAB_GO1_26, G_GO1_26, G_STATUS_RUNNING


def _sample_evidence() -> EvidenceMetadata:
    return EvidenceMetadata(
        case_id="CASE-1",
        input_path=Path("/tmp/sample.raw"),
        file_name="sample.raw",
        file_size=1024,
        sha256="a" * 64,
        hash_algorithm="SHA-256",
        analysis_timestamp="2026-01-01T00:00:00.000Z",
        read_only=True,
    )


def _sample_result(**overrides) -> AnalysisResult:
    defaults = dict(
        case_id="CASE-1",
        evidence=_sample_evidence(),
        environment={"tool_version": "0.1.0"},
        os="linux",
        architecture="x86_64",
        processes=[
            ProcessInfo(
                pid=2,
                ppid=1,
                name="init",
                executable_path=None,
                architecture="x86_64",
                os="linux",
                create_time=None,
                memory_layer_available=True,
            ),
            ProcessInfo(
                pid=1,
                ppid=0,
                name="systemd",
                executable_path="/sbin/init",
                architecture="x86_64",
                os="linux",
                create_time="2026-01-01T00:00:00",
                memory_layer_available=True,
            ),
        ],
        errors=[],
        statistics=AnalysisStatistics(processes_discovered=2, processes_with_memory_access=2),
    )
    defaults.update(overrides)
    return AnalysisResult(**defaults)


def test_to_json_dict_top_level_shape():
    result = _sample_result()
    data = result.to_json_dict()

    assert set(data.keys()) == {
        "case",
        "evidence",
        "environment",
        "system",
        "processes",
        "go_runtimes",
        "go_candidates",
        "strings",
        "functions",
        "goroutines",
        "network_artifacts",
        "credential_artifacts",
        "crypto_artifacts",
        "persistence_artifacts",
        "iocs",
        "correlations",
        "findings",
        "errors",
        "statistics",
    }
    assert data["go_runtimes"] == []
    assert data["go_candidates"] == []
    assert data["strings"] == []
    assert data["case"] == {"case_id": "CASE-1"}
    assert data["system"] == {"os": "linux", "architecture": "x86_64"}
    assert data["evidence"]["sha256"] == "a" * 64
    assert data["evidence"]["input_path"] == str(Path("/tmp/sample.raw"))


def test_to_json_dict_is_json_serializable():
    result = _sample_result()
    # Must not raise - Confidence enum members must serialize as plain strings.
    serialized = json.dumps(result.to_json_dict())
    assert '"unknown"' in serialized  # go_confidence default


def test_write_json_creates_parent_directories_and_valid_json(tmp_path):
    result = _sample_result()
    output_path = tmp_path / "nested" / "analysis.json"

    result.write_json(output_path)

    assert output_path.exists()
    with output_path.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    assert loaded["case"]["case_id"] == "CASE-1"
    assert len(loaded["processes"]) == 2


def test_has_fatal_error_false_when_all_recoverable():
    result = _sample_result(
        errors=[AnalysisError(component="x", message="minor", recoverable=True)]
    )
    assert has_fatal_error(result) is False


def test_has_fatal_error_true_when_any_non_recoverable():
    result = _sample_result(
        errors=[AnalysisError(component="volatility.integration.initialize", message="boom", recoverable=False)]
    )
    assert has_fatal_error(result) is True


def test_process_info_default_go_fields_are_inert():
    process = ProcessInfo(
        pid=1, ppid=None, name=None, executable_path=None,
        architecture="unknown", os="unknown", create_time=None,
        memory_layer_available=False,
    )
    assert process.is_go_candidate is False
    assert process.go_confidence == Confidence.UNKNOWN


# --- _recover_functions (Phase 4: function table + call-site pipeline glue) -

_TEXT_BASE = 0x140000000
_PCLNTABLE_BASE = 0x140100000
_FUNCNAMETAB_BASE = 0x140200000
_FTAB_BASE = 0x140300000
_ENTRY_OFF = 0x10

# mov rax, 0x2a (7 bytes) ; call rel32 -> entry+0x117 (5 bytes) - both
# encodings hand-verified against Capstone disassembly (see
# tests/unit/test_backward_analysis.py's verification notes) before use.
_CALL_TARGET = _TEXT_BASE + _ENTRY_OFF + 7 + 5 + 0x100
_CODE_AT_ENTRY = bytes([0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x01, 0x00, 0x00])


def _function_recovery_reader() -> MockMemoryReader:
    text_bytes = bytearray(4096)
    text_bytes[_ENTRY_OFF : _ENTRY_OFF + len(_CODE_AT_ENTRY)] = _CODE_AT_ENTRY

    functab_bytes = build_struct_bytes(FUNCTAB_GO1_26, 8, {"entryoff": _ENTRY_OFF, "funcoff": 0})
    func_bytes = build_struct_bytes(
        FUNC_GO1_26, 8,
        {
            "entryOff": _ENTRY_OFF, "nameOff": 1, "args": 0, "deferreturn": 0,
            "pcsp": 0, "pcfile": 0, "pcln": 0, "npcdata": 0, "cuOffset": 0,
            "startLine": 0, "funcID": 0, "flag": 0, "pad": 0, "nfuncdata": 0,
        },
    )
    funcnametab_bytes = b"\x00main.f\x00"

    return MockMemoryReader(
        _TEXT_BASE,
        bytes(text_bytes),
        extra_regions={
            _PCLNTABLE_BASE: func_bytes,
            _FUNCNAMETAB_BASE: funcnametab_bytes,
            _FTAB_BASE: functab_bytes,
        },
    )


def _function_recovery_runtime(**overrides) -> GoRuntime:
    defaults = dict(
        pid=1,
        architecture="x86_64",
        go_version="1.22+",
        go_version_confidence=Confidence.HIGH,
        runtime_id="GORUNTIME-1-test",
        text_start=_TEXT_BASE,
        pclntable_address=_PCLNTABLE_BASE,
        funcnametab_address=_FUNCNAMETAB_BASE,
        cutab_address=None,
        filetab_address=None,
        pctab_address=None,
        ftab_address=_FTAB_BASE,
        ftab_length=1,
        gofunc_address=None,
    )
    defaults.update(overrides)
    return GoRuntime(**defaults)


class TestRecoverFunctions:
    def test_recovers_function_and_call_site_for_x86_64_register_abi(self):
        # The call target here (_CALL_TARGET) is an external address with
        # no recovered ArgInfo shape - per the Phase 4.1 correction,
        # argument recovery must NOT guess an argument from whatever
        # register happens to hold a value in that case, even though rax
        # genuinely does hold 42 right before the call. See
        # test_end_to_end_argument_recovery_uses_callees_own_arginfo_shape
        # below for the positive case, where the callee's real shape IS
        # known.
        reader = _function_recovery_reader()
        runtime = _function_recovery_runtime()

        functions, errors = _recover_functions(reader, 8, runtime, [], pid=1)

        assert errors == []
        assert len(functions) == 1
        func = functions[0]
        assert func.name == "main.f"
        assert len(func.recovered_call_sites) == 1
        call_site = func.recovered_call_sites[0]
        assert call_site.target_address == _CALL_TARGET
        assert call_site.recovered_arguments == []
        assert call_site.argument_analysis_status.value == "unsupported"

    def test_end_to_end_argument_recovery_uses_callees_own_arginfo_shape(self):
        """Phase 4.1: exercises the full production wiring -
        FunctionTableParser decodes the callee's real ArgInfo funcdata,
        ABI-maps it to an ArgumentLocation, pipeline._recover_functions
        builds known_function_argument_locations from it, and
        backward_analysis consumes exactly that (and only that) location
        when analyzing the caller's real CALL instruction to it.
        """
        callee_entry_off = 0x30
        callee_entry_pc = _TEXT_BASE + callee_entry_off
        call_insn_addr = _TEXT_BASE + _ENTRY_OFF + 7  # right after the 7-byte `mov rax, 0x2a`
        call_disp = callee_entry_pc - (call_insn_addr + 5)
        code_at_entry = bytes([0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, 0xE8]) + struct.pack("<i", call_disp)

        text_bytes = bytearray(4096)
        text_bytes[_ENTRY_OFF : _ENTRY_OFF + len(code_at_entry)] = code_at_entry

        caller_func_bytes = build_struct_bytes(
            FUNC_GO1_26, 8,
            {
                "entryOff": _ENTRY_OFF, "nameOff": 1, "args": 0, "deferreturn": 0,
                "pcsp": 0, "pcfile": 0, "pcln": 0, "npcdata": 0, "cuOffset": 0,
                "startLine": 0, "funcID": 0, "flag": 0, "pad": 0, "nfuncdata": 0,
            },
        )
        callee_funcoff = len(caller_func_bytes)
        # ArgInfo: one int arg (leaf offset=0, size=8), then EndSeq -
        # matches `func g(n int)`. funcdata[5] (FUNCDATA_ArgInfo) points
        # to offset 0 of the gofunc region below.
        arginfo_bytes = bytes([0x00, 0x08, 0xFF])
        callee_func_bytes = build_struct_bytes(
            FUNC_GO1_26, 8,
            {
                "entryOff": callee_entry_off, "nameOff": 8, "args": 0, "deferreturn": 0,
                "pcsp": 0, "pcfile": 0, "pcln": 0, "npcdata": 0, "cuOffset": 0,
                "startLine": 0, "funcID": 0, "flag": 0, "pad": 0, "nfuncdata": 6,
            },
        ) + b"\xff\xff\xff\xff" * 5 + struct.pack("<I", 0)  # funcdata[5]=0 -> ArgInfo at gofunc+0

        functab_bytes = build_struct_bytes(
            FUNCTAB_GO1_26, 8, {"entryoff": _ENTRY_OFF, "funcoff": 0}
        ) + build_struct_bytes(
            FUNCTAB_GO1_26, 8, {"entryoff": callee_entry_off, "funcoff": callee_funcoff}
        )
        funcnametab_bytes = b"\x00main.f\x00main.g\x00"  # f at offset 1, g at offset 8
        gofunc_base = 0x140800000

        reader = MockMemoryReader(
            _TEXT_BASE,
            bytes(text_bytes),
            extra_regions={
                _PCLNTABLE_BASE: caller_func_bytes + callee_func_bytes,
                _FUNCNAMETAB_BASE: funcnametab_bytes,
                _FTAB_BASE: functab_bytes,
                gofunc_base: arginfo_bytes,
            },
        )
        runtime = _function_recovery_runtime(ftab_length=2, gofunc_address=gofunc_base)

        functions, errors = _recover_functions(reader, 8, runtime, [], pid=1)

        assert errors == []
        by_name = {f.name: f for f in functions}
        callee_locations = by_name["main.g"].argument_locations
        assert callee_locations is not None
        assert len(callee_locations) == 1
        assert callee_locations[0].abi_location == "register:rax"

        caller = by_name["main.f"]
        assert len(caller.recovered_call_sites) == 1
        call_site = caller.recovered_call_sites[0]
        assert call_site.target_function == "main.g"
        assert call_site.argument_analysis_status.value == "supported"
        assert len(call_site.recovered_arguments) == 1
        arg = call_site.recovered_arguments[0]
        assert arg.location == "register:rax"
        assert arg.value == "42"
        assert arg.index == 0
        assert arg.leaf_index == 0

    def test_skips_call_site_analysis_cleanly_for_non_x86_64(self):
        reader = _function_recovery_reader()
        runtime = _function_recovery_runtime(architecture="arm64")

        functions, errors = _recover_functions(reader, 8, runtime, [], pid=1)

        assert errors == []
        assert len(functions) == 1
        assert functions[0].recovered_call_sites == []

    def test_no_functions_recovered_returns_empty_with_no_crash(self):
        reader = _function_recovery_reader()
        runtime = _function_recovery_runtime(go_version="1.16-1.17")  # unsupported layout era

        functions, errors = _recover_functions(reader, 8, runtime, [], pid=1)

        assert functions == []
        assert len(errors) == 1
        assert "UNSUPPORTED_RUNTIME_LAYOUT" in errors[0].message
        assert errors[0].reason == FailureReason.UNSUPPORTED_GO_VERSION


# --- _recover_goroutines (Phase 5: goroutine discovery + unwinding glue) ---

_G_STACK_LO = 0xC000010000
_G_STACK_HI = 0xC000018000
_G_ADDR = 0xC000020000
_ALLGS_ARRAY = 0xC000030000
_ALLGS_HEADER = 0xC000040000


def _goroutine_pipeline_function(entry_pc: int, name: str = "main.f") -> FunctionArtifact:
    return FunctionArtifact(
        id=f"FUNC-1-{entry_pc:x}", pid=1, address=entry_pc, entry_address=entry_pc,
        name=name, package="main", source_file="main.go", source_line=1, function_size=None,
        classification=FunctionClassification.APPLICATION, confidence=Confidence.HIGH,
        extraction_method="test", go_version="1.22+", architecture="x86_64",
        func_id=0, func_flag=FUNC_FLAG_TOP_FRAME, pcsp_offset=None,
    )


def _goroutine_pipeline_reader(sched_pc: int) -> MockMemoryReader:
    g_bytes = build_struct_bytes(G_GO1_26, 8, {
        "stack_lo": _G_STACK_LO, "stack_hi": _G_STACK_HI,
        "sched_sp": _G_STACK_HI - 0x100, "sched_pc": sched_pc,
        "atomicstatus": G_STATUS_RUNNING, "goid": 7,
    })
    allgs_array_bytes = struct.pack("<Q", _G_ADDR)
    allgs_header_bytes = struct.pack("<QQQ", _ALLGS_ARRAY, 1, 1)
    return MockMemoryReader(
        0x1000, b"\x00" * 16,
        extra_regions={_G_ADDR: g_bytes, _ALLGS_ARRAY: allgs_array_bytes, _ALLGS_HEADER: allgs_header_bytes},
    )


def _goroutine_pipeline_regions() -> list[MemoryRegion]:
    return [MemoryRegion(start=_ALLGS_HEADER, end=_ALLGS_HEADER + 4096, readable=True, writable=True, executable=False, source="test")]


class TestRecoverGoroutines:
    def test_recovers_and_unwinds_goroutine_on_x86_64(self):
        entry_pc = 0x140001000
        fn = _goroutine_pipeline_function(entry_pc)
        runtime = _function_recovery_runtime(pctab_address=0x140500000)  # TopFrame func needs no real pcsp stream
        reader = _goroutine_pipeline_reader(sched_pc=entry_pc)
        regions = _goroutine_pipeline_regions()

        goroutines, errors, stats = _recover_goroutines(reader, 8, runtime, [fn], regions, pid=1)

        assert errors == []
        assert len(goroutines) == 1
        g = goroutines[0]
        assert g.goid == 7
        assert g.unwind_status.value == "complete"
        assert len(g.frames) == 1
        assert g.frames[0].function_name == "main.f"
        assert stats.valid_goroutines == 1

    def test_skips_unwinding_cleanly_for_non_x86_64(self):
        entry_pc = 0x140001000
        fn = _goroutine_pipeline_function(entry_pc)
        runtime = _function_recovery_runtime(architecture="arm64", pctab_address=0x140500000)
        reader = _goroutine_pipeline_reader(sched_pc=entry_pc)
        regions = _goroutine_pipeline_regions()

        goroutines, errors, stats = _recover_goroutines(reader, 8, runtime, [fn], regions, pid=1)

        assert len(goroutines) == 1
        assert goroutines[0].unwind_status.value == "not_attempted"
        assert goroutines[0].frames == []
        assert any("Stack unwinding skipped" in e.message for e in errors)
        assert any(e.reason == FailureReason.UNSUPPORTED_ARCHITECTURE for e in errors)

    def test_skips_unwinding_cleanly_when_pctab_address_unavailable(self):
        entry_pc = 0x140001000
        fn = _goroutine_pipeline_function(entry_pc)
        runtime = _function_recovery_runtime(pctab_address=None)
        reader = _goroutine_pipeline_reader(sched_pc=entry_pc)
        regions = _goroutine_pipeline_regions()

        goroutines, errors, stats = _recover_goroutines(reader, 8, runtime, [fn], regions, pid=1)

        assert len(goroutines) == 1
        assert goroutines[0].unwind_status.value == "not_attempted"
        assert any(e.reason == FailureReason.STACK_UNAVAILABLE for e in errors)

    def test_no_goroutines_found_returns_empty_with_no_crash(self):
        runtime = _function_recovery_runtime()
        reader = MockMemoryReader(0x1000, b"\x00" * 16)
        goroutines, errors, stats = _recover_goroutines(reader, 8, runtime, [], [], pid=1)

        assert goroutines == []
        assert stats.valid_goroutines == 0
        assert any("no structurally valid runtime.allgs candidate" in e.message for e in errors)
        assert any(e.reason == FailureReason.ALLGS_NOT_FOUND for e in errors)


# --- _recover_network_artifacts (Phase 6A: pipeline-level glue) ---


class TestRecoverNetworkArtifacts:
    def test_extracts_artifacts_from_process_strings(self):
        strings = [
            StringArtifact(
                id="STR-1-0001",
                pid=1,
                string_address=0x500000,
                data_address=0x500000,
                length=7,
                value="8.8.8.8",
                region="static",
                extraction_method="static_section_scan",
                confidence=Confidence.HIGH,
                is_utf8=True,
                printable_ratio=1.0,
            )
        ]
        artifacts, errors, stats = _recover_network_artifacts(1, "proc.exe", "1.26.2", "x86_64", strings, [], [])
        assert len(artifacts) == 1
        assert artifacts[0].raw_value == "8.8.8.8"
        assert errors == []
        assert stats.artifacts_extracted == 1

    def test_no_strings_returns_empty_with_no_crash(self):
        artifacts, errors, stats = _recover_network_artifacts(1, None, None, "x86_64", [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_unexpected_failure_is_caught_and_recorded(self):
        class _BrokenString:
            pid = 1

            @property
            def value(self):
                raise RuntimeError("simulated corruption")

        artifacts, errors, stats = _recover_network_artifacts(
            1, None, None, "x86_64", [_BrokenString()], [], []
        )
        assert artifacts == []
        assert len(errors) == 1
        assert errors[0].component == "analyzers.network"
        assert errors[0].reason == FailureReason.INTERNAL_ERROR
        assert errors[0].recoverable is True


# --- _recover_credential_artifacts (Phase 6B: pipeline-level glue) ---


class TestRecoverCredentialArtifacts:
    def test_extracts_artifacts_from_process_strings(self):
        strings = [
            StringArtifact(
                id="STR-1-0001",
                pid=1,
                string_address=0x500000,
                data_address=0x500000,
                length=len("password=hunter2Q!"),
                value="password=hunter2Q!",
                region="static",
                extraction_method="static_section_scan",
                confidence=Confidence.HIGH,
                is_utf8=True,
                printable_ratio=1.0,
            )
        ]
        artifacts, errors, stats = _recover_credential_artifacts(
            1, "proc.exe", "1.26.2", "x86_64", strings, [], [], []
        )
        assert len(artifacts) == 1
        assert artifacts[0].raw_value == "password=hunter2Q!"
        assert errors == []
        assert stats.artifacts_extracted == 1

    def test_no_strings_returns_empty_with_no_crash(self):
        artifacts, errors, stats = _recover_credential_artifacts(1, None, None, "x86_64", [], [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_unexpected_failure_is_caught_and_recorded(self):
        class _BrokenString:
            pid = 1

            @property
            def value(self):
                raise RuntimeError("simulated corruption")

        artifacts, errors, stats = _recover_credential_artifacts(
            1, None, None, "x86_64", [_BrokenString()], [], [], []
        )
        assert artifacts == []
        assert len(errors) == 1
        assert errors[0].component == "analyzers.credentials"
        assert errors[0].reason == FailureReason.INTERNAL_ERROR
        assert errors[0].recoverable is True


# --- _recover_crypto_artifacts (Phase 6C: pipeline-level glue) ---


class TestRecoverCryptoArtifacts:
    def test_extracts_artifacts_from_process_strings(self):
        strings = [
            StringArtifact(
                id="STR-1-0001",
                pid=1,
                string_address=0x500000,
                data_address=0x500000,
                length=len("Ed25519"),
                value="Ed25519",
                region="static",
                extraction_method="static_section_scan",
                confidence=Confidence.HIGH,
                is_utf8=True,
                printable_ratio=1.0,
            )
        ]
        artifacts, errors, stats = _recover_crypto_artifacts(
            1, "proc.exe", "1.26.2", "x86_64", strings, [], [], [], []
        )
        assert len(artifacts) == 1
        assert artifacts[0].raw_value == "Ed25519"
        assert errors == []
        assert stats.artifacts_extracted == 1

    def test_no_strings_returns_empty_with_no_crash(self):
        artifacts, errors, stats = _recover_crypto_artifacts(1, None, None, "x86_64", [], [], [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_unexpected_failure_is_caught_and_recorded(self):
        class _BrokenString:
            pid = 1

            @property
            def value(self):
                raise RuntimeError("simulated corruption")

        artifacts, errors, stats = _recover_crypto_artifacts(
            1, None, None, "x86_64", [_BrokenString()], [], [], [], []
        )
        assert artifacts == []
        assert len(errors) == 1
        assert errors[0].component == "analyzers.crypto"
        assert errors[0].reason == FailureReason.INTERNAL_ERROR
        assert errors[0].recoverable is True


# --- _recover_persistence_artifacts (Phase 6D: pipeline-level glue) ---


class TestRecoverPersistenceArtifacts:
    def test_extracts_artifacts_from_process_strings(self):
        strings = [
            StringArtifact(
                id="STR-1-0001",
                pid=1,
                string_address=0x500000,
                data_address=0x500000,
                length=len("/etc/rc.local"),
                value="/etc/rc.local",
                region="static",
                extraction_method="static_section_scan",
                confidence=Confidence.HIGH,
                is_utf8=True,
                printable_ratio=1.0,
            )
        ]
        artifacts, errors, stats = _recover_persistence_artifacts(
            1, "proc.exe", "1.26.2", "x86_64", strings, [], [], [], [], []
        )
        assert len(artifacts) == 1
        assert artifacts[0].raw_value == "/etc/rc.local"
        assert errors == []
        assert stats.artifacts_extracted == 1

    def test_no_strings_returns_empty_with_no_crash(self):
        artifacts, errors, stats = _recover_persistence_artifacts(1, None, None, "x86_64", [], [], [], [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_unexpected_failure_is_caught_and_recorded(self):
        class _BrokenString:
            pid = 1

            @property
            def value(self):
                raise RuntimeError("simulated corruption")

        artifacts, errors, stats = _recover_persistence_artifacts(
            1, None, None, "x86_64", [_BrokenString()], [], [], [], [], []
        )
        assert artifacts == []
        assert len(errors) == 1
        assert errors[0].component == "analyzers.persistence"
        assert errors[0].reason == FailureReason.INTERNAL_ERROR
        assert errors[0].recoverable is True


# --- _recover_iocs / _recover_correlations (Phase 6E: pipeline-level glue) ---


def _pipeline_network_artifact():
    return NetworkArtifact(
        id="NET-1-0001",
        pid=1,
        process_name=None,
        artifact_type=NetworkArtifactType.IPV4,
        raw_value="8.8.8.8",
        normalized_value={"ip": "8.8.8.8", "is_private": False},
        address=0x600000,
        length=7,
        memory_region="static",
        source_artifact_id="STR-1-0001",
        function_id=None,
        goroutine_id=None,
        extraction_method="go_string_network_classification",
        confidence=Confidence.MEDIUM,
        validation_status=NetworkValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


class TestRecoverIocs:
    def test_extracts_iocs_from_network_artifacts(self):
        net = _pipeline_network_artifact()
        iocs, errors, stats = _recover_iocs(1, "proc.exe", [net], [], [], [])
        assert len(iocs) == 1
        assert iocs[0].raw_value == "8.8.8.8"
        assert errors == []
        assert stats.iocs_extracted == 1

    def test_no_artifacts_returns_empty_with_no_crash(self):
        iocs, errors, stats = _recover_iocs(1, None, [], [], [], [])
        assert iocs == []
        assert errors == []
        assert stats.iocs_extracted == 0

    def test_unexpected_failure_is_caught_and_recorded(self):
        # None (rather than a list) breaks iteration outside any inner
        # per-candidate try/except, exercising _recover_iocs's own
        # top-level exception handler specifically.
        artifacts, errors, stats = _recover_iocs(1, None, None, [], [], [])
        assert artifacts == []
        assert len(errors) == 1
        assert errors[0].component == "analyzers.correlation"
        assert errors[0].reason == FailureReason.INTERNAL_ERROR
        assert errors[0].recoverable is True


class TestRecoverCorrelations:
    def test_emits_string_to_network_edge(self):
        net = _pipeline_network_artifact()
        records, errors, stats = _recover_correlations(1, [], [], [net], [], [], [])
        assert len(records) == 1
        assert errors == []
        assert stats.relationships_emitted == 1

    def test_no_artifacts_returns_empty_with_no_crash(self):
        records, errors, stats = _recover_correlations(1, [], [], [], [], [], [])
        assert records == []
        assert errors == []
        assert stats.relationships_emitted == 0


# --- _recover_findings (Phase 6F: pipeline-level glue) ---


class TestRecoverFindings:
    def test_generates_finding_from_ioc(self):
        net = _pipeline_network_artifact()
        iocs, _errors, _stats = _recover_iocs(1, "proc.exe", [net], [], [], [])
        findings, errors, stats = _recover_findings(1, "proc.exe", iocs, [])
        assert len(findings) == 1
        assert errors == []
        assert stats.findings_generated == 1

    def test_no_iocs_returns_empty_with_no_crash(self):
        findings, errors, stats = _recover_findings(1, None, [], [])
        assert findings == []
        assert errors == []
        assert stats.findings_generated == 0

    def test_unexpected_failure_is_caught_and_recorded(self):
        # None (rather than a list) breaks iteration outside any inner
        # per-candidate try/except, exercising _recover_findings's own
        # top-level exception handler specifically.
        findings, errors, stats = _recover_findings(1, None, None, [])
        assert findings == []
        assert len(errors) == 1
        assert errors[0].component == "analyzers.findings"
        assert errors[0].reason == FailureReason.INTERNAL_ERROR
        assert errors[0].recoverable is True
