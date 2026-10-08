"""Tests for :func:`gomemforensics.analyzers.network.extract_network_artifacts`.

All fixtures here are hand-built dataclass instances (SYNTHETIC) - the
analyzer under test consumes already-recovered
StringArtifact/FunctionArtifact/GoroutineArtifact objects directly, with
no MemoryReader involved, so no memory-reading fixture is needed to
exercise its logic.
"""

from __future__ import annotations

from itertools import count

from gomemforensics.analyzers.models import NetworkArtifactType, NetworkValidationStatus
from gomemforensics.analyzers.network import (
    MAX_ARTIFACTS_PER_PROCESS,
    MAX_STRING_VALUE_LENGTH,
    extract_network_artifacts,
)
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.models import (
    ArgumentArtifact,
    ArgumentRecoveryStatus,
    CallSiteArtifact,
    FunctionArtifact,
    FunctionClassification,
    GoroutineArtifact,
    GoroutineFrame,
    StringArtifact,
    UnwindStatus,
)

_id_counter = count(1)


def _string(pid=1, value="example.com", address=None, region="static", string_id=None):
    n = next(_id_counter)
    addr = address if address is not None else 0x500000 + n * 0x10
    return StringArtifact(
        id=string_id or f"STR-{pid}-{n:04d}",
        pid=pid,
        string_address=addr,
        data_address=addr,
        length=len(value),
        value=value,
        region=region,
        extraction_method="static_section_scan",
        confidence=Confidence.HIGH,
        is_utf8=True,
        printable_ratio=1.0,
    )


def _function(pid=1, func_id="FUNC-1-abc", name="main.connect", call_sites=None):
    return FunctionArtifact(
        id=func_id,
        pid=pid,
        address=0x140001000,
        entry_address=0x140001000,
        name=name,
        package="main",
        source_file="main.go",
        source_line=10,
        function_size=64,
        classification=FunctionClassification.APPLICATION,
        confidence=Confidence.HIGH,
        extraction_method="functab",
        go_version="1.26.2",
        architecture="x86_64",
        recovered_call_sites=call_sites or [],
    )


def _string_ref_call_site(pid, string_id):
    argument = ArgumentArtifact(
        index=0,
        type_hint="string",
        value=f"string_ref:{string_id}",
        location="register:rdi",
        confidence=Confidence.MEDIUM,
        extraction_method="capstone_backward_analysis",
        status=ArgumentRecoveryStatus.SUPPORTED,
        is_pointer=True,
    )
    return CallSiteArtifact(
        id=f"CS-{pid}-1",
        pid=pid,
        caller_function="main.connect",
        call_address=0x140001010,
        target_address=0x140002000,
        target_function="net.Dial",
        recovered_arguments=[argument],
        argument_analysis_status=ArgumentRecoveryStatus.SUPPORTED,
    )


def _goroutine(pid=1, goroutine_id="GOR-1-1", frames=None, current_function_id=None):
    return GoroutineArtifact(
        id=goroutine_id,
        pid=pid,
        goroutine_address=0x900000,
        goid=5,
        status=2,
        status_name="running",
        is_scanning=False,
        wait_reason=None,
        wait_reason_name=None,
        m_address=None,
        start_pc=None,
        start_function_name=None,
        go_pc=None,
        go_pc_function_name=None,
        sched_pc=0x140001000,
        sched_sp=0xC000010000,
        used_syscall_state=False,
        stack_lo=0xC000000000,
        stack_hi=0xC000020000,
        stack_size=0x20000,
        current_function_id=current_function_id,
        current_function_name=None,
        current_source_file=None,
        current_source_line=None,
        frames=frames or [],
        unwind_status=UnwindStatus.COMPLETE,
    )


def _frame(function_id):
    return GoroutineFrame(
        frame_index=0,
        pc=0x140001000,
        sp=0xC000010000,
        function_id=function_id,
        function_name="main.connect",
        source_file="main.go",
        source_line=10,
        confidence=Confidence.HIGH,
        unwind_method="pcsp_frame_delta",
    )


class TestBasicExtraction:
    def test_extracts_ipv4_artifact_with_full_provenance(self):
        s = _string(value="192.168.1.10")
        artifacts, errors, stats = extract_network_artifacts(1, "app.exe", "1.26.2", "x86_64", [s], [], [])

        assert errors == []
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.artifact_type == NetworkArtifactType.IPV4
        assert artifact.raw_value == "192.168.1.10"
        assert artifact.pid == 1
        assert artifact.process_name == "app.exe"
        assert artifact.address == s.data_address
        assert artifact.source_artifact_id == s.id
        assert artifact.validation_status == NetworkValidationStatus.STRUCTURALLY_VALID
        assert artifact.confidence == Confidence.MEDIUM
        assert artifact.go_version == "1.26.2"
        assert artifact.architecture == "x86_64"
        assert artifact.provenance is not None
        assert artifact.provenance.pid == 1
        assert artifact.provenance.related_artifacts[0] == s.id

    def test_non_network_string_produces_no_artifact(self):
        s = _string(value="not a network artifact at all")
        artifacts, errors, stats = extract_network_artifacts(1, None, None, "x86_64", [s], [], [])
        assert artifacts == []
        assert stats.strings_scanned == 1
        assert stats.artifacts_extracted == 0

    def test_raw_value_never_altered(self):
        s = _string(value="HTTPS://Example.COM:443/path")
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [], [])
        assert artifacts[0].raw_value == "HTTPS://Example.COM:443/path"
        assert artifacts[0].normalized_value["hostname"] == "example.com"

    def test_only_strings_for_the_given_pid_are_considered(self):
        s1 = _string(pid=1, value="8.8.8.8")
        s2 = _string(pid=2, value="8.8.4.4")
        artifacts, _errors, stats = extract_network_artifacts(1, None, None, "x86_64", [s1, s2], [], [])
        assert len(artifacts) == 1
        assert artifacts[0].raw_value == "8.8.8.8"
        assert stats.strings_scanned == 1


class TestFunctionAssociation:
    def test_string_referenced_by_call_site_is_associated_with_caller_function(self):
        s = _string(value="10.0.0.5:9001")
        func = _function(call_sites=[_string_ref_call_site(1, s.id)])
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [func], [])
        assert artifacts[0].function_id == func.id
        assert func.id in artifacts[0].provenance.related_artifacts

    def test_unreferenced_string_has_no_function_association(self):
        s = _string(value="10.0.0.5:9001")
        func = _function(call_sites=[])  # no call site references this string
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [func], [])
        assert artifacts[0].function_id is None

    def test_proximity_alone_is_never_used(self):
        # A function exists and a network string exists, but nothing
        # explicitly links them - must not be associated merely because
        # both are present for the same process.
        s = _string(value="proximity-only.example.com")
        func = _function(call_sites=[])
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [func], [])
        assert artifacts[0].function_id is None
        assert func.id not in artifacts[0].provenance.related_artifacts


class TestGoroutineAssociation:
    def test_goroutine_with_frame_referencing_associated_function_is_linked(self):
        s = _string(value="203.0.113.5")
        func = _function(call_sites=[_string_ref_call_site(1, s.id)])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [func], [goroutine])
        assert artifacts[0].goroutine_id == goroutine.id
        assert goroutine.id in artifacts[0].provenance.related_artifacts

    def test_goroutine_current_function_id_also_establishes_link(self):
        s = _string(value="203.0.113.6")
        func = _function(call_sites=[_string_ref_call_site(1, s.id)])
        goroutine = _goroutine(current_function_id=func.id, frames=[])
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [func], [goroutine])
        assert artifacts[0].goroutine_id == goroutine.id

    def test_goroutine_not_touching_the_function_is_not_linked(self):
        s = _string(value="203.0.113.7")
        func = _function(call_sites=[_string_ref_call_site(1, s.id)])
        unrelated_goroutine = _goroutine(goroutine_id="GOR-1-99", frames=[_frame("FUNC-1-other")])
        artifacts, _errors, _stats = extract_network_artifacts(
            1, None, None, "x86_64", [s], [func], [unrelated_goroutine]
        )
        assert artifacts[0].goroutine_id is None

    def test_does_not_claim_the_goroutine_contacted_the_endpoint(self):
        # Evidence-chain-only claim: the artifact records an association,
        # never an assertion of an actual network operation having
        # occurred (Phase 6A stage 8).
        s = _string(value="203.0.113.8")
        func = _function(call_sites=[_string_ref_call_site(1, s.id)])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [func], [goroutine])
        assert "contact" not in (artifacts[0].notes or "").lower()
        assert "connect" not in (artifacts[0].notes or "").lower()


class TestDeduplicationAndProvenance:
    def test_same_value_different_addresses_both_preserved(self):
        s1 = _string(value="1.2.3.4", address=0x600000)
        s2 = _string(value="1.2.3.4", address=0x700000)
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s1, s2], [], [])
        assert len(artifacts) == 2
        addresses = {a.address for a in artifacts}
        assert addresses == {0x600000, 0x700000}
        assert artifacts[0].id != artifacts[1].id
        assert artifacts[0].source_artifact_id != artifacts[1].source_artifact_id

    def test_deterministic_ordering(self):
        strings = [_string(value=f"10.0.0.{i}") for i in range(1, 6)]
        artifacts_a, _e1, _s1 = extract_network_artifacts(1, None, None, "x86_64", strings, [], [])
        artifacts_b, _e2, _s2 = extract_network_artifacts(1, None, None, "x86_64", strings, [], [])
        assert [a.id for a in artifacts_a] == [a.id for a in artifacts_b]
        assert [a.raw_value for a in artifacts_a] == [s.value for s in strings]

    def test_single_string_never_produces_two_artifact_types(self):
        # A string classifies into at most one NetworkArtifactType - there
        # is no "same address, different artifact type" case to merge by
        # construction (each StringArtifact.value maps to 0 or 1 artifact).
        s = _string(value="https://example.com:443/path")
        artifacts, _errors, _stats = extract_network_artifacts(1, None, None, "x86_64", [s], [], [])
        assert len(artifacts) == 1
        assert artifacts[0].artifact_type == NetworkArtifactType.URL


class TestBoundsAndSafety:
    def test_over_length_string_skipped_and_recorded_in_stats(self):
        s = _string(value="http://example.com/" + "a" * MAX_STRING_VALUE_LENGTH)
        artifacts, _errors, stats = extract_network_artifacts(1, None, None, "x86_64", [s], [], [])
        assert artifacts == []
        assert stats.strings_skipped_length_bound == 1

    def test_artifact_cap_enforced_and_recorded(self):
        strings = [_string(value=f"10.{i // 256}.{i % 256}.1") for i in range(MAX_ARTIFACTS_PER_PROCESS + 5)]
        artifacts, errors, stats = extract_network_artifacts(1, None, None, "x86_64", strings, [], [])
        assert len(artifacts) == MAX_ARTIFACTS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)
        assert all(e.recoverable for e in errors)

    def test_malformed_string_value_does_not_abort_the_rest(self):
        # A pathological/binary-noise string must not crash classification
        # of the remaining strings.
        noisy = _string(value="\x00\x01\xff" * 50)
        good = _string(value="8.8.8.8")
        artifacts, _errors, stats = extract_network_artifacts(1, None, None, "x86_64", [noisy, good], [], [])
        assert stats.strings_scanned == 2
        assert any(a.raw_value == "8.8.8.8" for a in artifacts)


class TestPipelineSemantics:
    def test_no_strings_returns_empty_clean_result(self):
        artifacts, errors, stats = extract_network_artifacts(1, None, None, "x86_64", [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_multiple_processes_are_independent(self):
        s1 = _string(pid=1, value="1.1.1.1")
        s2 = _string(pid=2, value="2.2.2.2")
        artifacts_p1, _e1, _s1 = extract_network_artifacts(1, None, None, "x86_64", [s1, s2], [], [])
        artifacts_p2, _e2, _s2 = extract_network_artifacts(2, None, None, "x86_64", [s1, s2], [], [])
        assert [a.raw_value for a in artifacts_p1] == ["1.1.1.1"]
        assert [a.raw_value for a in artifacts_p2] == ["2.2.2.2"]
