"""Tests for :func:`gomemforensics.analyzers.persistence.extract_persistence_artifacts`.

All fixtures here are hand-built dataclass instances (SYNTHETIC) - the
analyzer under test consumes already-recovered
StringArtifact/FunctionArtifact/GoroutineArtifact/NetworkArtifact/
CredentialArtifact/CryptoArtifact objects directly, with no MemoryReader
and no OS/filesystem/registry access involved.
"""

from __future__ import annotations

import logging
from itertools import count

from gomemforensics.analyzers.credentials import CredentialArtifactType, CredentialValidationStatus
from gomemforensics.analyzers.models import (
    CredentialArtifact,
    CryptoArtifact,
    CryptoArtifactType,
    CryptoValidationStatus,
    NetworkArtifact,
    NetworkArtifactType,
    NetworkValidationStatus,
    PersistenceArtifactType,
)
from gomemforensics.analyzers.persistence import (
    MAX_ARTIFACTS_PER_PROCESS,
    MAX_PERSISTENCE_VALUE_LENGTH,
    extract_persistence_artifacts,
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


def _string(pid=1, value=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", address=None, region="static", string_id=None):
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


def _function(pid=1, func_id="FUNC-1-abc", call_sites=None):
    return FunctionArtifact(
        id=func_id,
        pid=pid,
        address=0x140001000,
        entry_address=0x140001000,
        name="main.install",
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


def _string_ref_argument(index, string_id, register="rdi"):
    return ArgumentArtifact(
        index=index,
        type_hint="string",
        value=f"string_ref:{string_id}",
        location=f"register:{register}",
        confidence=Confidence.MEDIUM,
        extraction_method="capstone_backward_analysis",
        status=ArgumentRecoveryStatus.SUPPORTED,
        is_pointer=True,
    )


def _call_site(pid, string_id):
    return CallSiteArtifact(
        id=f"CS-{pid}-1",
        pid=pid,
        caller_function="main.install",
        call_address=0x140001010,
        target_address=0x140002000,
        target_function="RegSetValueExW",
        recovered_arguments=[_string_ref_argument(0, string_id)],
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
        function_name="main.install",
        source_file="main.go",
        source_line=10,
        confidence=Confidence.HIGH,
        unwind_method="pcsp_frame_delta",
    )


def _network_artifact(pid, source_artifact_id, artifact_id="NET-1-0001"):
    return NetworkArtifact(
        id=artifact_id,
        pid=pid,
        process_name=None,
        artifact_type=NetworkArtifactType.URL,
        raw_value="https://example.com/payload.exe",
        normalized_value={"scheme": "https"},
        address=0x600000,
        length=10,
        memory_region="static",
        source_artifact_id=source_artifact_id,
        function_id=None,
        goroutine_id=None,
        extraction_method="go_string_network_classification",
        confidence=Confidence.MEDIUM,
        validation_status=NetworkValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _credential_artifact(pid, source_artifact_id, artifact_id="CRED-1-0001"):
    return CredentialArtifact(
        id=artifact_id,
        pid=pid,
        process_name=None,
        artifact_type=CredentialArtifactType.PASSWORD,
        raw_value="password=hunter2Q!",
        redacted_value="pas...Q!",
        normalized_value={},
        address=0x700000,
        length=18,
        memory_region="static",
        source_artifact_id=source_artifact_id,
        function_id=None,
        goroutine_id=None,
        network_artifact_id=None,
        extraction_method="go_string_credential_classification",
        confidence=Confidence.MEDIUM,
        validation_status=CredentialValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _crypto_artifact(pid, source_artifact_id, artifact_id="CRYPTO-1-0001"):
    return CryptoArtifact(
        id=artifact_id,
        pid=pid,
        process_name=None,
        artifact_type=CryptoArtifactType.CRYPTO_CONTEXT,
        algorithm="AES-256-GCM",
        key_type="context",
        raw_value="AES-256-GCM",
        redacted_value="***********",
        normalized_value={},
        address=0x800000,
        length=11,
        memory_region="static",
        source_artifact_id=source_artifact_id,
        function_id=None,
        goroutine_id=None,
        network_artifact_id=None,
        credential_artifact_id=None,
        extraction_method="go_string_crypto_classification",
        confidence=Confidence.LOW,
        validation_status=CryptoValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


class TestBasicExtraction:
    def test_extracts_registry_run_artifact_with_full_provenance(self):
        s = _string()
        artifacts, errors, stats = extract_persistence_artifacts(
            1, "app.exe", "1.26.2", "x86_64", [s], [], [], [], [], []
        )
        assert errors == []
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.artifact_type == PersistenceArtifactType.WINDOWS_REGISTRY_RUN
        assert artifact.platform == "windows"
        assert artifact.raw_value == s.value
        assert artifact.redacted_value != s.value
        assert artifact.pid == 1
        assert artifact.process_name == "app.exe"
        assert artifact.address == s.data_address
        assert artifact.source_artifact_id == s.id
        assert artifact.provenance is not None

    def test_raw_value_never_altered(self):
        s = _string(value="/etc/systemd/system/fake.service")
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [], [], [])
        assert artifacts[0].raw_value == "/etc/systemd/system/fake.service"

    def test_notes_never_claim_confirmed_persistence(self):
        s = _string()
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [], [], [])
        notes = artifacts[0].notes.upper()
        assert "PERSISTENCE_CONFIRMED" not in notes
        assert "PERSISTENCE_ESTABLISHED" not in notes
        assert "COMMAND_EXECUTED" not in notes


class TestFunctionAssociation:
    def test_string_referenced_by_call_site_is_associated_with_function(self):
        s = _string()
        func = _function(call_sites=[_call_site(1, s.id)])
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [func], [], [], [], [])
        assert artifacts[0].function_id == func.id
        assert "PERSISTENCE_FUNCTION_ASSOCIATED" in artifacts[0].notes

    def test_unreferenced_string_has_no_function_association(self):
        s = _string()
        func = _function(call_sites=[])
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [func], [], [], [], [])
        assert artifacts[0].function_id is None

    def test_proximity_alone_is_never_used(self):
        s = _string()
        func = _function(call_sites=[])
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [func], [], [], [], [])
        assert func.id not in (artifacts[0].provenance.related_artifacts or [])


class TestGoroutineAssociation:
    def test_goroutine_with_frame_referencing_function_is_linked(self):
        s = _string()
        func = _function(call_sites=[_call_site(1, s.id)])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [func], [goroutine], [], [], [])
        assert artifacts[0].goroutine_id == goroutine.id

    def test_does_not_claim_goroutine_established_persistence(self):
        s = _string()
        func = _function(call_sites=[_call_site(1, s.id)])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [func], [goroutine], [], [], [])
        notes = artifacts[0].notes.lower()
        # The disclaimer text itself legitimately contains "established
        # persistence mechanism" as part of a NEGATION ("not proof of...
        # successfully established persistence mechanism") - check for
        # the specific positive-claim phrasing this must never contain.
        assert "goroutine established" not in notes
        assert "goroutine performed" not in notes
        assert "confirmed persistence" not in notes


class TestCrossAnalyzerAssociation:
    def test_network_association_only_recorded_not_interpreted_as_installation(self):
        s = _string(value="/etc/systemd/system/fake.service")
        net = _network_artifact(1, s.id)
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [net], [], [])
        assert artifacts[0].network_artifact_id == net.id
        assert "downloaded and installed" not in (artifacts[0].notes or "").lower()

    def test_credential_artifact_linked_via_shared_source_string(self):
        s = _string(value="/home/test/.ssh/authorized_keys")
        cred = _credential_artifact(1, s.id)
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [], [cred], [])
        assert artifacts[0].credential_artifact_id == cred.id

    def test_crypto_artifact_linked_via_shared_source_string(self):
        s = _string(value="/etc/systemd/system/fake.service")
        crypto = _crypto_artifact(1, s.id)
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [], [], [crypto])
        assert artifacts[0].crypto_artifact_id == crypto.id

    def test_unrelated_cross_artifacts_not_linked(self):
        s = _string(value="/etc/systemd/system/fake.service")
        other = _string(value="unrelated")
        net = _network_artifact(1, other.id)
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [net], [], [])
        assert artifacts[0].network_artifact_id is None


class TestDeduplicationAndSafety:
    def test_same_value_different_addresses_both_preserved(self):
        s1 = _string(address=0x600000)
        s2 = _string(address=0x700000)
        artifacts, _errors, _stats = extract_persistence_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [], [], [])
        assert len(artifacts) == 2
        addresses = {a.address for a in artifacts}
        assert addresses == {0x600000, 0x700000}

    def test_over_length_string_skipped(self):
        s = _string(value=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" + "a" * MAX_PERSISTENCE_VALUE_LENGTH)
        artifacts, _errors, stats = extract_persistence_artifacts(1, None, None, "x86_64", [s], [], [], [], [], [])
        assert artifacts == []
        assert stats.strings_skipped_length_bound == 1

    def test_artifact_cap_enforced(self):
        strings = [_string(value=f"/etc/cron.d/fake-fixture-{i}") for i in range(MAX_ARTIFACTS_PER_PROCESS + 5)]
        artifacts, errors, stats = extract_persistence_artifacts(1, None, None, "x86_64", strings, [], [], [], [], [])
        assert len(artifacts) == MAX_ARTIFACTS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)

    def test_malformed_string_does_not_abort_the_rest(self):
        noisy = _string(value="\x00\x01\xff" * 50)
        good = _string(value="/etc/rc.local")
        artifacts, _errors, stats = extract_persistence_artifacts(1, None, None, "x86_64", [noisy, good], [], [], [], [], [])
        assert stats.strings_scanned == 2
        assert any(a.raw_value == "/etc/rc.local" for a in artifacts)


class TestRedactionAndLogSafety:
    def test_no_secret_value_appears_in_log_output(self, caplog):
        marker = "UNIQUESENTINELPATHVALUE"
        s = _string(value=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{marker}")
        with caplog.at_level(logging.DEBUG):
            extract_persistence_artifacts(1, "proc.exe", "1.26.2", "x86_64", [s], [], [], [], [], [])
        for record in caplog.records:
            assert marker not in record.getMessage()


class TestPipelineSemantics:
    def test_no_strings_returns_empty_clean_result(self):
        artifacts, errors, stats = extract_persistence_artifacts(1, None, None, "x86_64", [], [], [], [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_multiple_processes_are_independent(self):
        s1 = _string(pid=1, value=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
        s2 = _string(pid=2, value="/etc/systemd/system/fake.service")
        artifacts_p1, _e1, _s1 = extract_persistence_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [], [], [])
        artifacts_p2, _e2, _s2 = extract_persistence_artifacts(2, None, None, "x86_64", [s1, s2], [], [], [], [], [])
        assert [a.platform for a in artifacts_p1] == ["windows"]
        assert [a.platform for a in artifacts_p2] == ["linux"]
