"""Tests for :func:`gomemforensics.analyzers.credentials.extract_credential_artifacts`.

All fixtures here are hand-built dataclass instances (SYNTHETIC) - the
analyzer under test consumes already-recovered
StringArtifact/FunctionArtifact/GoroutineArtifact/NetworkArtifact objects
directly, with no MemoryReader involved.
"""

from __future__ import annotations

import logging
from itertools import count

from gomemforensics.analyzers.credentials import (
    MAX_ARTIFACTS_PER_PROCESS,
    MAX_STRING_VALUE_LENGTH,
    extract_credential_artifacts,
)
from gomemforensics.analyzers.models import (
    CredentialArtifactType,
    CredentialValidationStatus,
    NetworkArtifact,
    NetworkArtifactType,
    NetworkValidationStatus,
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


def _string(pid=1, value="password=hunter2Q!", address=None, region="static", string_id=None):
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
        name="main.login",
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


def _string_ref_argument(index, string_id, register):
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


def _call_site(pid, arguments):
    return CallSiteArtifact(
        id=f"CS-{pid}-1",
        pid=pid,
        caller_function="main.login",
        call_address=0x140001010,
        target_address=0x140002000,
        target_function="net/http.NewRequest",
        recovered_arguments=arguments,
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
        function_name="main.login",
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
        raw_value="postgres://admin:s3cr3t@db.internal:5432/appdb",
        normalized_value={"scheme": "postgres"},
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


class TestBasicExtraction:
    def test_extracts_password_artifact_with_full_provenance(self):
        s = _string(value="password=hunter2Q!")
        artifacts, errors, stats = extract_credential_artifacts(1, "app.exe", "1.26.2", "x86_64", [s], [], [], [])

        assert errors == []
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.artifact_type == CredentialArtifactType.PASSWORD
        assert artifact.raw_value == "password=hunter2Q!"
        assert artifact.redacted_value != artifact.raw_value
        assert artifact.pid == 1
        assert artifact.process_name == "app.exe"
        assert artifact.address == s.data_address
        assert artifact.source_artifact_id == s.id
        assert artifact.validation_status == CredentialValidationStatus.STRUCTURALLY_VALID
        assert artifact.go_version == "1.26.2"
        assert artifact.architecture == "x86_64"
        assert artifact.provenance is not None
        assert artifact.provenance.related_artifacts[0] == s.id

    def test_raw_value_never_altered(self):
        s = _string(value="Authorization: Bearer abc.def.ghi")
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [])
        assert artifacts[0].raw_value == "Authorization: Bearer abc.def.ghi"

    def test_non_secret_string_produces_no_artifact(self):
        s = _string(value="not a secret at all, just prose")
        artifacts, _errors, stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [])
        assert artifacts == []
        assert stats.strings_scanned == 1

    def test_only_strings_for_the_given_pid_are_considered(self):
        s1 = _string(pid=1, value="password=aaaaaaaa")
        s2 = _string(pid=2, value="password=bbbbbbbb")
        artifacts, _errors, stats = extract_credential_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [])
        assert len(artifacts) == 1
        assert artifacts[0].raw_value == "password=aaaaaaaa"
        assert stats.strings_scanned == 1


class TestFunctionAssociation:
    def test_string_referenced_by_call_site_is_associated_with_caller_function(self):
        s = _string(value="api_key=abcdef0123456789")
        func = _function(call_sites=[_call_site(1, [_string_ref_argument(0, s.id, "rdi")])])
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [func], [], [])
        assert artifacts[0].function_id == func.id
        assert func.id in artifacts[0].provenance.related_artifacts

    def test_unreferenced_string_has_no_function_association(self):
        s = _string(value="api_key=abcdef0123456789")
        func = _function(call_sites=[])
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [func], [], [])
        assert artifacts[0].function_id is None

    def test_proximity_alone_is_never_used(self):
        s = _string(value="api_key=abcdef0123456789")
        func = _function(call_sites=[])
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [func], [], [])
        assert func.id not in (artifacts[0].provenance.related_artifacts or [])


class TestGoroutineAssociation:
    def test_goroutine_with_frame_referencing_associated_function_is_linked(self):
        s = _string(value="client_secret=abcDEF123456")
        func = _function(call_sites=[_call_site(1, [_string_ref_argument(0, s.id, "rdi")])])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [func], [goroutine], [])
        assert artifacts[0].goroutine_id == goroutine.id

    def test_does_not_claim_the_goroutine_used_the_credential(self):
        s = _string(value="client_secret=abcDEF123456")
        func = _function(call_sites=[_call_site(1, [_string_ref_argument(0, s.id, "rdi")])])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [func], [goroutine], [])
        notes = (artifacts[0].notes or "").lower()
        assert "used" not in notes
        assert "authenticated" not in notes


class TestNetworkAssociation:
    def test_shared_source_string_links_to_network_artifact(self):
        s = _string(value="postgres://admin:s3cr3t@db.internal:5432/appdb")
        net = _network_artifact(1, s.id)
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [net])
        assert artifacts[0].artifact_type == CredentialArtifactType.DATABASE_CREDENTIAL
        assert artifacts[0].network_artifact_id == net.id
        assert net.id in artifacts[0].provenance.related_artifacts

    def test_no_network_artifact_means_no_association(self):
        s = _string(value="postgres://admin:s3cr3t@db.internal:5432/appdb")
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [])
        assert artifacts[0].network_artifact_id is None

    def test_association_is_never_interpreted_as_actual_contact(self):
        s = _string(value="postgres://admin:s3cr3t@db.internal:5432/appdb")
        net = _network_artifact(1, s.id)
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [net])
        notes = (artifacts[0].notes or "").lower()
        assert "contact" not in notes
        assert "connected" not in notes


class TestDeduplication:
    def test_same_value_different_addresses_both_preserved(self):
        s1 = _string(value="password=identicalvalue", address=0x600000)
        s2 = _string(value="password=identicalvalue", address=0x700000)
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [])
        assert len(artifacts) == 2
        addresses = {a.address for a in artifacts}
        assert addresses == {0x600000, 0x700000}
        assert artifacts[0].id != artifacts[1].id
        assert artifacts[0].source_artifact_id != artifacts[1].source_artifact_id

    def test_deterministic_ordering(self):
        strings = [_string(value=f"password=value{i:04d}xx") for i in range(1, 6)]
        artifacts_a, _e1, _s1 = extract_credential_artifacts(1, None, None, "x86_64", strings, [], [], [])
        artifacts_b, _e2, _s2 = extract_credential_artifacts(1, None, None, "x86_64", strings, [], [], [])
        assert [a.id for a in artifacts_a] == [a.id for a in artifacts_b]


class TestBoundsAndSafety:
    def test_over_length_string_skipped_and_recorded(self):
        s = _string(value="password=" + "a" * MAX_STRING_VALUE_LENGTH)
        artifacts, _errors, stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [])
        assert artifacts == []
        assert stats.strings_skipped_length_bound == 1

    def test_artifact_cap_enforced_and_recorded(self):
        strings = [_string(value=f"password=value{i:06d}xx") for i in range(MAX_ARTIFACTS_PER_PROCESS + 5)]
        artifacts, errors, stats = extract_credential_artifacts(1, None, None, "x86_64", strings, [], [], [])
        assert len(artifacts) == MAX_ARTIFACTS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)
        assert all(e.recoverable for e in errors)

    def test_malformed_string_value_does_not_abort_the_rest(self):
        noisy = _string(value="\x00\x01\xff" * 50)
        good = _string(value="password=goodvalue123")
        artifacts, _errors, stats = extract_credential_artifacts(1, None, None, "x86_64", [noisy, good], [], [], [])
        assert stats.strings_scanned == 2
        assert any(a.raw_value == "password=goodvalue123" for a in artifacts)


class TestRedactionAndLogSafety:
    def test_pem_redaction_never_exposes_key_material(self):
        secret_body = "MIIBOgIBAAJBAKveryverysecretkeymaterial"
        value = f"-----BEGIN RSA PRIVATE KEY-----\n{secret_body}\n-----END RSA PRIVATE KEY-----"
        s = _string(value=value)
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [])
        assert secret_body not in artifacts[0].redacted_value

    def test_password_value_not_fully_exposed_in_redacted_form(self):
        s = _string(value="password=hunter2VerySecretValue")
        artifacts, _errors, _stats = extract_credential_artifacts(1, None, None, "x86_64", [s], [], [], [])
        assert "hunter2VerySecretValue" not in artifacts[0].redacted_value

    def test_no_secret_value_appears_in_log_output(self, caplog):
        secret = "hunter2VeryUniqueSentinelValue"
        s = _string(value=f"password={secret}")
        with caplog.at_level(logging.DEBUG):
            extract_credential_artifacts(1, "proc.exe", "1.26.2", "x86_64", [s], [], [], [])
        for record in caplog.records:
            assert secret not in record.getMessage()


class TestPipelineSemantics:
    def test_no_strings_returns_empty_clean_result(self):
        artifacts, errors, stats = extract_credential_artifacts(1, None, None, "x86_64", [], [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_multiple_processes_are_independent(self):
        s1 = _string(pid=1, value="password=processonesecret")
        s2 = _string(pid=2, value="password=processtwosecret")
        artifacts_p1, _e1, _s1 = extract_credential_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [])
        artifacts_p2, _e2, _s2 = extract_credential_artifacts(2, None, None, "x86_64", [s1, s2], [], [], [])
        assert [a.raw_value for a in artifacts_p1] == ["password=processonesecret"]
        assert [a.raw_value for a in artifacts_p2] == ["password=processtwosecret"]
