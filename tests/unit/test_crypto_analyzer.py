"""Tests for :func:`gomemforensics.analyzers.crypto.extract_crypto_artifacts`.

All fixtures here are hand-built dataclass instances (SYNTHETIC) - the
analyzer under test consumes already-recovered
StringArtifact/FunctionArtifact/GoroutineArtifact/NetworkArtifact/
CredentialArtifact objects directly, with no MemoryReader involved.
"""

from __future__ import annotations

import logging
from itertools import count

from gomemforensics.analyzers.crypto import (
    MAX_ARTIFACTS_PER_PROCESS,
    MAX_STRING_VALUE_LENGTH,
    extract_crypto_artifacts,
)
from gomemforensics.analyzers.models import (
    CredentialArtifact,
    CredentialArtifactType,
    CredentialValidationStatus,
    CryptoArtifactType,
    CryptoValidationStatus,
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
_FAKE_CERT_BODY = "MIIDdTCCAl2gAwIBAgIUFAKECERTFAKECERTFAKECERTFAKEMA0GCSqGSIb3DQEB"


def _string(pid=1, value="AES-256-GCM", length=None, address=None, region="static", string_id=None):
    n = next(_id_counter)
    addr = address if address is not None else 0x500000 + n * 0x10
    return StringArtifact(
        id=string_id or f"STR-{pid}-{n:04d}",
        pid=pid,
        string_address=addr,
        data_address=addr,
        length=length if length is not None else len(value),
        value=value,
        region=region,
        extraction_method="static_section_scan",
        confidence=Confidence.HIGH,
        is_utf8=True,
        printable_ratio=1.0,
    )


def _function(pid=1, func_id="FUNC-1-abc", name="main.setup", call_sites=None):
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


def _call_site(pid, target_function, arguments):
    return CallSiteArtifact(
        id=f"CS-{pid}-1",
        pid=pid,
        caller_function="main.setup",
        call_address=0x140001010,
        target_address=0x140002000,
        target_function=target_function,
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
        function_name="main.setup",
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
        raw_value="https://example.com",
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


def _credential_private_key(pid, source_artifact_id, artifact_id="CRED-1-0001", credential_type=CredentialArtifactType.PEM_PRIVATE_KEY):
    return CredentialArtifact(
        id=artifact_id,
        pid=pid,
        process_name=None,
        artifact_type=credential_type,
        raw_value="-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----",
        redacted_value="-----BEGIN RSA PRIVATE KEY----- [REDACTED, 20 bytes] -----END RSA PRIVATE KEY-----",
        normalized_value={"label": "RSA PRIVATE KEY", "complete": True, "body_length": 20},
        address=0x700000,
        length=70,
        memory_region="static",
        source_artifact_id=source_artifact_id,
        function_id=None,
        goroutine_id=None,
        network_artifact_id=None,
        extraction_method="go_string_credential_classification",
        confidence=Confidence.HIGH,
        validation_status=CredentialValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


class TestPemStringExtraction:
    def test_extracts_certificate_with_full_provenance(self):
        value = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}\n-----END CERTIFICATE-----"
        s = _string(value=value)
        artifacts, errors, stats = extract_crypto_artifacts(1, "app.exe", "1.26.2", "x86_64", [s], [], [], [], [])

        assert errors == []
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.artifact_type == CryptoArtifactType.CERTIFICATE
        assert artifact.raw_value == value
        assert artifact.redacted_value != value
        assert artifact.pid == 1
        assert artifact.process_name == "app.exe"
        assert artifact.address == s.data_address
        assert artifact.source_artifact_id == s.id
        assert artifact.provenance is not None

    def test_raw_value_never_altered(self):
        s = _string(value="TLS_AES_128_GCM_SHA256")
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [])
        assert artifacts[0].raw_value == "TLS_AES_128_GCM_SHA256"


class TestPrivateKeyReuse:
    def test_reuses_credential_artifact_without_reparsing(self):
        s = _string(value="-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----")
        credential = _credential_private_key(1, s.id)
        artifacts, _errors, stats = extract_crypto_artifacts(1, None, "1.26.2", "x86_64", [s], [], [], [], [credential])

        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.artifact_type == CryptoArtifactType.PRIVATE_KEY
        assert artifact.credential_artifact_id == credential.id
        assert artifact.raw_value == credential.raw_value
        assert artifact.redacted_value == credential.redacted_value
        assert stats.credential_artifacts_reused == 1

    def test_non_private_key_credential_types_not_reused(self):
        s = _string(value="password=hunter2Q!")
        credential = _credential_private_key(1, s.id, credential_type=CredentialArtifactType.PASSWORD)
        artifacts, _errors, stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [credential])
        assert artifacts == []
        assert stats.credential_artifacts_reused == 0

    def test_fragment_status_preserved(self):
        s = _string(value="-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...")
        credential = _credential_private_key(
            1, s.id, credential_type=CredentialArtifactType.PRIVATE_KEY_FRAGMENT
        )
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [credential])
        assert artifacts[0].validation_status == CryptoValidationStatus.STRUCTURALLY_INCOMPLETE


class TestAesKeyEvidence:
    def test_evidence_backed_aes_key_from_call_site(self):
        key_string = _string(value="A" * 32, length=32)  # AES-256 key length
        call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(0, key_string.id)])
        func = _function(call_sites=[call_site])

        artifacts, _errors, stats = extract_crypto_artifacts(
            1, None, None, "x86_64", [key_string], [func], [], [], []
        )

        aes_artifacts = [a for a in artifacts if a.artifact_type == CryptoArtifactType.AES_KEY]
        assert len(aes_artifacts) == 1
        artifact = aes_artifacts[0]
        assert artifact.algorithm == "AES"
        assert artifact.function_id == func.id
        assert "KEY_MATERIAL_PASSED_AS_ARGUMENT" in artifact.notes
        assert "KEY_USED" not in artifact.notes
        assert "encryption occurred" not in artifact.notes.lower() or "not proof" in artifact.notes.lower()
        assert stats.call_sites_evaluated == 1

    def test_wrong_length_argument_rejected(self):
        key_string = _string(value="A" * 20, length=20)  # not 16/24/32
        call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(0, key_string.id)])
        func = _function(call_sites=[call_site])
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [key_string], [func], [], [], [])
        assert not any(a.artifact_type == CryptoArtifactType.AES_KEY for a in artifacts)

    def test_unrelated_function_not_matched(self):
        key_string = _string(value="A" * 32, length=32)
        call_site = _call_site(1, "net/http.NewRequest", [_string_ref_argument(0, key_string.id)])
        func = _function(call_sites=[call_site])
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [key_string], [func], [], [], [])
        assert not any(a.artifact_type == CryptoArtifactType.AES_KEY for a in artifacts)

    def test_wrong_argument_index_not_matched(self):
        key_string = _string(value="A" * 32, length=32)
        # Argument at index 1, not the required index 0.
        call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(1, key_string.id)])
        func = _function(call_sites=[call_site])
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [key_string], [func], [], [], [])
        assert not any(a.artifact_type == CryptoArtifactType.AES_KEY for a in artifacts)

    def test_16_and_24_byte_lengths_also_accepted(self):
        for length in (16, 24, 32):
            key_string = _string(value="K" * length, length=length)
            call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(0, key_string.id)])
            func = _function(func_id=f"FUNC-1-{length}", call_sites=[call_site])
            artifacts, _errors, _stats = extract_crypto_artifacts(
                1, None, None, "x86_64", [key_string], [func], [], [], []
            )
            assert any(a.artifact_type == CryptoArtifactType.AES_KEY for a in artifacts), f"failed for length {length}"


class TestGoroutineAssociation:
    def test_goroutine_with_frame_referencing_aes_function_is_linked(self):
        key_string = _string(value="A" * 32, length=32)
        call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(0, key_string.id)])
        func = _function(call_sites=[call_site])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_crypto_artifacts(
            1, None, None, "x86_64", [key_string], [func], [goroutine], [], []
        )
        aes = [a for a in artifacts if a.artifact_type == CryptoArtifactType.AES_KEY][0]
        assert aes.goroutine_id == goroutine.id

    def test_does_not_claim_goroutine_performed_encryption(self):
        key_string = _string(value="A" * 32, length=32)
        call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(0, key_string.id)])
        func = _function(call_sites=[call_site])
        goroutine = _goroutine(frames=[_frame(func.id)])
        artifacts, _errors, _stats = extract_crypto_artifacts(
            1, None, None, "x86_64", [key_string], [func], [goroutine], [], []
        )
        aes = [a for a in artifacts if a.artifact_type == CryptoArtifactType.AES_KEY][0]
        assert "performed encryption" not in (aes.notes or "").lower()
        assert "goroutine performed" not in (aes.notes or "").lower()


class TestNetworkAssociation:
    def test_shared_source_string_links_to_network_artifact(self):
        s = _string(value="TLS_AES_128_GCM_SHA256")
        net = _network_artifact(1, s.id)
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [net], [])
        assert artifacts[0].network_artifact_id == net.id

    def test_unrelated_network_artifact_not_linked(self):
        s = _string(value="TLS_AES_128_GCM_SHA256")
        other = _string(value="unrelated")
        net = _network_artifact(1, other.id)
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [net], [])
        assert artifacts[0].network_artifact_id is None


class TestCredentialAssociation:
    def test_private_key_cross_references_credential_artifact(self):
        s = _string(value="-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----")
        credential = _credential_private_key(1, s.id)
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [credential])
        assert artifacts[0].credential_artifact_id == credential.id

    def test_certificate_has_no_credential_cross_reference(self):
        value = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}\n-----END CERTIFICATE-----"
        s = _string(value=value)
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [])
        assert artifacts[0].credential_artifact_id is None


class TestDeduplicationAndSafety:
    def test_same_value_different_addresses_both_preserved(self):
        s1 = _string(value="Ed25519", address=0x600000)
        s2 = _string(value="Ed25519", address=0x700000)
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [], [])
        assert len(artifacts) == 2
        addresses = {a.address for a in artifacts}
        assert addresses == {0x600000, 0x700000}

    def test_over_length_string_skipped(self):
        s = _string(value="AES-256-GCM" + "a" * MAX_STRING_VALUE_LENGTH)
        artifacts, _errors, stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [])
        assert artifacts == []
        assert stats.strings_skipped_length_bound == 1

    def test_artifact_cap_enforced(self):
        strings = [_string(value=f"TLS_AES_128_GCM_SHA{256 + i}") for i in range(MAX_ARTIFACTS_PER_PROCESS + 5)]
        artifacts, errors, stats = extract_crypto_artifacts(1, None, None, "x86_64", strings, [], [], [], [])
        assert len(artifacts) == MAX_ARTIFACTS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)

    def test_malformed_string_does_not_abort_the_rest(self):
        noisy = _string(value="\x00\x01\xff" * 50)
        good = _string(value="Ed25519")
        artifacts, _errors, stats = extract_crypto_artifacts(1, None, None, "x86_64", [noisy, good], [], [], [], [])
        assert stats.strings_scanned == 2
        assert any(a.raw_value == "Ed25519" for a in artifacts)


class TestRedactionAndLogSafety:
    def test_pem_redaction_never_exposes_key_material(self):
        value = f"-----BEGIN PUBLIC KEY-----\n{_FAKE_CERT_BODY}\n-----END PUBLIC KEY-----"
        s = _string(value=value)
        artifacts, _errors, _stats = extract_crypto_artifacts(1, None, None, "x86_64", [s], [], [], [], [])
        assert _FAKE_CERT_BODY not in artifacts[0].redacted_value

    def test_no_secret_value_appears_in_log_output(self, caplog):
        secret_marker = "UNIQUESENTINELKEYMATERIALVALUE1"  # 32 bytes
        key_string = _string(value=secret_marker, length=32)
        call_site = _call_site(1, "crypto/aes.NewCipher", [_string_ref_argument(0, key_string.id)])
        func = _function(call_sites=[call_site])
        with caplog.at_level(logging.DEBUG):
            extract_crypto_artifacts(1, "proc.exe", "1.26.2", "x86_64", [key_string], [func], [], [], [])
        for record in caplog.records:
            assert secret_marker not in record.getMessage()


class TestPipelineSemantics:
    def test_no_strings_returns_empty_clean_result(self):
        artifacts, errors, stats = extract_crypto_artifacts(1, None, None, "x86_64", [], [], [], [], [])
        assert artifacts == []
        assert errors == []
        assert stats.strings_scanned == 0

    def test_multiple_processes_are_independent(self):
        s1 = _string(pid=1, value="Ed25519")
        s2 = _string(pid=2, value="X25519")
        artifacts_p1, _e1, _s1 = extract_crypto_artifacts(1, None, None, "x86_64", [s1, s2], [], [], [], [])
        artifacts_p2, _e2, _s2 = extract_crypto_artifacts(2, None, None, "x86_64", [s1, s2], [], [], [], [])
        assert [a.raw_value for a in artifacts_p1] == ["Ed25519"]
        assert [a.raw_value for a in artifacts_p2] == ["X25519"]
