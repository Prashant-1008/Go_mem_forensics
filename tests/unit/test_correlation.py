"""Tests for :func:`gomemforensics.analyzers.correlation.correlate_artifacts`.

All fixtures are hand-built dataclass instances (SYNTHETIC) - correlation
operates purely on already-recovered artifact fields, with no memory
access and no new inference beyond restating existing evidence-chain
fields as explicit edges.
"""

from __future__ import annotations

from itertools import count

from gomemforensics.analyzers.correlation import (
    MAX_CORRELATIONS_PER_PROCESS,
    MAX_SAME_SOURCE_GROUP_SIZE,
    correlate_artifacts,
)
from gomemforensics.analyzers.models import (
    CorrelationType,
    CredentialArtifactType,
    CredentialValidationStatus,
    CryptoArtifactType,
    CryptoValidationStatus,
    NetworkArtifactType,
    NetworkValidationStatus,
    PersistenceArtifactType,
    PersistenceValidationStatus,
)
from gomemforensics.analyzers.models import CredentialArtifact, CryptoArtifact, NetworkArtifact, PersistenceArtifact
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.models import (
    ArgumentArtifact,
    ArgumentRecoveryStatus,
    CallSiteArtifact,
    FunctionArtifact,
    FunctionClassification,
    GoroutineArtifact,
    GoroutineFrame,
    UnwindStatus,
)

_id_counter = count(1)


def _network(pid=1, source_id="STR-1-0001", function_id=None, goroutine_id=None):
    n = next(_id_counter)
    return NetworkArtifact(
        id=f"NET-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        artifact_type=NetworkArtifactType.URL,
        raw_value="https://example.com",
        normalized_value={"scheme": "https"},
        address=0x600000,
        length=10,
        memory_region="static",
        source_artifact_id=source_id,
        function_id=function_id,
        goroutine_id=goroutine_id,
        extraction_method="go_string_network_classification",
        confidence=Confidence.MEDIUM,
        validation_status=NetworkValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _credential(pid=1, source_id="STR-1-0002", network_artifact_id=None):
    n = next(_id_counter)
    return CredentialArtifact(
        id=f"CRED-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        artifact_type=CredentialArtifactType.DATABASE_CREDENTIAL,
        raw_value="postgres://user:pass@host/db",
        redacted_value="***",
        normalized_value={},
        address=0x700000,
        length=20,
        memory_region="static",
        source_artifact_id=source_id,
        function_id=None,
        goroutine_id=None,
        network_artifact_id=network_artifact_id,
        extraction_method="go_string_credential_classification",
        confidence=Confidence.HIGH,
        validation_status=CredentialValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _crypto(pid=1, source_id="STR-1-0003", network_artifact_id=None, credential_artifact_id=None):
    n = next(_id_counter)
    return CryptoArtifact(
        id=f"CRYPTO-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        artifact_type=CryptoArtifactType.CRYPTO_CONTEXT,
        algorithm=None,
        key_type="context",
        raw_value="AES-256-GCM",
        redacted_value="***",
        normalized_value={},
        address=0x800000,
        length=11,
        memory_region="static",
        source_artifact_id=source_id,
        function_id=None,
        goroutine_id=None,
        network_artifact_id=network_artifact_id,
        credential_artifact_id=credential_artifact_id,
        extraction_method="go_string_crypto_classification",
        confidence=Confidence.LOW,
        validation_status=CryptoValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _persistence(pid=1, source_id="STR-1-0004", network_artifact_id=None, credential_artifact_id=None, crypto_artifact_id=None):
    n = next(_id_counter)
    return PersistenceArtifact(
        id=f"PERSIST-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        platform="windows",
        artifact_type=PersistenceArtifactType.WINDOWS_REGISTRY_RUN,
        persistence_mechanism="registry_run_key",
        raw_value=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        redacted_value="***",
        normalized_value={},
        address=0x900000,
        length=10,
        memory_region="static",
        source_artifact_id=source_id,
        function_id=None,
        goroutine_id=None,
        network_artifact_id=network_artifact_id,
        credential_artifact_id=credential_artifact_id,
        crypto_artifact_id=crypto_artifact_id,
        extraction_method="go_string_persistence_classification",
        confidence=Confidence.HIGH,
        validation_status=PersistenceValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _function(pid=1, func_id="FUNC-1-abc"):
    return FunctionArtifact(
        id=func_id, pid=pid, address=0x140001000, entry_address=0x140001000, name="main.setup",
        package="main", source_file="main.go", source_line=10, function_size=64,
        classification=FunctionClassification.APPLICATION, confidence=Confidence.HIGH,
        extraction_method="functab", go_version="1.26.2", architecture="x86_64",
    )


def _goroutine(pid=1, goroutine_id="GOR-1-1"):
    return GoroutineArtifact(
        id=goroutine_id, pid=pid, goroutine_address=0x900000, goid=5, status=2, status_name="running",
        is_scanning=False, wait_reason=None, wait_reason_name=None, m_address=None, start_pc=None,
        start_function_name=None, go_pc=None, go_pc_function_name=None, sched_pc=0x140001000,
        sched_sp=0xC000010000, used_syscall_state=False, stack_lo=0xC000000000, stack_hi=0xC000020000,
        stack_size=0x20000, current_function_id=None, current_function_name=None, current_source_file=None,
        current_source_line=None, frames=[], unwind_status=UnwindStatus.COMPLETE,
    )


class TestStringToEdges:
    def test_string_to_network(self):
        net = _network()
        records, errors, stats = correlate_artifacts(1, [], [], [net], [], [], [])
        assert errors == []
        matches = [r for r in records if r.relationship_type == CorrelationType.STRING_TO_NETWORK]
        assert len(matches) == 1
        assert matches[0].source_id == net.source_artifact_id
        assert matches[0].source_type == "string_artifact"
        assert matches[0].target_id == net.id
        assert matches[0].target_type == "network_artifact"

    def test_string_to_credential(self):
        cred = _credential()
        records, _errors, _stats = correlate_artifacts(1, [], [], [], [cred], [], [])
        assert any(r.relationship_type == CorrelationType.STRING_TO_CREDENTIAL for r in records)

    def test_string_to_crypto(self):
        crypto = _crypto()
        records, _errors, _stats = correlate_artifacts(1, [], [], [], [], [crypto], [])
        assert any(r.relationship_type == CorrelationType.STRING_TO_CRYPTO for r in records)

    def test_string_to_persistence(self):
        persist = _persistence()
        records, _errors, _stats = correlate_artifacts(1, [], [], [], [], [], [persist])
        assert any(r.relationship_type == CorrelationType.STRING_TO_PERSISTENCE for r in records)


class TestCrossArtifactEdges:
    def test_network_to_credential(self):
        net = _network(source_id="STR-1-shared")
        cred = _credential(source_id="STR-1-other", network_artifact_id=net.id)
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [cred], [], [])
        matches = [r for r in records if r.relationship_type == CorrelationType.NETWORK_TO_CREDENTIAL]
        assert len(matches) == 1
        assert matches[0].source_id == net.id
        assert matches[0].target_id == cred.id

    def test_network_to_crypto(self):
        net = _network()
        crypto = _crypto(network_artifact_id=net.id)
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [], [crypto], [])
        assert any(r.relationship_type == CorrelationType.NETWORK_TO_CRYPTO for r in records)

    def test_credential_to_crypto(self):
        cred = _credential()
        crypto = _crypto(credential_artifact_id=cred.id)
        records, _errors, _stats = correlate_artifacts(1, [], [], [], [cred], [crypto], [])
        assert any(r.relationship_type == CorrelationType.CREDENTIAL_TO_CRYPTO for r in records)

    def test_network_to_persistence(self):
        net = _network()
        persist = _persistence(network_artifact_id=net.id)
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [], [], [persist])
        assert any(r.relationship_type == CorrelationType.NETWORK_TO_PERSISTENCE for r in records)

    def test_credential_to_persistence(self):
        cred = _credential()
        persist = _persistence(credential_artifact_id=cred.id)
        records, _errors, _stats = correlate_artifacts(1, [], [], [], [cred], [], [persist])
        assert any(r.relationship_type == CorrelationType.CREDENTIAL_TO_PERSISTENCE for r in records)

    def test_crypto_to_persistence(self):
        crypto = _crypto()
        persist = _persistence(crypto_artifact_id=crypto.id)
        records, _errors, _stats = correlate_artifacts(1, [], [], [], [], [crypto], [persist])
        assert any(r.relationship_type == CorrelationType.CRYPTO_TO_PERSISTENCE for r in records)

    def test_no_cross_edge_without_explicit_field(self):
        net = _network()
        cred = _credential()  # network_artifact_id defaults to None
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [cred], [], [])
        assert not any(r.relationship_type == CorrelationType.NETWORK_TO_CREDENTIAL for r in records)


class TestSameSourceString:
    def test_two_artifacts_sharing_source_string_linked(self):
        net = _network(source_id="STR-1-shared")
        cred = _credential(source_id="STR-1-shared")
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [cred], [], [])
        matches = [r for r in records if r.relationship_type == CorrelationType.SAME_SOURCE_STRING]
        assert len(matches) == 1
        ids = {matches[0].source_id, matches[0].target_id}
        assert ids == {net.id, cred.id}

    def test_unrelated_strings_never_linked(self):
        net = _network(source_id="STR-1-a")
        cred = _credential(source_id="STR-1-b")
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [cred], [], [])
        assert not any(r.relationship_type == CorrelationType.SAME_SOURCE_STRING for r in records)

    def test_group_size_bound_skips_pairwise_expansion(self):
        shared = "STR-1-huge-group"
        networks = [_network(source_id=shared) for _ in range(MAX_SAME_SOURCE_GROUP_SIZE + 2)]
        records, errors, _stats = correlate_artifacts(1, [], [], networks, [], [], [])
        assert not any(r.relationship_type == CorrelationType.SAME_SOURCE_STRING for r in records)
        assert any("bound" in e.message.lower() for e in errors)


class TestFunctionGoroutineAssociation:
    def test_function_references_artifact(self):
        func = _function()
        net = _network(function_id=func.id)
        records, _errors, _stats = correlate_artifacts(1, [func], [], [net], [], [], [])
        matches = [r for r in records if r.relationship_type == CorrelationType.FUNCTION_REFERENCES_ARTIFACT]
        assert len(matches) == 1
        assert matches[0].source_id == func.id
        assert matches[0].target_id == net.id

    def test_goroutine_frame_references_artifact(self):
        goroutine = _goroutine()
        net = _network(goroutine_id=goroutine.id)
        records, _errors, _stats = correlate_artifacts(1, [], [goroutine], [net], [], [], [])
        matches = [r for r in records if r.relationship_type == CorrelationType.GOROUTINE_FRAME_REFERENCES_ARTIFACT]
        assert len(matches) == 1

    def test_no_association_without_ids(self):
        net = _network()  # function_id/goroutine_id both None
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [], [], [])
        assert not any(
            r.relationship_type in (CorrelationType.FUNCTION_REFERENCES_ARTIFACT, CorrelationType.GOROUTINE_FRAME_REFERENCES_ARTIFACT)
            for r in records
        )


class TestNoProximityCorrelation:
    def test_same_process_alone_does_not_correlate(self):
        # Two artifacts in the same process, no shared source string, no
        # function/goroutine link, no explicit cross-reference field -
        # must produce zero edges between them.
        net = _network(pid=1, source_id="STR-1-a")
        persist = _persistence(pid=1, source_id="STR-1-b")
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [], [], [persist])
        cross_types = {
            CorrelationType.SAME_SOURCE_STRING, CorrelationType.NETWORK_TO_PERSISTENCE,
        }
        assert not any(r.relationship_type in cross_types for r in records)

    def test_no_relationship_from_nearby_addresses_alone(self):
        net = _network(source_id="STR-1-a")
        net.address = 0x600000
        persist = _persistence(source_id="STR-1-b")
        persist.address = 0x600008  # deliberately adjacent address, unrelated source string
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [], [], [persist])
        assert not any(r.relationship_type == CorrelationType.NETWORK_TO_PERSISTENCE for r in records)


class TestBoundsAndDeterminism:
    def test_correlation_cap_enforced_and_recorded(self):
        networks = [_network(source_id=f"STR-1-{i:04d}") for i in range(MAX_CORRELATIONS_PER_PROCESS + 5)]
        records, errors, stats = correlate_artifacts(1, [], [], networks, [], [], [])
        assert len(records) <= MAX_CORRELATIONS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)

    def test_deterministic_ordering(self):
        net = _network()
        records_a, _e1, _s1 = correlate_artifacts(1, [], [], [net], [], [], [])
        records_b, _e2, _s2 = correlate_artifacts(1, [], [], [net], [], [], [])
        assert [r.id for r in records_a] == [r.id for r in records_b]

    def test_every_record_has_evidence_basis(self):
        net = _network()
        records, _errors, _stats = correlate_artifacts(1, [], [], [net], [], [], [])
        for record in records:
            assert record.evidence_basis
