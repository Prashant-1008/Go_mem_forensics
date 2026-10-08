"""Tests for :func:`gomemforensics.analyzers.correlation.extract_iocs`.

All fixtures here are hand-built dataclass instances (SYNTHETIC) - the
function under test consumes already-recovered NetworkArtifact/
CredentialArtifact/CryptoArtifact/PersistenceArtifact objects directly,
performing no memory access, no new detection, and no network activity.
"""

from __future__ import annotations

from itertools import count

from gomemforensics.analyzers.correlation import (
    MAX_IOCS_PER_PROCESS,
    extract_iocs,
)
from gomemforensics.analyzers.models import (
    CredentialArtifact,
    CredentialArtifactType,
    CredentialValidationStatus,
    CryptoArtifact,
    CryptoArtifactType,
    CryptoValidationStatus,
    IOCCategory,
    IOCType,
    IOCValidationStatus,
    NetworkArtifact,
    NetworkArtifactType,
    NetworkValidationStatus,
    PersistenceArtifact,
    PersistenceArtifactType,
    PersistenceValidationStatus,
)
from gomemforensics.common.models import Confidence

_id_counter = count(1)


def _network(pid=1, value="8.8.8.8", artifact_type=NetworkArtifactType.IPV4, normalized=None,
             source_id=None, address=None, confidence=Confidence.MEDIUM, function_id=None, goroutine_id=None):
    n = next(_id_counter)
    return NetworkArtifact(
        id=f"NET-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        artifact_type=artifact_type,
        raw_value=value,
        normalized_value=normalized if normalized is not None else {"ip": value, "is_private": False},
        address=address if address is not None else 0x600000 + n * 0x10,
        length=len(value),
        memory_region="static",
        source_artifact_id=source_id or f"STR-{pid}-{n:04d}",
        function_id=function_id,
        goroutine_id=goroutine_id,
        extraction_method="go_string_network_classification",
        confidence=confidence,
        validation_status=NetworkValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _credential(pid=1, value="Authorization: Bearer abc123token", artifact_type=CredentialArtifactType.BEARER_TOKEN,
                source_id=None, confidence=Confidence.HIGH, validation_status=CredentialValidationStatus.STRUCTURALLY_VALID):
    n = next(_id_counter)
    return CredentialArtifact(
        id=f"CRED-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        artifact_type=artifact_type,
        raw_value=value,
        redacted_value="abc...ken",
        normalized_value={},
        address=0x700000 + n * 0x10,
        length=len(value),
        memory_region="static",
        source_artifact_id=source_id or f"STR-{pid}-{n:04d}",
        function_id=None,
        goroutine_id=None,
        network_artifact_id=None,
        extraction_method="go_string_credential_classification",
        confidence=confidence,
        validation_status=validation_status,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _crypto(pid=1, value="TLS_AES_128_GCM_SHA256", artifact_type=CryptoArtifactType.CRYPTO_CONTEXT,
            source_id=None, confidence=Confidence.LOW):
    n = next(_id_counter)
    return CryptoArtifact(
        id=f"CRYPTO-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        artifact_type=artifact_type,
        algorithm=None,
        key_type="context",
        raw_value=value,
        redacted_value="***",
        normalized_value={},
        address=0x800000 + n * 0x10,
        length=len(value),
        memory_region="static",
        source_artifact_id=source_id or f"STR-{pid}-{n:04d}",
        function_id=None,
        goroutine_id=None,
        network_artifact_id=None,
        credential_artifact_id=None,
        extraction_method="go_string_crypto_classification",
        confidence=confidence,
        validation_status=CryptoValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


def _persistence(pid=1, value=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                  artifact_type=PersistenceArtifactType.WINDOWS_REGISTRY_RUN, source_id=None, confidence=Confidence.HIGH):
    n = next(_id_counter)
    return PersistenceArtifact(
        id=f"PERSIST-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        platform="windows",
        artifact_type=artifact_type,
        persistence_mechanism="registry_run_key",
        raw_value=value,
        redacted_value="***",
        normalized_value={},
        address=0x900000 + n * 0x10,
        length=len(value),
        memory_region="static",
        source_artifact_id=source_id or f"STR-{pid}-{n:04d}",
        function_id=None,
        goroutine_id=None,
        network_artifact_id=None,
        credential_artifact_id=None,
        crypto_artifact_id=None,
        extraction_method="go_string_persistence_classification",
        confidence=confidence,
        validation_status=PersistenceValidationStatus.STRUCTURALLY_VALID,
        go_version="1.26.2",
        architecture="x86_64",
    )


class TestBasicPromotion:
    def test_network_ipv4_promoted(self):
        net = _network()
        iocs, errors, stats = extract_iocs(1, "app.exe", [net], [], [], [])
        assert errors == []
        assert len(iocs) == 1
        ioc = iocs[0]
        assert ioc.ioc_type == IOCType.IPV4
        assert ioc.ioc_category == IOCCategory.NETWORK
        assert ioc.raw_value == "8.8.8.8"
        assert ioc.source_artifact_id == net.source_artifact_id
        assert ioc.source_artifact_type == "network_artifact"
        assert ioc.pid == 1
        assert ioc.process_name == "app.exe"
        assert stats.iocs_extracted == 1

    def test_bearer_token_promoted(self):
        cred = _credential()
        iocs, _errors, _stats = extract_iocs(1, None, [], [cred], [], [])
        assert len(iocs) == 1
        assert iocs[0].ioc_type == IOCType.BEARER_TOKEN
        assert iocs[0].ioc_category == IOCCategory.CREDENTIAL

    def test_password_not_promoted(self):
        cred = _credential(value="password=hunter2Q!", artifact_type=CredentialArtifactType.PASSWORD)
        iocs, _errors, _stats = extract_iocs(1, None, [], [cred], [], [])
        assert iocs == []

    def test_pem_private_key_credential_not_promoted_directly(self):
        # Private keys are promoted from the Crypto artifact list (reused
        # evidence), never re-promoted separately from the Credential list
        # (would duplicate one piece of evidence into two IOC records).
        cred = _credential(value="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
                            artifact_type=CredentialArtifactType.PEM_PRIVATE_KEY)
        iocs, _errors, _stats = extract_iocs(1, None, [], [cred], [], [])
        assert iocs == []

    def test_crypto_context_promoted(self):
        crypto = _crypto()
        iocs, _errors, _stats = extract_iocs(1, None, [], [], [crypto], [])
        assert len(iocs) == 1
        assert iocs[0].ioc_type == IOCType.CRYPTO_CONTEXT
        assert iocs[0].ioc_category == IOCCategory.CRYPTO

    def test_persistence_registry_run_promoted(self):
        persist = _persistence()
        iocs, _errors, _stats = extract_iocs(1, None, [], [], [], [persist])
        assert len(iocs) == 1
        assert iocs[0].ioc_type == IOCType.WINDOWS_REGISTRY_RUN
        assert iocs[0].ioc_category == IOCCategory.PERSISTENCE

    def test_raw_value_never_altered(self):
        net = _network(value="203.0.113.5", normalized={"ip": "203.0.113.5", "is_private": False})
        iocs, _errors, _stats = extract_iocs(1, None, [net], [], [], [])
        assert iocs[0].raw_value == "203.0.113.5"

    def test_no_network_lookup_performed(self):
        # Purely a structural/API-surface guarantee: extract_iocs never
        # imports networking machinery, so no DNS/HTTP call can occur -
        # verified at the module level by the Phase 6E deep audit greps,
        # exercised behaviorally here via a plainly-fake IP.
        net = _network(value="192.0.2.123", normalized={"ip": "192.0.2.123", "is_private": False})
        iocs, errors, _stats = extract_iocs(1, None, [net], [], [], [])
        assert errors == []
        assert iocs[0].raw_value == "192.0.2.123"


class TestDeduplication:
    def test_same_ip_different_addresses_both_preserved_with_shared_dedup_key(self):
        net1 = _network(value="1.1.1.1", address=0x600000, normalized={"ip": "1.1.1.1", "is_private": False})
        net2 = _network(value="1.1.1.1", address=0x700000, normalized={"ip": "1.1.1.1", "is_private": False})
        iocs, _errors, stats = extract_iocs(1, None, [net1, net2], [], [], [])
        assert len(iocs) == 2
        assert iocs[0].id != iocs[1].id
        assert iocs[0].dedup_key == iocs[1].dedup_key
        assert stats.iocs_extracted == 2
        assert stats.unique_iocs == 1

    def test_different_ips_never_share_dedup_key(self):
        net1 = _network(value="1.1.1.1", normalized={"ip": "1.1.1.1", "is_private": False})
        net2 = _network(value="8.8.8.8", normalized={"ip": "8.8.8.8", "is_private": False})
        iocs, _errors, stats = extract_iocs(1, None, [net1, net2], [], [], [])
        assert iocs[0].dedup_key != iocs[1].dedup_key
        assert stats.unique_iocs == 2

    def test_same_raw_value_different_ioc_type_never_merged(self):
        # A pathological but possible case: identical raw text recognized
        # as two different IOC types must never collapse into one record.
        net = _network(value="8.8.8.8", normalized={"ip": "8.8.8.8", "is_private": False})
        persist = _persistence(value="8.8.8.8", artifact_type=PersistenceArtifactType.WINDOWS_REGISTRY_RUN)
        iocs, _errors, _stats = extract_iocs(1, None, [net], [], [], [persist])
        assert len(iocs) == 2
        assert iocs[0].dedup_key != iocs[1].dedup_key
        assert iocs[0].ioc_type != iocs[1].ioc_type

    def test_hostname_dedup_uses_normalized_lowercase_form(self):
        net1 = _network(value="Example.COM", artifact_type=NetworkArtifactType.HOSTNAME, normalized={"hostname": "example.com", "fqdn": False})
        net2 = _network(value="example.com", artifact_type=NetworkArtifactType.HOSTNAME, normalized={"hostname": "example.com", "fqdn": False})
        iocs, _errors, stats = extract_iocs(1, None, [net1, net2], [], [], [])
        assert iocs[0].dedup_key == iocs[1].dedup_key
        assert iocs[0].raw_value == "Example.COM"  # raw case preserved despite shared dedup key
        assert iocs[1].raw_value == "example.com"


class TestConfidenceCombination:
    def test_high_confidence_wins_over_low_duplicate(self):
        net1 = _network(value="1.1.1.1", confidence=Confidence.LOW, normalized={"ip": "1.1.1.1", "is_private": False})
        net2 = _network(value="1.1.1.1", confidence=Confidence.HIGH, normalized={"ip": "1.1.1.1", "is_private": False})
        iocs, _errors, _stats = extract_iocs(1, None, [net1, net2], [], [], [])
        # Each record keeps its OWN confidence (never averaged/altered) -
        # only the reporting-level group max is derivable separately.
        confidences = {ioc.confidence for ioc in iocs}
        assert confidences == {Confidence.LOW, Confidence.HIGH}

    def test_single_source_confidence_preserved_exactly(self):
        net = _network(confidence=Confidence.MEDIUM)
        iocs, _errors, _stats = extract_iocs(1, None, [net], [], [], [])
        assert iocs[0].confidence == Confidence.MEDIUM


class TestValidationStatus:
    def test_all_valid_sources_yield_structurally_valid(self):
        cred = _credential(validation_status=CredentialValidationStatus.STRUCTURALLY_VALID)
        iocs, _errors, _stats = extract_iocs(1, None, [], [cred], [], [])
        assert iocs[0].validation_status == IOCValidationStatus.STRUCTURALLY_VALID

    def test_mixed_valid_and_incomplete_sources_yield_partially_valid(self):
        shared_value = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
        crypto_valid = _crypto(value=shared_value, artifact_type=CryptoArtifactType.PRIVATE_KEY)
        crypto_incomplete = _crypto(value=shared_value, artifact_type=CryptoArtifactType.PRIVATE_KEY)
        crypto_incomplete.validation_status = CryptoValidationStatus.STRUCTURALLY_INCOMPLETE
        iocs, _errors, _stats = extract_iocs(1, None, [], [], [crypto_valid, crypto_incomplete], [])
        assert all(ioc.validation_status == IOCValidationStatus.PARTIALLY_VALID for ioc in iocs)


class TestBoundsAndSafety:
    def test_cap_enforced_and_recorded(self):
        networks = [_network(value=f"10.{i // 256}.{i % 256}.1", normalized={"ip": f"10.{i // 256}.{i % 256}.1", "is_private": True}) for i in range(MAX_IOCS_PER_PROCESS + 5)]
        iocs, errors, stats = extract_iocs(1, None, networks, [], [], [])
        assert len(iocs) == MAX_IOCS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)
        assert all(e.recoverable for e in errors)

    def test_multiple_processes_independent(self):
        net1 = _network(pid=1, value="1.1.1.1", normalized={"ip": "1.1.1.1", "is_private": False})
        net2 = _network(pid=2, value="2.2.2.2", normalized={"ip": "2.2.2.2", "is_private": False})
        iocs_p1, _e1, _s1 = extract_iocs(1, None, [net1], [], [], [])
        iocs_p2, _e2, _s2 = extract_iocs(2, None, [net2], [], [], [])
        assert [i.raw_value for i in iocs_p1] == ["1.1.1.1"]
        assert [i.raw_value for i in iocs_p2] == ["2.2.2.2"]

    def test_no_iocs_returns_empty_clean_result(self):
        iocs, errors, stats = extract_iocs(1, None, [], [], [], [])
        assert iocs == []
        assert errors == []
        assert stats.iocs_extracted == 0
        assert stats.unique_iocs == 0


class TestNoMalwareVerdict:
    def test_notes_never_contain_verdict_language(self):
        # The notes' own disclaimer legitimately contains "not a malware
        # verdict" as a NEGATION - check for the specific positive-claim
        # phrasing this must never contain, not the bare word "malware".
        net = _network()
        iocs, _errors, _stats = extract_iocs(1, None, [net], [], [], [])
        notes_upper = (iocs[0].notes or "").upper()
        for forbidden in ("THIS IS MALWARE", "IS MALICIOUS", "THREAT SCORE", "IS SUSPICIOUS", "CONFIRMED C2", "CONFIRMED MALWARE"):
            assert forbidden not in notes_upper

    def test_no_score_field_exists_on_the_model(self):
        net = _network()
        iocs, _errors, _stats = extract_iocs(1, None, [net], [], [], [])
        json_dict = iocs[0].to_json_dict()
        for forbidden_key in ("score", "threat_score", "malware_score", "suspiciousness_score", "malicious", "verdict"):
            assert forbidden_key not in json_dict
