"""Tests for :func:`gomemforensics.analyzers.findings.generate_findings`.

All fixtures are hand-built dataclass instances (SYNTHETIC) - finding
generation consumes only already-recovered IOCArtifact/CorrelationRecord
objects, performing no memory access, no new detection, and no network
activity.
"""

from __future__ import annotations

from itertools import count

from gomemforensics.analyzers.findings import MAX_FINDINGS_PER_PROCESS, generate_findings
from gomemforensics.analyzers.models import (
    CorrelationRecord,
    CorrelationType,
    Finding,
    FindingSeverity,
    FindingType,
    FindingValidationStatus,
    IOCArtifact,
    IOCCategory,
    IOCType,
    IOCValidationStatus,
)
from gomemforensics.common.models import Confidence

_id_counter = count(1)


def _ioc(pid=1, ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK, raw_value="8.8.8.8",
         dedup_key=None, source_id=None, confidence=Confidence.MEDIUM,
         validation_status=IOCValidationStatus.STRUCTURALLY_VALID, function_id=None, goroutine_id=None,
         related_network=None, related_credential=None, related_crypto=None, related_persistence=None,
         ioc_id=None):
    n = next(_id_counter)
    source = source_id or f"STR-{pid}-{n:04d}"
    return IOCArtifact(
        id=ioc_id or f"IOC-{pid}-{n:04d}",
        pid=pid,
        process_name=None,
        ioc_type=ioc_type,
        ioc_category=ioc_category,
        raw_value=raw_value,
        normalized_value={},
        redacted_value=None,
        address=0x600000 + n * 0x10,
        length=len(raw_value),
        memory_region="static",
        source_artifact_id=source,
        source_artifact_type="network_artifact",
        dedup_key=dedup_key or f"{ioc_type.value}:{raw_value}",
        function_id=function_id,
        goroutine_id=goroutine_id,
        related_network_artifact_id=related_network,
        related_credential_artifact_id=related_credential,
        related_crypto_artifact_id=related_crypto,
        related_persistence_artifact_id=related_persistence,
        confidence=confidence,
        validation_status=validation_status,
        extraction_method="go_string_network_classification",
        go_version="1.26.2",
        architecture="x86_64",
    )


def _correlation(pid, relationship_type, source_id, target_id, source_type="network_artifact", target_type="credential_artifact"):
    n = next(_id_counter)
    return CorrelationRecord(
        id=f"CORR-{pid}-{n:04d}",
        pid=pid,
        relationship_type=relationship_type,
        source_id=source_id,
        source_type=source_type,
        target_id=target_id,
        target_type=target_type,
        evidence_basis="shared source_artifact_id",
    )


class TestEvidenceRules:
    def test_ipv4_produces_network_ip_observed(self):
        ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK)
        findings, errors, stats = generate_findings(1, "app.exe", [ioc], [])
        assert errors == []
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.NETWORK_IP_OBSERVED
        assert findings[0].pid == 1
        assert findings[0].process_name == "app.exe"

    def test_ipv6_also_produces_network_ip_observed(self):
        ioc = _ioc(ioc_type=IOCType.IPV6, ioc_category=IOCCategory.NETWORK, raw_value="::1", dedup_key="ipv6:::1")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.NETWORK_IP_OBSERVED

    def test_hostname_produces_network_hostname_observed(self):
        ioc = _ioc(ioc_type=IOCType.HOSTNAME, ioc_category=IOCCategory.NETWORK, raw_value="example.com")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.NETWORK_HOSTNAME_OBSERVED

    def test_url_produces_network_url_observed(self):
        ioc = _ioc(ioc_type=IOCType.URL, ioc_category=IOCCategory.NETWORK, raw_value="https://example.com")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.NETWORK_URL_OBSERVED

    def test_host_port_produces_network_endpoint_observed(self):
        ioc = _ioc(ioc_type=IOCType.HOST_PORT, ioc_category=IOCCategory.NETWORK, raw_value="1.2.3.4:443")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.NETWORK_ENDPOINT_OBSERVED

    def test_bearer_token_produces_authorization_material_observed(self):
        ioc = _ioc(ioc_type=IOCType.BEARER_TOKEN, ioc_category=IOCCategory.CREDENTIAL, raw_value="Bearer abc")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.AUTHORIZATION_MATERIAL_OBSERVED

    def test_cookie_produces_session_material_observed(self):
        ioc = _ioc(ioc_type=IOCType.COOKIE, ioc_category=IOCCategory.CREDENTIAL, raw_value="Cookie: a=b")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.SESSION_MATERIAL_OBSERVED

    def test_database_credential_produces_database_credential_observed(self):
        ioc = _ioc(ioc_type=IOCType.DATABASE_CREDENTIAL, ioc_category=IOCCategory.CREDENTIAL, raw_value="postgres://u:p@h/d")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.DATABASE_CREDENTIAL_OBSERVED

    def test_jwt_and_api_key_and_cloud_credential_produce_token_observed(self):
        for ioc_type, value in ((IOCType.JWT, "a.b.c"), (IOCType.API_KEY, "AKIA1234567890ABCDEF"), (IOCType.CLOUD_CREDENTIAL, "AKIAIOSFODNN7EXAMPLE")):
            ioc = _ioc(ioc_type=ioc_type, ioc_category=IOCCategory.CREDENTIAL, raw_value=value)
            findings, _errors, _stats = generate_findings(1, None, [ioc], [])
            assert findings[0].finding_type == FindingType.TOKEN_OBSERVED, f"failed for {ioc_type}"

    def test_public_key_produces_crypto_public_key_observed(self):
        ioc = _ioc(ioc_type=IOCType.PUBLIC_KEY, ioc_category=IOCCategory.CRYPTO, raw_value="-----BEGIN PUBLIC KEY-----")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.CRYPTO_PUBLIC_KEY_OBSERVED

    def test_private_key_produces_crypto_private_key_observed(self):
        ioc = _ioc(ioc_type=IOCType.PRIVATE_KEY, ioc_category=IOCCategory.CRYPTO, raw_value="-----BEGIN PRIVATE KEY-----")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.CRYPTO_PRIVATE_KEY_OBSERVED

    def test_certificate_and_chain_produce_certificate_observed(self):
        for ioc_type in (IOCType.CERTIFICATE, IOCType.CERTIFICATE_CHAIN):
            ioc = _ioc(ioc_type=ioc_type, ioc_category=IOCCategory.CRYPTO, raw_value="-----BEGIN CERTIFICATE-----")
            findings, _errors, _stats = generate_findings(1, None, [ioc], [])
            assert findings[0].finding_type == FindingType.CERTIFICATE_OBSERVED

    def test_crypto_context_produces_crypto_context_observed(self):
        ioc = _ioc(ioc_type=IOCType.CRYPTO_CONTEXT, ioc_category=IOCCategory.CRYPTO, raw_value="AES-256-GCM")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.CRYPTO_CONTEXT_OBSERVED

    def test_aes_key_produces_aes_key_observed(self):
        ioc = _ioc(ioc_type=IOCType.AES_KEY, ioc_category=IOCCategory.CRYPTO, raw_value="A" * 32)
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.AES_KEY_OBSERVED

    def test_windows_persistence_type_produces_windows_persistence_reference(self):
        ioc = _ioc(ioc_type=IOCType.WINDOWS_REGISTRY_RUN, ioc_category=IOCCategory.PERSISTENCE, raw_value=r"HKCU\Run")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.WINDOWS_PERSISTENCE_REFERENCE
        assert findings[0].platform == "windows"

    def test_linux_persistence_type_produces_linux_persistence_reference(self):
        ioc = _ioc(ioc_type=IOCType.LINUX_CRON, ioc_category=IOCCategory.PERSISTENCE, raw_value="/etc/cron.d/x")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type == FindingType.LINUX_PERSISTENCE_REFERENCE
        assert findings[0].platform == "linux"

    def test_no_finding_for_non_qualifying_ioc_category_combination(self):
        # A category/type mismatch that should never occur in real data,
        # but confirms the rule tables are consulted per-category, not a
        # blanket type->finding lookup.
        ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.PERSISTENCE)
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings == []


class TestDeduplication:
    def test_same_dedup_key_produces_one_finding_with_all_evidence(self):
        ioc1 = _ioc(dedup_key="ipv4:1.1.1.1", source_id="STR-1-a", raw_value="1.1.1.1")
        ioc2 = _ioc(dedup_key="ipv4:1.1.1.1", source_id="STR-1-b", raw_value="1.1.1.1")
        findings, _errors, stats = generate_findings(1, None, [ioc1, ioc2], [])
        assert len(findings) == 1
        assert set(findings[0].supporting_ioc_ids) == {ioc1.id, ioc2.id}
        assert set(findings[0].supporting_artifact_ids) == {"STR-1-a", "STR-1-b"}
        assert stats.findings_generated == 1

    def test_different_dedup_keys_produce_separate_findings(self):
        ioc1 = _ioc(dedup_key="ipv4:1.1.1.1", raw_value="1.1.1.1")
        ioc2 = _ioc(dedup_key="ipv4:8.8.8.8", raw_value="8.8.8.8")
        findings, _errors, _stats = generate_findings(1, None, [ioc1, ioc2], [])
        assert len(findings) == 2

    def test_different_finding_types_never_merge_even_with_same_raw_value(self):
        ioc1 = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK, raw_value="8.8.8.8", dedup_key="ipv4:8.8.8.8")
        ioc2 = _ioc(ioc_type=IOCType.WINDOWS_REGISTRY_RUN, ioc_category=IOCCategory.PERSISTENCE, raw_value="8.8.8.8", dedup_key="windows_registry_run:8.8.8.8")
        findings, _errors, _stats = generate_findings(1, None, [ioc1, ioc2], [])
        assert len(findings) == 2
        assert {f.finding_type for f in findings} == {FindingType.NETWORK_IP_OBSERVED, FindingType.WINDOWS_PERSISTENCE_REFERENCE}


class TestConfidenceAndValidation:
    def test_confidence_propagated_from_single_source(self):
        ioc = _ioc(confidence=Confidence.HIGH)
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].confidence == Confidence.HIGH

    def test_group_confidence_is_max_not_average(self):
        ioc1 = _ioc(dedup_key="ipv4:1.1.1.1", confidence=Confidence.LOW, raw_value="1.1.1.1")
        ioc2 = _ioc(dedup_key="ipv4:1.1.1.1", confidence=Confidence.HIGH, raw_value="1.1.1.1")
        findings, _errors, _stats = generate_findings(1, None, [ioc1, ioc2], [])
        assert findings[0].confidence == Confidence.HIGH

    def test_all_valid_sources_yield_structurally_valid(self):
        ioc = _ioc(validation_status=IOCValidationStatus.STRUCTURALLY_VALID)
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].validation_status == FindingValidationStatus.STRUCTURALLY_VALID

    def test_mixed_validity_yields_partially_valid(self):
        ioc1 = _ioc(dedup_key="k", validation_status=IOCValidationStatus.STRUCTURALLY_VALID)
        ioc2 = _ioc(dedup_key="k", validation_status=IOCValidationStatus.STRUCTURALLY_INCOMPLETE)
        findings, _errors, _stats = generate_findings(1, None, [ioc1, ioc2], [])
        assert findings[0].validation_status == FindingValidationStatus.PARTIALLY_VALID


class TestSeverity:
    def test_network_findings_are_informational(self):
        ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK)
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].severity == FindingSeverity.INFORMATIONAL

    def test_credential_findings_are_medium(self):
        ioc = _ioc(ioc_type=IOCType.BEARER_TOKEN, ioc_category=IOCCategory.CREDENTIAL, raw_value="Bearer x")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].severity == FindingSeverity.MEDIUM

    def test_private_key_and_aes_key_are_high(self):
        for ioc_type, value in ((IOCType.PRIVATE_KEY, "-----BEGIN PRIVATE KEY-----"), (IOCType.AES_KEY, "A" * 32)):
            ioc = _ioc(ioc_type=ioc_type, ioc_category=IOCCategory.CRYPTO, raw_value=value)
            findings, _errors, _stats = generate_findings(1, None, [ioc], [])
            assert findings[0].severity == FindingSeverity.HIGH

    def test_public_key_and_certificate_and_context_are_low(self):
        for ioc_type, value in ((IOCType.PUBLIC_KEY, "-----BEGIN PUBLIC KEY-----"), (IOCType.CERTIFICATE, "-----BEGIN CERTIFICATE-----"), (IOCType.CRYPTO_CONTEXT, "AES-256-GCM")):
            ioc = _ioc(ioc_type=ioc_type, ioc_category=IOCCategory.CRYPTO, raw_value=value)
            findings, _errors, _stats = generate_findings(1, None, [ioc], [])
            assert findings[0].severity == FindingSeverity.LOW

    def test_severity_is_not_a_maliciousness_score(self):
        # Structural guarantee: FindingSeverity has exactly 4 fixed
        # values, none named after maliciousness/probability.
        allowed = {"informational", "low", "medium", "high"}
        assert {s.value for s in FindingSeverity} == allowed


class TestCorrelationFindings:
    def test_network_to_credential_produces_multi_artifact_evidence(self):
        net_ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK, ioc_id="IOC-1-net", related_network="NET-1-0001")
        cred_ioc = _ioc(ioc_type=IOCType.BEARER_TOKEN, ioc_category=IOCCategory.CREDENTIAL, ioc_id="IOC-1-cred", related_credential="CRED-1-0001", raw_value="Bearer x")
        corr = _correlation(1, CorrelationType.NETWORK_TO_CREDENTIAL, "NET-1-0001", "CRED-1-0001")
        findings, _errors, _stats = generate_findings(1, None, [net_ioc, cred_ioc], [corr])
        multi = [f for f in findings if f.finding_type == FindingType.MULTI_ARTIFACT_EVIDENCE]
        assert len(multi) == 1
        assert corr.id in multi[0].supporting_correlation_ids
        assert {net_ioc.id, cred_ioc.id} == set(multi[0].supporting_ioc_ids)

    def test_same_source_string_produces_shared_source_evidence(self):
        net_ioc = _ioc(ioc_type=IOCType.URL, ioc_category=IOCCategory.NETWORK, ioc_id="IOC-1-net", related_network="NET-1-0001", raw_value="https://x")
        cred_ioc = _ioc(ioc_type=IOCType.DATABASE_CREDENTIAL, ioc_category=IOCCategory.CREDENTIAL, ioc_id="IOC-1-cred", related_credential="CRED-1-0001", raw_value="postgres://u:p@h/d")
        corr = _correlation(1, CorrelationType.SAME_SOURCE_STRING, "NET-1-0001", "CRED-1-0001")
        findings, _errors, _stats = generate_findings(1, None, [net_ioc, cred_ioc], [corr])
        shared = [f for f in findings if f.finding_type == FindingType.SHARED_SOURCE_EVIDENCE]
        assert len(shared) == 1

    def test_correlation_without_both_iocs_produces_no_finding(self):
        net_ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK, ioc_id="IOC-1-net", related_network="NET-1-0001")
        # No corresponding IOC exists for CRED-1-nonexistent (e.g. a raw
        # PASSWORD credential, never promoted to IOC status).
        corr = _correlation(1, CorrelationType.NETWORK_TO_CREDENTIAL, "NET-1-0001", "CRED-1-nonexistent")
        findings, _errors, _stats = generate_findings(1, None, [net_ioc], [corr])
        assert not any(f.finding_type == FindingType.MULTI_ARTIFACT_EVIDENCE for f in findings)

    def test_string_to_x_and_function_reference_correlations_produce_no_finding(self):
        # STRING_TO_NETWORK / FUNCTION_REFERENCES_ARTIFACT are context,
        # already folded into the IOC-based finding's own
        # supporting_artifact_ids/function_ids - never a separate finding.
        net_ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK, ioc_id="IOC-1-net", related_network="NET-1-0001")
        corr1 = _correlation(1, CorrelationType.STRING_TO_NETWORK, "STR-1-0001", "NET-1-0001", source_type="string_artifact", target_type="network_artifact")
        corr2 = _correlation(1, CorrelationType.FUNCTION_REFERENCES_ARTIFACT, "FUNC-1-abc", "NET-1-0001", source_type="function", target_type="network_artifact")
        findings, _errors, _stats = generate_findings(1, None, [net_ioc], [corr1, corr2])
        # Only the plain IOC-based NETWORK_IP_OBSERVED finding exists.
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.NETWORK_IP_OBSERVED


class TestFunctionGoroutineContext:
    def test_function_id_included_never_a_behavioral_claim(self):
        ioc = _ioc(function_id="FUNC-1-abc")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].function_ids == ["FUNC-1-abc"]
        assert "contacted" not in findings[0].interpretation.lower()
        assert "established" not in findings[0].observed_evidence.lower()

    def test_goroutine_id_included_never_a_behavioral_claim(self):
        ioc = _ioc(goroutine_id="GOR-1-1")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].goroutine_ids == ["GOR-1-1"]


class TestProhibitedInference:
    def test_ip_never_produces_c2_established(self):
        ioc = _ioc(ioc_type=IOCType.IPV4, ioc_category=IOCCategory.NETWORK)
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        types = {f.finding_type.value for f in findings}
        assert not any("c2" in t or "established" in t for t in types)

    def test_persistence_never_produces_persistence_established(self):
        # The interpretation's own disclaimer legitimately contains "...
        # was established" as part of a NEGATION ("not proof that...
        # persistence was established") - check for the specific
        # positive-claim phrasing this must never contain.
        ioc = _ioc(ioc_type=IOCType.WINDOWS_REGISTRY_RUN, ioc_category=IOCCategory.PERSISTENCE, raw_value=r"HKCU\Run")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        assert findings[0].finding_type != "persistence_established"
        text = (findings[0].observed_evidence + findings[0].interpretation).lower()
        assert "malware established" not in text
        assert "persistence was successfully established" not in text
        assert "not proof" in text or "not evidence" in text

    def test_credential_never_produces_credential_theft(self):
        ioc = _ioc(ioc_type=IOCType.BEARER_TOKEN, ioc_category=IOCCategory.CREDENTIAL, raw_value="Bearer x")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        text = (findings[0].title + findings[0].observed_evidence + findings[0].interpretation).lower()
        assert "theft" not in text
        assert "stolen" not in text

    def test_url_plus_credential_never_produces_data_exfiltration(self):
        net_ioc = _ioc(ioc_type=IOCType.URL, ioc_category=IOCCategory.NETWORK, ioc_id="IOC-1-net", related_network="NET-1-0001", raw_value="https://x")
        cred_ioc = _ioc(ioc_type=IOCType.BEARER_TOKEN, ioc_category=IOCCategory.CREDENTIAL, ioc_id="IOC-1-cred", related_credential="CRED-1-0001", raw_value="Bearer x")
        corr = _correlation(1, CorrelationType.NETWORK_TO_CREDENTIAL, "NET-1-0001", "CRED-1-0001")
        findings, _errors, _stats = generate_findings(1, None, [net_ioc, cred_ioc], [corr])
        all_text = " ".join(f.title + f.observed_evidence + f.interpretation for f in findings).lower()
        assert "exfiltrat" not in all_text

    def test_private_key_never_produces_key_usage_confirmed(self):
        ioc = _ioc(ioc_type=IOCType.PRIVATE_KEY, ioc_category=IOCCategory.CRYPTO, raw_value="-----BEGIN PRIVATE KEY-----")
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        text = (findings[0].observed_evidence + findings[0].interpretation).lower()
        assert "confirmed" not in text
        assert "used to sign" not in text or "not evidence" in text

    def test_no_score_or_verdict_fields_on_the_model(self):
        ioc = _ioc()
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        json_dict = findings[0].to_json_dict()
        for forbidden_key in ("score", "threat_score", "malware_score", "malware_probability", "risk_score", "verdict", "malicious"):
            assert forbidden_key not in json_dict


class TestBoundsAndSafety:
    def test_cap_enforced_and_recorded(self):
        iocs = [_ioc(dedup_key=f"ipv4:10.0.0.{i}", raw_value=f"10.0.0.{i}") for i in range(MAX_FINDINGS_PER_PROCESS + 5)]
        findings, errors, stats = generate_findings(1, None, iocs, [])
        assert len(findings) == MAX_FINDINGS_PER_PROCESS
        assert stats.capped is True
        assert any("cap" in e.message.lower() for e in errors)

    def test_no_iocs_or_correlations_returns_empty_clean_result(self):
        findings, errors, stats = generate_findings(1, None, [], [])
        assert findings == []
        assert errors == []
        assert stats.findings_generated == 0

    def test_deterministic_ordering(self):
        ioc = _ioc()
        findings_a, _e1, _s1 = generate_findings(1, None, [ioc], [])
        findings_b, _e2, _s2 = generate_findings(1, None, [ioc], [])
        assert [f.finding_id for f in findings_a] == [f.finding_id for f in findings_b]


class TestProvenance:
    def test_provenance_present_and_traces_to_supporting_ioc(self):
        ioc = _ioc()
        findings, _errors, _stats = generate_findings(1, None, [ioc], [])
        finding = findings[0]
        assert finding.provenance is not None
        assert ioc.id in finding.provenance.related_artifacts
        assert ioc.source_artifact_id in finding.provenance.related_artifacts
