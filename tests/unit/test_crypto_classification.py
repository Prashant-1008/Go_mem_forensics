"""Unit tests for the Phase 6C string->crypto-artifact classifier
(:func:`gomemforensics.analyzers.crypto.classify_crypto_string`).

Every test here is UNIT-level: pure Python string classification, no
memory reader, no Go runtime structures involved at all.
"""

from __future__ import annotations

from gomemforensics.analyzers.crypto import (
    MAX_STRING_VALUE_LENGTH,
    classify_crypto_string,
    fingerprint_value,
    redact_value,
)
from gomemforensics.analyzers.models import CryptoArtifactType, CryptoValidationStatus
from gomemforensics.common.models import Confidence


def _type(value: str):
    result = classify_crypto_string(value)
    return result.artifact_type if result else None


_FAKE_CERT_BODY = "MIIDdTCCAl2gAwIBAgIUFAKECERTFAKECERTFAKECERTFAKEMA0GCSqGSIb3DQEB"
_FAKE_PUBKEY_BODY = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKveryverysyntheticpublickeybody"


class TestPemCertificates:
    def test_single_complete_certificate(self):
        value = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}\n-----END CERTIFICATE-----"
        result = classify_crypto_string(value)
        assert result.artifact_type == CryptoArtifactType.CERTIFICATE
        assert result.confidence == Confidence.HIGH
        assert result.validation_status == CryptoValidationStatus.STRUCTURALLY_VALID
        assert result.key_type == "certificate"

    def test_certificate_metadata_not_parsed(self):
        value = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}\n-----END CERTIFICATE-----"
        result = classify_crypto_string(value)
        assert "subject" not in result.normalized
        assert "issuer" not in result.normalized
        assert "no certificate content" in result.notes.lower()

    def test_certificate_chain_two_blocks(self):
        block = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}\n-----END CERTIFICATE-----"
        value = block + "\n" + block
        result = classify_crypto_string(value)
        assert result.artifact_type == CryptoArtifactType.CERTIFICATE_CHAIN
        assert result.normalized["count"] == 2

    def test_truncated_certificate_is_incomplete(self):
        value = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}"
        result = classify_crypto_string(value)
        assert result.artifact_type == CryptoArtifactType.CERTIFICATE
        assert result.validation_status == CryptoValidationStatus.STRUCTURALLY_INCOMPLETE
        assert result.confidence == Confidence.LOW

    def test_certificate_never_classified_as_private_key(self):
        value = f"-----BEGIN CERTIFICATE-----\n{_FAKE_CERT_BODY}\n-----END CERTIFICATE-----"
        result = classify_crypto_string(value)
        assert result.artifact_type != CryptoArtifactType.PRIVATE_KEY
        assert result.key_type != "private"


class TestPemPublicKeys:
    def test_generic_public_key(self):
        value = f"-----BEGIN PUBLIC KEY-----\n{_FAKE_PUBKEY_BODY}\n-----END PUBLIC KEY-----"
        result = classify_crypto_string(value)
        assert result.artifact_type == CryptoArtifactType.PUBLIC_KEY
        assert result.key_type == "public"
        assert result.algorithm is None  # PKCS#8/SPKI - algorithm embedded in DER, not determinable from label

    def test_rsa_public_key_algorithm_from_label(self):
        value = f"-----BEGIN RSA PUBLIC KEY-----\n{_FAKE_PUBKEY_BODY}\n-----END RSA PUBLIC KEY-----"
        result = classify_crypto_string(value)
        assert result.artifact_type == CryptoArtifactType.PUBLIC_KEY
        assert result.algorithm == "RSA"

    def test_ec_public_key_algorithm_from_label(self):
        value = f"-----BEGIN EC PUBLIC KEY-----\n{_FAKE_PUBKEY_BODY}\n-----END EC PUBLIC KEY-----"
        result = classify_crypto_string(value)
        assert result.algorithm == "EC"

    def test_truncated_public_key_is_incomplete(self):
        value = f"-----BEGIN PUBLIC KEY-----\n{_FAKE_PUBKEY_BODY}"
        result = classify_crypto_string(value)
        assert result.artifact_type == CryptoArtifactType.PUBLIC_KEY
        assert result.validation_status == CryptoValidationStatus.STRUCTURALLY_INCOMPLETE

    def test_private_key_pem_not_classified_here(self):
        # Private-key PEM material is Phase 6B's scope, reused not
        # re-parsed by this module's string classifier.
        value = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
        assert _type(value) is None


class TestCryptoContext:
    def test_aes_gcm_identifier(self):
        result = classify_crypto_string("AES-256-GCM")
        assert result.artifact_type == CryptoArtifactType.CRYPTO_CONTEXT
        assert result.confidence == Confidence.LOW

    def test_chacha20_poly1305_identifier(self):
        assert _type("ChaCha20-Poly1305") == CryptoArtifactType.CRYPTO_CONTEXT

    def test_ed25519_identifier(self):
        assert _type("Ed25519") == CryptoArtifactType.CRYPTO_CONTEXT

    def test_tls_cipher_suite_name(self):
        result = classify_crypto_string("TLS_AES_128_GCM_SHA256")
        assert result.artifact_type == CryptoArtifactType.CRYPTO_CONTEXT
        assert "not evidence" in result.notes.lower()

    def test_bare_tls_word_not_classified(self):
        # Stage 13: "Do not claim TLS connection detected from a generic
        # string such as ClientHello or TLS alone."
        assert _type("TLS") is None
        assert _type("ClientHello") is None

    def test_bare_algorithm_word_not_classified(self):
        assert _type("AES") is None
        assert _type("hash") is None
        assert _type("encryption") is None


class TestRedactionAndFingerprint:
    def test_short_value_fully_masked(self):
        assert redact_value("abc123") == "******"

    def test_long_value_partially_masked(self):
        redacted = redact_value("abcdefghijklmnopqrstuvwxyz")
        assert "..." in redacted
        assert redacted != "abcdefghijklmnopqrstuvwxyz"

    def test_fingerprint_is_deterministic(self):
        assert fingerprint_value("same-value") == fingerprint_value("same-value")

    def test_fingerprint_differs_for_different_values(self):
        assert fingerprint_value("value-a") != fingerprint_value("value-b")

    def test_fingerprint_is_sha256_hex_length(self):
        assert len(fingerprint_value("anything")) == 64

    def test_fingerprint_never_equals_the_original_value(self):
        value = "some-key-material-shaped-value"
        assert fingerprint_value(value) != value


class TestFalsePositives:
    def test_arbitrary_16_byte_data(self):
        assert _type("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10") is None

    def test_arbitrary_24_byte_data(self):
        assert _type("A" * 24) is None

    def test_arbitrary_32_byte_data(self):
        assert _type("B" * 32) is None

    def test_arbitrary_64_byte_data(self):
        assert _type("C" * 64) is None

    def test_uuid(self):
        assert _type("550e8400-e29b-41d4-a716-446655440000") is None

    def test_sha256_digest_hex(self):
        assert _type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None

    def test_sha512_digest_hex(self):
        assert _type("a" * 128) is None

    def test_md5_digest_hex(self):
        assert _type("d41d8cd98f00b204e9800998ecf8427") is None

    def test_random_base64(self):
        assert _type("SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Qgc3RyaW5n") is None

    def test_random_hex(self):
        assert _type("deadbeefcafebabe0011223344556677") is None

    def test_ip_address(self):
        assert _type("192.168.1.10") is None

    def test_timestamp(self):
        assert _type("2024-01-15T12:30:00Z") is None

    def test_hash_in_source_code_comment(self):
        assert _type("// checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None

    def test_normal_url(self):
        assert _type("https://example.com/path") is None

    def test_go_package_name(self):
        assert _type("crypto/aes") is None
        assert _type("crypto/tls") is None

    def test_algorithm_name_without_crypto_object(self):
        assert _type("the AES algorithm is widely used") is None

    def test_normal_english_text(self):
        assert _type("the quick brown fox jumps over the lazy dog") is None

    def test_empty_string(self):
        assert _type("") is None

    def test_over_length_bound(self):
        assert _type("AES-256-GCM" + "a" * MAX_STRING_VALUE_LENGTH) is None
