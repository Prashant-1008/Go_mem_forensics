"""Unit tests for the Phase 6B string->credential-artifact classifier
(:func:`gomemforensics.analyzers.credentials.classify_credential_string`).

Every test here is UNIT-level: pure Python string classification, no
memory reader, no Go runtime structures involved at all.
"""

from __future__ import annotations

from gomemforensics.analyzers.credentials import (
    MAX_STRING_VALUE_LENGTH,
    classify_credential_string,
    redact_value,
)
from gomemforensics.analyzers.models import CredentialArtifactType, CredentialValidationStatus
from gomemforensics.common.models import Confidence


def _type(value: str):
    result = classify_credential_string(value)
    return result.artifact_type if result else None


class TestPemPrivateKeys:
    def test_complete_rsa_private_key(self):
        value = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.PEM_PRIVATE_KEY
        assert result.confidence == Confidence.HIGH
        assert result.validation_status == CredentialValidationStatus.STRUCTURALLY_VALID
        assert result.normalized["complete"] is True

    def test_complete_generic_private_key(self):
        value = "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----"
        assert _type(value) == CredentialArtifactType.PEM_PRIVATE_KEY

    def test_complete_ec_private_key(self):
        value = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQ...\n-----END EC PRIVATE KEY-----"
        assert _type(value) == CredentialArtifactType.PEM_PRIVATE_KEY

    def test_complete_openssh_private_key(self):
        value = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n-----END OPENSSH PRIVATE KEY-----"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.SSH_PRIVATE_KEY

    def test_incomplete_key_is_fragment(self):
        value = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK..."
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.PRIVATE_KEY_FRAGMENT
        assert result.validation_status == CredentialValidationStatus.STRUCTURALLY_INCOMPLETE
        assert result.confidence == Confidence.LOW

    def test_certificate_block_alone_not_classified(self):
        # A public certificate is not itself secret-like.
        value = "-----BEGIN CERTIFICATE-----\nMIIDdTCCAl2g...\n-----END CERTIFICATE-----"
        assert _type(value) is None


class TestDatabaseConnectionStrings:
    def test_postgres_with_password(self):
        value = "postgres://admin:s3cr3t@db.internal:5432/appdb"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.DATABASE_CREDENTIAL
        assert result.confidence == Confidence.HIGH
        assert result.normalized["username"] == "admin"
        assert result.normalized["has_password"] is True
        assert result.normalized["database"] == "appdb"

    def test_mysql_username_only(self):
        value = "mysql://readonly@db.internal/appdb"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.DATABASE_CREDENTIAL
        assert result.confidence == Confidence.MEDIUM
        assert result.normalized["has_password"] is False

    def test_mongodb_srv(self):
        value = "mongodb+srv://user:pass@cluster0.example.mongodb.net/mydb"
        assert _type(value) == CredentialArtifactType.DATABASE_CREDENTIAL

    def test_http_url_not_classified_as_database_credential(self):
        # http/https belong to Phase 6A's network analyzer, not this one -
        # even with embedded userinfo, this analyzer defers to that scope.
        assert _type("http://user:pass@example.com/") is None

    def test_url_without_userinfo_not_classified(self):
        assert _type("postgres://db.internal:5432/appdb") is None


class TestAuthorizationHeaders:
    def test_bearer_full_header(self):
        value = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJ"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.BEARER_TOKEN
        assert result.confidence == Confidence.HIGH

    def test_bearer_bare_form(self):
        value = "Bearer abc123.def456-ghi789_jkl"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.BEARER_TOKEN

    def test_bearer_with_prose_rejected(self):
        # "Bearer" as an ordinary English word, not a token structure.
        assert _type("Bearer of good news travels fast") is None

    def test_basic_auth_decodes_successfully(self):
        # "Aladdin:open sesame" - the exact example from Go's own
        # net/http source comment (parseBasicAuth).
        value = "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.BASIC_AUTH
        assert result.normalized["username"] == "Aladdin"
        assert result.confidence == Confidence.HIGH

    def test_basic_auth_malformed_base64_downgrades_gracefully(self):
        value = "Authorization: Basic not-valid-base64!!!"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.AUTHORIZATION_HEADER
        assert result.normalized["decoded"] is False

    def test_generic_scheme_recognized_but_not_decoded(self):
        value = "Authorization: Digest username=\"foo\", realm=\"bar\""
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.AUTHORIZATION_HEADER
        assert result.normalized["scheme"] == "Digest"


class TestCookies:
    def test_cookie_header(self):
        value = "Cookie: theme=dark; lang=en"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.COOKIE
        assert result.normalized["cookie_name"] == "theme"

    def test_set_cookie_header(self):
        value = "Set-Cookie: session=abc123; Path=/; HttpOnly"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.SESSION_TOKEN
        assert result.normalized["cookie_name"] == "session"

    def test_jsessionid_recognized_as_session(self):
        value = "Cookie: JSESSIONID=A1B2C3D4E5"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.SESSION_TOKEN

    def test_non_cookie_header_text_rejected(self):
        assert _type("theme=dark; lang=en") is None


class TestJwt:
    def test_valid_shaped_jwt_with_decodable_header(self):
        # {"alg":"HS256","typ":"JWT"} base64url-encoded, plus a plausible
        # payload/signature segment.
        value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.JWT
        assert result.confidence == Confidence.MEDIUM
        assert result.normalized["header_alg"] == "HS256"
        assert "not verified" in result.notes.lower() or "not" in result.notes.lower()

    def test_three_segment_shape_without_decodable_header_is_low_confidence(self):
        value = "notbase64header.somepayloadsegment.somesignaturesegment"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.JWT
        assert result.confidence == Confidence.LOW

    def test_semantic_version_not_misclassified(self):
        assert _type("1.2.3") is None

    def test_two_segments_rejected(self):
        assert _type("abcdefghij.klmnop") is None


class TestUsernamePasswordPairs:
    def test_same_string_pair_recognized(self):
        value = "username=alice password=Sup3rSecret!"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.USERNAME_PASSWORD
        assert result.normalized["username"] == "alice"

    def test_user_pass_colon_form(self):
        value = "user:alice, pass:Sup3rSecret!"
        result = classify_credential_string(value)
        assert result.artifact_type == CredentialArtifactType.USERNAME_PASSWORD

    def test_standalone_username_not_a_pair(self):
        assert _type("username=alice") == CredentialArtifactType.USERNAME

    def test_standalone_password_not_a_pair(self):
        assert _type("password=Sup3rSecret!") == CredentialArtifactType.PASSWORD


class TestContextualKeywords:
    def test_password_context(self):
        assert _type("password=hunter2Q!") == CredentialArtifactType.PASSWORD

    def test_client_secret_context(self):
        assert _type("client_secret=abcDEF123456") == CredentialArtifactType.CLIENT_SECRET

    def test_access_token_context(self):
        assert _type("access_token=ya29.a0AfH6SMC") == CredentialArtifactType.ACCESS_TOKEN

    def test_api_key_context(self):
        assert _type("api_key=abcdef0123456789") == CredentialArtifactType.API_KEY

    def test_aws_env_context(self):
        assert _type("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG") == CredentialArtifactType.CLOUD_CREDENTIAL

    def test_auth_token_context(self):
        assert _type("auth_token=abcdef123456") == CredentialArtifactType.AUTH_TOKEN

    def test_bare_token_context_is_low_confidence_auth_token(self):
        result = classify_credential_string("token=abcdef123456")
        assert result.artifact_type == CredentialArtifactType.AUTH_TOKEN
        assert result.confidence == Confidence.LOW

    def test_database_url_env_context(self):
        assert _type("DATABASE_URL=somevalue123") == CredentialArtifactType.ENV_SECRET_LIKE

    def test_generic_secret_context(self):
        assert _type("secret_key=abcdef123456") == CredentialArtifactType.CONFIG_SECRET_LIKE

    def test_json_style_quoted_context(self):
        assert _type('"password": "hunter2Q!"') == CredentialArtifactType.PASSWORD

    def test_equality_comparison_not_misclassified(self):
        # Common Go source pattern: `if password == "admin123456"` - the
        # "==" must never be parsed as a key=value assignment.
        assert _type('if password == "admin123456"') is None

    def test_trivial_short_value_rejected(self):
        assert _type("pwd=1") is None


class TestPrefixedProviderTokens:
    def test_aws_access_key_id_shape(self):
        result = classify_credential_string("AKIAIOSFODNN7EXAMPLE")
        assert result.artifact_type == CredentialArtifactType.CLOUD_CREDENTIAL
        assert "not confirmed" in result.notes.lower()

    def test_github_token_shape(self):
        value = "ghp_" + "a" * 36
        assert _type(value) == CredentialArtifactType.API_KEY

    def test_google_api_key_shape(self):
        value = "AIza" + "A" * 35
        assert _type(value) == CredentialArtifactType.API_KEY

    def test_slack_token_shape(self):
        value = "xoxb-1234567890-abcdefghij"
        assert _type(value) == CredentialArtifactType.API_KEY

    def test_near_miss_prefix_rejected(self):
        assert _type("AKIA-not-the-right-shape") is None


class TestRedaction:
    def test_short_value_fully_masked(self):
        assert redact_value("abc123") == "******"

    def test_long_value_partially_masked(self):
        redacted = redact_value("sk-abcdefghijklmnopqrstuvwxyz1234")
        assert redacted.startswith("sk-")
        assert redacted.endswith("234")
        assert "..." in redacted

    def test_redaction_never_reveals_the_full_value(self):
        value = "hunter2verysecretpassword"
        redacted = redact_value(value)
        assert redacted != value
        assert value not in redacted


class TestFalsePositives:
    def test_normal_english_text(self):
        assert _type("the quick brown fox jumps over the lazy dog") is None

    def test_go_import_path(self):
        assert _type("github.com/user/repo") is None

    def test_filesystem_path(self):
        assert _type("/usr/local/bin/app") is None
        assert _type(r"C:\Users\foo\bar.exe") is None

    def test_url_without_credentials(self):
        assert _type("https://example.com/path") is None

    def test_ip_address(self):
        assert _type("192.168.1.10") is None

    def test_uuid(self):
        assert _type("550e8400-e29b-41d4-a716-446655440000") is None

    def test_sha256_hash(self):
        assert _type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None

    def test_random_high_entropy_string_without_context(self):
        assert _type("xK9$mQ2#vL8@pR4!wN7&") is None

    def test_semantic_version(self):
        assert _type("v1.2.3") is None

    def test_timestamp(self):
        assert _type("2024-01-15T12:30:00Z") is None

    def test_json_without_secret_context(self):
        assert _type('{"name": "example", "count": 42}') is None

    def test_normal_cookie_without_session_keyword(self):
        result = classify_credential_string("Cookie: theme=dark")
        assert result.artifact_type == CredentialArtifactType.COOKIE  # recognized as a cookie, never as a session/auth token

    def test_authorization_word_alone(self):
        assert _type("Authorization") is None

    def test_source_code_containing_password_word(self):
        assert _type("var password string") is None
        assert _type("// TODO: hash the password before storing") is None

    def test_documentation_containing_api_key_phrase(self):
        assert _type("See your API key in account settings") is None

    def test_fixture_marker_string(self):
        assert _type("GOMEMFORENSICS_FIXTURE_STATIC_MARKER_39f1") is None

    def test_public_key_pem_not_classified_as_private(self):
        value = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEB...\n-----END PUBLIC KEY-----"
        assert _type(value) is None

    def test_base64_blob_without_context(self):
        assert _type("SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Qgc3RyaW5n") is None

    def test_empty_string(self):
        assert _type("") is None

    def test_over_length_bound(self):
        assert _type("password=" + "a" * MAX_STRING_VALUE_LENGTH) is None
