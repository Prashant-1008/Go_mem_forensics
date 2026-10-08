"""Unit tests for the Phase 6A string->network-artifact classifier
(:func:`gomemforensics.analyzers.network.classify_network_string`).

Every test here is UNIT-level: pure Python string classification, no
memory reader, no Go runtime structures involved at all - the classifier
itself has no Go-version or architecture dependency (see
gomemforensics/analyzers/network.py's module docstring).
"""

from __future__ import annotations

from gomemforensics.analyzers.models import NetworkArtifactType
from gomemforensics.analyzers.network import MAX_STRING_VALUE_LENGTH, classify_network_string


def _type(value: str):
    result = classify_network_string(value)
    return result.artifact_type if result else None


class TestIPv4:
    def test_valid_public(self):
        result = classify_network_string("8.8.8.8")
        assert result.artifact_type == NetworkArtifactType.IPV4
        assert result.normalized["ip"] == "8.8.8.8"
        assert result.normalized["is_private"] is False

    def test_valid_private(self):
        result = classify_network_string("192.168.1.10")
        assert result.artifact_type == NetworkArtifactType.IPV4
        assert result.normalized["is_private"] is True

    def test_loopback(self):
        result = classify_network_string("127.0.0.1")
        assert result.artifact_type == NetworkArtifactType.IPV4
        assert result.normalized["is_loopback"] is True

    def test_broadcast(self):
        result = classify_network_string("255.255.255.255")
        assert result.artifact_type == NetworkArtifactType.IPV4

    def test_invalid_octet_rejected(self):
        assert _type("192.168.1.256") is None

    def test_too_few_octets_rejected(self):
        assert _type("192.168.1") is None

    def test_too_many_octets_rejected(self):
        assert _type("192.168.1.1.1") is None

    def test_leading_zero_octet_rejected(self):
        # Ambiguous (could imply octal) - Python's ipaddress module itself
        # rejects this; relied upon rather than re-implemented.
        assert _type("192.168.001.1") is None


class TestIPv6:
    def test_loopback(self):
        result = classify_network_string("::1")
        assert result.artifact_type == NetworkArtifactType.IPV6
        assert result.normalized["is_loopback"] is True

    def test_compressed_form(self):
        result = classify_network_string("2001:db8::1")
        assert result.artifact_type == NetworkArtifactType.IPV6

    def test_full_form(self):
        result = classify_network_string("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert result.artifact_type == NetworkArtifactType.IPV6

    def test_ipv4_mapped(self):
        result = classify_network_string("::ffff:192.168.1.1")
        assert result.artifact_type == NetworkArtifactType.IPV6

    def test_invalid_form_rejected(self):
        assert _type("2001:zzzz::1") is None

    def test_too_few_groups_without_compression_rejected(self):
        assert _type("1:2:3:4:5") is None


class TestHostnames:
    def test_normal_domain(self):
        result = classify_network_string("example.com")
        assert result.artifact_type == NetworkArtifactType.HOSTNAME
        assert result.normalized["hostname"] == "example.com"

    def test_subdomain(self):
        result = classify_network_string("api.internal.example.com")
        assert result.artifact_type == NetworkArtifactType.HOSTNAME

    def test_localhost(self):
        result = classify_network_string("localhost")
        assert result.artifact_type == NetworkArtifactType.HOSTNAME
        assert result.normalized["hostname"] == "localhost"

    def test_trailing_dot_preserved_as_fqdn(self):
        result = classify_network_string("example.com.")
        assert result.artifact_type == NetworkArtifactType.HOSTNAME
        assert result.normalized["fqdn"] is True
        assert result.normalized["hostname"] == "example.com"

    def test_invalid_label_rejected(self):
        assert _type("-example.com") is None
        assert _type("example-.com") is None

    def test_underscore_allowed_mid_label(self):
        # Deliberate, documented relaxation from strict RFC 1035 - some
        # legitimate (esp. service/internal) hostnames use underscores.
        result = classify_network_string("_service.example.com")
        assert result.artifact_type == NetworkArtifactType.HOSTNAME

    def test_single_label_non_localhost_rejected(self):
        assert _type("fmt") is None

    def test_unrecognized_tld_rejected(self):
        # Documented false-positive-control tradeoff: an exotic/uncommon
        # TLD not in the curated allowlist is not recognized.
        assert _type("example.qqzz") is None


class TestURLs:
    def test_http(self):
        result = classify_network_string("http://example.com")
        assert result.artifact_type == NetworkArtifactType.URL
        assert result.normalized["scheme"] == "http"

    def test_https(self):
        result = classify_network_string("https://example.com")
        assert result.artifact_type == NetworkArtifactType.URL
        assert result.normalized["scheme"] == "https"

    def test_case_and_port_and_path_preserved_in_normalized(self):
        result = classify_network_string("HTTPS://Example.COM:443/path")
        assert result.artifact_type == NetworkArtifactType.URL
        assert result.normalized["scheme"] == "https"
        assert result.normalized["hostname"] == "example.com"
        assert result.normalized["port"] == 443
        assert result.normalized["path"] == "/path"

    def test_url_with_ipv4_host(self):
        result = classify_network_string("http://192.168.1.10:8080/")
        assert result.artifact_type == NetworkArtifactType.URL
        assert result.normalized["hostname"] == "192.168.1.10"
        assert result.normalized["port"] == 8080

    def test_url_with_ipv6_host(self):
        result = classify_network_string("http://[2001:db8::1]:8080/")
        assert result.artifact_type == NetworkArtifactType.URL
        assert result.normalized["port"] == 8080

    def test_url_with_path_and_query(self):
        result = classify_network_string("https://example.com/a/b?x=1&y=2#frag")
        assert result.normalized["path"] == "/a/b"
        assert result.normalized["query"] == "x=1&y=2"
        assert result.normalized["fragment"] == "frag"

    def test_unsupported_scheme_rejected(self):
        assert _type("ftp://example.com") is None

    def test_malformed_url_missing_host_rejected(self):
        assert _type("https://") is None

    def test_malformed_url_bad_port_rejected(self):
        assert _type("https://example.com:999999/") is None

    def test_not_every_double_slash_colon_is_a_url(self):
        assert _type("path/to://something") is None


class TestHostPort:
    def test_ipv4_port(self):
        result = classify_network_string("192.168.1.10:443")
        assert result.artifact_type == NetworkArtifactType.HOST_PORT
        assert result.normalized["host"] == "192.168.1.10"
        assert result.normalized["port"] == 443

    def test_hostname_port(self):
        result = classify_network_string("example.com:8080")
        assert result.artifact_type == NetworkArtifactType.HOST_PORT
        assert result.normalized["host"] == "example.com"

    def test_bracketed_ipv6_port(self):
        result = classify_network_string("[::1]:8080")
        assert result.artifact_type == NetworkArtifactType.HOST_PORT
        assert result.normalized["port"] == 8080
        assert result.normalized["bracketed_ipv6"] is True

    def test_port_zero_valid(self):
        result = classify_network_string("example.com:0")
        assert result.normalized["port"] == 0

    def test_port_65535_valid(self):
        result = classify_network_string("example.com:65535")
        assert result.normalized["port"] == 65535

    def test_port_above_65535_rejected(self):
        assert _type("example.com:70000") is None

    def test_invalid_port_text_rejected(self):
        assert _type("example.com:abc") is None

    def test_bare_ipv6_not_misclassified_as_host_port(self):
        # Ordering guarantee: unbracketed IPv6 is classified as IPV6, not
        # (mis-parsed as) a malformed host:port.
        assert _type("2001:db8::1") == NetworkArtifactType.IPV6

    def test_unbracketed_ipv6_with_trailing_digits_parses_as_ipv6_not_host_port(self):
        # RFC 3986 requires brackets to disambiguate an IPv6 literal from
        # an "IPv6:port" endpoint precisely because, unbracketed, this is
        # syntactically just a (longer) valid IPv6 address - "8080" here
        # is a valid hex group, not a port. Classified as IPV6 (the
        # RFC-correct reading), never guessed at as a malformed endpoint.
        assert _type("2001:db8::1:8080") == NetworkArtifactType.IPV6


class TestFalsePositives:
    def test_timestamp_rejected(self):
        assert _type("2024-01-15T12:30:00Z") is None
        assert _type("12:30:00") is None

    def test_sha256_hash_rejected(self):
        assert _type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None

    def test_uuid_rejected(self):
        assert _type("550e8400-e29b-41d4-a716-446655440000") is None

    def test_go_import_path_rejected(self):
        assert _type("github.com/user/repo") is None
        assert _type("encoding/json") is None

    def test_go_selector_expression_rejected(self):
        assert _type("io.Reader") is None
        assert _type("time.Now") is None
        assert _type("os.Exit") is None

    def test_windows_path_rejected(self):
        assert _type(r"C:\Users\foo\bar.exe") is None

    def test_linux_path_rejected(self):
        assert _type("/usr/local/bin/app") is None

    def test_semantic_version_rejected(self):
        assert _type("1.2.3") is None
        assert _type("v1.2.3") is None

    def test_random_number_rejected(self):
        assert _type("123456789") is None

    def test_email_address_not_explicitly_supported(self):
        # Email is not in the Phase 6A supported category list - never
        # silently reclassified as a hostname/URL fragment.
        assert _type("user@example.com") is None

    def test_empty_string_rejected(self):
        assert _type("") is None

    def test_over_length_bound_rejected(self):
        long_value = "http://example.com/" + "a" * MAX_STRING_VALUE_LENGTH
        assert _type(long_value) is None
