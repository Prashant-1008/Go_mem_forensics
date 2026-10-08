"""Unit tests for Go function path classification (approved plan Section 7).

Each case below matches a representative recovered source path shape
(GOROOT stdlib/runtime, internal, vendor, module-cache third-party,
application) and was hand-verified against the classification rules
documented in gomemforensics.go_runtime.classification before being
asserted here.
"""

from gomemforensics.go_runtime.classification import classify_function_path
from gomemforensics.go_runtime.models import FunctionClassification


class TestRuntimeClassification:
    def test_runtime_package_path(self):
        assert (
            classify_function_path("/usr/local/go/src/runtime/proc.go")
            == FunctionClassification.RUNTIME
        )

    def test_runtime_package_windows_style_path(self):
        assert (
            classify_function_path(r"C:\Program Files (x86)\Go\src\runtime\mgc.go")
            == FunctionClassification.RUNTIME
        )


class TestInternalClassification:
    def test_runtime_critical_internal_package(self):
        assert (
            classify_function_path("/usr/local/go/src/internal/abi/abi.go")
            == FunctionClassification.RUNTIME_INTERNAL
        )

    def test_other_internal_package_is_stdlib(self):
        assert (
            classify_function_path("/usr/local/go/src/internal/poll/fd_unix.go")
            == FunctionClassification.STDLIB
        )

    def test_bare_internal_segment_with_no_subpackage_is_unknown_not_crash(self):
        # "internal" alone, no subpackage segment - not enough information
        # to classify as runtime-critical vs. ordinary internal.
        result = classify_function_path("/usr/local/go/src/internal")
        assert result in (FunctionClassification.UNKNOWN, FunctionClassification.APPLICATION)


class TestStdlibClassification:
    def test_public_stdlib_package(self):
        assert (
            classify_function_path("/usr/local/go/src/net/http/server.go")
            == FunctionClassification.STDLIB
        )

    def test_public_stdlib_package_os(self):
        assert (
            classify_function_path("/usr/local/go/src/os/file.go")
            == FunctionClassification.STDLIB
        )

    def test_stdlib_filename_with_dot_is_not_mistaken_for_a_host(self):
        # Regression test for classification bug #2: "server.go" contains a
        # "." but is the filename, not a hostname segment, and must not
        # cause a false THIRD_PARTY classification.
        assert (
            classify_function_path("/usr/local/go/src/net/http/server.go")
            != FunctionClassification.THIRD_PARTY
        )


class TestThirdPartyClassification:
    def test_vendor_directory(self):
        assert (
            classify_function_path("/build/module/vendor/github.com/pkg/errors/errors.go")
            == FunctionClassification.THIRD_PARTY
        )

    def test_module_cache_github_path(self):
        # Regression test for classification bug #1: the host segment is
        # not the first segment once module-cache prefixes are present.
        assert (
            classify_function_path(
                "/root/go/pkg/mod/github.com/user/repo@v1.2.3/file.go"
            )
            == FunctionClassification.THIRD_PARTY
        )

    def test_known_third_party_host_without_dot_match(self):
        assert (
            classify_function_path("/build/gitlab.com/user/repo/main.go")
            == FunctionClassification.THIRD_PARTY
        )


class TestApplicationClassification:
    def test_application_main_package(self):
        assert (
            classify_function_path("/home/user/myproject/main.go")
            == FunctionClassification.APPLICATION
        )

    def test_application_own_module_path(self):
        assert (
            classify_function_path("/home/user/myproject/internal_helpers/util.go")
            == FunctionClassification.APPLICATION
        )


class TestUnknownClassification:
    def test_none_path(self):
        assert classify_function_path(None) == FunctionClassification.UNKNOWN

    def test_empty_string_path(self):
        assert classify_function_path("") == FunctionClassification.UNKNOWN

    def test_malformed_path_only_slashes(self):
        assert classify_function_path("///") == FunctionClassification.UNKNOWN
