"""Go function classification by recovered source path (paper Section 3.3.2).

Classification is an analytical categorization only - never a
maliciousness verdict (CLAUDE.md section 20/CLAUDE.md section 7: "Do not
infer maliciousness from a package name alone"). Rules, verbatim from the
paper:

    Paths beginning with runtime/ are classified as runtime core, while
    paths under internal/ are split into runtime-critical internal
    packages (e.g., internal/abi, internal/cpu) and other standard-library
    internal packages (e.g., internal/poll). Paths whose first segment
    matches a public standard library package (e.g., net, os, fmt) are
    classified as public standard library. [...] third-party functions are
    identified by domain-based prefixes (e.g., github.com, gitlab.com) or
    by paths under vendor/ directories. Remaining functions, including
    those in the main package and other user-defined packages within the
    same module, are classified as application-level code.

The standard-library package name list below is not invented: it is the
literal set of top-level package directories under the local go1.26.2
install's ``src/`` (excluding ``cmd/``, ``internal/``, ``vendor/``, and
non-package files like build scripts/READMEs/testdata), obtained via
directory listing, matching Go's own public stdlib layout.
"""

from __future__ import annotations

from gomemforensics.go_runtime.models import FunctionClassification

#: Verified via directory listing of the local go1.26.2 install's
#: `src/` (public stdlib top-level package names only).
_STDLIB_TOP_LEVEL_PACKAGES = frozenset(
    {
        "archive", "arena", "bufio", "builtin", "bytes", "cmp", "compress",
        "container", "context", "crypto", "database", "debug", "embed",
        "encoding", "errors", "expvar", "flag", "fmt", "go", "hash", "html",
        "image", "index", "io", "iter", "log", "maps", "math", "mime", "net",
        "os", "path", "plugin", "reflect", "regexp", "simd", "slices", "sort",
        "strconv", "strings", "structs", "sync", "syscall", "testing", "text",
        "time", "unicode", "unique", "unsafe", "weak",
    }
)

#: Internal packages that are part of the runtime's own implementation
#: (as opposed to internal-only standard-library helper packages like
#: internal/poll). This list reflects packages under the local go1.26.2
#: install's `src/internal/` whose name/purpose is runtime-adjacent per
#: the paper's own two named examples (internal/abi, internal/cpu) plus
#: the small set of directly analogous packages actually present in that
#: same `src/internal/` directory (verified by listing it) - not an
#: exhaustive invented classification.
_RUNTIME_CRITICAL_INTERNAL_PACKAGES = frozenset(
    {
        "abi", "cpu", "bytealg", "chacha8rand", "coverage", "goarch",
        "godebug", "goexperiment", "goos", "runtime", "syscall",
    }
)

#: Common third-party module host prefixes (approved plan Section 7:
#: "domain-based prefixes (e.g., github.com, gitlab.com)"). Deliberately a
#: small, documented set rather than a full public-suffix-list dependency
#: - a path containing a "." in its first segment (a real domain name) is
#: also treated as third-party, covering hosts not in this explicit list.
_KNOWN_THIRD_PARTY_HOSTS = frozenset(
    {"github.com", "gitlab.com", "bitbucket.org", "golang.org", "gopkg.in", "google.golang.org"}
)


def _looks_like_host_segment(segment: str) -> bool:
    """Whether a path segment looks like a domain name (approved plan
    Section 7: "domain-based prefixes"). A dot plus at least one
    alphabetic character on each side is a cheap, honest proxy for "this
    is a hostname, not a Go identifier" - Go import path segments never
    legitimately contain a literal ``.`` in this position for stdlib or
    application code.
    """
    if segment in _KNOWN_THIRD_PARTY_HOSTS:
        return True
    if "." not in segment:
        return False
    parts = segment.split(".")
    return len(parts) >= 2 and all(parts) and all(p.isalnum() or "-" in p for p in parts)


def classify_function_path(source_path: str | None) -> FunctionClassification:
    """Classify a function by its recovered source file path.

    Deterministic, path-prefix-only (never inspects the function's name,
    behavior, or arguments - CLAUDE.md section 7). Returns ``UNKNOWN`` for
    an empty/unrecoverable path rather than guessing.
    """
    if not source_path:
        return FunctionClassification.UNKNOWN

    # Go source paths recovered from filetab are typically absolute build
    # paths (e.g. "/usr/local/go/src/runtime/proc.go" for stdlib/runtime,
    # or a module-cache/build-environment path such as
    # ".../pkg/mod/github.com/user/repo@v1.2.3/file.go" for third-party
    # code) or a bare module-relative import path. We classify off of the
    # import-path-shaped suffix, which for stdlib/runtime paths reliably
    # starts right after the last "src/" segment when present.
    normalized = source_path.replace("\\", "/")
    if "/src/" in normalized:
        normalized = normalized.split("/src/", 1)[1]
    normalized = normalized.lstrip("/")

    segments = [s for s in normalized.split("/") if s]
    if not segments:
        return FunctionClassification.UNKNOWN

    first = segments[0]

    if first == "runtime":
        return FunctionClassification.RUNTIME

    if first == "internal" and len(segments) > 1:
        second = segments[1]
        if second in _RUNTIME_CRITICAL_INTERNAL_PACKAGES:
            return FunctionClassification.RUNTIME_INTERNAL
        return FunctionClassification.STDLIB

    if "vendor" in segments:
        return FunctionClassification.THIRD_PARTY

    # A domain-like segment anywhere in the *directory* portion of the
    # path (not just first, to cover build-environment/module-cache paths
    # where the host segment isn't at the very start, e.g.
    # ".../pkg/mod/github.com/...") covers third-party hosts. The final
    # segment is always the filename (e.g. "server.go") and is excluded -
    # a filename's own "." must never be mistaken for a hostname.
    directory_segments = segments[:-1] if len(segments) > 1 else []
    if any(_looks_like_host_segment(s) for s in directory_segments):
        return FunctionClassification.THIRD_PARTY

    if first in _STDLIB_TOP_LEVEL_PACKAGES:
        return FunctionClassification.STDLIB

    # Everything else (main package, other user-defined packages within
    # the same module) is application-level code, per the paper.
    return FunctionClassification.APPLICATION
