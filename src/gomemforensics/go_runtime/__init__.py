"""Go runtime metadata detection and reconstruction (Phase 2).

Scope, per the approved Phase 2 plan: process -> Go candidate detection ->
pclntab -> pcHeader -> Go version -> moduledata -> a validated
:class:`~gomemforensics.go_runtime.models.GoRuntime`. Go string/function/
goroutine recovery, IOC extraction, and correlation are explicitly later
phases and are not implemented here.

Every struct offset used by this package is traced to real Go runtime
source (either the locally installed Go 1.26.2 toolchain, or specific
tagged releases fetched from https://github.com/golang/go for historical
verification) - see :mod:`gomemforensics.go_runtime.layouts` for the full
citations and docs/architecture/go-runtime.md for the narrative writeup.
Nothing here invents an offset.
"""
