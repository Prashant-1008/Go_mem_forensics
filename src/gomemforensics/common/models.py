"""Minimal, extensible shared data models.

These are foundations for the full JSON schema designed in the Phase 0
planning discussion; they are intentionally small. The complete artifact
schemas (strings, functions, goroutines, network artifacts, findings, ...)
are Phase 3+ work and are not implemented here.

Every artifact produced by later analyzers must eventually embed an
:class:`ArtifactProvenance` record, so it is traceable back to the case,
evidence file, process, and extraction method that produced it
(CLAUDE.md section 13).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from gomemforensics.common.utils import utc_now_iso


class Confidence(str, Enum):
    """Explicit confidence levels (CLAUDE.md section 14).

    Confidence must always be grounded in the strength of structural
    validation applied to an artifact, never presented as a numeric
    "malware score".
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class ArtifactProvenance:
    """Traceability record attachable to any recovered artifact.

    Fields deliberately mirror CLAUDE.md section 13's example artifact
    provenance shape.
    """

    artifact_id: str
    artifact_type: str
    analyzer: str
    extraction_method: str
    confidence: Confidence
    case_id: str | None = None
    pid: int | None = None
    virtual_address: str | None = None
    physical_address: str | None = None
    memory_region: str | None = None
    analyzer_version: str | None = None
    related_artifacts: list[str] = field(default_factory=list)


class FailureReason(str, Enum):
    """A closed taxonomy of *why* an :class:`AnalysisError` occurred.

    Phase 5.5 requirement: failure causes must never be collapsed into a
    single generic "error" bucket, so that a real memory-image run's
    output can distinguish (for example) "Volatility could not parse this
    image at all" from "a Go runtime was never found in this process"
    from "this process's Go runtime uses an unsupported version" - each
    implies a different investigator action. ``None`` (the default on
    :class:`AnalysisError`) means the call site predates this taxonomy or
    is intentionally unclassified; new call sites should always set one of
    these values rather than leaving it unset.
    """

    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    EVIDENCE_INVALID = "evidence_invalid"
    EVIDENCE_TRUNCATED = "evidence_truncated"
    VOLATILITY_UNSUPPORTED = "volatility_unsupported"
    OS_PROCESS_DISCOVERY_FAILED = "os_process_discovery_failed"
    ADDRESS_SPACE_UNAVAILABLE = "address_space_unavailable"
    GO_RUNTIME_NOT_FOUND = "go_runtime_not_found"
    PCLNTAB_INVALID = "pclntab_invalid"
    MODULEDATA_INVALID = "moduledata_invalid"
    UNSUPPORTED_GO_VERSION = "unsupported_go_version"
    UNSUPPORTED_ARCHITECTURE = "unsupported_architecture"
    ALLGS_NOT_FOUND = "allgs_not_found"
    G_VALIDATION_FAILED = "g_validation_failed"
    STACK_UNAVAILABLE = "stack_unavailable"
    PCSP_INVALID = "pcsp_invalid"
    UNWIND_STOPPED = "unwind_stopped"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    INTERNAL_ERROR = "internal_error"


@dataclass
class AnalysisError:
    """A recoverable-or-not error encountered during analysis.

    Per CLAUDE.md section 24 ("recover -> record error -> continue"),
    analyzers should construct these instead of raising uncaught exceptions
    that would abort an entire run over one bad process or artifact.
    """

    component: str
    message: str
    pid: int | None = None
    recoverable: bool = True
    reason: FailureReason | None = None
    timestamp: str = field(default_factory=utc_now_iso)


@dataclass
class AnalysisStatistics:
    """Small, extensible run-level counters.

    Named fields cover the counts already anticipated by the CLI progress
    output (CLAUDE.md section 21) and the Phase 1 JSON output; ``extra``
    allows later phases to record additional counters without a model
    migration.
    """

    processes_discovered: int = 0
    processes_with_memory_access: int = 0
    processes_failed: int = 0
    errors_count: int = 0
    go_candidate_processes: int = 0
    go_runtimes_reconstructed: int = 0
    strings_recovered: int = 0
    strings_recovered_heap: int = 0
    strings_recovered_static: int = 0
    extra: dict[str, int] = field(default_factory=dict)


@dataclass
class ProcessInfo:
    """Normalized, OS-independent process metadata.

    Populated by :mod:`gomemforensics.volatility.integration` from either
    Windows (``EPROCESS``) or Linux (``task_struct``) process objects. Every
    field is best-effort: if a value could not be recovered, it is left as
    ``None`` rather than guessed (CLAUDE.md section 40).

    Go detection fields (populated by
    :mod:`gomemforensics.go_runtime.detector` as of Phase 2):
    ``is_go_candidate`` is only ever ``True`` when a pcHeader was recovered
    with at least MEDIUM confidence (a magic-validated pcHeader); a
    structural-only (LOW confidence) candidate never flips this to
    ``True`` (CLAUDE.md's "a magic-byte match... must not automatically
    become a confirmed Go process"). ``go_runtime_id`` cross-references the
    corresponding entry in the run's ``go_runtimes`` list rather than
    embedding the full runtime object here - see
    :class:`gomemforensics.go_runtime.models.GoRuntime`.
    """

    pid: int
    ppid: int | None
    name: str | None
    executable_path: str | None
    architecture: str
    os: str
    create_time: str | None
    memory_layer_available: bool
    is_go_candidate: bool = False
    go_confidence: Confidence = Confidence.UNKNOWN
    go_version: str | None = None
    go_runtime_id: str | None = None
