"""GoMemForensics: automated Go malware memory forensics and runtime artifact analysis.

This package is under active, incremental development. See CLAUDE.md in the
repository root for the governing project methodology and README.md for
current status and supported capabilities.
"""

__version__ = "0.14.0"

#: Human-readable development phase marker, surfaced by the CLI ``info`` and
#: ``version`` commands so investigators always know how much of the pipeline
#: is actually implemented versus planned.
PROJECT_PHASE = "Phase 6H - End-to-End Integration and Validation"

#: Whether ANY capability in this project has been validated against a real,
#: approved captured memory image (as opposed to a synthetic buffer or a
#: compiled-binary-file read at its real virtual addresses). This has been
#: ``False`` since Phase 0 and remains ``False`` as of Phase 6H - Phase 5.5
#: found no approved image available in this development environment (see
#: docs/validation/validation-plan.md's "Phase 5.5" section) and no later
#: phase has changed that. Every report (CLAUDE.md section 14/34, Phase 6G
#: stage 8/37) must surface this exact value - compiled-fixture validation
#: or synthetic/negative testing must never be presented as real-memory
#: validation. This flag is not computed per-run; it is a fact about the
#: project's own current validation state.
REAL_MEMORY_VALIDATED = False

__all__ = ["__version__", "PROJECT_PHASE", "REAL_MEMORY_VALIDATED"]
