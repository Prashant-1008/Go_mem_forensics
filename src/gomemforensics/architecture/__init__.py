"""Architecture abstraction layer.

CLAUDE.md section 7 requires that architecture-specific behavior never be
scattered through the codebase as ad hoc constants. Everything
architecture-dependent (pointer size, registers, calling convention,
instruction decoding configuration, and - in later phases - ABI-aware
backward analysis and stack unwinding) must be expressed through
:class:`gomemforensics.architecture.base.ArchitectureLayout`.
"""
