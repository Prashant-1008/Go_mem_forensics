"""Artifact-extraction analyzers that consume already-recovered Go runtime
artifacts (strings, functions, goroutines) rather than independently
re-scanning process memory.

Phase 6A adds :mod:`gomemforensics.analyzers.network`. Later phases may add
credential/crypto/persistence analyzers per CLAUDE.md section 11's planned
directory layout - none of those exist yet.
"""
