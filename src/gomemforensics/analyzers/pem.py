"""Shared PEM boundary detection (RFC 7468 textual encoding).

Phase 6B introduced private-key PEM recognition
(:mod:`gomemforensics.analyzers.credentials`); Phase 6C adds public-key/
certificate PEM recognition (:mod:`gomemforensics.analyzers.crypto`).
Factored here once so neither module re-implements the same boundary-
matching regex/logic (CLAUDE.md section 36: "duplicated parser logic").

This module only finds boundaries and measures the body between them - it
never interprets, decodes, or validates the base64 body, and it is not a
Go runtime structure at all (this is a text/wire-format convention, RFC
7468, not something that needs Go-version source archaeology).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_BEGIN_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+?)-----")
_END_TEMPLATE = "-----END {label}-----"


@dataclass(frozen=True)
class PemBlock:
    """One PEM boundary pair (or unmatched BEGIN) found in a string."""

    label: str
    complete: bool
    body_length: int
    start: int
    #: End index of the match: past the END marker if complete, past the
    #: BEGIN marker if not (used as the resume point for
    #: :func:`find_all_pem_blocks`).
    end: int


def find_pem_block(value: str, start: int = 0) -> PemBlock | None:
    """Find the next PEM boundary at or after ``start``.

    Returns ``None`` if no ``-----BEGIN ...-----`` marker is found.
    """
    match = _BEGIN_RE.search(value, start)
    if match is None:
        return None
    label = match.group(1)
    end_marker = _END_TEMPLATE.format(label=label)
    end_index = value.find(end_marker, match.end())
    if end_index == -1:
        return PemBlock(label=label, complete=False, body_length=0, start=match.start(), end=match.end())
    body_length = end_index - match.end()
    return PemBlock(
        label=label, complete=True, body_length=body_length, start=match.start(), end=end_index + len(end_marker)
    )


def find_all_pem_blocks(value: str) -> list[PemBlock]:
    """Find every PEM boundary in ``value`` (e.g. a certificate bundle
    containing several consecutive blocks). Stops at the first incomplete
    (unmatched BEGIN) block, since there is no reliable resume point past
    it."""
    blocks: list[PemBlock] = []
    pos = 0
    while True:
        block = find_pem_block(value, pos)
        if block is None:
            break
        blocks.append(block)
        if not block.complete:
            break
        pos = block.end
    return blocks
