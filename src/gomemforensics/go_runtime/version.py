"""Go version detection from pclntab magic bytes and moduledata structure.

Primary source: pclntab/pcHeader magic, exactly as the reference paper
describes (Section 3.1.1) and as verified against
``internal/abi/symtab.go`` in the locally installed Go 1.26.2 toolchain
(``C:\\Program Files (x86)\\Go\\src\\internal\\abi\\symtab.go``, which also
confirms ``CurrentPCLnTabMagic = Go120PCLnTabMagic`` - i.e. the paper's
"Go 1.20+" magic is still the current magic as of 1.26.2, six-plus years of
releases later).

This module never guesses an exact patch version from memory alone -
magic bytes bound a *range*; moduledata era matching (see
:mod:`gomemforensics.go_runtime.layouts`) can sometimes narrow that range
further, but the result is always reported as the most precise range the
evidence actually supports, never invented precision.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from gomemforensics.common.models import Confidence

#: Verified against internal/abi/symtab.go, local go1.26.2 install.
GO_1_2_MAGIC = 0xFFFFFFFB
GO_1_16_MAGIC = 0xFFFFFFFA
GO_1_18_MAGIC = 0xFFFFFFF0
GO_1_20_MAGIC = 0xFFFFFFF1

#: (magic, version_range_label, era_id) in the same order the paper lists
#: them (Section 3.1.1).
_MAGIC_TABLE: tuple[tuple[int, str, str], ...] = (
    (GO_1_20_MAGIC, "1.20+", "go1_20_plus"),
    (GO_1_18_MAGIC, "1.18-1.19", "go1_18_19"),
    (GO_1_16_MAGIC, "1.16-1.17", "go1_16_17"),
    (GO_1_2_MAGIC, "1.2-1.15", "go1_2_15"),
)

#: Fast lookup: raw magic int -> (version_range_label, era_id).
MAGIC_TO_ERA: dict[int, tuple[str, str]] = {magic: (label, era) for magic, label, era in _MAGIC_TABLE}


def magic_bytes_le(magic: int) -> bytes:
    """Little-endian byte encoding of a pclntab magic value (x86/ARM target byte order)."""
    return struct.pack("<I", magic)


@dataclass
class GoVersionEstimate:
    """A version conclusion with its supporting evidence, never over-precise.

    ``version`` is only ever populated with an exact version when the
    evidence genuinely narrows to one; otherwise it stays ``None`` and
    ``version_range`` carries the level of precision the evidence supports
    (e.g. ``"1.20+"``, later narrowed to ``"1.22+"`` by moduledata era
    matching, but never invented down to a patch release).
    """

    version: str | None
    version_range: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)


class GoVersionDetector:
    """Derives a :class:`GoVersionEstimate` from pclntab/moduledata evidence."""

    def detect_from_magic(self, magic: int) -> GoVersionEstimate:
        """Primary detection path: a validated pcHeader's magic value.

        Confidence is HIGH because arriving here means the magic was
        already paired with a structurally-validated pcHeader (never a
        bare magic-byte match alone - that distinction is enforced by the
        caller, gomemforensics.go_runtime.pclntab.PclntabParser).
        """
        era = MAGIC_TO_ERA.get(magic)
        if era is None:
            return GoVersionEstimate(
                version=None,
                version_range="unknown",
                confidence=Confidence.UNKNOWN,
                evidence=[f"Unrecognized pclntab magic 0x{magic:x}"],
            )
        version_range, _era_id = era
        return GoVersionEstimate(
            version=None,
            version_range=version_range,
            confidence=Confidence.HIGH,
            evidence=[f"Validated pcHeader magic 0x{magic:x} -> Go {version_range}"],
        )

    def refine_with_moduledata_layout(
        self, estimate: GoVersionEstimate, moduledata_layout_id: str
    ) -> GoVersionEstimate:
        """Narrow a magic-based range using which moduledata layout actually validated.

        Only applies within the Go 1.20+ magic family, where a single
        magic value covers two structurally distinct moduledata shapes
        (see MODULEDATA_GO120_FAMILY_CANDIDATES) - matching one over the
        other is itself real structural evidence, not a guess.
        """
        if estimate.version_range != "1.20+":
            return estimate

        if moduledata_layout_id == "moduledata@go1.22+":
            return GoVersionEstimate(
                version=None,
                version_range="1.22+",
                confidence=estimate.confidence,
                evidence=[
                    *estimate.evidence,
                    "moduledata matched the go1.22+ layout (includes epclntab field) "
                    "-> narrowed from 1.20+ to 1.22+",
                ],
            )
        if moduledata_layout_id == "moduledata@go1.20-1.21":
            return GoVersionEstimate(
                version=None,
                version_range="1.20-1.21",
                confidence=estimate.confidence,
                evidence=[
                    *estimate.evidence,
                    "moduledata matched the go1.20-1.21 layout (no epclntab field) "
                    "-> narrowed from 1.20+ to 1.20-1.21",
                ],
            )
        return estimate
