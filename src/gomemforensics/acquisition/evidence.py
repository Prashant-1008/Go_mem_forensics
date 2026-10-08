"""Evidence validation and metadata recording.

This module never opens the evidence file for writing. It only ever opens
files in binary read ("rb") mode, and hashing is fully chunked
(see :mod:`gomemforensics.common.hashing`) so a multi-gigabyte memory image
is never loaded into RAM in full just to be validated.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gomemforensics.common.hashing import DEFAULT_CHUNK_SIZE, compute_sha256
from gomemforensics.common.logging import get_logger
from gomemforensics.common.utils import utc_now_iso

logger = get_logger("acquisition.evidence")


class EvidenceValidationError(Exception):
    """Base class for evidence validation failures."""


class EvidenceNotFoundError(EvidenceValidationError):
    """The supplied evidence path does not exist."""


class EvidenceNotAFileError(EvidenceValidationError):
    """The supplied evidence path exists but is not a regular file."""


class EvidenceAccessError(EvidenceValidationError):
    """The evidence file exists but could not be read (permissions, I/O)."""


@dataclass(frozen=True)
class EvidenceMetadata:
    """Structured, immutable record describing a validated evidence file.

    Mirrors the minimum field set specified in CLAUDE.md section 12.
    """

    case_id: str | None
    input_path: Path
    file_name: str
    file_size: int
    sha256: str
    hash_algorithm: str
    analysis_timestamp: str
    read_only: bool = True


class EvidenceValidator:
    """Validates a candidate evidence file without ever modifying it."""

    def validate(
        self,
        path: Path,
        case_id: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> EvidenceMetadata:
        """Validate ``path`` and return its :class:`EvidenceMetadata`.

        Raises:
            EvidenceNotFoundError: if ``path`` does not exist.
            EvidenceNotAFileError: if ``path`` is not a regular file
                (for example, a directory).
            EvidenceAccessError: if the file exists but cannot be read.
        """
        path = Path(path)
        logger.debug("Validating evidence path: %s", path)

        if not path.exists():
            raise EvidenceNotFoundError(f"Evidence file not found: {path}")
        if path.is_dir():
            raise EvidenceNotAFileError(f"Expected a regular file, got a directory: {path}")
        if not path.is_file():
            raise EvidenceNotAFileError(f"Expected a regular file: {path}")

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            raise EvidenceAccessError(f"Could not stat evidence file {path}: {exc}") from exc

        try:
            digest = compute_sha256(path, chunk_size=chunk_size)
        except OSError as exc:
            raise EvidenceAccessError(f"Could not read evidence file {path}: {exc}") from exc

        metadata = EvidenceMetadata(
            case_id=case_id,
            input_path=path,
            file_name=path.name,
            file_size=file_size,
            sha256=digest,
            hash_algorithm="SHA-256",
            analysis_timestamp=utc_now_iso(),
            read_only=True,
        )
        logger.info("Evidence validated: %s (%d bytes)", path, file_size)
        return metadata
