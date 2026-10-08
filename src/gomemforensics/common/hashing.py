"""Chunked cryptographic hashing utilities.

Memory images can be multi-gigabyte files. Every hashing routine in this
module streams the file in fixed-size chunks and must never read an entire
image into memory at once (CLAUDE.md section 12/44).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

#: 4 MiB strikes a reasonable balance between syscall overhead and memory
#: footprint for multi-gigabyte forensic images.
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


def compute_file_hash(
    path: Path,
    algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Compute a hex digest of ``path`` using incremental, chunked reads.

    The file is always opened read-only (``"rb"``); this function never
    writes to or modifies the target file.

    Raises:
        FileNotFoundError: if ``path`` does not exist.
        IsADirectoryError: if ``path`` is a directory.
        ValueError: if ``algorithm`` is not supported by :mod:`hashlib`.
    """
    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")
    if path.is_dir():
        raise IsADirectoryError(f"Expected a regular file, got a directory: {path}")

    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"Unsupported hash algorithm: {algorithm!r}") from exc

    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def compute_sha256(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Convenience wrapper for SHA-256, the minimum required algorithm
    per CLAUDE.md section 12."""
    return compute_file_hash(path, algorithm="sha256", chunk_size=chunk_size)
