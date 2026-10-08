"""Tests for evidence validation and chunked hashing.

No test in this module downloads, executes, or requires real malware or a
real memory image; all inputs are small synthetic files.
"""

import hashlib

import pytest

from gomemforensics.acquisition.evidence import (
    EvidenceAccessError,
    EvidenceNotAFileError,
    EvidenceNotFoundError,
    EvidenceValidator,
)
from gomemforensics.common.hashing import compute_file_hash, compute_sha256


def test_sha256_matches_hashlib(tmp_path):
    content = b"The quick brown fox jumps over the lazy dog"
    path = tmp_path / "sample.raw"
    path.write_bytes(content)

    assert compute_sha256(path) == hashlib.sha256(content).hexdigest()


def test_chunked_hashing_matches_single_shot_for_small_chunk_size(tmp_path):
    content = bytes(range(256)) * 100  # 25,600 bytes
    path = tmp_path / "sample.raw"
    path.write_bytes(content)

    # Force many small reads to exercise the chunk boundary logic.
    chunked = compute_file_hash(path, algorithm="sha256", chunk_size=7)

    assert chunked == hashlib.sha256(content).hexdigest()


def test_empty_file_hash(tmp_path):
    path = tmp_path / "empty.raw"
    path.write_bytes(b"")

    assert compute_sha256(path) == hashlib.sha256(b"").hexdigest()


def test_hash_nonexistent_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        compute_sha256(tmp_path / "missing.raw")


def test_hash_directory_raises(tmp_path):
    with pytest.raises(IsADirectoryError):
        compute_sha256(tmp_path)


def test_unsupported_algorithm_raises(tmp_path):
    path = tmp_path / "sample.raw"
    path.write_bytes(b"data")
    with pytest.raises(ValueError):
        compute_file_hash(path, algorithm="not-a-real-algorithm")


class TestEvidenceValidator:
    def test_validate_success(self, tmp_path):
        content = b"synthetic memory image bytes"
        path = tmp_path / "image.raw"
        path.write_bytes(content)

        metadata = EvidenceValidator().validate(path, case_id="CASE-001")

        assert metadata.file_name == "image.raw"
        assert metadata.file_size == len(content)
        assert metadata.sha256 == hashlib.sha256(content).hexdigest()
        assert metadata.hash_algorithm == "SHA-256"
        assert metadata.read_only is True
        assert metadata.case_id == "CASE-001"
        assert metadata.analysis_timestamp.endswith("Z")

    def test_validate_empty_file_succeeds(self, tmp_path):
        path = tmp_path / "empty.raw"
        path.write_bytes(b"")

        metadata = EvidenceValidator().validate(path)

        assert metadata.file_size == 0
        assert metadata.sha256 == hashlib.sha256(b"").hexdigest()

    def test_validate_nonexistent_file_raises(self, tmp_path):
        with pytest.raises(EvidenceNotFoundError):
            EvidenceValidator().validate(tmp_path / "missing.raw")

    def test_validate_directory_raises(self, tmp_path):
        with pytest.raises(EvidenceNotAFileError):
            EvidenceValidator().validate(tmp_path)

    def test_validate_does_not_modify_file(self, tmp_path):
        content = b"do not touch me"
        path = tmp_path / "image.raw"
        path.write_bytes(content)
        original_mtime = path.stat().st_mtime

        EvidenceValidator().validate(path)

        assert path.read_bytes() == content
        assert path.stat().st_mtime == original_mtime

    def test_hash_is_stable_across_repeated_validation(self, tmp_path):
        # Phase 5.5 evidence-integrity requirement: re-validating the same,
        # unmodified evidence file must reproduce an identical SHA-256 -
        # this is the before/after check a real acquisition workflow relies
        # on to prove the image was not altered during analysis.
        path = tmp_path / "image.raw"
        path.write_bytes(b"stable content" * 1000)

        first = EvidenceValidator().validate(path)
        second = EvidenceValidator().validate(path)

        assert first.sha256 == second.sha256
        assert first.file_size == second.file_size

    def test_duplicate_content_different_paths_hash_identically(self, tmp_path):
        # Two distinct evidence files with identical bytes (e.g. the same
        # image copied under a case-specific name) must be recognized as
        # duplicates by hash while still preserving distinct provenance
        # (input_path/file_name) - never silently merged into one record.
        content = b"same bytes, two files"
        path_a = tmp_path / "case-001.raw"
        path_b = tmp_path / "case-001-copy.raw"
        path_a.write_bytes(content)
        path_b.write_bytes(content)

        meta_a = EvidenceValidator().validate(path_a, case_id="CASE-001")
        meta_b = EvidenceValidator().validate(path_b, case_id="CASE-001")

        assert meta_a.sha256 == meta_b.sha256
        assert meta_a.file_name != meta_b.file_name
        assert meta_a.input_path != meta_b.input_path

    def test_unreadable_evidence_raises_access_error_not_generic_exception(self, tmp_path, monkeypatch):
        # Simulates a permission-denied/IO failure surfaced while hashing
        # (Windows file locks and POSIX permission bits are both
        # unreliable to force portably in a unit test, so the underlying
        # I/O failure is simulated directly at the point EvidenceValidator
        # itself invokes it, rather than skipped).
        path = tmp_path / "locked.raw"
        path.write_bytes(b"unreachable")

        def _raise_permission_error(*_args, **_kwargs):
            raise OSError("simulated permission denied")

        monkeypatch.setattr(
            "gomemforensics.acquisition.evidence.compute_sha256", _raise_permission_error
        )

        with pytest.raises(EvidenceAccessError):
            EvidenceValidator().validate(path)

    def test_truncated_evidence_is_recorded_not_rejected(self, tmp_path):
        # GoMemForensics has no expected/reference size to compare against
        # (CLAUDE.md: never fabricate missing data) - a short/truncated
        # capture is not an error condition at this layer, it is simply
        # evidence whose observed size must be recorded exactly as found,
        # for downstream layers (Volatility) to report their own
        # truncation-related failures explicitly (see FailureReason).
        path = tmp_path / "truncated.raw"
        content = b"\x00" * 17  # far smaller than any real memory image
        path.write_bytes(content)

        metadata = EvidenceValidator().validate(path)

        assert metadata.file_size == 17
        assert metadata.sha256 == hashlib.sha256(content).hexdigest()
