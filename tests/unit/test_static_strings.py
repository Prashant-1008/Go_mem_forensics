"""Unit tests for static-section Go string-header recovery (strings.py).

Kept in a separate test module from heap recovery (test_strings.py), per
the approved plan, to keep the two extraction paths' test coverage
structurally distinct.
"""

import struct

from gomemforensics.common.memory import MemoryRegion, MockMemoryReader
from gomemforensics.common.models import Confidence
from gomemforensics.go_runtime.models import GoRuntime
from gomemforensics.go_runtime.strings import StringRecoveryEngine

STATIC_REGION_START = 0x140060000
DATA_ADDR = 0x140070000


def _runtime() -> GoRuntime:
    return GoRuntime(
        pid=7, architecture="x86_64", go_version="1.22+", go_version_confidence=Confidence.HIGH,
        runtime_id="GORUNTIME-7-test",
    )


def _rodata_region(start=STATIC_REGION_START, size=64):
    return MemoryRegion(start=start, end=start + size, readable=True, writable=False, executable=False)


def _data_region(start=STATIC_REGION_START, size=64):
    return MemoryRegion(start=start, end=start + size, readable=True, writable=True, executable=False)


class TestStaticStringRecovery:
    def test_valid_static_header_recovered_medium_confidence(self):
        header = struct.pack("<QQ", DATA_ADDR, 5)
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: b"hello"})
        runtime = _runtime()

        artifacts, errors = StringRecoveryEngine(reader, 8).recover_static_strings(runtime, [_rodata_region()])

        assert errors == []
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.value == "hello"
        assert artifact.region == "static"
        assert artifact.extraction_method == "static_string_header_scan"
        assert artifact.confidence == Confidence.MEDIUM  # never HIGH for static
        assert artifact.classification == "unknown"

    def test_static_confidence_is_never_high(self):
        # Even a perfectly clean UTF-8 static candidate is capped at MEDIUM
        # - static recovery is pattern-derived, not allocator-validated
        # (approved plan Section I).
        header = struct.pack("<QQ", DATA_ADDR, 11)
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: b"hello world"})
        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [_rodata_region()])
        assert all(a.confidence != Confidence.HIGH for a in artifacts)

    def test_non_utf8_static_candidate_gets_low_confidence(self):
        # 17 printable bytes + 1 non-UTF-8 byte = 94% printable, clears
        # MIN_PRINTABLE_RATIO, but still fails strict UTF-8 decoding.
        raw = b"cmd.exe /c whoami" + bytes([0xFF])
        header = struct.pack("<QQ", DATA_ADDR, len(raw))
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: raw})
        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [_rodata_region()])
        assert len(artifacts) == 1
        assert artifacts[0].confidence == Confidence.LOW

    def test_truncated_backing_data_rejected(self):
        header = struct.pack("<QQ", DATA_ADDR, 1000)  # far more than backed
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: b"short"})
        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [_rodata_region()])
        assert artifacts == []

    def test_non_printable_random_candidate_rejected(self):
        raw = bytes(range(256))
        header = struct.pack("<QQ", DATA_ADDR, len(raw))
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: raw})
        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [_rodata_region()])
        assert artifacts == []

    def test_duplicate_shared_backing_strings_both_preserved(self):
        # Two distinct header positions referencing the SAME backing bytes
        # (a common, legitimate case) must both be recovered as separate
        # artifacts - never silently merged (approved plan Section J).
        header = struct.pack("<QQ", DATA_ADDR, 5)
        data = header + b"\x00" * 8 + header + b"\x00" * 32  # header at offset 0 and offset 24
        reader = MockMemoryReader(STATIC_REGION_START, data, extra_regions={DATA_ADDR: b"hello"})

        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [_rodata_region()])

        assert len(artifacts) == 2
        addresses = {a.string_address for a in artifacts}
        assert len(addresses) == 2  # distinct header addresses
        assert all(a.data_address == DATA_ADDR for a in artifacts)  # same shared backing
        assert all(a.value == "hello" for a in artifacts)

    def test_empty_region_list_yields_no_strings(self):
        reader = MockMemoryReader(STATIC_REGION_START, b"\x00" * 16)
        artifacts, errors = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [])
        assert artifacts == []
        assert errors == []

    def test_pure_executable_region_excluded(self):
        header = struct.pack("<QQ", DATA_ADDR, 5)
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: b"hello"})
        text_region = MemoryRegion(
            start=STATIC_REGION_START, end=STATIC_REGION_START + 64, readable=True, writable=False, executable=True
        )
        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [text_region])
        assert artifacts == []

    def test_data_like_writable_region_still_scanned(self):
        header = struct.pack("<QQ", DATA_ADDR, 5)
        reader = MockMemoryReader(STATIC_REGION_START, header + b"\x00" * 48, extra_regions={DATA_ADDR: b"hello"})
        artifacts, _ = StringRecoveryEngine(reader, 8).recover_static_strings(_runtime(), [_data_region()])
        assert len(artifacts) == 1
