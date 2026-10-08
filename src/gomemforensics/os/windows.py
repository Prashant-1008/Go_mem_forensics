"""Windows OS profile.

Phase 1 priority target (CLAUDE.md section 7): Windows x86-64. Windows
ARM64 is Phase 3 future work and is not listed as supported here.
"""

from __future__ import annotations

from gomemforensics.os.base import OperatingSystemProfile


class WindowsProfile(OperatingSystemProfile):
    """Windows target profile."""

    @property
    def name(self) -> str:
        return "Windows"

    @property
    def supported(self) -> bool:
        return True

    @property
    def supported_architectures(self) -> tuple[str, ...]:
        return ("x86_64",)


#: Shared, stateless instance for convenient reuse.
WINDOWS = WindowsProfile()
