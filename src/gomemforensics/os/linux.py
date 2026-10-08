"""Linux OS profile.

Phase 1 priority target (CLAUDE.md section 7): Linux x86-64. Linux ARM64 is
Phase 2 future work and is not listed as supported here.
"""

from __future__ import annotations

from gomemforensics.os.base import OperatingSystemProfile


class LinuxProfile(OperatingSystemProfile):
    """Linux target profile."""

    @property
    def name(self) -> str:
        return "Linux"

    @property
    def supported(self) -> bool:
        return True

    @property
    def supported_architectures(self) -> tuple[str, ...]:
        return ("x86_64",)


#: Shared, stateless instance for convenient reuse.
LINUX = LinuxProfile()
