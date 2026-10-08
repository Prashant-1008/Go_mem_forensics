"""Small, dependency-free helpers shared across subsystems.

Kept intentionally minimal; do not accrete unrelated helpers here without a
clear justification (CLAUDE.md section 36).
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix.

    Used for timestamps that must remain reproducible and unambiguous across
    time zones (CLAUDE.md section 34).
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def format_address(address: int) -> str:
    """Render an integer address as a canonical lowercase hex string."""
    if address < 0:
        raise ValueError(f"Address must be non-negative, got {address}")
    return f"0x{address:x}"
