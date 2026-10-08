"""Structured logging foundation for GoMemForensics.

Investigator-facing progress ("[+] Evidence validated", ...) is printed
directly by the CLI layer via ``click.echo`` and is a separate concern from
this module. This module governs *diagnostic* logging, which is intended for
forensic troubleshooting rather than routine progress reporting, per
CLAUDE.md section 25:

    Normal logs should be suitable for investigators.
    Debug logs may include detailed addresses and parser information.

Log level mapping rationale:

- ``QUIET``   -> ERROR    : only surface failures.
- ``NORMAL``  -> WARNING  : diagnostic noise stays out of the way; routine
                             progress is the CLI's job, not the logger's.
- ``VERBOSE`` -> INFO     : internal step-by-step narration, still free of
                             raw addresses/offsets.
- ``DEBUG``   -> DEBUG    : full parser internals, including addresses -
                             never printed by default.
"""

from __future__ import annotations

import logging
import sys
from enum import Enum
from typing import TextIO

_LOGGER_NAMESPACE = "gomemforensics"

_COMPACT_FORMAT = "%(levelname)s: %(message)s"
_DETAILED_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class LogLevel(str, Enum):
    """Supported CLI-selectable logging verbosity levels."""

    QUIET = "quiet"
    NORMAL = "normal"
    VERBOSE = "verbose"
    DEBUG = "debug"

    def to_stdlib_level(self) -> int:
        """Map a :class:`LogLevel` to the corresponding :mod:`logging` level."""
        return {
            LogLevel.QUIET: logging.ERROR,
            LogLevel.NORMAL: logging.WARNING,
            LogLevel.VERBOSE: logging.INFO,
            LogLevel.DEBUG: logging.DEBUG,
        }[self]


def configure_logging(level: LogLevel = LogLevel.NORMAL, stream: TextIO = sys.stderr) -> logging.Logger:
    """Configure the root ``gomemforensics`` logger and return it.

    Idempotent: repeated calls replace the existing handler rather than
    stacking duplicate handlers, so it is safe to call once per CLI
    invocation (including from tests).
    """
    logger = logging.getLogger(_LOGGER_NAMESPACE)
    logger.setLevel(level.to_stdlib_level())

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream)
    fmt = _DETAILED_FORMAT if level in (LogLevel.VERBOSE, LogLevel.DEBUG) else _COMPACT_FORMAT
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``gomemforensics`` namespace.

    Example: ``get_logger("acquisition.evidence")`` ->
    logger named ``gomemforensics.acquisition.evidence``.
    """
    return logging.getLogger(f"{_LOGGER_NAMESPACE}.{name}")
