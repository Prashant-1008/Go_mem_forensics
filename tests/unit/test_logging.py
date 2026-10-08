"""Tests for the structured logging foundation."""

import logging

from gomemforensics.common.logging import LogLevel, configure_logging, get_logger


def test_log_level_stdlib_mapping():
    assert LogLevel.QUIET.to_stdlib_level() == logging.ERROR
    assert LogLevel.NORMAL.to_stdlib_level() == logging.WARNING
    assert LogLevel.VERBOSE.to_stdlib_level() == logging.INFO
    assert LogLevel.DEBUG.to_stdlib_level() == logging.DEBUG


def test_configure_logging_sets_level():
    logger = configure_logging(LogLevel.DEBUG)
    assert logger.level == logging.DEBUG
    assert logger.name == "gomemforensics"


def test_configure_logging_is_idempotent():
    configure_logging(LogLevel.VERBOSE)
    logger = configure_logging(LogLevel.QUIET)

    assert logger.level == logging.ERROR
    # Repeated configuration must not accumulate duplicate handlers.
    assert len(logger.handlers) == 1


def test_get_logger_namespacing():
    logger = get_logger("acquisition.evidence")
    assert logger.name == "gomemforensics.acquisition.evidence"
