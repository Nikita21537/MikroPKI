"""Logging configuration for MicroPKI."""

import logging
import sys
from datetime import datetime
from typing import Optional


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    """
    Configure and return a logger instance.

    Args:
        log_file: Optional path to log file. If None, logs to stderr.

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatter with ISO 8601 timestamp with milliseconds
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    # Add handler
    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger