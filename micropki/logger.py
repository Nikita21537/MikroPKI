import logging
import sys

from datetime import datetime
from typing import Optional


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:

    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)

    logger.handlers.clear()

    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )


    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger