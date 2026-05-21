"""routezero/utils/logging.py — Simple structured logger."""
import logging
import sys


def get_logger(name: str = "routezero") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "[%(levelname)s] %(name)s: %(message)s"
        ))
        logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    return logger
