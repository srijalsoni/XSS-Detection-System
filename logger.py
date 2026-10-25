import logging
import sys


def setup_logger(name="p211_logger", level=logging.INFO):
    """
    Sets up a centralized, reusable application logger.
    Avoids duplicate handlers on repeated setup.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


# Default application logger instance
logger = setup_logger()
