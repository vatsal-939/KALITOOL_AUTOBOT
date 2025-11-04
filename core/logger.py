"""
logger.py
==========
Provides a centralized logger for the KaliTool AutoBot project.
Handles console and file logging with consistent formatting.
"""

import logging
import os
import sys
from datetime import datetime

# ----------------------------------------------------------------------
# Directory Setup
# ----------------------------------------------------------------------
LOG_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, f"kalitool_{datetime.now().strftime('%Y%m%d')}.log")


# ----------------------------------------------------------------------
# Logger Configuration
# ----------------------------------------------------------------------
def get_logger(name: str = "KaliToolAutoBot") -> logging.Logger:
    """
    Create or return a logger instance with both console and file handlers.
    :param name: Logger name, default is 'KaliToolAutoBot'
    :return: Configured logger instance
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if logger.hasHandlers():
        # Avoid adding multiple handlers if already configured
        return logger

    # ------------------------------------------------------------------
    # File Handler (writes to logs/kalitool_YYYYMMDD.log)
    # ------------------------------------------------------------------
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Console Handler (colored output)
    # ------------------------------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    # ------------------------------------------------------------------
    # Add Handlers
    # ------------------------------------------------------------------
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# ----------------------------------------------------------------------
# Example Direct Run
# ----------------------------------------------------------------------
if __name__ == "__main__":
    log = get_logger()
    log.info("Logger initialized successfully!")
    log.debug("Debugging mode active.")
    log.warning("This is a warning example.")
    log.error("Error example for testing.")
