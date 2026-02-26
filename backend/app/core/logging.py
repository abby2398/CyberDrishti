# backend/app/core/logging.py
# ─────────────────────────────────────────
#  Structured logging for CyberDrishti.
#  Every action is logged with timestamp,
#  level, module, and message.
# ─────────────────────────────────────────

import logging
import sys
import os
from datetime import datetime, timezone


def setup_logging(log_level: str = "INFO", log_file: str = "logs/cyberdrishti.log"):
    """Configure application-wide logging."""

    # Ensure logs directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    level = getattr(logging, log_level.upper(), logging.INFO)

    # Log format — structured and readable
    fmt = "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S UTC"

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
    root.addHandler(console)

    # File handler
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
        root.addHandler(file_handler)
    except Exception:
        pass  # If log file fails, console logging continues

    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger for a module."""
    return logging.getLogger(name)
