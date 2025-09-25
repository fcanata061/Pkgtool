# pkgtool/logger.py
\"\"\"Structured logging for pkgtool.

Uses `rich` if available for console coloring. Also writes logs to rotating files (simple).
Provides:
 - get_logger(name)
 - log levels: debug/info/warn/error/success (success is alias to info with green)
 - tail-like follow not implemented here (will be in CLI wrapper)
\"\"\"

from __future__ import annotations
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

try:
    from rich.logging import RichHandler
    RICH = True
except Exception:
    RICH = False

DEFAULT_LOG_DIR = Path("/var/log/pkgtool")
DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)

def _ensure_logfile(name: str) -> Path:
    DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    p = DEFAULT_LOG_DIR / f"{name}.log"
    return p

def get_logger(name: str = "pkgtool", logfile: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    if RICH:
        sh = RichHandler(show_time=True, show_level=True, show_path=False)
    else:
        sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    sh.setFormatter(logging.Formatter(fmt))
    logger.addHandler(sh)

    # file handler
    logpath = logfile or str(_ensure_logfile(name))
    fh = RotatingFileHandler(logpath, maxBytes=10*1024*1024, backupCount=5)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt))
    logger.addHandler(fh)
    return logger

# convenience
_logger = get_logger()

def debug(msg: str) -> None:
    _logger.debug(msg)

def info(msg: str) -> None:
    _logger.info(msg)

def success(msg: str) -> None:
    # log as info but include marker
    _logger.info("[SUCCESS] " + msg)

def warn(msg: str) -> None:
    _logger.warning(msg)

def error(msg: str) -> None:
    _logger.error(msg)
