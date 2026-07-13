"""
common/logging_config.py — Structured logging configuration.

Implements structured (JSON-capable) logging with:
  - Request ID injection
  - Error ID generation
  - Environment-aware formatters (JSON for production, human-readable for dev)

OWASP ASVS V7.1: Log sufficient information for incident response.
OWASP ASVS V7.3: Protect log data from unauthorised modification.
"""

import logging
import sys
import os
import json
import uuid
import traceback
from datetime import datetime, timezone
from typing import Optional


class JSONFormatter(logging.Formatter):
    """
    JSON log formatter for structured, machine-parseable log output.
    Suitable for cloud log aggregators (Datadog, CloudWatch, Loki).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "level":      record.levelname,
            "logger":     record.name,
            "message":    record.getMessage(),
            "module":     record.module,
            "function":   record.funcName,
            "line":       record.lineno,
        }

        # Attach exception info
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
            log_entry["error_id"] = str(uuid.uuid4())

        # Attach any extra fields
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in (
                "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "name",
                "message"
            ):
                continue
            log_entry[key] = value

        return json.dumps(log_entry, default=str)


class HumanFormatter(logging.Formatter):
    """Human-readable formatter for development/local use."""

    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if sys.stdout.isatty() else ""
        color = color if sys.stdout.isatty() else ""
        fmt = f"[%(asctime)s] {color}[%(name)s] [%(levelname)s]{reset} %(message)s"
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


def configure_logging(
    level: Optional[str] = None,
    log_file: str = "nids.log",
    use_json: bool = False
) -> None:
    """
    Configure application-wide logging.

    Args:
        level:    Log level string (DEBUG/INFO/WARNING/ERROR). Defaults to env LOG_LEVEL or INFO.
        log_file: Path to the log file. Set to "" to disable file logging.
        use_json: Use JSON formatter. Auto-enabled when LOG_FORMAT=json env var is set.
    """
    log_level_str = level or os.environ.get("LOG_LEVEL", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    use_json = use_json or os.environ.get("LOG_FORMAT", "").lower() == "json"

    handlers: list[logging.Handler] = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    if use_json:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(HumanFormatter())
    handlers.append(console_handler)

    # File handler (rotating would need RotatingFileHandler for production)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(log_level)
            # Always use JSON in file logs for parsing
            file_handler.setFormatter(JSONFormatter())
            handlers.append(file_handler)
        except (PermissionError, OSError) as e:
            print(f"[WARNING] Cannot open log file '{log_file}': {e}", file=sys.stderr)

    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True,
    )

    # Silence noisy third-party loggers
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.ERROR)

    logging.getLogger("Main").info(
        f"Logging configured. level={log_level_str} json={use_json} file={log_file or 'disabled'}"
    )


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper for consistent logger creation."""
    return logging.getLogger(name)
