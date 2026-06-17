"""Logging configuration for the ecosystem registry.

Honours two environment variables:
- ECOSYSTEM_LOG_LEVEL  (default INFO)
- ECOSYSTEM_LOG_FORMAT (text | json, default text)

JSON output is suitable for log aggregators (Loki, CloudWatch, ELK).
"""

from __future__ import annotations

import json
import logging
import os


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Configure the root logger from the environment (idempotent)."""
    level_name = os.environ.get("ECOSYSTEM_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = os.environ.get("ECOSYSTEM_LOG_FORMAT", "text").lower()

    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )

    root = logging.getLogger()
    # Replace existing handlers so re-invocation does not duplicate output.
    root.handlers = [handler]
    root.setLevel(level)
