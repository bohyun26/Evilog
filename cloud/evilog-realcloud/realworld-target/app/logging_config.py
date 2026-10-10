"""
Structured JSON logging for the RealWorld target app.

Format follows the widely-used structured-logging convention (ECS-like):
one JSON object per line on stdout, so that any log shipper
(Fluent Bit -> CloudWatch Logs, Fluentd, Vector) can ingest it unmodified.

Field contract (stable -- the harness parses these):
    ts        RFC3339 UTC timestamp
    level     DEBUG | INFO | WARN | ERROR
    service   logical service name
    trace_id  request correlation id
    event     dotted event name, e.g. "db.pool.timeout"
    msg       human-readable message
    ...       arbitrary event-specific fields

IMPORTANT for the experiment: fields that can contain attacker-controlled
text are NOT sanitised here. That is deliberate. This app models a normal
production service that logs user input verbatim, which is precisely the
condition the AIOps log-injection threat model assumes.
"""

import json
import logging
import os
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

SERVICE_NAME = os.getenv("SERVICE_NAME", "realworld-api")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Correlation id for the in-flight request.
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="-")


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


class JsonFormatter(logging.Formatter):
    """Renders one JSON object per line."""

    _RESERVED = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
        "color_message",
    }

    _LEVEL_MAP = {"WARNING": "WARN", "CRITICAL": "ERROR"}

    def format(self, record: logging.LogRecord) -> str:
        level = self._LEVEL_MAP.get(record.levelname, record.levelname)

        payload = {
            "ts": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": level,
            "service": SERVICE_NAME,
            "trace_id": trace_id_var.get(),
            "event": getattr(record, "event", "app.log"),
            "msg": record.getMessage(),
        }

        # Merge event-specific extras.
        for key, value in record.__dict__.items():
            if key in self._RESERVED or key.startswith("_"):
                continue
            if key in ("event",):
                continue
            payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging() -> logging.Logger:
    root = logging.getLogger()
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(LOG_LEVEL)

    # Uvicorn's own access log would be a second, non-JSON format on stdout.
    # We emit our own access events instead, so silence it.
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = False

    for passthrough in ("uvicorn", "uvicorn.error"):
        logging.getLogger(passthrough).handlers.clear()
        logging.getLogger(passthrough).propagate = True

    return logging.getLogger(SERVICE_NAME)


log = logging.getLogger(SERVICE_NAME)


def emit(level: str, event: str, msg: str, **fields) -> None:
    """Emit a structured event. `level` is one of debug/info/warn/error."""
    fn = {
        "debug": log.debug,
        "info": log.info,
        "warn": log.warning,
        "warning": log.warning,
        "error": log.error,
    }[level.lower()]
    fn(msg, extra={"event": event, **fields})


class Timer:
    """Context manager yielding elapsed milliseconds."""

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.ms = round((time.perf_counter() - self._start) * 1000, 2)
        return False
