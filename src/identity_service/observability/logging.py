"""Structured logging with centralized conservative redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, TextIO

from identity_service.config import Settings

REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = {
    "authorization",
    "cookie",
    "set_cookie",
    "token",
    "oauth_code",
    "state",
    "nonce",
    "pkce",
    "client_secret",
    "password",
    "database_url",
    "email",
    "name",
    "avatar",
    "issuer",
    "subject",
    "user_id",
    "request_body",
    "response_body",
}
STANDARD_LOG_RECORD_FIELDS = set(logging.makeLogRecord({}).__dict__)
UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
URL_PATTERN = re.compile(r"\b(?:postgresql(?:\+psycopg)?|https?)://[^\s]+", re.IGNORECASE)
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
COMMON_JSON_FIELDS = frozenset(
    {"timestamp", "level", "logger", "message", "service", "service_version", "environment"}
)
UVICORN_PROPAGATING_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.asgi")
CONTROLLED_PROPAGATING_LOGGERS = ("identity_service", *UVICORN_PROPAGATING_LOGGERS)
UVICORN_LIFECYCLE_EVENTS = (
    ("Started server process", "server_started"),
    ("Waiting for application startup", "application_startup_wait"),
    ("Application startup complete", "application_startup_complete"),
    ("Uvicorn running on", "server_listening"),
    ("Shutting down", "server_shutdown_started"),
    ("Waiting for application shutdown", "application_shutdown_wait"),
    ("Application shutdown complete", "application_shutdown_complete"),
    ("Finished server process", "server_stopped"),
)


def _sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def redact_text(value: str) -> str:
    redacted = BEARER_PATTERN.sub(REDACTED, value)
    redacted = JWT_PATTERN.sub(REDACTED, redacted)
    redacted = URL_PATTERN.sub(REDACTED, redacted)
    redacted = EMAIL_PATTERN.sub(REDACTED, redacted)
    return UUID_PATTERN.sub(REDACTED, redacted)


def redact_value(value: Any, *, key: str = "") -> Any:
    if key.lower().replace("-", "_") == "request_id":
        return value
    if key and _sensitive_key(key):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(item_key): redact_value(item, key=str(item_key)) for item_key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, (list, set)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_value(record.msg)
        if record.args:
            record.args = redact_value(record.args)
        for key, value in tuple(record.__dict__.items()):
            if key not in STANDARD_LOG_RECORD_FIELDS:
                record.__dict__[key] = redact_value(value, key=key)
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def _event_for_record(record: logging.LogRecord) -> str:
    message = record.getMessage()
    if record.name.startswith("uvicorn"):
        for prefix, event in UVICORN_LIFECYCLE_EVENTS:
            if message.startswith(prefix):
                return event
        return "uvicorn_log"
    if record.name.startswith("identity_service") and re.fullmatch(
        r"[a-z][a-z0-9_]{0,63}", message
    ):
        return message
    return "log_record"


class JsonFormatter(logging.Formatter):
    def __init__(
        self,
        *,
        service: str = "identity-service",
        service_version: str = "unknown",
        environment: str = "unknown",
    ) -> None:
        super().__init__()
        self.service = service
        self.service_version = service_version
        self.environment = environment

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "service_version": self.service_version,
            "environment": self.environment,
            "event": _event_for_record(record),
        }
        for key, value in record.__dict__.items():
            if (
                key not in STANDARD_LOG_RECORD_FIELDS
                and key not in COMMON_JSON_FIELDS
                and not key.startswith("_")
            ):
                payload[key] = value
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def configure_logging(settings: Settings, *, stream: TextIO | None = None) -> None:
    """Install the single service log pipeline and neutralize Uvicorn defaults."""

    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    if settings.log_format == "json":
        handler.setFormatter(
            JsonFormatter(
                service_version=settings.service_version,
                environment=settings.app_env.value,
            )
        )
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    logger_names = set(CONTROLLED_PROPAGATING_LOGGERS)
    logger_names.update(
        name
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger) and name.startswith("identity_service.")
    )
    for logger_name in logger_names:
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.setLevel(logging.NOTSET)
        logger.disabled = False
        logger.propagate = True

    access_logger = logging.getLogger("uvicorn.access")
    access_logger.handlers.clear()
    access_logger.disabled = True
    access_logger.propagate = False

    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
