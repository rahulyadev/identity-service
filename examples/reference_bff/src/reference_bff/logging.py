"""Single redacted log pipeline for the reference BFF."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import TextIO

from reference_bff.auth_diagnostics import (
    CALLBACK_REJECTION_EVENT,
    CallbackRejection,
    CallbackRequestId,
    safe_category,
)
from reference_bff.config import Settings

SENSITIVE_TEXT = re.compile(
    r"(?i)(?:client_secret|redis_url|state|nonce|code|code_verifier|pkce_verifier|"
    r"transaction_id|oauth_binding|__host-oauth|cookie|authorization|access_token|id_token|"
    r"refresh_token|session_id|csrf_token|x-csrf-token|"
    r"subject)\s*[=:]\s*[^\s,]+"
)
CREDENTIAL_URL = re.compile(r"(?i)(redis(?:s)?://)[^/@\s:]+(?::[^/@\s]*)?@")


def _diagnostic_fields(record: logging.LogRecord) -> dict[str, str] | None:
    if "callback_rejection" not in record.__dict__ and not (
        type(record.msg) is str and record.msg == CALLBACK_REJECTION_EVENT
    ):
        return None
    diagnostic = record.__dict__.get("callback_rejection")
    category = None
    request_id = "unavailable"
    if type(diagnostic) is CallbackRejection:
        category = diagnostic.category
        correlation = diagnostic.request_id
        if (
            type(correlation) is CallbackRequestId
            and type(correlation.value) is str
            and re.fullmatch(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}", correlation.value)
        ):
            request_id = correlation.value
    # Build this allowlist before either formatter serializes anything. No message,
    # arguments, exception, stack, arbitrary extra or caller ID is consulted.
    return {
        "event": CALLBACK_REJECTION_EVENT,
        "category": safe_category(category).value,
        "request_id": request_id,
    }


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if _diagnostic_fields(record) is not None:
            record.msg = CALLBACK_REJECTION_EVENT
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
            return True
        message = record.getMessage()
        message = SENSITIVE_TEXT.sub("sensitive=[REDACTED]", message)
        message = CREDENTIAL_URL.sub(r"\1[REDACTED]@", message)
        record.msg = message
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    def format(self, record: logging.LogRecord) -> str:
        diagnostic = _diagnostic_fields(record)
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": "WARNING" if diagnostic is not None else record.levelname,
                "logger": "reference_bff.http" if diagnostic is not None else record.name,
                **(diagnostic if diagnostic is not None else {"event": record.getMessage()}),
                "service": "reference-bff",
                "service_version": self._settings.service_version,
                "environment": self._settings.app_env.value,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


class TextFormatter(logging.Formatter):
    def __init__(self, settings: Settings) -> None:
        super().__init__("%(levelname)s %(name)s %(message)s")
        self._json = JsonFormatter(settings)

    def format(self, record: logging.LogRecord) -> str:
        if _diagnostic_fields(record) is not None:
            # The same validated envelope in both modes; never append exception text.
            return " ".join(
                f"{key}={value}" for key, value in json.loads(self._json.format(record)).items()
            )
        return super().format(record)


def configure_logging(settings: Settings, *, stream: TextIO | None = None) -> None:
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter(settings))
    else:
        handler.setFormatter(TextFormatter(settings))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)
    for name in ("uvicorn", "uvicorn.error", "reference_bff"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.disabled = False
        logger.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.disabled = True
    access.propagate = False
    logging.getLogger("redis").setLevel(logging.WARNING)
    logging.getLogger("httpx2").setLevel(logging.WARNING)
