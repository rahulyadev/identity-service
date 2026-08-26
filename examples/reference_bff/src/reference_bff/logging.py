"""Single redacted log pipeline for the reference BFF."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import TextIO

from reference_bff.config import Settings

SENSITIVE_TEXT = re.compile(
    r"(?i)(?:client_secret|redis_url|state|nonce|code|code_verifier|pkce_verifier|"
    r"transaction_id|oauth_binding|__host-oauth|cookie|authorization|access_token|id_token|"
    r"refresh_token|session_id|csrf_token|x-csrf-token|"
    r"subject)\s*[=:]\s*[^\s,]+"
)
CREDENTIAL_URL = re.compile(r"(?i)(redis(?:s)?://)[^/@\s:]+(?::[^/@\s]*)?@")


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
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
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "event": record.getMessage(),
                "service": "reference-bff",
                "service_version": self._settings.service_version,
                "environment": self._settings.app_env.value,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def configure_logging(settings: Settings, *, stream: TextIO | None = None) -> None:
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter(settings))
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
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
