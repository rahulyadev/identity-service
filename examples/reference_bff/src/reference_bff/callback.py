"""Strict raw-query parsing for the one-time OAuth callback."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote_to_bytes

from reference_bff.transactions import OPAQUE_TOKEN

OAUTH_CODE = re.compile(r"[\x21-\x7e]{1,8192}")
PROVIDER_ERROR = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,255}")
PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}")


class InvalidCallbackQueryError(ValueError):
    """The callback query was ambiguous, malformed, mixed, or oversized."""


@dataclass(frozen=True, slots=True)
class CallbackSuccess:
    state: str = field(repr=False)
    code: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class CallbackDenied:
    state: str = field(repr=False)
    provider_error: str = field(repr=False)


ParsedCallback = CallbackSuccess | CallbackDenied


def _decode_value(raw: str) -> str:
    if not raw or "+" in raw:
        raise InvalidCallbackQueryError("invalid callback query")
    index = 0
    while index < len(raw):
        if raw[index] == "%":
            if index + 3 > len(raw) or PERCENT_ESCAPE.fullmatch(raw[index : index + 3]) is None:
                raise InvalidCallbackQueryError("invalid callback query")
            index += 3
        else:
            index += 1
    try:
        decoded = unquote_to_bytes(raw).decode("utf-8", errors="strict")
    except UnicodeError:
        raise InvalidCallbackQueryError("invalid callback query") from None
    if quote(decoded, safe="-._~") != raw:
        raise InvalidCallbackQueryError("invalid callback query")
    return decoded


def parse_callback_query(
    query_string: bytes,
    *,
    max_query_bytes: int,
    max_code_bytes: int,
    max_error_bytes: int,
) -> ParsedCallback:
    if not query_string or len(query_string) > max_query_bytes:
        raise InvalidCallbackQueryError("invalid callback query")
    try:
        raw_query = query_string.decode("ascii", errors="strict")
    except UnicodeError:
        raise InvalidCallbackQueryError("invalid callback query") from None
    parameters: dict[str, str] = {}
    for segment in raw_query.split("&"):
        if not segment or segment.count("=") != 1:
            raise InvalidCallbackQueryError("invalid callback query")
        name, raw_value = segment.split("=", maxsplit=1)
        if name not in {"code", "state", "error"} or name in parameters:
            raise InvalidCallbackQueryError("invalid callback query")
        parameters[name] = _decode_value(raw_value)
    if set(parameters) == {"code", "state"}:
        state = parameters["state"]
        code = parameters["code"]
        if OPAQUE_TOKEN.fullmatch(state) is None or (
            len(code.encode("utf-8")) > max_code_bytes or OAUTH_CODE.fullmatch(code) is None
        ):
            raise InvalidCallbackQueryError("invalid callback query")
        return CallbackSuccess(state=state, code=code)
    if set(parameters) == {"error", "state"}:
        state = parameters["state"]
        provider_error = parameters["error"]
        if OPAQUE_TOKEN.fullmatch(state) is None or (
            len(provider_error.encode("utf-8")) > max_error_bytes
            or PROVIDER_ERROR.fullmatch(provider_error) is None
        ):
            raise InvalidCallbackQueryError("invalid callback query")
        return CallbackDenied(state=state, provider_error=provider_error)
    raise InvalidCallbackQueryError("invalid callback query")
