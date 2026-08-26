"""Strict raw-query parsing for the one-time OAuth callback."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import quote, unquote_to_bytes

from reference_bff.transactions import OPAQUE_TOKEN

OAUTH_CODE = re.compile(r"[\x21-\x7e]{1,8192}")
PROVIDER_ERROR = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,255}")
PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}")
COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")
COOKIE_VALUE = re.compile(r"[\x21-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]{0,4096}")
OAUTH_BINDING_COOKIE_NAME = "__Host-oauth"
MAX_COOKIE_HEADER_BYTES = 8192
MAX_COOKIE_HEADERS = 16
MAX_COOKIE_PAIRS = 64


class InvalidCallbackQueryError(ValueError):
    """The callback query was ambiguous, malformed, mixed, or oversized."""


class InvalidOAuthBrowserBindingError(ValueError):
    """The callback omitted or ambiguously encoded its browser binding."""


@dataclass(frozen=True, slots=True)
class CallbackSuccess:
    state: str = field(repr=False)
    code: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class CallbackDenied:
    state: str = field(repr=False)
    provider_error: str = field(repr=False)


ParsedCallback = CallbackSuccess | CallbackDenied


@dataclass(frozen=True, slots=True)
class OAuthBrowserBinding:
    transaction_id: str = field(repr=False)


def parse_oauth_browser_binding(
    headers: Iterable[tuple[bytes, bytes]],
) -> OAuthBrowserBinding:
    """Parse raw ASGI Cookie fields without duplicate collapsing or reflection."""

    total_bytes = 0
    cookie_headers = 0
    cookie_pairs = 0
    oauth_value: str | None = None
    for raw_name, raw_value in headers:
        if raw_name.lower() != b"cookie":
            continue
        cookie_headers += 1
        total_bytes += len(raw_name) + len(raw_value)
        if (
            cookie_headers > MAX_COOKIE_HEADERS
            or total_bytes > MAX_COOKIE_HEADER_BYTES
            or not raw_value
            or any(value < 0x20 or value > 0x7E for value in raw_value)
        ):
            raise InvalidOAuthBrowserBindingError("invalid OAuth browser binding")
        try:
            text = raw_value.decode("ascii", errors="strict")
        except UnicodeError:
            raise InvalidOAuthBrowserBindingError("invalid OAuth browser binding") from None
        for position, raw_pair in enumerate(text.split(";")):
            pair = raw_pair[1:] if position > 0 and raw_pair.startswith(" ") else raw_pair
            cookie_pairs += 1
            if (
                cookie_pairs > MAX_COOKIE_PAIRS
                or not pair
                or pair != pair.strip(" ")
                or "=" not in pair
            ):
                raise InvalidOAuthBrowserBindingError("invalid OAuth browser binding")
            name, _, value = pair.partition("=")
            if COOKIE_NAME.fullmatch(name) is None or COOKIE_VALUE.fullmatch(value) is None:
                raise InvalidOAuthBrowserBindingError("invalid OAuth browser binding")
            if name == OAUTH_BINDING_COOKIE_NAME:
                if oauth_value is not None or OPAQUE_TOKEN.fullmatch(value) is None:
                    raise InvalidOAuthBrowserBindingError("invalid OAuth browser binding")
                oauth_value = value
    if oauth_value is None:
        raise InvalidOAuthBrowserBindingError("invalid OAuth browser binding")
    return OAuthBrowserBinding(transaction_id=oauth_value)


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
