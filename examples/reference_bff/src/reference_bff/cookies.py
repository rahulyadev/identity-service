"""Bounded duplicate-safe parsing for raw ASGI Cookie header fields."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType

COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")
COOKIE_VALUE = re.compile(r"[\x21-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]{0,4096}")
MAX_COOKIE_HEADER_BYTES = 8192
MAX_COOKIE_HEADERS = 16
MAX_COOKIE_PAIRS = 64


class InvalidCookieHeaderError(ValueError):
    """Cookie fields were malformed, ambiguous, or outside the fixed bounds."""


def parse_cookie_headers(headers: Iterable[tuple[bytes, bytes]]) -> Mapping[str, str]:
    """Parse raw Cookie fields without framework collapsing or quoted-value recovery."""

    total_bytes = 0
    cookie_headers = 0
    cookie_pairs = 0
    cookies: dict[str, str] = {}
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
            raise InvalidCookieHeaderError("invalid cookie header")
        try:
            text = raw_value.decode("ascii", errors="strict")
        except UnicodeError:
            raise InvalidCookieHeaderError("invalid cookie header") from None
        for position, raw_pair in enumerate(text.split(";")):
            pair = raw_pair[1:] if position > 0 and raw_pair.startswith(" ") else raw_pair
            cookie_pairs += 1
            if (
                cookie_pairs > MAX_COOKIE_PAIRS
                or not pair
                or pair != pair.strip(" ")
                or "=" not in pair
            ):
                raise InvalidCookieHeaderError("invalid cookie header")
            name, _, value = pair.partition("=")
            if (
                COOKIE_NAME.fullmatch(name) is None
                or COOKIE_VALUE.fullmatch(value) is None
                or '"' in value
                or name in cookies
            ):
                raise InvalidCookieHeaderError("invalid cookie header")
            cookies[name] = value
    return MappingProxyType(cookies)
