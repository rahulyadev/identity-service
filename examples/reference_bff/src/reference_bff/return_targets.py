"""Canonical local return-target validation without open-redirect ambiguity."""

from __future__ import annotations

import unicodedata
from urllib.parse import quote, unquote, urlsplit


class InvalidReturnTargetError(ValueError):
    """The supplied target is not one canonical local path."""


def canonical_local_return_target(value: str, *, max_bytes: int = 2048) -> str:
    """Return an unchanged bounded local target or reject it without normalization."""

    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise InvalidReturnTargetError("invalid return target") from None
    if (
        not value
        or len(encoded) > max_bytes
        or value != unicodedata.normalize("NFC", value)
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "%" in value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        raise InvalidReturnTargetError("invalid return target")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        raise InvalidReturnTargetError("invalid return target")
    segments = parsed.path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise InvalidReturnTargetError("invalid return target")
    if any(not segment for segment in segments[1:-1]):
        raise InvalidReturnTargetError("invalid return target")
    return value


def return_target_from_query(query_string: bytes, *, max_bytes: int = 2048) -> str:
    """Extract the sole optional query parameter using one canonical outer encoding."""

    if not query_string:
        return "/"
    if len(query_string) > max_bytes * 3 + 32:
        raise InvalidReturnTargetError("invalid return target")
    try:
        raw_query = query_string.decode("ascii", errors="strict")
    except UnicodeError:
        raise InvalidReturnTargetError("invalid return target") from None
    prefix = "return_to="
    if not raw_query.startswith(prefix) or "&" in raw_query or raw_query.count("=") != 1:
        raise InvalidReturnTargetError("invalid return target")
    raw_value = raw_query.removeprefix(prefix)
    if not raw_value:
        raise InvalidReturnTargetError("invalid return target")
    try:
        decoded = unquote(raw_value, encoding="utf-8", errors="strict")
    except UnicodeError:
        raise InvalidReturnTargetError("invalid return target") from None
    if quote(decoded, safe="") != raw_value:
        raise InvalidReturnTargetError("invalid return target")
    return canonical_local_return_target(decoded, max_bytes=max_bytes)
