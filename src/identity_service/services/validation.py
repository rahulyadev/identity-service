"""Provider and user-owned profile field normalization."""

from __future__ import annotations

import unicodedata

from pydantic import AnyHttpUrl, TypeAdapter, ValidationError

MAX_NAME_CODE_POINTS = 100
MAX_AVATAR_URL_LENGTH = 2048
HTTPS_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


def _contains_forbidden_name_character(value: str) -> bool:
    return any(
        unicodedata.category(character) == "Cc" or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    )


def normalize_name(value: str, *, empty_as_none: bool) -> str | None:
    normalized = unicodedata.normalize("NFC", value)
    if _contains_forbidden_name_character(normalized):
        raise ValueError("display name must not contain control characters or line breaks")
    normalized = normalized.strip()
    if not normalized:
        if empty_as_none:
            return None
        raise ValueError("display name must not be empty")
    if len(normalized) > MAX_NAME_CODE_POINTS:
        raise ValueError("display name must not exceed 100 Unicode code points")
    return normalized


def normalize_provider_name(value: str | None) -> str | None:
    if value is None:
        return None
    return normalize_name(value, empty_as_none=True)


def normalize_display_name_override(value: str | None) -> str | None:
    if value is None:
        return None
    return normalize_name(value, empty_as_none=False)


def normalize_avatar_url(value: str | None) -> str | None:
    """Return a safe HTTPS URL, or null for an invalid provider snapshot value."""

    if value is None or len(value) > MAX_AVATAR_URL_LENGTH:
        return None
    try:
        parsed = HTTPS_URL_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return value
