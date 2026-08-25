"""Strict parser for a future single-value Authorization header."""

from __future__ import annotations

from collections.abc import Sequence

from identity_service.security.errors import InvalidBearerSyntaxError


def parse_bearer_authorization(values: Sequence[str], *, max_token_bytes: int) -> str:
    if len(values) != 1:
        raise InvalidBearerSyntaxError("exactly one Authorization value is required")
    value = values[0]
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InvalidBearerSyntaxError("Authorization contains a control character")
    if "," in value:
        raise InvalidBearerSyntaxError("multiple bearer credentials are forbidden")
    parts = value.split(" ")
    if len(parts) != 2 or not parts[0] or not parts[1] or parts[0].casefold() != "bearer":
        raise InvalidBearerSyntaxError("Authorization must contain one bearer credential")
    token = parts[1]
    if (
        any(character.isspace() for character in token)
        or len(token.encode("utf-8")) > max_token_bytes
    ):
        raise InvalidBearerSyntaxError("bearer credential is malformed or oversized")
    if token.count(".") != 2:
        raise InvalidBearerSyntaxError("bearer credential must be a compact JWT")
    return token
