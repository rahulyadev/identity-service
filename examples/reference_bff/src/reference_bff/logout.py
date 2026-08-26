"""Strict empty logout request validation without unsafe value reflection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class LogoutRequestError(Exception):
    status: int
    code: str


@dataclass(frozen=True, slots=True, repr=False)
class RawLogoutRequest:
    headers: tuple[tuple[bytes, bytes], ...] = field(repr=False)
    query_string: bytes = field(repr=False)
    body_present: bool
    body_complete: bool

    def __repr__(self) -> str:
        return "RawLogoutRequest(<redacted>)"


def _header_values(raw: RawLogoutRequest, name: bytes) -> list[bytes]:
    return [value for candidate, value in raw.headers if candidate.lower() == name]


def validate_logout_request(raw: RawLogoutRequest) -> None:
    """Accept only an empty unsafe request with one unambiguous framing choice."""

    if (
        raw.query_string
        or not raw.body_complete
        or raw.body_present
        or _header_values(raw, b"authorization")
        or _header_values(raw, b"transfer-encoding")
        or _header_values(raw, b"content-type")
    ):
        raise LogoutRequestError(400, "bad_request")
    lengths = _header_values(raw, b"content-length")
    if len(lengths) > 1 or (lengths and lengths[0] != b"0"):
        raise LogoutRequestError(400, "bad_request")
