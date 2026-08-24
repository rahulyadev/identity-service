"""Immutable security-domain values that intentionally exclude raw bearer material."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedAccessToken:
    issuer: str
    subject: str
    client_id: str
    audience: frozenset[str]
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    auth_time: datetime
    not_before: datetime | None
    key_id_fingerprint: str

    def __repr__(self) -> str:
        return "VerifiedAccessToken(<redacted>)"

    def __str__(self) -> str:
        return "VerifiedAccessToken(<redacted>)"
