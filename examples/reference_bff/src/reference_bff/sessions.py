"""Opaque session identifiers and bounded server-side session records."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

SESSION_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class SessionRecord:
    issuer: str
    subject: str = field(repr=False)
    client_id: str
    user_id: str
    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    access_expires_at: int
    created_at: int
    last_activity_at: int
    absolute_expires_at: int
    refresh_version: int = 0
    version: int = SESSION_SCHEMA_VERSION

    def as_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "issuer": self.issuer,
                "subject": self.subject,
                "client_id": self.client_id,
                "user_id": self.user_id,
                "access_token": self.access_token,
                "id_token": self.id_token,
                "refresh_token": self.refresh_token,
                "access_expires_at": self.access_expires_at,
                "created_at": self.created_at,
                "last_activity_at": self.last_activity_at,
                "absolute_expires_at": self.absolute_expires_at,
                "refresh_version": self.refresh_version,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SessionHandle:
    session_id: str = field(repr=False)
    max_age: int


def opaque_session_id() -> str:
    """Return an unpadded BASE64URL identifier with exactly 256 random bits."""

    return secrets.token_urlsafe(32)
