"""Opaque cookies and strict bounded server-side session documents."""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from reference_bff.config import Settings
from reference_bff.cookies import InvalidCookieHeaderError, parse_cookie_headers
from reference_bff.json_safety import UnsafeJsonError, load_json_object

SESSION_SCHEMA_VERSION = 2
SESSION_COOKIE_NAME = "__Host-session"
CANONICAL_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")
TOKEN_FAMILY_VALUE = re.compile(r"[\x21-\x7E]{1,255}")
SESSION_FIELDS = frozenset(
    {
        "version",
        "issuer",
        "subject",
        "client_id",
        "user_id",
        "nonce",
        "token_family_id",
        "access_token",
        "id_token",
        "refresh_token",
        "access_expires_at",
        "created_at",
        "last_activity_at",
        "absolute_expires_at",
        "refresh_version",
    }
)
MAX_TIMESTAMP = 9_999_999_999
MAX_REFRESH_VERSION = 2_147_483_647


class InvalidSessionCookieError(ValueError):
    """The browser did not supply one canonical opaque session identifier."""


class InvalidSessionRecordError(ValueError):
    """The Redis session document failed its fixed schema or validity contract."""


@dataclass(frozen=True, slots=True, repr=False)
class SessionRecord:
    issuer: str
    subject: str = field(repr=False)
    client_id: str
    user_id: str
    nonce: str = field(repr=False)
    token_family_id: str = field(repr=False)
    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    access_expires_at: int
    created_at: int
    last_activity_at: int
    absolute_expires_at: int
    refresh_version: int = 0
    version: int = SESSION_SCHEMA_VERSION

    def __repr__(self) -> str:
        return "SessionRecord(<redacted>)"

    def as_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "issuer": self.issuer,
                "subject": self.subject,
                "client_id": self.client_id,
                "user_id": self.user_id,
                "nonce": self.nonce,
                "token_family_id": self.token_family_id,
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


@dataclass(frozen=True, slots=True, repr=False)
class StoredSession:
    record: SessionRecord
    serialized: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "StoredSession(<redacted>)"

    @classmethod
    def from_record(cls, record: SessionRecord) -> StoredSession:
        return cls(record=record, serialized=record.as_json_bytes())


@dataclass(frozen=True, slots=True, repr=False)
class SessionHandle:
    session_id: str = field(repr=False)
    max_age: int

    def __repr__(self) -> str:
        return "SessionHandle(<redacted>)"


def opaque_session_id() -> str:
    """Return an unpadded BASE64URL identifier with exactly 256 random bits."""

    return secrets.token_urlsafe(32)


def refresh_lock_owner() -> str:
    """Return an independent canonical 256-bit refresh-lock owner marker."""

    return secrets.token_urlsafe(32)


def is_canonical_session_id(value: str) -> bool:
    if CANONICAL_SESSION_ID.fullmatch(value) is None:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except binascii.Error, ValueError:
        return False
    return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() == value


def parse_session_cookie(headers: list[tuple[bytes, bytes]]) -> str:
    try:
        value = parse_cookie_headers(headers).get(SESSION_COOKIE_NAME)
    except InvalidCookieHeaderError:
        raise InvalidSessionCookieError("invalid session cookie") from None
    if value is None or not is_canonical_session_id(value):
        raise InvalidSessionCookieError("invalid session cookie")
    return value


def _bounded_text(value: Any, *, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise InvalidSessionRecordError("invalid session document")
    return value


def _token(value: Any, *, maximum: int, jwt: bool) -> str:
    token = _bounded_text(value, maximum=maximum)
    if not token.isascii() or len(token) < 16 or (jwt and token.count(".") != 2):
        raise InvalidSessionRecordError("invalid session document")
    return token


def _timestamp(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TIMESTAMP:
        raise InvalidSessionRecordError("invalid session document")
    return value


def parse_session_record(raw: bytes, settings: Settings, *, now: int) -> StoredSession:
    """Reject duplicates, schema drift, invalid bindings, and expired lifetimes."""

    if type(raw) is not bytes or not raw or len(raw) > settings.max_session_bytes:
        raise InvalidSessionRecordError("invalid session document")
    try:
        document = load_json_object(raw)
    except UnsafeJsonError:
        raise InvalidSessionRecordError("invalid session document") from None
    if set(document) != SESSION_FIELDS or document.get("version") != SESSION_SCHEMA_VERSION:
        raise InvalidSessionRecordError("invalid session document")
    issuer = _bounded_text(document["issuer"], maximum=2048)
    client_id = _bounded_text(document["client_id"], maximum=256)
    if issuer != settings.cognito_issuer or client_id != settings.client_id:
        raise InvalidSessionRecordError("invalid session document")
    subject = _bounded_text(document["subject"], maximum=255)
    user_id = _bounded_text(document["user_id"], maximum=36)
    try:
        parsed_user_id = uuid.UUID(user_id)
    except ValueError, AttributeError:
        raise InvalidSessionRecordError("invalid session document") from None
    if parsed_user_id.version != 4 or str(parsed_user_id) != user_id:
        raise InvalidSessionRecordError("invalid session document")
    nonce = document["nonce"]
    if type(nonce) is not str or not is_canonical_session_id(nonce):
        raise InvalidSessionRecordError("invalid session document")
    token_family = document["token_family_id"]
    if type(token_family) is not str or TOKEN_FAMILY_VALUE.fullmatch(token_family) is None:
        raise InvalidSessionRecordError("invalid session document")
    access_token = _token(document["access_token"], maximum=settings.jwt_max_token_bytes, jwt=True)
    id_token = _token(document["id_token"], maximum=settings.jwt_max_token_bytes, jwt=True)
    refresh_token = _token(
        document["refresh_token"], maximum=settings.jwt_max_token_bytes, jwt=False
    )
    access_expires_at = _timestamp(document["access_expires_at"])
    created_at = _timestamp(document["created_at"])
    last_activity_at = _timestamp(document["last_activity_at"])
    absolute_expires_at = _timestamp(document["absolute_expires_at"])
    refresh_version = document["refresh_version"]
    if type(refresh_version) is not int or not 0 <= refresh_version <= MAX_REFRESH_VERSION:
        raise InvalidSessionRecordError("invalid session document")
    if (
        absolute_expires_at != created_at + settings.session_absolute_seconds
        or not created_at <= last_activity_at < absolute_expires_at
        or last_activity_at > now + settings.jwt_clock_skew_seconds
        or access_expires_at <= created_at
        or now >= absolute_expires_at
        or now - last_activity_at >= settings.session_idle_seconds
    ):
        raise InvalidSessionRecordError("invalid session document")
    record = SessionRecord(
        issuer=issuer,
        subject=subject,
        client_id=client_id,
        user_id=user_id,
        nonce=nonce,
        token_family_id=token_family,
        access_token=access_token,
        id_token=id_token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at,
        created_at=created_at,
        last_activity_at=last_activity_at,
        absolute_expires_at=absolute_expires_at,
        refresh_version=refresh_version,
    )
    return StoredSession(record=record, serialized=raw)


def session_max_age(record: SessionRecord, settings: Settings, *, now: int) -> int:
    return min(settings.session_idle_seconds, record.absolute_expires_at - now)
