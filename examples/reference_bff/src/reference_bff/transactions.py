"""Cryptographic OAuth authorization-transaction primitives."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from reference_bff.return_targets import InvalidReturnTargetError, canonical_local_return_target

TRANSACTION_SCHEMA_VERSION = 1
OPAQUE_TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}")
PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
RECORD_FIELDS = frozenset(
    {
        "version",
        "transaction_id",
        "state",
        "nonce",
        "pkce_verifier",
        "return_to",
        "created_at",
        "expires_at",
        "callback_uri",
    }
)


class MalformedTransactionError(ValueError):
    """A consumed record failed its strict schema or integrity boundary."""


class ExpiredTransactionError(MalformedTransactionError):
    """A consumed record has passed its fixed expiry."""


def opaque_token() -> str:
    """Return an unpadded BASE64URL token carrying exactly 256 random bits."""

    return secrets.token_urlsafe(32)


def pkce_verifier() -> str:
    """Return an independent RFC 7636 verifier with more than 256 random bits."""

    return secrets.token_urlsafe(64)


def pkce_s256_challenge(verifier: str) -> str:
    if PKCE_VERIFIER.fullmatch(verifier) is None:
        raise ValueError("invalid PKCE verifier")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class AuthorizationTransaction:
    transaction_id: str
    state: str
    nonce: str
    pkce_verifier: str
    return_to: str
    created_at: int
    expires_at: int
    callback_uri: str
    version: int = TRANSACTION_SCHEMA_VERSION

    @property
    def code_challenge(self) -> str:
        return pkce_s256_challenge(self.pkce_verifier)

    def as_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "transaction_id": self.transaction_id,
                "state": self.state,
                "nonce": self.nonce,
                "pkce_verifier": self.pkce_verifier,
                "return_to": self.return_to,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "callback_uri": self.callback_uri,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


def new_transaction(
    *, return_to: str, callback_uri: str, ttl_seconds: int, now: int | None = None
) -> AuthorizationTransaction:
    created_at = int(time.time()) if now is None else now
    if not 60 <= ttl_seconds <= 600:
        raise ValueError("invalid transaction lifetime")
    canonical_return_to = canonical_local_return_target(return_to)
    return AuthorizationTransaction(
        transaction_id=opaque_token(),
        state=opaque_token(),
        nonce=opaque_token(),
        pkce_verifier=pkce_verifier(),
        return_to=canonical_return_to,
        created_at=created_at,
        expires_at=created_at + ttl_seconds,
        callback_uri=callback_uri,
    )


def _required_string(record: dict[str, Any], field: str, pattern: re.Pattern[str]) -> str:
    value = record.get(field)
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise MalformedTransactionError("malformed transaction")
    return value


def parse_consumed_transaction(
    serialized: bytes,
    *,
    expected_state: str,
    expected_callback_uri: str,
    expected_ttl_seconds: int,
    now: int | None = None,
) -> AuthorizationTransaction:
    try:
        decoded = serialized.decode("utf-8", errors="strict")
        raw = json.loads(decoded)
    except UnicodeError, json.JSONDecodeError:
        raise MalformedTransactionError("malformed transaction") from None
    if type(raw) is not dict or set(raw) != RECORD_FIELDS:
        raise MalformedTransactionError("malformed transaction")
    record: dict[str, Any] = raw
    if type(record["version"]) is not int or record["version"] != TRANSACTION_SCHEMA_VERSION:
        raise MalformedTransactionError("malformed transaction")
    transaction_id = _required_string(record, "transaction_id", OPAQUE_TOKEN)
    state = _required_string(record, "state", OPAQUE_TOKEN)
    nonce = _required_string(record, "nonce", OPAQUE_TOKEN)
    verifier = _required_string(record, "pkce_verifier", PKCE_VERIFIER)
    return_to = record.get("return_to")
    callback_uri = record.get("callback_uri")
    created_at = record.get("created_at")
    expires_at = record.get("expires_at")
    if (
        type(return_to) is not str
        or type(callback_uri) is not str
        or type(created_at) is not int
        or type(expires_at) is not int
        or callback_uri != expected_callback_uri
        or expires_at - created_at != expected_ttl_seconds
        or not secrets.compare_digest(state, expected_state)
    ):
        raise MalformedTransactionError("malformed transaction")
    try:
        canonical_local_return_target(return_to)
    except InvalidReturnTargetError:
        raise MalformedTransactionError("malformed transaction") from None
    current_time = int(time.time()) if now is None else now
    if created_at > current_time or current_time >= expires_at:
        raise ExpiredTransactionError("expired transaction")
    return AuthorizationTransaction(
        transaction_id=transaction_id,
        state=state,
        nonce=nonce,
        pkce_verifier=verifier,
        return_to=return_to,
        created_at=created_at,
        expires_at=expires_at,
        callback_uri=callback_uri,
    )
