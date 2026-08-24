"""Strict Cognito RS256 access-token verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt

from identity_service.config import Settings
from identity_service.security.contracts import VerifiedAccessToken
from identity_service.security.errors import (
    InsufficientScopeError,
    InvalidTokenError,
    TokenVerificationUnavailableError,
)
from identity_service.security.jwks import JwksCache

REQUIRED_CLAIMS = (
    "iss",
    "sub",
    "client_id",
    "aud",
    "token_use",
    "scope",
    "exp",
    "iat",
    "auth_time",
)
KEY_LOCATION_HEADERS = frozenset({"jku", "x5u", "jwk"})
COMPATIBLE_TOKEN_TYPES = frozenset({"jwt", "at+jwt", "application/at+jwt"})
MAX_SCOPE_LENGTH = 256
MAX_SCOPE_COUNT = 64
MAX_SCOPE_CLAIM_LENGTH = 4096
MAX_AUDIENCE_COUNT = 16
MAX_JWT_JSON_DEPTH = 64


class TokenMetrics(Protocol):
    def record_jwt_validation(self, outcome: str) -> None: ...


class AccessTokenVerifier:
    def __init__(
        self,
        settings: Settings,
        jwks_cache: JwksCache,
        *,
        metrics: TokenMetrics | None = None,
    ) -> None:
        self._issuer = settings.cognito_issuer
        self._allowed_clients = frozenset(settings.cognito_allowed_client_ids)
        self._resource = settings.oauth_resource
        self._clock_skew = settings.jwt_clock_skew_seconds
        self._max_token_bytes = settings.jwt_max_token_bytes
        self._jwks_cache = jwks_cache
        self._metrics = metrics

    def verify_access_token(
        self, raw_token: str, required_scopes: Iterable[str] = ()
    ) -> VerifiedAccessToken:
        try:
            verified = self._verify(raw_token, frozenset(required_scopes))
        except InvalidTokenError as error:
            self._record(error.outcome)
            raise
        except InsufficientScopeError:
            self._record("insufficient_scope")
            raise
        except TokenVerificationUnavailableError:
            self._record("dependency_unavailable")
            raise
        self._record("valid")
        return verified

    def _verify(self, raw_token: str, required_scopes: frozenset[str]) -> VerifiedAccessToken:
        if (
            not isinstance(raw_token, str)
            or not raw_token.isascii()
            or len(raw_token.encode("ascii")) > self._max_token_bytes
            or raw_token.count(".") != 2
        ):
            raise InvalidTokenError("malformed")
        if any(not self._valid_scope_token(scope) for scope in required_scopes):
            raise ValueError("required scopes must be bounded opaque values")
        self._reject_excessive_json_nesting(raw_token)

        try:
            header = jwt.get_unverified_header(raw_token)
        except jwt.InvalidTokenError, TypeError, ValueError, OverflowError, RecursionError:
            raise InvalidTokenError("malformed") from None
        if not isinstance(header, dict) or header.get("alg") != "RS256":
            raise InvalidTokenError("malformed")
        key_id = header.get("kid")
        if (
            not isinstance(key_id, str)
            or not 1 <= len(key_id) <= 128
            or any(ord(character) < 33 or ord(character) == 127 for character in key_id)
        ):
            raise InvalidTokenError("malformed")
        token_type = header.get("typ")
        if token_type is not None and (
            not isinstance(token_type, str) or token_type.casefold() not in COMPATIBLE_TOKEN_TYPES
        ):
            raise InvalidTokenError("malformed")
        critical = header.get("crit")
        if critical not in (None, []):
            raise InvalidTokenError("malformed")
        if KEY_LOCATION_HEADERS.intersection(header):
            raise InvalidTokenError("malformed")

        key = self._jwks_cache.get_key(key_id)
        try:
            claims = jwt.decode(
                raw_token,
                key=key,
                algorithms=["RS256"],
                audience=self._resource,
                issuer=self._issuer,
                leeway=self._clock_skew,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "enforce_minimum_key_length": True,
                },
            )
        except jwt.ExpiredSignatureError:
            raise InvalidTokenError("expired") from None
        except jwt.ImmatureSignatureError:
            raise InvalidTokenError("not_yet_valid") from None
        except jwt.InvalidSignatureError:
            raise InvalidTokenError("bad_signature") from None
        except jwt.InvalidIssuerError:
            raise InvalidTokenError("wrong_issuer") from None
        except jwt.InvalidAudienceError:
            raise InvalidTokenError("wrong_audience") from None
        except jwt.InvalidKeyError:
            raise TokenVerificationUnavailableError(
                "verification key material is unavailable"
            ) from None
        except jwt.InvalidTokenError:
            raise InvalidTokenError("malformed") from None
        except TypeError, ValueError, OverflowError, RecursionError:
            raise InvalidTokenError("malformed") from None
        if not isinstance(claims, dict):
            raise InvalidTokenError("malformed")

        subject = claims.get("sub")
        if (
            not isinstance(subject, str)
            or not 1 <= len(subject) <= 255
            or any(ord(character) < 32 or ord(character) == 127 for character in subject)
        ):
            raise InvalidTokenError("malformed")
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or client_id not in self._allowed_clients:
            raise InvalidTokenError("wrong_client")
        if claims.get("token_use") != "access":
            raise InvalidTokenError("wrong_token_use")
        audiences = self._parse_audience(claims.get("aud"))
        if self._resource not in audiences:
            raise InvalidTokenError("wrong_audience")
        scopes = self._parse_scopes(claims.get("scope"))
        if not required_scopes.issubset(scopes):
            raise InsufficientScopeError("access token lacks a required scope")

        issued_at = self._numeric_date(claims.get("iat"))
        expires_at = self._numeric_date(claims.get("exp"))
        auth_time = self._numeric_date(claims.get("auth_time"))
        not_before = self._numeric_date(claims["nbf"]) if "nbf" in claims else None
        now = datetime.now(UTC).timestamp()
        if issued_at.timestamp() > now + self._clock_skew:
            raise InvalidTokenError("not_yet_valid")
        if expires_at <= issued_at:
            raise InvalidTokenError("malformed")
        if auth_time.timestamp() > issued_at.timestamp() + self._clock_skew:
            raise InvalidTokenError("malformed")

        return VerifiedAccessToken(
            issuer=self._issuer,
            subject=subject,
            client_id=client_id,
            audience=audiences,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            auth_time=auth_time,
            not_before=not_before,
            key_id_fingerprint=hashlib.sha256(key_id.encode("utf-8")).hexdigest()[:16],
        )

    @staticmethod
    def _numeric_date(value: Any) -> datetime:
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
        ):
            raise InvalidTokenError("malformed")
        try:
            return datetime.fromtimestamp(value, UTC)
        except OverflowError, OSError, ValueError:
            raise InvalidTokenError("malformed") from None

    @staticmethod
    def _reject_excessive_json_nesting(raw_token: str) -> None:
        """Reject unsafe JSON depth without interpreting unverified claims."""
        for encoded in raw_token.split(".")[:2]:
            padding = "=" * (-len(encoded) % 4)
            try:
                document = base64.b64decode(
                    encoded + padding,
                    altchars=b"-_",
                    validate=True,
                )
            except binascii.Error, ValueError:
                raise InvalidTokenError("malformed") from None

            depth = 0
            in_string = False
            escaped = False
            for character in document:
                if in_string:
                    if escaped:
                        escaped = False
                    elif character == ord("\\"):
                        escaped = True
                    elif character == ord('"'):
                        in_string = False
                elif character == ord('"'):
                    in_string = True
                elif character in (ord("["), ord("{")):
                    depth += 1
                    if depth > MAX_JWT_JSON_DEPTH:
                        raise InvalidTokenError("malformed")
                elif character in (ord("]"), ord("}")):
                    depth -= 1

    @classmethod
    def _parse_scopes(cls, value: Any) -> frozenset[str]:
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_SCOPE_CLAIM_LENGTH:
            raise InvalidTokenError("malformed")
        values = value.split(" ")
        if (
            not 1 <= len(values) <= MAX_SCOPE_COUNT
            or any(not cls._valid_scope_token(scope) for scope in values)
            or len(set(values)) != len(values)
        ):
            raise InvalidTokenError("malformed")
        return frozenset(values)

    @staticmethod
    def _valid_scope_token(value: str) -> bool:
        return (
            bool(value)
            and len(value) <= MAX_SCOPE_LENGTH
            and all(
                33 <= ord(character) <= 126 and character not in {'"', "\\"} for character in value
            )
        )

    @staticmethod
    def _parse_audience(value: Any) -> frozenset[str]:
        raw_values = [value] if isinstance(value, str) else value
        if (
            not isinstance(raw_values, list)
            or not 1 <= len(raw_values) <= MAX_AUDIENCE_COUNT
            or any(
                not isinstance(item, str)
                or not 1 <= len(item) <= 512
                or any(ord(character) < 33 or ord(character) == 127 for character in item)
                for item in raw_values
            )
            or len(set(raw_values)) != len(raw_values)
        ):
            raise InvalidTokenError("wrong_audience")
        return frozenset(raw_values)

    def _record(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_jwt_validation(outcome)
