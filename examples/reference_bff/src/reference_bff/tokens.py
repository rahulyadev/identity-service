"""Independent strict Cognito ID/access-token verification for the BFF."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any

import jwt

from reference_bff.config import REQUIRED_SCOPES, Settings
from reference_bff.json_safety import UnsafeJsonError, load_json_object
from reference_bff.jwks import AsyncJwksCache, InvalidSigningKeyError, JwksUnavailableError

COMPATIBLE_TOKEN_TYPES = frozenset({"jwt", "at+jwt", "application/at+jwt"})
KEY_LOCATION_HEADERS = frozenset({"jku", "x5u", "jwk", "x5c"})
ALLOWED_HEADERS = frozenset({"alg", "kid", "typ"})
MAX_SCOPE_COUNT = 64
MAX_SCOPE_LENGTH = 256
MAX_SCOPE_CLAIM_LENGTH = 4096


class InvalidProviderTokenError(ValueError):
    """One or both provider tokens failed the fixed verification contract."""


class TokenVerificationUnavailableError(RuntimeError):
    """Signing-key verification is temporarily unavailable."""


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedTokens:
    issuer: str
    subject: str = field(repr=False)
    client_id: str
    token_family_id: str = field(repr=False)
    access_expires_at: int
    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)

    def __repr__(self) -> str:
        return "VerifiedTokens(<redacted>)"


class CognitoTokenVerifier:
    def __init__(self, settings: Settings, jwks: AsyncJwksCache) -> None:
        self._issuer = settings.cognito_issuer
        self._client_id = settings.client_id
        self._resource = settings.oauth_resource
        self._clock_skew = settings.jwt_clock_skew_seconds
        self._max_token_bytes = settings.jwt_max_token_bytes
        self._jwks = jwks

    async def verify(
        self,
        *,
        id_token: str,
        access_token: str,
        refresh_token: str,
        expected_nonce: str,
    ) -> VerifiedTokens:
        return await self._verify_pair(
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
            expected_nonce=expected_nonce,
            expected_subject=None,
            expected_token_family_id=None,
            refresh_semantics=False,
        )

    async def verify_refresh(
        self,
        *,
        id_token: str,
        access_token: str,
        refresh_token: str,
        expected_nonce: str,
        expected_subject: str,
        expected_token_family_id: str | None,
    ) -> VerifiedTokens:
        return await self._verify_pair(
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
            expected_nonce=expected_nonce,
            expected_subject=expected_subject,
            expected_token_family_id=expected_token_family_id,
            refresh_semantics=True,
        )

    async def _verify_pair(
        self,
        *,
        id_token: str,
        access_token: str,
        refresh_token: str,
        expected_nonce: str,
        expected_subject: str | None,
        expected_token_family_id: str | None,
        refresh_semantics: bool,
    ) -> VerifiedTokens:
        id_claims = await self._verify_one(
            id_token,
            token_use="id",  # nosec B106
            expected_audience=self._client_id,
            require_nonce=not refresh_semantics,
        )
        access_claims = await self._verify_one(
            access_token,
            token_use="access",  # nosec B106
            expected_audience=self._resource,
            require_nonce=False,
        )
        nonce = id_claims.get("nonce")
        if (not refresh_semantics and type(nonce) is not str) or (
            nonce is not None
            and (type(nonce) is not str or not hmac.compare_digest(nonce, expected_nonce))
        ):
            raise InvalidProviderTokenError("invalid ID token nonce")
        access_client = access_claims.get("client_id")
        if type(access_client) is not str or not hmac.compare_digest(
            access_client, self._client_id
        ):
            raise InvalidProviderTokenError("invalid access-token client")
        scopes = self._scopes(access_claims.get("scope"))
        if not REQUIRED_SCOPES.issubset(scopes):
            raise InvalidProviderTokenError("access token lacks required scopes")
        id_subject = self._subject(id_claims.get("sub"))
        access_subject = self._subject(access_claims.get("sub"))
        if not hmac.compare_digest(id_subject, access_subject):
            raise InvalidProviderTokenError("provider token subjects differ")
        if expected_subject is not None and not hmac.compare_digest(id_subject, expected_subject):
            raise InvalidProviderTokenError("provider token subject changed")
        id_family = self._identifier(id_claims.get("origin_jti"))
        access_family = self._identifier(access_claims.get("origin_jti"))
        self._identifier(id_claims.get("jti"))
        self._identifier(access_claims.get("jti"))
        if not hmac.compare_digest(id_family, access_family):
            raise InvalidProviderTokenError("provider token family differs")
        if refresh_semantics and (
            expected_token_family_id is None
            or not hmac.compare_digest(id_family, expected_token_family_id)
        ):
            raise InvalidProviderTokenError("provider token family changed")
        at_hash = id_claims.get("at_hash")
        if at_hash is not None and (
            type(at_hash) is not str
            or not hmac.compare_digest(
                at_hash,
                self._access_token_hash(access_token),
            )
        ):
            raise InvalidProviderTokenError("invalid access-token hash")
        if (
            type(refresh_token) is not str
            or not refresh_token.isascii()
            or not 16 <= len(refresh_token) <= self._max_token_bytes
            or any(ord(character) < 33 or ord(character) == 127 for character in refresh_token)
        ):
            raise InvalidProviderTokenError("invalid refresh token")
        expires_at = self._numeric_date(access_claims.get("exp"))
        return VerifiedTokens(
            issuer=self._issuer,
            subject=id_subject,
            client_id=self._client_id,
            token_family_id=id_family,
            access_expires_at=expires_at,
            access_token=access_token,
            id_token=id_token,
            refresh_token=refresh_token,
        )

    async def _verify_one(
        self,
        raw_token: str,
        *,
        token_use: str,
        expected_audience: str,
        require_nonce: bool,
    ) -> dict[str, Any]:
        header, unverified_claims = self._strict_documents(raw_token)
        if set(header) - ALLOWED_HEADERS or header.get("alg") != "RS256":
            raise InvalidProviderTokenError("invalid token header")
        key_id = header.get("kid")
        if (
            type(key_id) is not str
            or not 1 <= len(key_id) <= 128
            or any(ord(character) < 33 or ord(character) == 127 for character in key_id)
        ):
            raise InvalidProviderTokenError("invalid token key identifier")
        token_type = header.get("typ")
        if token_type is not None and (
            type(token_type) is not str or token_type.casefold() not in COMPATIBLE_TOKEN_TYPES
        ):
            raise InvalidProviderTokenError("invalid token type")
        if KEY_LOCATION_HEADERS.intersection(header) or "crit" in header or "b64" in header:
            raise InvalidProviderTokenError("unsafe token header")
        try:
            key = await self._jwks.get_key(key_id)
        except InvalidSigningKeyError:
            raise InvalidProviderTokenError("unknown token signing key") from None
        except JwksUnavailableError:
            raise TokenVerificationUnavailableError("token signing keys are unavailable") from None
        required = ["iss", "sub", "aud", "token_use", "exp", "iat", "auth_time"]
        if token_use == "id":  # nosec B105
            if require_nonce:
                required.append("nonce")
        else:
            required.extend(("client_id", "scope"))
        try:
            claims = jwt.decode(
                raw_token,
                key=key,
                algorithms=["RS256"],
                audience=expected_audience,
                issuer=self._issuer,
                leeway=self._clock_skew,
                options={
                    "require": required,
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "enforce_minimum_key_length": True,
                },
            )
        except jwt.InvalidKeyError:
            raise TokenVerificationUnavailableError("token key material is unusable") from None
        except jwt.InvalidTokenError, TypeError, ValueError, OverflowError, RecursionError:
            raise InvalidProviderTokenError("provider token verification failed") from None
        if type(claims) is not dict or claims != unverified_claims:
            raise InvalidProviderTokenError("provider token claims are ambiguous")
        if claims.get("iss") != self._issuer or claims.get("token_use") != token_use:
            raise InvalidProviderTokenError("provider token binding is invalid")
        audience = claims.get("aud")
        if type(audience) is not str or not hmac.compare_digest(audience, expected_audience):
            raise InvalidProviderTokenError("provider token audience is invalid")
        issued_at = self._numeric_date(claims.get("iat"))
        expires_at = self._numeric_date(claims.get("exp"))
        auth_time = self._numeric_date(claims.get("auth_time"))
        not_before = self._numeric_date(claims["nbf"]) if "nbf" in claims else None
        now = int(time.time())
        if (
            issued_at > now + self._clock_skew
            or expires_at <= issued_at
            or auth_time > issued_at + self._clock_skew
            or (not_before is not None and not_before > expires_at)
        ):
            raise InvalidProviderTokenError("provider token times are invalid")
        return claims

    def _strict_documents(self, raw_token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if (
            type(raw_token) is not str
            or not raw_token.isascii()
            or not 1 <= len(raw_token) <= self._max_token_bytes
            or raw_token.count(".") != 2
        ):
            raise InvalidProviderTokenError("malformed provider token")
        documents: list[dict[str, Any]] = []
        for position, encoded in enumerate(raw_token.split(".")):
            if (
                not encoded
                or any(
                    character
                    not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"  # pragma: allowlist secret (public base64url alphabet)  # noqa: E501
                    for character in encoded
                )
            ):
                raise InvalidProviderTokenError("malformed provider token")
            try:
                raw = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4),
                    altchars=b"-_",
                    validate=True,
                )
                if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
                    raise InvalidProviderTokenError("non-canonical provider token")
                if position < 2:
                    documents.append(load_json_object(raw))
            except binascii.Error, ValueError, UnsafeJsonError:
                raise InvalidProviderTokenError("malformed provider token") from None
        return documents[0], documents[1]

    @staticmethod
    def _numeric_date(value: Any) -> int:
        if type(value) is not int or value < 0:
            raise InvalidProviderTokenError("invalid provider token date")
        return value

    @staticmethod
    def _subject(value: Any) -> str:
        if (
            type(value) is not str
            or not 1 <= len(value) <= 255
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise InvalidProviderTokenError("invalid provider subject")
        return value

    @staticmethod
    def _identifier(value: Any) -> str:
        if (
            type(value) is not str
            or not 1 <= len(value) <= 255
            or not value.isascii()
            or any(ord(character) < 33 or ord(character) == 127 for character in value)
        ):
            raise InvalidProviderTokenError("invalid token-family identifier")
        return value

    @staticmethod
    def _scopes(value: Any) -> frozenset[str]:
        if type(value) is not str or not 1 <= len(value) <= MAX_SCOPE_CLAIM_LENGTH:
            raise InvalidProviderTokenError("invalid access-token scope")
        scopes = value.split(" ")
        if (
            not 1 <= len(scopes) <= MAX_SCOPE_COUNT
            or len(set(scopes)) != len(scopes)
            or any(
                not scope
                or len(scope) > MAX_SCOPE_LENGTH
                or any(
                    not 33 <= ord(character) <= 126 or character in {'"', "\\"}
                    for character in scope
                )
                for scope in scopes
            )
        ):
            raise InvalidProviderTokenError("invalid access-token scope")
        return frozenset(scopes)

    @staticmethod
    def _access_token_hash(access_token: str) -> str:
        digest = hashlib.sha256(access_token.encode("ascii")).digest()[:16]
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
