"""Independent strict Cognito ID/access-token verification for the BFF."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import jwt

from reference_bff.auth_diagnostics import TokenFailureCategory as Category
from reference_bff.auth_diagnostics import safe_category
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

    def __init__(self, category: Category = Category.VERIFICATION) -> None:
        self.category = safe_category(category)
        super().__init__(self.category.value)


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
            raise InvalidProviderTokenError(Category.ID_NONCE)
        access_client = access_claims.get("client_id")
        if type(access_client) is not str or not hmac.compare_digest(
            access_client, self._client_id
        ):
            raise InvalidProviderTokenError(Category.ACCESS_CLIENT)
        scopes = self._scopes(access_claims.get("scope"))
        if not REQUIRED_SCOPES.issubset(scopes):
            raise InvalidProviderTokenError(Category.ACCESS_SCOPE)
        id_subject = self._subject(id_claims.get("sub"), Category.ID_SUBJECT)
        access_subject = self._subject(access_claims.get("sub"), Category.ACCESS_SUBJECT)
        if not hmac.compare_digest(id_subject, access_subject):
            raise InvalidProviderTokenError(Category.SUBJECT_CONTINUITY)
        if expected_subject is not None and not hmac.compare_digest(id_subject, expected_subject):
            raise InvalidProviderTokenError(Category.SUBJECT_CONTINUITY)
        id_family = self._identifier(id_claims.get("origin_jti"), Category.ID_FAMILY)
        access_family = self._identifier(access_claims.get("origin_jti"), Category.ACCESS_FAMILY)
        self._identifier(id_claims.get("jti"), Category.ID_FAMILY)
        self._identifier(access_claims.get("jti"), Category.ACCESS_FAMILY)
        if not hmac.compare_digest(id_family, access_family):
            raise InvalidProviderTokenError(Category.FAMILY_CONTINUITY)
        if refresh_semantics and (
            expected_token_family_id is None
            or not hmac.compare_digest(id_family, expected_token_family_id)
        ):
            raise InvalidProviderTokenError(Category.FAMILY_CONTINUITY)
        at_hash = id_claims.get("at_hash")
        if at_hash is not None and (
            type(at_hash) is not str
            or not hmac.compare_digest(
                at_hash,
                self._access_token_hash(access_token),
            )
        ):
            raise InvalidProviderTokenError(Category.ID_AT_HASH)
        if (
            type(refresh_token) is not str
            or not refresh_token.isascii()
            or not 16 <= len(refresh_token) <= self._max_token_bytes
            or any(ord(character) < 33 or ord(character) == 127 for character in refresh_token)
        ):
            raise InvalidProviderTokenError(Category.REFRESH_FORMAT)
        expires_at = self._numeric_date(access_claims.get("exp"), Category.ACCESS_TIME)
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
        token_use: Literal["id", "access"],
        expected_audience: str,
        require_nonce: bool,
    ) -> dict[str, Any]:
        # Context comes only from the verifier's ID/access call sites, never token claims.
        def category(id_category: Category, access_category: Category) -> Category:
            return id_category if token_use == "id" else access_category  # nosec B105

        header, unverified_claims = self._strict_documents(
            raw_token, category(Category.ID_FORMAT, Category.ACCESS_FORMAT)
        )
        if set(header) - ALLOWED_HEADERS or header.get("alg") != "RS256":
            raise InvalidProviderTokenError(category(Category.ID_HEADER, Category.ACCESS_HEADER))
        key_id = header.get("kid")
        if (
            type(key_id) is not str
            or not 1 <= len(key_id) <= 128
            or any(ord(character) < 33 or ord(character) == 127 for character in key_id)
        ):
            raise InvalidProviderTokenError(category(Category.ID_HEADER, Category.ACCESS_HEADER))
        token_type = header.get("typ")
        if token_type is not None and (
            type(token_type) is not str or token_type.casefold() not in COMPATIBLE_TOKEN_TYPES
        ):
            raise InvalidProviderTokenError(category(Category.ID_HEADER, Category.ACCESS_HEADER))
        if KEY_LOCATION_HEADERS.intersection(header) or "crit" in header or "b64" in header:
            raise InvalidProviderTokenError(category(Category.ID_HEADER, Category.ACCESS_HEADER))
        try:
            key = await self._jwks.get_key(key_id)
        except InvalidSigningKeyError:
            raise InvalidProviderTokenError(
                category(Category.ID_SIGNING_KEY, Category.ACCESS_SIGNING_KEY)
            ) from None
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
        except jwt.InvalidTokenError as error:
            # Pinned PyJWT types identify stages; generic DecodeError and builtin errors
            # are ambiguous (including some malformed dates), so never parse their messages.
            if isinstance(error, jwt.InvalidSignatureError):
                failure = category(Category.ID_SIGNATURE, Category.ACCESS_SIGNATURE)
            elif isinstance(error, jwt.MissingRequiredClaimError):
                failure = (
                    category(Category.ID_REQUIRED_CLAIM, Category.ACCESS_REQUIRED_CLAIM)
                    if type(error.claim) is str and error.claim in required
                    else category(Category.ID_VERIFICATION, Category.ACCESS_VERIFICATION)
                )
            elif isinstance(error, jwt.InvalidIssuerError):
                failure = category(Category.ID_ISSUER, Category.ACCESS_ISSUER)
            elif isinstance(error, jwt.InvalidAudienceError):
                failure = category(Category.ID_AUDIENCE, Category.ACCESS_AUDIENCE)
            elif isinstance(
                error,
                (jwt.ExpiredSignatureError, jwt.ImmatureSignatureError, jwt.InvalidIssuedAtError),
            ):
                failure = category(Category.ID_TIME, Category.ACCESS_TIME)
            elif isinstance(error, jwt.exceptions.InvalidSubjectError):
                failure = category(Category.ID_SUBJECT, Category.ACCESS_SUBJECT)
            elif isinstance(error, jwt.exceptions.InvalidJTIError):
                failure = category(Category.ID_FAMILY, Category.ACCESS_FAMILY)
            else:
                failure = category(Category.ID_VERIFICATION, Category.ACCESS_VERIFICATION)
            raise InvalidProviderTokenError(failure) from None
        except TypeError, ValueError, OverflowError, RecursionError:
            raise InvalidProviderTokenError(
                category(Category.ID_VERIFICATION, Category.ACCESS_VERIFICATION)
            ) from None
        if type(claims) is not dict or claims != unverified_claims:
            raise InvalidProviderTokenError(
                category(Category.ID_VERIFICATION, Category.ACCESS_VERIFICATION)
            )
        if claims.get("iss") != self._issuer or claims.get("token_use") != token_use:
            raise InvalidProviderTokenError(
                category(Category.ID_ISSUER, Category.ACCESS_ISSUER)
                if claims.get("iss") != self._issuer
                else category(Category.ID_USE, Category.ACCESS_USE)
            )
        audience = claims.get("aud")
        if type(audience) is not str or not hmac.compare_digest(audience, expected_audience):
            raise InvalidProviderTokenError(
                category(Category.ID_AUDIENCE, Category.ACCESS_AUDIENCE)
            )
        issued_at = self._numeric_date(
            claims.get("iat"), category(Category.ID_TIME, Category.ACCESS_TIME)
        )
        expires_at = self._numeric_date(
            claims.get("exp"), category(Category.ID_TIME, Category.ACCESS_TIME)
        )
        auth_time = self._numeric_date(
            claims.get("auth_time"), category(Category.ID_TIME, Category.ACCESS_TIME)
        )
        not_before = (
            self._numeric_date(claims["nbf"], category(Category.ID_TIME, Category.ACCESS_TIME))
            if "nbf" in claims
            else None
        )
        now = int(time.time())
        if (
            issued_at > now + self._clock_skew
            or expires_at <= issued_at
            or auth_time > issued_at + self._clock_skew
            or (not_before is not None and not_before > expires_at)
        ):
            raise InvalidProviderTokenError(category(Category.ID_TIME, Category.ACCESS_TIME))
        return claims

    def _strict_documents(
        self, raw_token: str, category: Category
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if (
            type(raw_token) is not str
            or not raw_token.isascii()
            or not 1 <= len(raw_token) <= self._max_token_bytes
            or raw_token.count(".") != 2
        ):
            raise InvalidProviderTokenError(category)
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
                raise InvalidProviderTokenError(category)
            try:
                raw = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4),
                    altchars=b"-_",
                    validate=True,
                )
                if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
                    raise InvalidProviderTokenError(category)
                if position < 2:
                    documents.append(load_json_object(raw))
            except binascii.Error, ValueError, UnsafeJsonError:
                raise InvalidProviderTokenError(category) from None
        return documents[0], documents[1]

    @staticmethod
    def _numeric_date(value: Any, category: Category) -> int:
        if type(value) is not int or value < 0:
            raise InvalidProviderTokenError(category)
        return value

    @staticmethod
    def _subject(value: Any, category: Category) -> str:
        if (
            type(value) is not str
            or not 1 <= len(value) <= 255
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise InvalidProviderTokenError(category)
        return value

    @staticmethod
    def _identifier(value: Any, category: Category) -> str:
        if (
            type(value) is not str
            or not 1 <= len(value) <= 255
            or not value.isascii()
            or any(ord(character) < 33 or ord(character) == 127 for character in value)
        ):
            raise InvalidProviderTokenError(category)
        return value

    @staticmethod
    def _scopes(value: Any) -> frozenset[str]:
        if type(value) is not str or not 1 <= len(value) <= MAX_SCOPE_CLAIM_LENGTH:
            raise InvalidProviderTokenError(Category.ACCESS_SCOPE)
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
            raise InvalidProviderTokenError(Category.ACCESS_SCOPE)
        return frozenset(scopes)

    @staticmethod
    def _access_token_hash(access_token: str) -> str:
        digest = hashlib.sha256(access_token.encode("ascii")).digest()[:16]
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
