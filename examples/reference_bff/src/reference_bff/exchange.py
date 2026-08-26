"""Confidential authorization-code exchange with exact PKCE binding."""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass, field
from typing import Any

from reference_bff.config import Settings
from reference_bff.http import AsyncUpstreamClient, UpstreamError, json_media_type
from reference_bff.json_safety import UnsafeJsonError, load_json_object
from reference_bff.transactions import AuthorizationTransaction

JSON_MEDIA_TYPES = frozenset({"application/json"})
TOKEN_FIELDS = frozenset(
    {"access_token", "id_token", "refresh_token", "token_type", "expires_in", "scope"}
)
REQUIRED_TOKEN_FIELDS = frozenset(
    {"access_token", "id_token", "refresh_token", "token_type", "expires_in"}
)


class CodeExchangeUnavailableError(RuntimeError):
    """The token endpoint failed or returned an unsafe response."""


class RefreshUnavailableError(RuntimeError):
    """The refresh endpoint or its safe response boundary is temporarily unavailable."""


class RefreshRejectedError(ValueError):
    """The provider definitively rejected the exact stored refresh grant."""


class InvalidRefreshResponseError(ValueError):
    """A nominally successful refresh omitted or corrupted rotated token material."""


@dataclass(frozen=True, slots=True, repr=False)
class TokenResponse:
    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_in: int

    def __repr__(self) -> str:
        return "TokenResponse(<redacted>)"


class AuthorizationCodeClient:
    def __init__(self, settings: Settings, client: AsyncUpstreamClient) -> None:
        self._settings = settings
        self._client = client

    async def exchange(self, code: str, transaction: AuthorizationTransaction) -> TokenResponse:
        try:
            response = await self._client.request(
                "POST",
                self._settings.token_endpoint,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Basic {self._basic_credential()}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "grant_type": "authorization_code",
                    "client_id": self._settings.client_id,
                    "code": code,
                    "redirect_uri": transaction.callback_uri,
                    "code_verifier": transaction.pkce_verifier,
                },
            )
        except UpstreamError:
            raise CodeExchangeUnavailableError("authorization-code exchange failed") from None
        if response.status_code != 200 or not json_media_type(
            response.headers,
            allowed=JSON_MEDIA_TYPES,
        ):
            raise CodeExchangeUnavailableError("token endpoint returned an unsafe response")
        try:
            document = load_json_object(response.body)
            return self._parse(document)
        except UnsafeJsonError, TypeError, ValueError:
            raise CodeExchangeUnavailableError("token endpoint returned invalid data") from None

    async def refresh(self, refresh_token: str) -> TokenResponse:
        """Request one complete rotated token set with confidential Basic authentication."""

        try:
            response = await self._client.request(
                "POST",
                self._settings.token_endpoint,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Basic {self._basic_credential()}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "grant_type": "refresh_token",
                    "client_id": self._settings.client_id,
                    "refresh_token": refresh_token,
                },
            )
        except UpstreamError:
            raise RefreshUnavailableError("token refresh is unavailable") from None
        if response.status_code in {400, 401}:
            raise RefreshRejectedError("refresh grant was rejected")
        if response.status_code != 200 or not json_media_type(
            response.headers,
            allowed=JSON_MEDIA_TYPES,
        ):
            raise RefreshUnavailableError("token endpoint returned an unsafe response")
        try:
            document = load_json_object(response.body)
            rotated = self._parse(document)
        except UnsafeJsonError, TypeError, ValueError:
            raise InvalidRefreshResponseError("rotated token response is invalid") from None
        if hmac.compare_digest(rotated.refresh_token, refresh_token):
            raise InvalidRefreshResponseError("refresh token did not rotate")
        return rotated

    def _basic_credential(self) -> str:
        return base64.b64encode(
            (
                f"{self._settings.client_id}:{self._settings.client_secret.get_secret_value()}"
            ).encode()
        ).decode("ascii")

    @staticmethod
    def _parse(document: dict[str, Any]) -> TokenResponse:
        if not REQUIRED_TOKEN_FIELDS.issubset(document) or set(document) - TOKEN_FIELDS:
            raise ValueError("unexpected token response shape")
        token_type = document["token_type"]
        expires_in = document["expires_in"]
        if type(token_type) is not str or token_type.casefold() != "bearer":
            raise ValueError("invalid token type")
        if type(expires_in) is not int or not 1 <= expires_in <= 86_400:
            raise ValueError("invalid token lifetime")
        tokens: dict[str, str] = {}
        for field_name in ("access_token", "id_token", "refresh_token"):
            value = document[field_name]
            if (
                type(value) is not str
                or not value.isascii()
                or not 16 <= len(value) <= 65_536
                or any(ord(character) < 33 or ord(character) == 127 for character in value)
            ):
                raise ValueError("invalid token value")
            tokens[field_name] = value
        scope = document.get("scope")
        if scope is not None and (
            type(scope) is not str
            or not 1 <= len(scope) <= 4096
            or any(not 32 <= ord(character) <= 126 for character in scope)
        ):
            raise ValueError("invalid token response scope")
        return TokenResponse(
            access_token=tokens["access_token"],
            id_token=tokens["id_token"],
            refresh_token=tokens["refresh_token"],
            expires_in=expires_in,
        )
