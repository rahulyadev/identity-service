"""Confidential authorization-code exchange with exact PKCE binding."""

from __future__ import annotations

import base64
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


@dataclass(frozen=True, slots=True)
class TokenResponse:
    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_in: int


class AuthorizationCodeClient:
    def __init__(self, settings: Settings, client: AsyncUpstreamClient) -> None:
        self._settings = settings
        self._client = client

    async def exchange(self, code: str, transaction: AuthorizationTransaction) -> TokenResponse:
        credential = base64.b64encode(
            (
                f"{self._settings.client_id}:{self._settings.client_secret.get_secret_value()}"
            ).encode()
        ).decode("ascii")
        try:
            response = await self._client.request(
                "POST",
                self._settings.token_endpoint,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Basic {credential}",
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
