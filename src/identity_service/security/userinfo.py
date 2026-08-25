"""Strict Cognito UserInfo adapter for provider-owned profile snapshots."""

from __future__ import annotations

import json
import unicodedata
from typing import Any, Protocol

from pydantic import ValidationError

from identity_service.config import Settings
from identity_service.security.contracts import VerifiedAccessToken
from identity_service.security.errors import (
    InsufficientScopeError,
    UpstreamNetworkError,
    UpstreamResponseTooLargeError,
    UpstreamTimeoutError,
    UserInfoResponseError,
    UserInfoTokenRejectedError,
    UserInfoUnavailableError,
)
from identity_service.security.http import UpstreamHttpClient
from identity_service.services.schemas import ProviderProfileInput


def _reject_nonfinite_json(_value: str) -> None:
    raise ValueError("non-finite JSON numbers are not accepted")


class UserInfoMetrics(Protocol):
    def record_userinfo_request(self, outcome: str) -> None: ...


class CognitoUserInfoClient:
    def __init__(
        self,
        settings: Settings,
        client: UpstreamHttpClient,
        *,
        metrics: UserInfoMetrics | None = None,
    ) -> None:
        self._url = settings.cognito_userinfo_url
        self._client = client
        self._metrics = metrics

    def fetch_userinfo(
        self, raw_access_token: str, verified_access_token: VerifiedAccessToken
    ) -> ProviderProfileInput:
        if "openid" not in verified_access_token.scopes:
            raise InsufficientScopeError("openid is required before UserInfo")
        try:
            response = self._client.get(
                self._url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {raw_access_token}",
                },
            )
        except UpstreamTimeoutError:
            self._record("timeout")
            raise UserInfoUnavailableError() from None
        except UpstreamNetworkError:
            self._record("network_error")
            raise UserInfoUnavailableError() from None
        except UpstreamResponseTooLargeError:
            self._record("malformed")
            raise UserInfoResponseError("UserInfo response is oversized") from None

        if response.status_code in {400, 401, 403}:
            self._record("token_rejected")
            raise UserInfoTokenRejectedError("UserInfo rejected the token")
        if response.status_code == 429:
            self._record("rate_limited")
            raise UserInfoUnavailableError(
                retry_after_seconds=self._safe_retry_after(response.headers.get("retry-after"))
            )
        if 500 <= response.status_code <= 599:
            self._record("server_error")
            raise UserInfoUnavailableError()
        if response.status_code != 200:
            self._record("malformed")
            raise UserInfoResponseError("UserInfo returned an unexpected status")
        content_type = response.headers.get("content-type", "").partition(";")[0].strip().casefold()
        if content_type != "application/json":
            self._record("malformed")
            raise UserInfoResponseError("UserInfo returned an unsupported media type")
        try:
            document = json.loads(response.body, parse_constant=_reject_nonfinite_json)
        except UnicodeDecodeError, RecursionError, ValueError:
            self._record("malformed")
            raise UserInfoResponseError("UserInfo returned malformed JSON") from None
        try:
            profile = self._parse_profile(document, verified_access_token.subject)
        except TypeError, ValueError, ValidationError:
            self._record("malformed")
            raise UserInfoResponseError("UserInfo returned invalid claims") from None
        self._record("success")
        return profile

    @classmethod
    def _parse_profile(cls, document: Any, expected_subject: str) -> ProviderProfileInput:
        if not isinstance(document, dict):
            raise TypeError("UserInfo must be an object")
        subject = document.get("sub")
        if (
            not isinstance(subject, str)
            or not 1 <= len(subject) <= 255
            or subject != expected_subject
        ):
            raise ValueError("UserInfo subject is missing or mismatched")
        email = cls._optional_text(document, "email", 320)
        display_name = cls._optional_text(document, "name", 100)
        picture = cls._optional_text(document, "picture", 2048)
        verification = document.get("email_verified", False)
        if isinstance(verification, bool):
            email_verified = verification
        elif verification == "true":
            email_verified = True
        elif verification == "false":
            email_verified = False
        else:
            raise TypeError("email verification claim has an invalid type")
        return ProviderProfileInput(
            email=email,
            email_verified=email_verified,
            display_name=display_name,
            avatar_url=picture,
        )

    @staticmethod
    def _optional_text(document: dict[str, Any], name: str, maximum: int) -> str | None:
        value = document.get(name)
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= maximum
            or any(unicodedata.category(character) in {"Cc", "Zl", "Zp"} for character in value)
        ):
            raise TypeError("UserInfo text claim has an invalid type or size")
        return value

    @staticmethod
    def _safe_retry_after(value: str | None) -> int | None:
        if value is None or not 1 <= len(value) <= 3 or not value.isascii() or not value.isdigit():
            return None
        parsed = int(value)
        return parsed if 0 <= parsed <= 300 else None

    def _record(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_userinfo_request(outcome)
