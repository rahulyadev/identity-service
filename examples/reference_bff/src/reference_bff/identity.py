"""Strict Identity profile bootstrap adapter for the callback flow."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from reference_bff.config import Settings
from reference_bff.http import AsyncUpstreamClient, UpstreamError, json_media_type
from reference_bff.json_safety import UnsafeJsonError, load_json_object

PROFILE_FIELDS = frozenset(
    {
        "user_id",
        "email",
        "email_verified",
        "display_name",
        "avatar_url",
        "version",
        "created_at",
        "updated_at",
    }
)
JSON_MEDIA_TYPES = frozenset({"application/json"})


class IdentityBootstrapUnavailableError(RuntimeError):
    """Identity bootstrap failed or returned an unsafe response."""


@dataclass(frozen=True, slots=True)
class BootstrapProfile:
    user_id: str
    created: bool


class IdentityBootstrapClient:
    def __init__(self, settings: Settings, client: AsyncUpstreamClient) -> None:
        self._url = settings.identity_api_origin + "/v1/me"
        self._client = client

    async def bootstrap(self, access_token: str) -> BootstrapProfile:
        try:
            response = await self._client.request(
                "PUT",
                self._url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
            )
        except UpstreamError:
            raise IdentityBootstrapUnavailableError("Identity bootstrap is unavailable") from None
        if response.status_code not in {200, 201} or not json_media_type(
            response.headers,
            allowed=JSON_MEDIA_TYPES,
        ):
            raise IdentityBootstrapUnavailableError(
                "Identity bootstrap returned an unsafe response"
            )
        try:
            profile = load_json_object(response.body)
            user_id = self._validate_profile(profile)
        except UnsafeJsonError, TypeError, ValueError:
            raise IdentityBootstrapUnavailableError(
                "Identity bootstrap returned invalid data"
            ) from None
        return BootstrapProfile(user_id=user_id, created=response.status_code == 201)

    @staticmethod
    def _validate_profile(profile: dict[str, Any]) -> str:
        if set(profile) != PROFILE_FIELDS:
            raise ValueError("unexpected profile shape")
        raw_user_id = profile["user_id"]
        if type(raw_user_id) is not str:
            raise ValueError("invalid user identifier")
        parsed = uuid.UUID(raw_user_id)
        if parsed.version != 4 or str(parsed) != raw_user_id:
            raise ValueError("invalid user identifier")
        if type(profile["email_verified"]) is not bool:
            raise ValueError("invalid profile")
        for field_name, maximum in (("email", 320), ("display_name", 256), ("avatar_url", 2048)):
            value = profile[field_name]
            if value is not None and (type(value) is not str or not 1 <= len(value) <= maximum):
                raise ValueError("invalid profile")
        if type(profile["version"]) is not int or profile["version"] < 1:
            raise ValueError("invalid profile")
        for field_name in ("created_at", "updated_at"):
            value = profile[field_name]
            if type(value) is not str or len(value) > 64:
                raise ValueError("invalid profile")
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            offset = timestamp.utcoffset()
            if offset is None or offset.total_seconds() != 0:
                raise ValueError("invalid profile")
        return raw_user_id
