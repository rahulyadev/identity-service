"""Strict Identity profile bootstrap adapter for the callback flow."""

from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass, field
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


class IdentityProfileUnavailableError(RuntimeError):
    """Identity profile read failed or returned structurally unsafe data."""


class IdentitySessionRejectedError(ValueError):
    """Identity rejected the exact server-held access token."""


class IdentityProfileConflictError(ValueError):
    """Identity rejected the exact optimistic profile precondition."""


@dataclass(frozen=True, slots=True)
class BootstrapProfile:
    user_id: str
    created: bool


@dataclass(frozen=True, slots=True)
class IdentityProfile:
    document: dict[str, Any] = field(repr=False)
    etag: str


STRONG_ETAG = re.compile(r'"v([1-9][0-9]*)"')
UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)"
)


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
            user_id = validate_profile(profile)
        except UnsafeJsonError, TypeError, ValueError:
            raise IdentityBootstrapUnavailableError(
                "Identity bootstrap returned invalid data"
            ) from None
        return BootstrapProfile(user_id=user_id, created=response.status_code == 201)


class IdentityProfileClient:
    def __init__(self, settings: Settings, client: AsyncUpstreamClient) -> None:
        self._url = settings.identity_api_origin + "/v1/me"
        self._client = client

    async def read(self, access_token: str, *, expected_user_id: str) -> IdentityProfile:
        try:
            response = await self._client.request(
                "GET",
                self._url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
            )
        except UpstreamError:
            raise IdentityProfileUnavailableError("Identity profile is unavailable") from None
        if response.status_code == 401:
            raise IdentitySessionRejectedError("Identity rejected the session")
        if response.status_code != 200 or not json_media_type(
            response.headers,
            allowed=JSON_MEDIA_TYPES,
        ):
            raise IdentityProfileUnavailableError("Identity returned an unsafe response")
        try:
            profile = load_json_object(response.body)
            user_id = validate_profile(profile)
            etag = response.headers.get("etag")
            if etag is None or user_id != expected_user_id:
                raise ValueError("Identity profile binding is invalid")
            match = STRONG_ETAG.fullmatch(etag)
            if match is None or int(match.group(1)) != profile["version"]:
                raise ValueError("Identity profile binding is invalid")
        except UnsafeJsonError, TypeError, ValueError, OverflowError:
            raise IdentityProfileUnavailableError("Identity returned invalid data") from None
        return IdentityProfile(document=profile, etag=etag)

    async def patch(
        self,
        access_token: str,
        *,
        expected_user_id: str,
        if_match: str,
        body: bytes,
    ) -> IdentityProfile:
        try:
            response = await self._client.request(
                "PATCH",
                self._url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/merge-patch+json",
                    "If-Match": if_match,
                },
                content=body,
            )
        except UpstreamError:
            raise IdentityProfileUnavailableError("Identity profile is unavailable") from None
        if response.status_code in {401, 403}:
            raise IdentitySessionRejectedError("Identity rejected the session")
        if response.status_code == 412:
            raise IdentityProfileConflictError("Identity rejected the profile precondition")
        if response.status_code != 200 or not json_media_type(
            response.headers,
            allowed=JSON_MEDIA_TYPES,
        ):
            raise IdentityProfileUnavailableError("Identity returned an unsafe response")
        try:
            profile = load_json_object(response.body)
            user_id = validate_profile(profile)
            etag = response.headers.get("etag")
            if etag is None or user_id != expected_user_id:
                raise ValueError("Identity profile binding is invalid")
            match = STRONG_ETAG.fullmatch(etag)
            if match is None or int(match.group(1)) != profile["version"]:
                raise ValueError("Identity profile binding is invalid")
        except UnsafeJsonError, TypeError, ValueError, OverflowError:
            raise IdentityProfileUnavailableError("Identity returned invalid data") from None
        return IdentityProfile(document=profile, etag=etag)


def _profile_text(value: Any, *, maximum: int) -> str | None:
    if value is None:
        return None
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(unicodedata.category(character) in {"Cc", "Zl", "Zp"} for character in value)
    ):
        raise ValueError("invalid profile")
    return value


def _utc_timestamp(value: Any) -> datetime:
    if type(value) is not str or len(value) > 64 or UTC_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("invalid profile")
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    offset = timestamp.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("invalid profile")
    return timestamp


def validate_profile(profile: dict[str, Any]) -> str:
    if set(profile) != PROFILE_FIELDS:
        raise ValueError("unexpected profile shape")
    raw_user_id = profile["user_id"]
    if type(raw_user_id) is not str:
        raise ValueError("invalid user identifier")
    parsed = uuid.UUID(raw_user_id)
    if parsed.version != 4 or str(parsed) != raw_user_id:
        raise ValueError("invalid user identifier")
    email = _profile_text(profile["email"], maximum=320)
    display_name = _profile_text(profile["display_name"], maximum=100)
    avatar_url = _profile_text(profile["avatar_url"], maximum=2048)
    del display_name, avatar_url
    if type(profile["email_verified"]) is not bool or (email is None and profile["email_verified"]):
        raise ValueError("invalid profile")
    if type(profile["version"]) is not int or profile["version"] < 1:
        raise ValueError("invalid profile")
    created_at = _utc_timestamp(profile["created_at"])
    updated_at = _utc_timestamp(profile["updated_at"])
    if updated_at < created_at:
        raise ValueError("invalid profile")
    return raw_user_id
