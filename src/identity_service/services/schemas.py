"""Strict internal service inputs and outputs."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr, field_validator, model_validator

from identity_service.models import Profile
from identity_service.services.validation import normalize_avatar_url, normalize_provider_name


class ProviderIdentityInput(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True)

    issuer: StrictStr
    subject: StrictStr
    auth_time: datetime | None = None

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, value: str) -> str:
        if not 1 <= len(value) <= 2048:
            raise ValueError("issuer must contain between 1 and 2048 code points")
        return value

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if not 1 <= len(value) <= 255:
            raise ValueError("subject must contain between 1 and 255 code points")
        return value

    @field_validator("auth_time")
    @classmethod
    def validate_auth_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("auth_time must be timezone-aware")
        return value


class ProviderProfileInput(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, validate_default=True)

    email: StrictStr | None = None
    email_verified: StrictBool = False
    display_name: StrictStr | None = None
    avatar_url: StrictStr | None = None

    @field_validator("email")
    @classmethod
    def validate_email_length(cls, value: str | None) -> str | None:
        if value is not None and not 1 <= len(value) <= 320:
            raise ValueError("provider email must contain between 1 and 320 code points")
        return value

    @model_validator(mode="after")
    def validate_email_verification_state(self) -> ProviderProfileInput:
        if self.email is None and self.email_verified:
            raise ValueError("a missing provider email cannot be verified")
        return self

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str | None) -> str | None:
        return normalize_provider_name(value)

    @field_validator("avatar_url")
    @classmethod
    def normalize_avatar(cls, value: str | None) -> str | None:
        return normalize_avatar_url(value)


class ProfileView(BaseModel):
    model_config = ConfigDict(frozen=True, from_attributes=True)

    user_id: uuid.UUID
    provider_email: str | None
    provider_email_verified: bool
    provider_display_name: str | None
    provider_avatar_url: str | None
    display_name_override: str | None
    effective_display_name: str | None
    version: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_profile(cls, profile: Profile) -> ProfileView:
        return cls(
            user_id=profile.user_id,
            provider_email=profile.provider_email,
            provider_email_verified=profile.provider_email_verified,
            provider_display_name=profile.provider_display_name,
            provider_avatar_url=profile.provider_avatar_url,
            display_name_override=profile.display_name_override,
            effective_display_name=profile.effective_display_name,
            version=profile.version,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
        )
