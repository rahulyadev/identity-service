"""Authoritative PostgreSQL identity model."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from identity_service.models.base import IDENTITY_SCHEMA, Base


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DELETED = "deleted"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled', 'deleted')", name="status_allowed"),
        CheckConstraint(
            "(status = 'deleted' AND deleted_at IS NOT NULL) OR "
            "(status <> 'deleted' AND deleted_at IS NULL)",
            name="deleted_at_matches_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default=UserStatus.ACTIVE.value, server_default="active"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProviderIdentity(Base):
    __tablename__ = "provider_identities"
    __table_args__ = (
        CheckConstraint("char_length(issuer) BETWEEN 1 AND 2048", name="issuer_length"),
        CheckConstraint("char_length(subject) BETWEEN 1 AND 255", name="subject_length"),
        UniqueConstraint("issuer", "subject", name="uq_provider_identities_issuer_subject"),
        Index("ix_provider_identities_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(f"{IDENTITY_SCHEMA}.users.id", ondelete="RESTRICT"), nullable=False
    )
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_auth_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claims_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Profile(Base):
    __tablename__ = "profiles"
    __table_args__ = (
        CheckConstraint(
            "provider_email IS NULL OR char_length(provider_email) BETWEEN 1 AND 320",
            name="provider_email_length",
        ),
        CheckConstraint(
            "provider_email IS NOT NULL OR provider_email_verified = false",
            name="provider_email_verification_consistent",
        ),
        CheckConstraint(
            "provider_display_name IS NULL OR char_length(provider_display_name) <= 100",
            name="provider_display_name_length",
        ),
        CheckConstraint(
            "provider_avatar_url IS NULL OR char_length(provider_avatar_url) <= 2048",
            name="provider_avatar_url_length",
        ),
        CheckConstraint(
            "display_name_override IS NULL OR char_length(display_name_override) <= 100",
            name="display_name_override_length",
        ),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(f"{IDENTITY_SCHEMA}.users.id", ondelete="RESTRICT"), primary_key=True
    )
    provider_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_email_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    provider_display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    display_name_override: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )

    @property
    def effective_display_name(self) -> str | None:
        if self.display_name_override is not None:
            return self.display_name_override
        return self.provider_display_name
