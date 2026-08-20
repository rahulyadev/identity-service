"""Concurrency-safe internal identity and profile service."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, Protocol

from sqlalchemy import exists, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from identity_service.db import SessionFactory
from identity_service.models import Profile, ProviderIdentity, User, UserStatus
from identity_service.services.errors import (
    IdentityNotFoundError,
    UserUnavailableError,
    VersionConflictError,
)
from identity_service.services.schemas import (
    ProfileView,
    ProviderIdentityInput,
    ProviderProfileInput,
)
from identity_service.services.validation import normalize_display_name_override

CreationStep = Literal["user", "provider_identity", "profile"]


class ServiceMetrics(Protocol):
    def record_bootstrap(self, outcome: str) -> None: ...

    def record_profile_update(self, outcome: str) -> None: ...

    def record_database_error(self, operation: str) -> None: ...


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_user_id() -> uuid.UUID:
    return uuid.uuid4()


def advisory_lock_key(issuer: str, subject: str) -> int:
    """Derive PostgreSQL's signed int8 lock key from an exact identity pair."""

    digest = hashlib.sha256(issuer.encode() + b"\x00" + subject.encode()).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


class IdentityProfileService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        metrics: ServiceMetrics | None = None,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = new_user_id,
    ) -> None:
        self._session_factory = session_factory
        self._metrics = metrics
        self._clock = clock
        self._uuid_factory = uuid_factory

    def _after_create_step(self, session: Session, step: CreationStep) -> None:
        """A no-op transaction checkpoint used to prove rollback behavior in tests."""

    def _record_bootstrap(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_bootstrap(outcome)

    def _record_profile_update(self, outcome: str) -> None:
        if self._metrics is not None:
            self._metrics.record_profile_update(outcome)

    def _record_database_error(self, operation: str) -> None:
        if self._metrics is not None:
            self._metrics.record_database_error(operation)

    def bootstrap_identity(
        self,
        provider_identity: ProviderIdentityInput,
        provider_profile: ProviderProfileInput,
    ) -> ProfileView:
        outcome = "error"
        try:
            with self._session_factory() as session, session.begin():
                session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {
                        "lock_key": advisory_lock_key(
                            provider_identity.issuer, provider_identity.subject
                        )
                    },
                )
                row = session.execute(
                    select(ProviderIdentity, User, Profile)
                    .join(User, User.id == ProviderIdentity.user_id)
                    .join(Profile, Profile.user_id == User.id)
                    .where(
                        ProviderIdentity.issuer == provider_identity.issuer,
                        ProviderIdentity.subject == provider_identity.subject,
                    )
                    .with_for_update(of=(ProviderIdentity, Profile))
                ).one_or_none()
                now = self._clock()

                if row is None:
                    profile = self._create_identity(
                        session,
                        provider_identity=provider_identity,
                        provider_profile=provider_profile,
                        now=now,
                    )
                    outcome = "created"
                else:
                    provider, user, profile = row._tuple()
                    self._require_active(user)
                    changed = self._synchronize_existing(
                        provider,
                        profile,
                        provider_identity=provider_identity,
                        provider_profile=provider_profile,
                        now=now,
                    )
                    session.flush()
                    outcome = "updated" if changed else "unchanged"

                result = ProfileView.from_profile(profile)
            self._record_bootstrap(outcome)
            return result
        except UserUnavailableError:
            self._record_bootstrap("rejected")
            raise
        except SQLAlchemyError:
            self._record_bootstrap("database_error")
            self._record_database_error("bootstrap")
            raise
        except Exception:
            self._record_bootstrap(outcome)
            raise

    def _create_identity(
        self,
        session: Session,
        *,
        provider_identity: ProviderIdentityInput,
        provider_profile: ProviderProfileInput,
        now: datetime,
    ) -> Profile:
        user_id = self._uuid_factory()
        if user_id.version != 4:
            raise ValueError("uuid_factory must return a UUIDv4 value")
        user = User(id=user_id, status=UserStatus.ACTIVE.value, created_at=now, updated_at=now)
        session.add(user)
        session.flush()
        self._after_create_step(session, "user")

        provider = ProviderIdentity(
            id=self._uuid_factory(),
            user_id=user_id,
            issuer=provider_identity.issuer,
            subject=provider_identity.subject,
            created_at=now,
            last_seen_at=now,
            last_auth_time=provider_identity.auth_time,
            claims_synced_at=now,
        )
        if provider.id.version != 4:
            raise ValueError("uuid_factory must return UUIDv4 values")
        session.add(provider)
        session.flush()
        self._after_create_step(session, "provider_identity")

        profile = Profile(
            user_id=user_id,
            provider_email=provider_profile.email,
            provider_email_verified=provider_profile.email_verified,
            provider_display_name=provider_profile.display_name,
            provider_avatar_url=provider_profile.avatar_url,
            display_name_override=None,
            version=1,
            created_at=now,
            updated_at=now,
        )
        session.add(profile)
        session.flush()
        self._after_create_step(session, "profile")
        return profile

    @staticmethod
    def _synchronize_existing(
        provider: ProviderIdentity,
        profile: Profile,
        *,
        provider_identity: ProviderIdentityInput,
        provider_profile: ProviderProfileInput,
        now: datetime,
    ) -> bool:
        provider.last_seen_at = now
        if provider_identity.auth_time is not None and (
            provider.last_auth_time is None or provider_identity.auth_time > provider.last_auth_time
        ):
            provider.last_auth_time = provider_identity.auth_time
        provider.claims_synced_at = now

        incoming = (
            provider_profile.email,
            provider_profile.email_verified,
            provider_profile.display_name,
            provider_profile.avatar_url,
        )
        current = (
            profile.provider_email,
            profile.provider_email_verified,
            profile.provider_display_name,
            profile.provider_avatar_url,
        )
        if incoming == current:
            return False
        (
            profile.provider_email,
            profile.provider_email_verified,
            profile.provider_display_name,
            profile.provider_avatar_url,
        ) = incoming
        profile.version += 1
        profile.updated_at = now
        return True

    @staticmethod
    def _require_active(user: User) -> None:
        if user.status != UserStatus.ACTIVE.value:
            raise UserUnavailableError("disabled or deleted users are unavailable")

    def get_profile_for_identity(self, issuer: str, subject: str) -> ProfileView:
        with self._session_factory() as session, session.begin():
            row = session.execute(
                select(User, Profile)
                .join(ProviderIdentity, ProviderIdentity.user_id == User.id)
                .join(Profile, Profile.user_id == User.id)
                .where(ProviderIdentity.issuer == issuer, ProviderIdentity.subject == subject)
            ).one_or_none()
            if row is None:
                raise IdentityNotFoundError("provider identity was not found")
            user, profile = row._tuple()
            self._require_active(user)
            return ProfileView.from_profile(profile)

    def update_display_name(
        self,
        user_id: uuid.UUID,
        expected_version: int,
        display_name: str | None,
    ) -> ProfileView:
        if expected_version < 1:
            raise ValueError("expected_version must be at least 1")
        normalized = normalize_display_name_override(display_name)
        try:
            with self._session_factory() as session, session.begin():
                active_user = exists(
                    select(User.id).where(
                        User.id == user_id,
                        User.status == UserStatus.ACTIVE.value,
                    )
                )
                changed_version = session.execute(
                    update(Profile)
                    .where(
                        Profile.user_id == user_id,
                        Profile.version == expected_version,
                        Profile.display_name_override.is_distinct_from(normalized),
                        active_user,
                    )
                    .values(
                        display_name_override=normalized,
                        version=Profile.version + 1,
                        updated_at=self._clock(),
                    )
                    .returning(Profile.version)
                ).scalar_one_or_none()

                row = session.execute(
                    select(User, Profile)
                    .join(Profile, Profile.user_id == User.id)
                    .where(User.id == user_id)
                ).one_or_none()
                if row is None:
                    raise IdentityNotFoundError("user profile was not found")
                user, profile = row._tuple()
                self._require_active(user)
                if changed_version is None and profile.version != expected_version:
                    raise VersionConflictError(expected_version)
                result = ProfileView.from_profile(profile)
            self._record_profile_update("updated" if changed_version is not None else "unchanged")
            return result
        except VersionConflictError:
            self._record_profile_update("conflict")
            raise
        except UserUnavailableError:
            self._record_profile_update("rejected")
            raise
        except IdentityNotFoundError:
            self._record_profile_update("not_found")
            raise
        except SQLAlchemyError:
            self._record_profile_update("database_error")
            self._record_database_error("profile_update")
            raise
