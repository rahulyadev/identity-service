"""Cookie-session touch, refresh rotation, and strict Identity profile orchestration."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from typing import Protocol

from reference_bff.config import Settings
from reference_bff.exchange import (
    AuthorizationCodeClient,
    InvalidRefreshResponseError,
    RefreshRejectedError,
    RefreshUnavailableError,
)
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import (
    IdentityProfileClient,
    IdentityProfileConflictError,
    IdentityProfileUnavailableError,
    IdentitySessionRejectedError,
)
from reference_bff.jwks import AsyncJwksCache
from reference_bff.logout import LogoutRequestError, RawLogoutRequest, validate_logout_request
from reference_bff.profile_updates import (
    ProfilePatchFailure,
    RawProfilePatch,
    require_csrf,
    validate_profile_patch,
)
from reference_bff.sessions import (
    InvalidSessionRecordError,
    SessionRecord,
    StoredSession,
    refresh_lock_owner,
    session_max_age,
)
from reference_bff.store import MAX_CAS_ATTEMPTS, TransactionStore, TransactionStoreUnavailableError
from reference_bff.tokens import (
    CognitoTokenVerifier,
    InvalidProviderTokenError,
    TokenVerificationUnavailableError,
    VerifiedTokens,
)


@dataclass(slots=True)
class SessionReadError(Exception):
    status: int
    code: str
    clear_cookie: bool


@dataclass(frozen=True, slots=True)
class SessionReadResult:
    profile: dict[str, object] = field(repr=False)
    etag: str
    max_age: int
    csrf_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ActiveSession:
    stored: StoredSession
    max_age: int


class SessionReader(Protocol):
    async def read(self, session_id: str) -> SessionReadResult: ...

    async def patch(self, session_id: str, raw: RawProfilePatch) -> SessionReadResult: ...

    async def logout(self, session_id: str, raw: RawLogoutRequest) -> None: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


def _session_required() -> SessionReadError:
    return SessionReadError(401, "session_required", True)


def _session_unavailable() -> SessionReadError:
    return SessionReadError(503, "session_unavailable", False)


def _identity_unavailable() -> SessionReadError:
    return SessionReadError(503, "identity_unavailable", False)


class SessionFlow:
    """Use Redis as the sole concurrency authority for one opaque browser session."""

    def __init__(
        self,
        *,
        settings: Settings,
        upstream: AsyncUpstreamClient,
        jwks: AsyncJwksCache,
        refresh: AuthorizationCodeClient,
        verifier: CognitoTokenVerifier,
        identity: IdentityProfileClient,
        store: TransactionStore,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._upstream = upstream
        self._jwks = jwks
        self._refresh = refresh
        self._verifier = verifier
        self._identity = identity
        self._store = store
        self._clock = clock
        self._monotonic = monotonic

    async def read(self, session_id: str) -> SessionReadResult:
        stored = await self._load(session_id)
        if stored is None:
            raise _session_required()
        active = await self._refresh_or_touch(session_id, stored)
        for _ in range(2):
            try:
                profile = await self._identity.read(
                    active.stored.record.access_token,
                    expected_user_id=active.stored.record.user_id,
                )
            except IdentityProfileUnavailableError:
                raise _identity_unavailable() from None
            except IdentitySessionRejectedError:
                newer = await self._invalidate_exact_version(session_id, active.stored)
                active = await self._touch(session_id, newer)
                continue
            return SessionReadResult(
                profile=dict(profile.document),
                etag=profile.etag,
                max_age=active.max_age,
                csrf_token=active.stored.record.csrf_token,
            )
        raise _session_required()

    async def patch(self, session_id: str, raw: RawProfilePatch) -> SessionReadResult:
        stored = await self._load(session_id)
        if stored is None:
            raise _session_required()
        try:
            require_csrf(
                raw,
                expected_origin=self._settings.bff_origin,
                expected_token=stored.record.csrf_token,
            )
            update = validate_profile_patch(raw)
        except ProfilePatchFailure as error:
            raise SessionReadError(error.status, error.code, False) from None

        active = await self._refresh_or_touch(session_id, stored)
        self._require_preserved_csrf(stored.record, active.stored.record)
        for _ in range(2):
            try:
                profile = await self._identity.patch(
                    active.stored.record.access_token,
                    expected_user_id=active.stored.record.user_id,
                    if_match=update.if_match,
                    body=update.body,
                )
            except IdentityProfileConflictError:
                raise SessionReadError(412, "profile_conflict", False) from None
            except IdentityProfileUnavailableError:
                raise _identity_unavailable() from None
            except IdentitySessionRejectedError:
                newer = await self._invalidate_exact_version(session_id, active.stored)
                self._require_preserved_csrf(stored.record, newer.record)
                active = await self._touch(session_id, newer)
                continue
            return SessionReadResult(
                profile=dict(profile.document),
                etag=profile.etag,
                max_age=active.max_age,
                csrf_token=active.stored.record.csrf_token,
            )
        raise _session_required()

    async def logout(self, session_id: str, raw: RawLogoutRequest) -> None:
        """Invalidate one exact session before one best-effort provider revocation."""

        stored = await self._load_for_logout(session_id)
        if stored is None:
            raise SessionReadError(401, "session_required", True)
        try:
            require_csrf(
                raw,
                expected_origin=self._settings.bff_origin,
                expected_token=stored.record.csrf_token,
            )
            validate_logout_request(raw)
        except ProfilePatchFailure as error:
            raise SessionReadError(error.status, error.code, False) from None
        except LogoutRequestError as error:
            raise SessionReadError(error.status, error.code, False) from None

        current = stored
        for _ in range(MAX_CAS_ATTEMPTS):
            if not secrets.compare_digest(
                stored.record.csrf_token,
                current.record.csrf_token,
            ):
                raise SessionReadError(403, "csrf_failed", False)
            try:
                deleted = await self._store.invalidate_session(session_id, current)
            except TransactionStoreUnavailableError:
                raise SessionReadError(503, "session_unavailable", True) from None
            if deleted:
                revoked = await self._refresh.revoke(current.record.refresh_token)
                logging.getLogger("reference_bff.http").info(
                    "provider_token_revocation_succeeded"
                    if revoked
                    else "provider_token_revocation_failed"
                )
                return
            latest = await self._load_for_logout(session_id)
            if latest is None:
                raise SessionReadError(401, "session_required", True)
            current = latest
        raise SessionReadError(503, "session_unavailable", True)

    @staticmethod
    def _require_preserved_csrf(before: SessionRecord, after: SessionRecord) -> None:
        if not secrets.compare_digest(before.csrf_token, after.csrf_token):
            raise _session_unavailable()

    async def _load(self, session_id: str) -> StoredSession | None:
        try:
            return await self._store.load_session(session_id)
        except InvalidSessionRecordError:
            raise _session_required() from None
        except TransactionStoreUnavailableError:
            raise _session_unavailable() from None

    async def _load_for_logout(self, session_id: str) -> StoredSession | None:
        try:
            return await self._store.load_session(session_id)
        except InvalidSessionRecordError:
            raise SessionReadError(401, "session_required", True) from None
        except TransactionStoreUnavailableError:
            raise SessionReadError(503, "session_unavailable", True) from None

    async def _refresh_or_touch(self, session_id: str, stored: StoredSession) -> _ActiveSession:
        now = int(self._clock())
        if stored.record.access_expires_at - now > self._settings.session_refresh_window_seconds:
            return await self._touch(session_id, stored)
        owner = refresh_lock_owner()
        try:
            acquired = await self._store.acquire_refresh_lock(
                session_id,
                stored.record.refresh_version,
                owner,
            )
        except TransactionStoreUnavailableError:
            raise _session_unavailable() from None
        if not acquired:
            return await self._wait_for_refresh(session_id, stored)
        try:
            try:
                async with asyncio.timeout(self._settings.refresh_lock_lease_seconds - 1):
                    return await self._refresh_as_owner(session_id, stored)
            except TimeoutError:
                return await self._fallback_or_unavailable(session_id, stored)
        finally:
            with suppress(TransactionStoreUnavailableError):
                await self._store.release_refresh_lock(
                    session_id,
                    stored.record.refresh_version,
                    owner,
                )

    async def _refresh_as_owner(self, session_id: str, stored: StoredSession) -> _ActiveSession:
        try:
            rotated = await self._refresh.refresh(stored.record.refresh_token)
        except RefreshUnavailableError:
            return await self._fallback_or_unavailable(session_id, stored)
        except RefreshRejectedError, InvalidRefreshResponseError:
            newer = await self._invalidate_exact_version(session_id, stored)
            return await self._touch(session_id, newer)
        try:
            verified = await self._verifier.verify_refresh(
                id_token=rotated.id_token,
                access_token=rotated.access_token,
                refresh_token=rotated.refresh_token,
                expected_nonce=stored.record.nonce,
                expected_subject=stored.record.subject,
                expected_token_family_id=stored.record.token_family_id,
            )
        except TokenVerificationUnavailableError:
            return await self._fallback_or_unavailable(session_id, stored)
        except InvalidProviderTokenError:
            newer = await self._invalidate_exact_version(session_id, stored)
            return await self._touch(session_id, newer)
        return await self._cas_refresh(session_id, stored, verified)

    async def _cas_refresh(
        self,
        session_id: str,
        expected: StoredSession,
        verified: VerifiedTokens,
    ) -> _ActiveSession:
        current = expected
        for _ in range(MAX_CAS_ATTEMPTS):
            now = int(self._clock())
            replacement = replace(
                current.record,
                subject=verified.subject,
                client_id=verified.client_id,
                token_family_id=verified.token_family_id,
                access_token=verified.access_token,
                id_token=verified.id_token,
                refresh_token=verified.refresh_token,
                access_expires_at=verified.access_expires_at,
                last_activity_at=max(current.record.last_activity_at, now),
                refresh_version=expected.record.refresh_version + 1,
            )
            try:
                changed = await self._store.cas_session(session_id, current, replacement)
            except TransactionStoreUnavailableError:
                raise _session_unavailable() from None
            if changed:
                return _ActiveSession(
                    stored=StoredSession.from_record(replacement),
                    max_age=session_max_age(replacement, self._settings, now=now),
                )
            latest = await self._load(session_id)
            if latest is None:
                raise _session_required()
            if latest.record.refresh_version > expected.record.refresh_version:
                return await self._touch(session_id, latest)
            if not self._same_refresh_input(latest.record, expected.record):
                raise _session_unavailable()
            current = latest
        raise _session_unavailable()

    @staticmethod
    def _same_refresh_input(current: SessionRecord, expected: SessionRecord) -> bool:
        return replace(current, last_activity_at=expected.last_activity_at) == expected

    async def _wait_for_refresh(self, session_id: str, expected: StoredSession) -> _ActiveSession:
        deadline = self._monotonic() + self._settings.refresh_wait_timeout_ms / 1000
        latest = expected
        while self._monotonic() < deadline:
            await asyncio.sleep(self._settings.refresh_poll_interval_ms / 1000)
            candidate = await self._load(session_id)
            if candidate is None:
                raise _session_required()
            if candidate.record.refresh_version > expected.record.refresh_version:
                return await self._touch(session_id, candidate)
            if candidate.record.refresh_version < expected.record.refresh_version:
                raise _session_required()
            latest = candidate
        return await self._fallback_or_unavailable(session_id, latest)

    async def _fallback_or_unavailable(
        self, session_id: str, stored: StoredSession
    ) -> _ActiveSession:
        if stored.record.access_expires_at > int(self._clock()):
            return await self._touch(session_id, stored)
        raise _session_unavailable()

    async def _touch(self, session_id: str, stored: StoredSession) -> _ActiveSession:
        current = stored
        for _ in range(MAX_CAS_ATTEMPTS):
            now = int(self._clock())
            max_age = session_max_age(current.record, self._settings, now=now)
            if max_age <= 0:
                raise _session_required()
            replacement = replace(
                current.record,
                last_activity_at=max(current.record.last_activity_at, now),
            )
            try:
                changed = await self._store.cas_session(session_id, current, replacement)
            except TransactionStoreUnavailableError:
                raise _session_unavailable() from None
            if changed:
                return _ActiveSession(
                    stored=StoredSession.from_record(replacement),
                    max_age=max_age,
                )
            latest = await self._load(session_id)
            if latest is None:
                raise _session_required()
            current = latest
        raise _session_unavailable()

    async def _invalidate_exact_version(
        self, session_id: str, rejected: StoredSession
    ) -> StoredSession:
        current = rejected
        for _ in range(MAX_CAS_ATTEMPTS):
            if current.record.refresh_version > rejected.record.refresh_version:
                return current
            if current.record.refresh_version < rejected.record.refresh_version:
                raise _session_required()
            try:
                deleted = await self._store.invalidate_session(session_id, current)
            except TransactionStoreUnavailableError:
                raise _session_unavailable() from None
            if deleted:
                raise _session_required()
            latest = await self._load(session_id)
            if latest is None:
                raise _session_required()
            current = latest
        raise _session_unavailable()

    async def ready(self) -> bool:
        return await self._jwks.ready()

    async def close(self) -> None:
        self._jwks.close()
        await self._upstream.close()
