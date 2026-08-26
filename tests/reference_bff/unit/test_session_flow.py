from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any, cast

import httpx2
import pytest
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityProfileClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.session_flow import SessionFlow, SessionReadError
from reference_bff.sessions import (
    InvalidSessionRecordError,
    SessionHandle,
    SessionRecord,
    StoredSession,
    opaque_session_id,
)
from reference_bff.store import TransactionStoreUnavailableError
from reference_bff.tokens import CognitoTokenVerifier
from reference_bff.transactions import AuthorizationTransaction, new_transaction

from tests.reference_bff.provider import SyntheticProvider


class MemorySessionStore:
    def __init__(self, stored: StoredSession) -> None:
        self.stored: StoredSession | None = stored
        self.owner: str | None = None
        self.unavailable = False
        self.lock_contended = False
        self.lock_unavailable = False
        self.cas_unavailable = False
        self.release_unavailable = False
        self.load_failure: Exception | None = None
        self.inject_on_cas: StoredSession | None = None
        self.cas_calls = 0
        self.invalidate_calls = 0

    async def create(self, return_to: str) -> AuthorizationTransaction:
        del return_to
        raise AssertionError("not used")

    async def consume(self, state: str) -> AuthorizationTransaction | None:
        del state
        raise AssertionError("not used")

    async def create_session(self, record: SessionRecord) -> SessionHandle:
        del record
        raise AssertionError("not used")

    async def load_session(self, session_id: str) -> StoredSession | None:
        del session_id
        if self.load_failure is not None:
            raise self.load_failure
        if self.unavailable:
            raise TransactionStoreUnavailableError("synthetic outage")
        return self.stored

    async def cas_session(
        self, session_id: str, expected: StoredSession, replacement: SessionRecord
    ) -> bool:
        del session_id
        if self.unavailable or self.cas_unavailable:
            raise TransactionStoreUnavailableError("synthetic outage")
        self.cas_calls += 1
        if self.inject_on_cas is not None:
            self.stored = self.inject_on_cas
            self.inject_on_cas = None
        if self.stored is None or self.stored.serialized != expected.serialized:
            return False
        self.stored = StoredSession.from_record(replacement)
        return True

    async def invalidate_session(self, session_id: str, expected: StoredSession) -> bool:
        del session_id
        if self.unavailable:
            raise TransactionStoreUnavailableError("synthetic outage")
        self.invalidate_calls += 1
        if self.stored is None or self.stored.serialized != expected.serialized:
            return False
        self.stored = None
        return True

    async def acquire_refresh_lock(self, session_id: str, refresh_version: int, owner: str) -> bool:
        del session_id, refresh_version
        if self.lock_unavailable:
            raise TransactionStoreUnavailableError("synthetic outage")
        if self.unavailable:
            raise TransactionStoreUnavailableError("synthetic outage")
        if self.lock_contended or self.owner is not None:
            return False
        self.owner = owner
        return True

    async def release_refresh_lock(self, session_id: str, refresh_version: int, owner: str) -> bool:
        del session_id, refresh_version
        if self.release_unavailable:
            raise TransactionStoreUnavailableError("synthetic outage")
        if self.owner != owner:
            return False
        self.owner = None
        return True

    async def ready(self) -> bool:
        return not self.unavailable

    async def close(self) -> None:
        return


def stack(
    settings: Settings,
    *,
    now: int,
    access_lifetime: int,
) -> tuple[SessionFlow, MemorySessionStore, SyntheticProvider, AsyncUpstreamClient, str]:
    transaction = new_transaction(
        return_to="/",
        callback_uri=settings.callback_uri,
        ttl_seconds=settings.oauth_transaction_ttl_seconds,
        now=now,
    )
    provider = SyntheticProvider(settings)
    provider.configure(transaction, now=now, access_lifetime=access_lifetime)
    record = SessionRecord(
        issuer=settings.cognito_issuer,
        subject=provider.subject,
        client_id=settings.client_id,
        user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
        nonce=transaction.nonce,
        token_family_id=provider.token_family_id,
        access_token=provider.access_token,
        id_token=provider.id_token,
        refresh_token=provider.refresh_token,
        access_expires_at=now + access_lifetime,
        created_at=now - 10,
        last_activity_at=now - 10,
        absolute_expires_at=now - 10 + settings.session_absolute_seconds,
    )
    store = MemorySessionStore(StoredSession.from_record(record))
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(provider.handle))
    upstream = AsyncUpstreamClient(settings, transport=transport)
    jwks = AsyncJwksCache(settings, upstream)
    flow = SessionFlow(
        settings=settings,
        upstream=upstream,
        jwks=jwks,
        refresh=AuthorizationCodeClient(settings, upstream),
        verifier=CognitoTokenVerifier(settings, jwks),
        identity=IdentityProfileClient(settings, upstream),
        store=store,
        clock=lambda: float(now),
    )
    return flow, store, provider, upstream, opaque_session_id()


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def test_valid_token_outside_refresh_window_only_touches_and_reads_identity(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=900)

    async def scenario() -> None:
        result = await flow.read(session_id)
        assert result.etag == '"v1"'
        assert result.max_age == settings.session_idle_seconds
        assert store.stored is not None
        assert store.stored.record.last_activity_at == now
        assert store.stored.record.refresh_version == 0
        await flow.close()

    run(scenario())
    assert provider.refresh_requests == 0
    assert provider.events == ["profile"]


def test_refresh_boundary_rotates_once_increments_once_and_preserves_absolute_session(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=settings.session_refresh_window_seconds
    )
    assert store.stored is not None
    original = store.stored.record

    async def scenario() -> None:
        result = await flow.read(session_id)
        assert result.profile["version"] == 1
        assert store.stored is not None
        rotated = store.stored.record
        assert rotated.refresh_version == 1
        assert rotated.refresh_token == provider.rotated_refresh_token
        assert rotated.created_at == original.created_at
        assert rotated.absolute_expires_at == original.absolute_expires_at
        assert rotated.nonce == original.nonce
        assert rotated.token_family_id == original.token_family_id
        assert store.owner is None
        await flow.close()

    run(scenario())
    assert provider.refresh_requests == 1
    assert provider.events == ["refresh", "jwks", "profile"]


def test_refresh_outage_falls_back_only_while_current_access_token_is_valid(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    valid_flow, valid_store, valid_provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=60
    )
    valid_provider.refresh_status = 503

    async def valid_scenario() -> None:
        result = await valid_flow.read(session_id)
        assert result.etag == '"v1"'
        assert valid_store.stored is not None
        assert valid_store.stored.record.refresh_version == 0
        await valid_flow.close()

    run(valid_scenario())

    expired_flow, expired_store, expired_provider, _upstream, expired_id = stack(
        settings, now=now, access_lifetime=1
    )
    assert expired_store.stored is not None
    expired_store.stored = StoredSession.from_record(
        replace(expired_store.stored.record, access_expires_at=now)
    )
    expired_provider.refresh_status = 503

    async def expired_scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await expired_flow.read(expired_id)
        assert captured.value.status == 503
        assert captured.value.code == "session_unavailable"
        assert captured.value.clear_cookie is False
        assert expired_store.stored is not None
        await expired_flow.close()

    run(expired_scenario())


@pytest.mark.parametrize("mode", ["refresh-rejected", "rotated-family", "identity-rejected"])
def test_definitive_refresh_or_identity_rejection_atomically_invalidates_and_returns_401(
    bff_settings_factory: Callable[..., Settings], mode: str
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    access_lifetime = 900 if mode == "identity-rejected" else 60
    flow, store, provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=access_lifetime
    )
    if mode == "refresh-rejected":
        provider.refresh_status = 400
    elif mode == "rotated-family":
        provider.token_family_id = "different-token-family"
        provider.rotated_access_token, provider.rotated_id_token = provider._token_pair(
            issued_at=now,
            lifetime=900,
            nonce=None,
            token_id="different-family-token",
        )
    else:
        provider.profile_status = 401

    async def scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.read(session_id)
        assert captured.value.status == 401
        assert captured.value.code == "session_required"
        assert captured.value.clear_cookie is True
        assert store.stored is None
        assert store.invalidate_calls >= 1
        await flow.close()

    run(scenario())


def test_identity_unsafe_response_is_fixed_503_and_preserves_valid_session(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=900)
    provider.identity_etag = 'W/"v1"'

    async def scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.read(session_id)
        assert captured.value.status == 503
        assert captured.value.code == "identity_unavailable"
        assert captured.value.clear_cookie is False
        assert store.stored is not None
        await flow.close()

    run(scenario())


@pytest.mark.parametrize(
    ("failure", "status"),
    [
        (None, 401),
        (InvalidSessionRecordError("synthetic malformed session"), 401),
        (TransactionStoreUnavailableError("synthetic outage"), 503),
    ],
)
def test_missing_malformed_and_unavailable_session_loads_are_fixed(
    bff_settings_factory: Callable[..., Settings], failure: Exception | None, status: int
) -> None:
    now = int(time.time())
    flow, store, _provider, _upstream, session_id = stack(
        bff_settings_factory(), now=now, access_lifetime=900
    )
    if failure is None:
        store.stored = None
    else:
        store.load_failure = failure

    async def scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.read(session_id)
        assert captured.value.status == status
        assert captured.value.code == (
            "session_required" if status == 401 else "session_unavailable"
        )
        await flow.close()

    run(scenario())


@pytest.mark.parametrize("outage", ["lock", "cas"])
def test_refresh_coordination_or_replacement_outage_is_fixed_503(
    bff_settings_factory: Callable[..., Settings], outage: str
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, _provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=settings.session_refresh_window_seconds
    )
    if outage == "lock":
        store.lock_unavailable = True
    else:
        store.cas_unavailable = True

    async def scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.read(session_id)
        assert captured.value.status == 503
        assert captured.value.code == "session_unavailable"
        assert store.stored is not None
        await flow.close()

    run(scenario())


def test_refresh_lock_loser_uses_bounded_valid_token_fallback(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=60)
    store.lock_contended = True
    monotonic_values = iter((0.0, 2.0))
    flow._monotonic = monotonic_values.__next__

    async def scenario() -> None:
        result = await flow.read(session_id)
        assert result.etag == '"v1"'
        assert store.stored is not None
        assert store.stored.record.refresh_version == 0
        await flow.close()

    run(scenario())
    assert provider.refresh_requests == 0


def test_refresh_signing_key_outage_falls_back_to_still_valid_access_token(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=60)
    provider.jwks_status = 503

    async def scenario() -> None:
        result = await flow.read(session_id)
        assert result.etag == '"v1"'
        assert store.stored is not None
        assert store.stored.record.refresh_version == 0
        await flow.close()

    run(scenario())
    assert provider.refresh_requests == 1


def test_refresh_owner_work_is_cancelled_before_the_redis_lease_can_expire(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    class SlowRefresh:
        async def refresh(self, refresh_token: str) -> None:
            del refresh_token
            await asyncio.sleep(5)

    now = int(time.time())
    settings = bff_settings_factory(refresh_lock_lease_seconds=3)
    flow, store, _provider, _upstream, session_id = stack(settings, now=now, access_lifetime=60)
    flow._refresh = cast(AuthorizationCodeClient, SlowRefresh())

    async def scenario() -> None:
        started = time.monotonic()
        result = await flow.read(session_id)
        assert time.monotonic() - started < settings.refresh_lock_lease_seconds
        assert result.etag == '"v1"'
        assert store.owner is None
        assert store.stored is not None
        assert store.stored.record.refresh_version == 0
        await flow.close()

    run(scenario())


def test_refresh_cas_observes_and_preserves_a_strictly_newer_version(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=settings.session_refresh_window_seconds
    )
    assert store.stored is not None
    newer = replace(
        store.stored.record,
        access_token=provider.rotated_access_token,
        id_token=provider.rotated_id_token,
        refresh_token=provider.rotated_refresh_token,
        access_expires_at=now + 900,
        refresh_version=1,
    )
    store.inject_on_cas = StoredSession.from_record(newer)

    async def scenario() -> None:
        result = await flow.read(session_id)
        assert result.etag == '"v1"'
        assert store.stored is not None
        assert store.stored.record.refresh_version == 1
        assert store.stored.record.refresh_token == provider.rotated_refresh_token
        await flow.close()

    run(scenario())
