from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import cast
from urllib.parse import parse_qs

import httpx2
import pytest
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityProfileClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.logout import RawLogoutRequest
from reference_bff.session_flow import SessionFlow, SessionReadError
from reference_bff.sessions import SessionRecord, opaque_session_id
from reference_bff.store import TransactionStore
from reference_bff.tokens import CognitoTokenVerifier
from reference_bff.transactions import new_transaction

from tests.reference_bff.integration.test_redis_transactions import _with_store, redis_settings
from tests.reference_bff.provider import SyntheticProvider


def raw_logout(settings: Settings, csrf_token: str) -> RawLogoutRequest:
    return RawLogoutRequest(
        headers=(
            (b"origin", settings.bff_origin.encode()),
            (b"x-csrf-token", csrf_token.encode()),
            (b"sec-fetch-site", b"same-origin"),
            (b"content-length", b"0"),
        ),
        query_string=b"",
        body_present=False,
        body_complete=True,
    )


def session_record(
    settings: Settings,
    provider: SyntheticProvider,
    *,
    now: int,
    access_lifetime: int,
) -> SessionRecord:
    assert provider.transaction is not None
    return SessionRecord(
        issuer=settings.cognito_issuer,
        subject=provider.subject,
        client_id=settings.client_id,
        user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
        nonce=provider.transaction.nonce,
        token_family_id=provider.token_family_id,
        csrf_token=opaque_session_id(),
        access_token=provider.access_token,
        id_token=provider.id_token,
        refresh_token=provider.refresh_token,
        access_expires_at=now + access_lifetime,
        created_at=now,
        last_activity_at=now,
        absolute_expires_at=now + settings.session_absolute_seconds,
    )


def flow_stack(
    settings: Settings,
    provider: SyntheticProvider,
    store: TransactionStore,
    transport: httpx2.AsyncBaseTransport,
) -> SessionFlow:
    upstream = AsyncUpstreamClient(settings, transport=transport)
    jwks = AsyncJwksCache(settings, upstream)
    return SessionFlow(
        settings=settings,
        upstream=upstream,
        jwks=jwks,
        refresh=AuthorizationCodeClient(settings, upstream),
        verifier=CognitoTokenVerifier(settings, jwks),
        identity=IdentityProfileClient(settings, upstream),
        store=store,
    )


@pytest.mark.redis_integration
def test_fifty_real_redis_logouts_have_one_delete_and_one_revoke(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(
        bff_settings_factory,
        namespace="reference-bff:test:redis-logout-concurrency",
    )

    async def scenario() -> None:
        async for store, client in _with_store(settings):
            now = int(time.time())
            transaction = new_transaction(
                return_to="/",
                callback_uri=settings.callback_uri,
                ttl_seconds=settings.oauth_transaction_ttl_seconds,
                now=now,
            )
            provider = SyntheticProvider(settings)
            provider.configure(transaction, now=now, access_lifetime=900)
            initial = session_record(settings, provider, now=now, access_lifetime=900)
            handle = await store.create_session(initial)
            transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(provider.handle))
            flow = flow_stack(settings, provider, store, transport)
            raw = raw_logout(settings, initial.csrf_token)
            try:
                results = await asyncio.gather(
                    *(flow.logout(handle.session_id, raw) for _ in range(50)),
                    return_exceptions=True,
                )
                successes = [result for result in results if result is None]
                failures = [result for result in results if isinstance(result, SessionReadError)]
                assert len(successes) == 1
                assert len(failures) == 49
                assert all(
                    (error.status, error.code, error.clear_cookie)
                    == (401, "session_required", True)
                    for error in failures
                )
                assert provider.revoke_requests == 1
                assert provider.events == ["revoke"]
                assert await store.load_session(handle.session_id) is None
                assert await client.exists(store.key_for_session_id(handle.session_id)) == 0
            finally:
                await flow.close()

    asyncio.run(scenario())


class BlockingRefreshTransport(httpx2.AsyncBaseTransport):
    def __init__(self, settings: Settings, provider: SyntheticProvider) -> None:
        self._settings = settings
        self._provider = provider
        self.refresh_started = asyncio.Event()
        self.allow_refresh = asyncio.Event()

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if str(request.url) == self._settings.token_endpoint and request.method == "POST":
            form = parse_qs(request.content.decode(), strict_parsing=True)
            if form.get("grant_type") == ["refresh_token"]:
                self.refresh_started.set()
                await self.allow_refresh.wait()
        return self._provider.handle(request)


@pytest.mark.redis_integration
def test_real_redis_logout_wins_controlled_inflight_refresh_without_resurrection(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(
        bff_settings_factory,
        namespace="reference-bff:test:redis-logout-refresh-race",
    )

    async def scenario() -> None:
        async for store, client in _with_store(settings):
            now = int(time.time())
            transaction = new_transaction(
                return_to="/",
                callback_uri=settings.callback_uri,
                ttl_seconds=settings.oauth_transaction_ttl_seconds,
                now=now,
            )
            provider = SyntheticProvider(settings)
            provider.configure(
                transaction,
                now=now,
                access_lifetime=settings.session_refresh_window_seconds,
            )
            initial = session_record(
                settings,
                provider,
                now=now,
                access_lifetime=settings.session_refresh_window_seconds,
            )
            handle = await store.create_session(initial)
            transport = BlockingRefreshTransport(settings, provider)
            flow = flow_stack(settings, provider, store, transport)
            refresh = asyncio.create_task(flow.read(handle.session_id))
            try:
                await asyncio.wait_for(transport.refresh_started.wait(), timeout=2)
                await flow.logout(
                    handle.session_id,
                    raw_logout(settings, initial.csrf_token),
                )
                assert await store.load_session(handle.session_id) is None
                transport.allow_refresh.set()
                with pytest.raises(SessionReadError) as captured:
                    await refresh
                assert (captured.value.status, captured.value.code) == (
                    401,
                    "session_required",
                )
                assert await store.load_session(handle.session_id) is None
                assert await client.exists(store.key_for_session_id(handle.session_id)) == 0
                assert provider.revoke_requests == 1
                assert provider.refresh_requests == 1
            finally:
                transport.allow_refresh.set()
                if not refresh.done():
                    refresh.cancel()
                    await asyncio.gather(refresh, return_exceptions=True)
                await flow.close()

    asyncio.run(scenario())
