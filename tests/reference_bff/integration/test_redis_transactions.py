from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator, Callable
from typing import cast

import httpx2
import pytest
from redis.asyncio import Redis
from redis.exceptions import ResponseError as RedisResponseError
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityProfileClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.session_flow import SessionFlow
from reference_bff.sessions import SessionRecord
from reference_bff.store import READINESS_TTL_SECONDS, RedisTransactionStore
from reference_bff.tokens import CognitoTokenVerifier
from reference_bff.transactions import MalformedTransactionError, new_transaction

from tests.reference_bff.provider import SyntheticProvider


def run(coroutine: object) -> object:
    return asyncio.run(coroutine)  # type: ignore[arg-type]


async def _delete_namespace(client: Redis, namespace: str) -> None:
    keys = [key async for key in client.scan_iter(match=f"{namespace}:*")]
    if keys:
        await client.delete(*keys)


async def _with_store(
    settings: Settings,
) -> AsyncIterator[tuple[RedisTransactionStore, Redis]]:
    client = Redis.from_url(settings.redis_url.get_secret_value(), decode_responses=False)
    store = RedisTransactionStore(settings, client)
    await _delete_namespace(client, settings.redis_key_namespace)
    try:
        yield store, client
    finally:
        await _delete_namespace(client, settings.redis_key_namespace)
        await store.close()


def redis_settings(
    bff_settings_factory: Callable[..., Settings], *, namespace: str, **overrides: object
) -> Settings:
    url = os.environ["BFF_TEST_REDIS_URL"]
    return bff_settings_factory(redis_url=url, redis_key_namespace=namespace, **overrides)


class GetdelDeniedClient:
    def __init__(self, client: Redis) -> None:
        self._client = client

    async def set(self, name: str, value: bytes, *, nx: bool, ex: int) -> bool | None:
        result = await self._client.set(name, value, nx=nx, ex=ex)
        return True if result is True else None

    async def getdel(self, name: str) -> bytes | None:
        raise RedisResponseError("synthetic GETDEL denial")

    async def get(self, name: str) -> bytes | None:
        value = await self._client.get(name)
        return value if isinstance(value, bytes) else None

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> object:
        return await self._client.eval(script, numkeys, *keys_and_args)

    async def aclose(self) -> None:
        return


@pytest.mark.redis_integration
def test_real_redis_set_nx_ex_getdel_and_fixed_ttl(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(bff_settings_factory, namespace="reference-bff:test:redis-atomic")

    async def scenario() -> None:
        async for store, client in _with_store(settings):
            transaction = await store.create("/profile")
            key = store.key_for_state(transaction.state)
            assert transaction.state.encode() not in key.encode()
            first_ttl = await client.pttl(key)
            assert 0 < first_ttl <= settings.oauth_transaction_ttl_seconds * 1000
            assert await client.get(key) is not None
            second_ttl = await client.pttl(key)
            assert 0 < second_ttl <= first_ttl
            assert await store.consume(transaction.state) == transaction
            assert await client.exists(key) == 0
            assert await store.consume(transaction.state) is None

    run(scenario())


@pytest.mark.redis_integration
def test_fifty_concurrent_consumers_have_exactly_one_winner(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(
        bff_settings_factory, namespace="reference-bff:test:redis-concurrency"
    )

    async def scenario() -> None:
        async for store, _client in _with_store(settings):
            transaction = await store.create("/")
            results = await asyncio.gather(*(store.consume(transaction.state) for _ in range(50)))
            assert sum(result == transaction for result in results) == 1
            assert sum(result is None for result in results) == 49

    run(scenario())


@pytest.mark.redis_integration
def test_real_redis_session_uses_digest_key_fixed_ttl_and_server_only_record(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(bff_settings_factory, namespace="reference-bff:test:redis-session")

    async def scenario() -> None:
        async for store, client in _with_store(settings):
            now = int(time.time())
            record = SessionRecord(
                issuer=settings.cognito_issuer,
                subject="synthetic-subject",
                client_id=settings.client_id,
                user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
                nonce="A" * 43,
                token_family_id="synthetic-token-family",
                access_token="header.payload.signature",
                id_token="header.payload.signature",
                refresh_token="synthetic-refresh-token",
                access_expires_at=now + 900,
                created_at=now,
                last_activity_at=now,
                absolute_expires_at=now + settings.session_absolute_seconds,
            )
            handle = await store.create_session(record)
            key = store.key_for_session_id(handle.session_id)
            stored = await client.get(key)
            assert stored is not None
            assert handle.session_id.encode() not in stored
            assert handle.session_id not in key
            ttl = await client.ttl(key)
            assert 0 < ttl <= handle.max_age == settings.session_idle_seconds
            assert await client.exists(key) == 1

    run(scenario())


@pytest.mark.redis_integration
def test_real_redis_namespace_malformed_record_and_cleanup(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(bff_settings_factory, namespace="reference-bff:test:redis-malformed")

    async def scenario() -> None:
        async for store, client in _with_store(settings):
            state = "A" * 43
            key = store.key_for_state(state)
            await client.set(key, b'{"version":999}', ex=300)
            with pytest.raises(MalformedTransactionError):
                await store.consume(state)
            assert await client.exists(key) == 0
            assert await store.ready() is True

    run(scenario())


@pytest.mark.redis_integration
def test_readiness_fails_closed_for_unavailable_redis_and_recovers_on_real_store(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(bff_settings_factory, namespace="reference-bff:test:redis-readiness")
    unavailable = bff_settings_factory(
        redis_url="redis://127.0.0.1:1/15",
        redis_key_namespace="reference-bff:test:redis-unavailable",
    )

    async def scenario() -> None:
        failed_store = RedisTransactionStore.from_settings(unavailable)
        try:
            assert await failed_store.ready() is False
        finally:
            await failed_store.close()
        async for store, client in _with_store(settings):
            assert await store.ready() is True
            readiness_keys = [
                key
                async for key in client.scan_iter(
                    match=f"{settings.redis_key_namespace}:readiness:*"
                )
            ]
            assert readiness_keys == []

    run(scenario())


@pytest.mark.redis_integration
def test_concurrent_real_redis_readiness_probes_do_not_collide_or_leak(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(
        bff_settings_factory, namespace="reference-bff:test:redis-readiness-concurrency"
    )

    async def scenario() -> None:
        async for store, client in _with_store(settings):
            assert await asyncio.gather(*(store.ready() for _ in range(50))) == [True] * 50
            readiness_keys = [
                key
                async for key in client.scan_iter(
                    match=f"{settings.redis_key_namespace}:readiness:*"
                )
            ]
            assert readiness_keys == []

    run(scenario())


@pytest.mark.redis_integration
def test_failed_getdel_probe_is_bounded_by_short_real_redis_expiry(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(
        bff_settings_factory, namespace="reference-bff:test:redis-readiness-expiry"
    )

    async def scenario() -> None:
        client = Redis.from_url(settings.redis_url.get_secret_value(), decode_responses=False)
        await _delete_namespace(client, settings.redis_key_namespace)
        store = RedisTransactionStore(settings, GetdelDeniedClient(client))
        try:
            assert await client.ping() is True
            assert await store.ready() is False
            readiness_keys = [
                key
                async for key in client.scan_iter(
                    match=f"{settings.redis_key_namespace}:readiness:*"
                )
            ]
            assert len(readiness_keys) == 1
            ttl = await client.ttl(readiness_keys[0])
            assert 0 < ttl <= READINESS_TTL_SECONDS <= 5
            await asyncio.sleep(READINESS_TTL_SECONDS + 0.2)
            assert [
                key
                async for key in client.scan_iter(
                    match=f"{settings.redis_key_namespace}:readiness:*"
                )
            ] == []
        finally:
            await _delete_namespace(client, settings.redis_key_namespace)
            await client.aclose()

    run(scenario())


@pytest.mark.redis_integration
def test_fifty_real_redis_profile_reads_have_one_refresh_one_version_and_no_stale_overwrite(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = redis_settings(
        bff_settings_factory,
        namespace="reference-bff:test:redis-refresh-single-flight",
        refresh_wait_timeout_ms=2000,
        refresh_poll_interval_ms=10,
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
            initial = SessionRecord(
                issuer=settings.cognito_issuer,
                subject=provider.subject,
                client_id=settings.client_id,
                user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
                nonce=transaction.nonce,
                token_family_id=provider.token_family_id,
                access_token=provider.access_token,
                id_token=provider.id_token,
                refresh_token=provider.refresh_token,
                access_expires_at=now + settings.session_refresh_window_seconds,
                created_at=now,
                last_activity_at=now,
                absolute_expires_at=now + settings.session_absolute_seconds,
            )
            handle = await store.create_session(initial)
            stale = await store.load_session(handle.session_id)
            assert stale is not None
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
            )
            try:
                results = await asyncio.gather(*(flow.read(handle.session_id) for _ in range(50)))
                assert len(results) == 50
                assert all(result.etag == '"v1"' for result in results)
                assert all(result.profile["version"] == 1 for result in results)
                assert provider.refresh_requests == 1
                current = await store.load_session(handle.session_id)
                assert current is not None
                assert current.record.refresh_version == 1
                assert current.record.refresh_token == provider.rotated_refresh_token
                assert current.record.created_at == initial.created_at
                assert current.record.absolute_expires_at == initial.absolute_expires_at
                assert await store.cas_session(handle.session_id, stale, stale.record) is False
                preserved = await store.load_session(handle.session_id)
                assert preserved is not None
                assert preserved.record.refresh_version == 1
                assert await client.exists(store.key_for_refresh_lock(handle.session_id, 0)) == 0
                namespace_keys = [
                    key async for key in client.scan_iter(match=f"{settings.redis_key_namespace}:*")
                ]
                assert namespace_keys == [store.key_for_session_id(handle.session_id).encode()]
            finally:
                await flow.close()

    run(scenario())
