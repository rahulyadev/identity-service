from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator, Callable

import pytest
from redis.asyncio import Redis
from redis.exceptions import ResponseError as RedisResponseError
from reference_bff.config import Settings
from reference_bff.sessions import SessionRecord
from reference_bff.store import READINESS_TTL_SECONDS, RedisTransactionStore
from reference_bff.transactions import MalformedTransactionError


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


def redis_settings(bff_settings_factory: Callable[..., Settings], *, namespace: str) -> Settings:
    url = os.environ["BFF_TEST_REDIS_URL"]
    return bff_settings_factory(redis_url=url, redis_key_namespace=namespace)


class GetdelDeniedClient:
    def __init__(self, client: Redis) -> None:
        self._client = client

    async def set(self, name: str, value: bytes, *, nx: bool, ex: int) -> bool | None:
        result = await self._client.set(name, value, nx=nx, ex=ex)
        return True if result is True else None

    async def getdel(self, name: str) -> bytes | None:
        raise RedisResponseError("synthetic GETDEL denial")

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
                access_token="synthetic-access-token",
                id_token="synthetic-id-token-value",
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
