from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable

import pytest
from redis.asyncio import Redis
from reference_bff.config import Settings
from reference_bff.store import RedisTransactionStore
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
        async for store, _client in _with_store(settings):
            assert await store.ready() is True

    run(scenario())
