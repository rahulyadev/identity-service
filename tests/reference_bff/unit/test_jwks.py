from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from reference_bff.config import Settings
from reference_bff.http import AsyncUpstreamClient
from reference_bff.jwks import (
    AsyncJwksCache,
    InvalidSigningKeyError,
    JwksUnavailableError,
)

from tests.reference_bff.provider import SyntheticProvider


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def upstream(
    settings: Settings, handler: Callable[[httpx2.Request], httpx2.Response]
) -> AsyncUpstreamClient:
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(handler))
    return AsyncUpstreamClient(settings, transport=transport)


def test_readiness_and_twenty_concurrent_key_reads_use_one_jwks_fetch(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    provider = SyntheticProvider(settings)
    client = upstream(settings, provider.handle)
    cache = AsyncJwksCache(settings, client)

    async def scenario() -> None:
        assert await asyncio.gather(*(cache.ready() for _ in range(20))) == [True] * 20
        keys = await asyncio.gather(*(cache.get_key(provider.key_id) for _ in range(20)))
        assert all(key.key.key_size == 2048 for key in keys)
        await client.close()

    run(scenario())
    assert provider.events == ["jwks"]


@pytest.mark.parametrize("mode", ["private", "weak", "wrong_alg", "duplicate", "duplicate_json"])
def test_jwks_rejects_private_weak_incompatible_duplicate_and_ambiguous_keys(
    bff_settings_factory: Callable[..., Settings], mode: str
) -> None:
    settings = bff_settings_factory()
    provider = SyntheticProvider(settings)
    document: dict[str, Any] = {"keys": [provider.public_jwk()]}
    raw: bytes | None = None
    if mode == "private":
        document["keys"][0]["d"] = "private-material"
    elif mode == "weak":
        provider.private_key = rsa.generate_private_key(65537, 1024)
        document = {"keys": [provider.public_jwk()]}
    elif mode == "wrong_alg":
        document["keys"][0]["alg"] = "RS512"
    elif mode == "duplicate":
        document["keys"].append(dict(document["keys"][0]))
    else:
        raw = b'{"keys":[],"keys":[]}'

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            request=request,
            headers={"Content-Type": "application/jwk-set+json"},
            content=raw if raw is not None else json.dumps(document).encode(),
        )

    client = upstream(settings, handler)
    cache = AsyncJwksCache(settings, client)

    async def scenario() -> None:
        assert await cache.ready() is False
        with pytest.raises(JwksUnavailableError):
            await cache.get_key(provider.key_id)
        await client.close()

    run(scenario())


def test_unknown_key_refresh_is_bounded_and_negative_cached(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory(jwks_refresh_min_interval_seconds=10)
    provider = SyntheticProvider(settings)
    client = upstream(settings, provider.handle)
    cache = AsyncJwksCache(settings, client)

    async def scenario() -> None:
        assert await cache.get_key(provider.key_id)
        with pytest.raises(InvalidSigningKeyError):
            await cache.get_key("unknown-key")
        with pytest.raises(InvalidSigningKeyError):
            await cache.get_key("unknown-key")
        await client.close()

    run(scenario())
    assert provider.events == ["jwks", "jwks"]


def test_rotation_refreshes_once_and_publishes_new_immutable_snapshot(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory(jwks_refresh_min_interval_seconds=1)
    provider = SyntheticProvider(settings)
    client = upstream(settings, provider.handle)
    cache = AsyncJwksCache(settings, client)

    async def scenario() -> None:
        original = await cache.get_key(provider.key_id)
        provider.private_key = rsa.generate_private_key(65537, 2048)
        provider.key_id = "synthetic-key-2"
        rotated = await cache.get_key(provider.key_id)
        assert original.key != rotated.key
        assert cache.snapshot is not None
        assert set(cache.snapshot.keys) == {"synthetic-key-2"}
        await client.close()

    run(scenario())
    assert provider.events == ["jwks", "jwks"]


def test_known_key_uses_bounded_stale_if_error_but_hard_stale_and_unknown_fail_closed(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory(
        jwks_cache_max_age_seconds=1,
        jwks_stale_if_error_seconds=5,
        jwks_refresh_min_interval_seconds=1,
    )
    provider = SyntheticProvider(settings)
    now = [100.0]
    available = [True]

    def handler(request: httpx2.Request) -> httpx2.Response:
        if not available[0]:
            raise httpx2.ConnectError("synthetic outage", request=request)
        return provider.handle(request)

    client = upstream(settings, handler)
    cache = AsyncJwksCache(settings, client, monotonic=lambda: now[0])

    async def scenario() -> None:
        known = await cache.get_key(provider.key_id)
        now[0] = 102.0
        available[0] = False
        assert await cache.get_key(provider.key_id) is known
        with pytest.raises(JwksUnavailableError):
            await cache.get_key("unknown-key")
        now[0] = 110.0
        with pytest.raises(JwksUnavailableError):
            await cache.get_key(provider.key_id)
        assert await cache.ready() is False
        await client.close()

    run(scenario())
