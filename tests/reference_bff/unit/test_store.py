from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from reference_bff.config import Settings
from reference_bff.sessions import SessionRecord
from reference_bff.store import (
    READINESS_TTL_SECONDS,
    RedisTransactionStore,
    TransactionCollisionError,
    TransactionStoreUnavailableError,
)
from reference_bff.transactions import MalformedTransactionError


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.set_results: list[bool | None] = []
        self.set_calls: list[tuple[str, bytes, bool, int]] = []
        self.getdel_calls: list[str] = []
        self.raise_errors = False
        self.deny_getdel = False
        self.missing_getdel_value = False
        self.wrong_getdel_value = False
        self.closed = False

    async def set(self, name: str, value: bytes, *, nx: bool, ex: int) -> bool | None:
        if self.raise_errors:
            raise RedisConnectionError("synthetic outage")
        self.set_calls.append((name, value, nx, ex))
        result = self.set_results.pop(0) if self.set_results else name not in self.values
        if result:
            self.values[name] = value
        return result

    async def getdel(self, name: str) -> bytes | None:
        if self.raise_errors or self.deny_getdel:
            raise RedisConnectionError("synthetic outage")
        self.getdel_calls.append(name)
        value = self.values.pop(name, None)
        if self.missing_getdel_value:
            return None
        return b"wrong-marker" if self.wrong_getdel_value and value is not None else value

    async def ping(self) -> bool:
        if self.raise_errors:
            raise RedisConnectionError("synthetic outage")
        return True

    async def aclose(self) -> None:
        if self.raise_errors:
            raise RedisConnectionError("synthetic outage")
        self.closed = True


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def session_record(*, now: int = 1_900_000_000) -> SessionRecord:
    return SessionRecord(
        issuer="http://127.0.0.1:9000/test-pool",
        subject="synthetic-subject",
        client_id="synthetic-reference-client",
        user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
        access_token="synthetic-access-token",
        id_token="synthetic-id-token-value",
        refresh_token="synthetic-refresh-token",
        access_expires_at=now + 900,
        created_at=now,
        last_activity_at=now,
        absolute_expires_at=now + 604_800,
    )


def test_create_uses_digest_key_atomic_nx_and_fixed_expiry(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    redis = FakeRedis()
    store = RedisTransactionStore(settings, redis, clock=lambda: 1_900_000_000.0)

    transaction = run(store.create("/profile"))

    assert len(redis.set_calls) == 1
    key, value, nx, expiry = redis.set_calls[0]
    assert nx is True
    assert expiry == 300
    assert transaction.state not in key
    assert key.startswith("reference-bff:test:pytest:oauth-transaction:")
    assert json.loads(value)["state"] == transaction.state
    assert len(value) <= settings.max_transaction_bytes


def test_bounded_collision_recovery_generates_a_fresh_transaction(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    redis.set_results = [None, None, True]
    store = RedisTransactionStore(bff_settings_factory(), redis, clock=lambda: 1_900_000_000.0)

    transaction = run(store.create("/"))

    assert len(redis.set_calls) == 3
    assert len({json.loads(call[1])["state"] for call in redis.set_calls}) == 3
    assert json.loads(redis.set_calls[-1][1])["state"] == transaction.state


def test_collision_budget_is_bounded(bff_settings_factory: Callable[..., Settings]) -> None:
    redis = FakeRedis()
    redis.set_results = [None, None, None, True]
    store = RedisTransactionStore(bff_settings_factory(), redis)
    with pytest.raises(TransactionCollisionError):
        run(store.create("/"))
    assert len(redis.set_calls) == 3


def test_getdel_consumes_exactly_once_without_extending_ttl(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    store = RedisTransactionStore(bff_settings_factory(), redis, clock=lambda: 1_900_000_000.0)
    transaction = run(store.create("/profile"))

    consumed = run(store.consume(transaction.state))
    missing = run(store.consume(transaction.state))

    assert consumed == transaction
    assert missing is None
    assert redis.getdel_calls == [store.key_for_state(transaction.state)] * 2
    assert len(redis.set_calls) == 1


def test_session_uses_independent_opaque_cookie_digest_key_and_bounded_record(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    redis = FakeRedis()
    store = RedisTransactionStore(settings, redis, clock=lambda: 1_900_000_000.0)

    handle = run(store.create_session(session_record()))

    assert len(handle.session_id) == 43
    assert handle.max_age == settings.session_idle_seconds == 43_200
    assert len(redis.set_calls) == 1
    key, serialized, nx, expiry = redis.set_calls[0]
    assert handle.session_id not in key
    assert handle.session_id.encode() not in serialized
    assert key == store.key_for_session_id(handle.session_id)
    assert key.startswith("reference-bff:test:pytest:session:")
    assert nx is True
    assert expiry == handle.max_age
    document = json.loads(serialized)
    assert document["version"] == 1
    assert document["refresh_version"] == 0
    assert document["access_token"] == "synthetic-access-token"
    assert len(serialized) <= settings.max_session_bytes


def test_session_ttl_is_capped_by_absolute_remainder_and_collisions_are_bounded(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    redis.set_results = [None, None, True]
    store = RedisTransactionStore(bff_settings_factory(), redis, clock=lambda: 1_900_000_100.0)
    record = replace(session_record(), absolute_expires_at=1_900_000_250)

    handle = run(store.create_session(record))

    assert len(redis.set_calls) == 3
    assert handle.max_age == 150
    assert {call[3] for call in redis.set_calls} == {150}
    assert len({call[0] for call in redis.set_calls}) == 3


def test_session_storage_outage_and_exhausted_lifetime_fail_closed(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    redis.raise_errors = True
    store = RedisTransactionStore(bff_settings_factory(), redis, clock=lambda: 1_900_000_000.0)
    with pytest.raises(TransactionStoreUnavailableError):
        run(store.create_session(session_record()))
    expired = session_record(now=1_899_000_000)
    available = RedisTransactionStore(
        bff_settings_factory(), FakeRedis(), clock=lambda: 1_900_000_000.0
    )
    with pytest.raises(TransactionStoreUnavailableError):
        run(available.create_session(expired))


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b'{"version":2}',
        b"[]",
        b'"type-confused"',
        b"\xff",
    ],
)
def test_malformed_records_are_rejected_after_one_time_removal(
    bff_settings_factory: Callable[..., Settings], payload: bytes
) -> None:
    redis = FakeRedis()
    store = RedisTransactionStore(bff_settings_factory(), redis)
    state = "A" * 43
    key = store.key_for_state(state)
    redis.values[key] = payload

    with pytest.raises(MalformedTransactionError):
        run(store.consume(state))
    assert key not in redis.values
    assert run(store.consume(state)) is None


def test_oversized_record_is_consumed_then_rejected(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory(max_transaction_bytes=1024)
    redis = FakeRedis()
    store = RedisTransactionStore(settings, redis)
    state = "A" * 43
    key = store.key_for_state(state)
    redis.values[key] = b"x" * 1025
    with pytest.raises(MalformedTransactionError):
        run(store.consume(state))
    assert key not in redis.values


def test_namespace_isolation_changes_the_derived_key(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    state = "A" * 43
    first = RedisTransactionStore(bff_settings_factory(), FakeRedis())
    second = RedisTransactionStore(
        bff_settings_factory(redis_key_namespace="reference-bff:test:other"), FakeRedis()
    )
    assert first.key_for_state(state) != second.key_for_state(state)


def test_outage_fails_closed_for_create_consume_and_readiness(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    redis.raise_errors = True
    store = RedisTransactionStore(bff_settings_factory(), redis)
    with pytest.raises(TransactionStoreUnavailableError):
        run(store.create("/"))
    with pytest.raises(TransactionStoreUnavailableError):
        run(store.consume("A" * 43))
    assert run(store.ready()) is False


def test_readiness_uses_unique_dedicated_set_nx_ex_getdel_probe(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    store = RedisTransactionStore(bff_settings_factory(), redis)

    assert run(store.ready()) is True
    assert run(store.ready()) is True

    assert len(redis.set_calls) == 4
    assert len(redis.getdel_calls) == 4
    assert {call[0] for call in redis.set_calls} == set(redis.getdel_calls)
    assert len({call[0] for call in redis.set_calls}) == 4
    assert all(":readiness:" in call[0] for call in redis.set_calls)
    assert all(":oauth-transaction:" not in call[0] for call in redis.set_calls)
    assert sum(call[0].endswith(":oauth-transaction") for call in redis.set_calls) == 2
    assert sum(call[0].endswith(":session") for call in redis.set_calls) == 2
    assert all(call[2] is True and call[3] == READINESS_TTL_SECONDS for call in redis.set_calls)
    assert redis.values == {}


def test_ping_success_does_not_mask_denied_set_or_getdel(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    denied_set = FakeRedis()
    denied_set.set_results = [None]
    assert run(denied_set.ping()) is True
    assert run(RedisTransactionStore(bff_settings_factory(), denied_set).ready()) is False
    assert denied_set.getdel_calls == []

    denied_getdel = FakeRedis()
    denied_getdel.deny_getdel = True
    assert run(denied_getdel.ping()) is True
    assert run(RedisTransactionStore(bff_settings_factory(), denied_getdel).ready()) is False
    assert len(denied_getdel.set_calls) == 1
    assert denied_getdel.set_calls[0][3] == READINESS_TTL_SECONDS


def test_readiness_rejects_missing_or_wrong_consumed_marker(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    missing = FakeRedis()
    missing.missing_getdel_value = True
    assert run(RedisTransactionStore(bff_settings_factory(), missing).ready()) is False

    wrong = FakeRedis()
    wrong.wrong_getdel_value = True
    assert run(RedisTransactionStore(bff_settings_factory(), wrong).ready()) is False
    assert wrong.values == {}


def test_invalid_state_never_reaches_redis_and_pool_closes(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    store = RedisTransactionStore(bff_settings_factory(), redis)
    assert run(store.consume("invalid state")) is None
    assert redis.getdel_calls == []
    run(store.close())
    assert redis.closed


def test_pool_close_failure_is_safely_bounded(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    redis = FakeRedis()
    redis.raise_errors = True
    store = RedisTransactionStore(bff_settings_factory(), redis)
    assert run(store.close()) is None
