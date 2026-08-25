"""Atomic Redis-backed storage for one-time OAuth authorization transactions."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from typing import Protocol, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

from reference_bff.config import Settings
from reference_bff.transactions import (
    OPAQUE_TOKEN,
    AuthorizationTransaction,
    MalformedTransactionError,
    new_transaction,
    parse_consumed_transaction,
)

MAX_COLLISION_ATTEMPTS = 3


class TransactionStoreUnavailableError(RuntimeError):
    """Redis could not safely complete the requested operation."""


class TransactionCollisionError(TransactionStoreUnavailableError):
    """The bounded state-collision budget was exhausted."""


class RedisClient(Protocol):
    async def set(self, name: str, value: bytes, *, nx: bool, ex: int) -> bool | None: ...

    async def getdel(self, name: str) -> bytes | None: ...

    async def ping(self) -> bool: ...

    async def aclose(self) -> None: ...


class TransactionStore(Protocol):
    async def create(self, return_to: str) -> AuthorizationTransaction: ...

    async def consume(self, state: str) -> AuthorizationTransaction | None: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


class RedisTransactionStore:
    """Use SET NX EX and GETDEL so every record has one fixed lifetime and consumer."""

    def __init__(
        self,
        settings: Settings,
        client: RedisClient,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._client = client
        self._clock = clock

    @classmethod
    def from_settings(cls, settings: Settings) -> RedisTransactionStore:
        client = Redis.from_url(
            settings.redis_url.get_secret_value(),
            decode_responses=False,
            max_connections=8,
            retry_on_timeout=False,
            socket_connect_timeout=settings.redis_connect_timeout_seconds,
            socket_timeout=settings.redis_operation_timeout_seconds,
        )
        return cls(settings, cast(RedisClient, client))

    def key_for_state(self, state: str) -> str:
        digest = hashlib.sha256(
            f"{self._settings.redis_key_namespace}\x00{state}".encode()
        ).hexdigest()
        return f"{self._settings.redis_key_namespace}:oauth-transaction:{digest}"

    async def create(self, return_to: str) -> AuthorizationTransaction:
        for _ in range(MAX_COLLISION_ATTEMPTS):
            transaction = new_transaction(
                return_to=return_to,
                callback_uri=self._settings.callback_uri,
                ttl_seconds=self._settings.oauth_transaction_ttl_seconds,
                now=int(self._clock()),
            )
            serialized = transaction.as_json_bytes()
            if len(serialized) > self._settings.max_transaction_bytes:
                raise MalformedTransactionError("transaction is too large")
            try:
                async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                    created = await self._client.set(
                        self.key_for_state(transaction.state),
                        serialized,
                        nx=True,
                        ex=self._settings.oauth_transaction_ttl_seconds,
                    )
            except RedisError, TimeoutError, OSError:
                raise TransactionStoreUnavailableError("transaction storage unavailable") from None
            if created is True:
                return transaction
        raise TransactionCollisionError("transaction storage unavailable")

    async def consume(self, state: str) -> AuthorizationTransaction | None:
        if OPAQUE_TOKEN.fullmatch(state) is None:
            return None
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                serialized = await self._client.getdel(self.key_for_state(state))
        except RedisError, TimeoutError, OSError:
            raise TransactionStoreUnavailableError("transaction storage unavailable") from None
        if serialized is None:
            return None
        if type(serialized) is not bytes or len(serialized) > self._settings.max_transaction_bytes:
            raise MalformedTransactionError("malformed transaction")
        return parse_consumed_transaction(
            serialized,
            expected_state=state,
            expected_callback_uri=self._settings.callback_uri,
            expected_ttl_seconds=self._settings.oauth_transaction_ttl_seconds,
            now=int(self._clock()),
        )

    async def ready(self) -> bool:
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                return await self._client.ping() is True
        except RedisError, TimeoutError, OSError:
            return False

    async def close(self) -> None:
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                await self._client.aclose()
        except RedisError, TimeoutError, OSError:
            return
