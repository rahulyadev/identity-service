"""Atomic Redis-backed storage for one-time OAuth authorization transactions."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from typing import Protocol, cast

from redis.asyncio import Redis
from redis.exceptions import RedisError

from reference_bff.config import Settings
from reference_bff.sessions import SessionHandle, SessionRecord, opaque_session_id
from reference_bff.transactions import (
    OPAQUE_TOKEN,
    AuthorizationTransaction,
    MalformedTransactionError,
    new_transaction,
    parse_consumed_transaction,
)

MAX_COLLISION_ATTEMPTS = 3
READINESS_TTL_SECONDS = 2


class TransactionStoreUnavailableError(RuntimeError):
    """Redis could not safely complete the requested operation."""


class TransactionCollisionError(TransactionStoreUnavailableError):
    """The bounded state-collision budget was exhausted."""


class RedisClient(Protocol):
    async def set(self, name: str, value: bytes, *, nx: bool, ex: int) -> bool | None: ...

    async def getdel(self, name: str) -> bytes | None: ...

    async def aclose(self) -> None: ...


class TransactionStore(Protocol):
    async def create(self, return_to: str) -> AuthorizationTransaction: ...

    async def consume(self, state: str) -> AuthorizationTransaction | None: ...

    async def create_session(self, record: SessionRecord) -> SessionHandle: ...

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

    def _readiness_key(self, probe_id: str) -> str:
        return f"{self._settings.redis_key_namespace}:readiness:{probe_id}"

    def key_for_session_id(self, session_id: str) -> str:
        digest = hashlib.sha256(
            f"{self._settings.redis_key_namespace}\x00session\x00{session_id}".encode()
        ).hexdigest()
        return f"{self._settings.redis_key_namespace}:session:{digest}"

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

    async def create_session(self, record: SessionRecord) -> SessionHandle:
        serialized = record.as_json_bytes()
        if len(serialized) > self._settings.max_session_bytes:
            raise TransactionStoreUnavailableError("session record is too large")
        now = int(self._clock())
        max_age = min(
            self._settings.session_idle_seconds,
            record.absolute_expires_at - now,
        )
        if max_age <= 0:
            raise TransactionStoreUnavailableError("session lifetime is exhausted")
        for _ in range(MAX_COLLISION_ATTEMPTS):
            session_id = opaque_session_id()
            try:
                async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                    created = await self._client.set(
                        self.key_for_session_id(session_id),
                        serialized,
                        nx=True,
                        ex=max_age,
                    )
            except RedisError, TimeoutError, OSError:
                raise TransactionStoreUnavailableError("session storage unavailable") from None
            if created is True:
                return SessionHandle(session_id=session_id, max_age=max_age)
        raise TransactionCollisionError("session storage unavailable")

    async def ready(self) -> bool:
        for operation in ("oauth-transaction", "session"):
            probe_id = secrets.token_hex(32)
            marker = secrets.token_bytes(32)
            key = f"{self._readiness_key(probe_id)}:{operation}"
            try:
                async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                    created = await self._client.set(
                        key,
                        marker,
                        nx=True,
                        ex=READINESS_TTL_SECONDS,
                    )
                    if created is not True:
                        return False
                    consumed = await self._client.getdel(key)
            except RedisError, TimeoutError, OSError:
                return False
            if type(consumed) is not bytes or not hmac.compare_digest(consumed, marker):
                return False
        return True

    async def close(self) -> None:
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                await self._client.aclose()
        except RedisError, TimeoutError, OSError:
            return
