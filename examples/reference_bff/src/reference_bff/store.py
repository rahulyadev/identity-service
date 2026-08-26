"""Atomic Redis storage for OAuth transactions and opaque browser sessions."""

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
from reference_bff.sessions import (
    InvalidSessionRecordError,
    SessionHandle,
    SessionRecord,
    StoredSession,
    is_canonical_session_id,
    opaque_session_id,
    parse_session_record,
    session_max_age,
)
from reference_bff.transactions import (
    OPAQUE_TOKEN,
    AuthorizationTransaction,
    MalformedTransactionError,
    new_transaction,
    parse_consumed_transaction,
)

MAX_COLLISION_ATTEMPTS = 3
MAX_CAS_ATTEMPTS = 3
READINESS_TTL_SECONDS = 2

CAS_SESSION_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if not current then return 0 end
if current ~= ARGV[1] then return -1 end
local changed = redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3], 'XX')
if not changed then return 0 end
return 1
"""
DELETE_IF_EQUAL_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if not current then return 0 end
if current ~= ARGV[1] then return -1 end
return redis.call('DEL', KEYS[1])
"""
RELEASE_LOCK_SCRIPT = DELETE_IF_EQUAL_SCRIPT


class TransactionStoreUnavailableError(RuntimeError):
    """Redis could not safely complete the requested operation."""


class TransactionCollisionError(TransactionStoreUnavailableError):
    """The bounded random-identifier collision budget was exhausted."""


class RedisClient(Protocol):
    async def set(self, name: str, value: bytes, *, nx: bool, ex: int) -> bool | None: ...

    async def get(self, name: str) -> bytes | None: ...

    async def getdel(self, name: str) -> bytes | None: ...

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> object: ...

    async def aclose(self) -> None: ...


class TransactionStore(Protocol):
    async def create(self, return_to: str) -> AuthorizationTransaction: ...

    async def consume(self, state: str) -> AuthorizationTransaction | None: ...

    async def create_session(self, record: SessionRecord) -> SessionHandle: ...

    async def load_session(self, session_id: str) -> StoredSession | None: ...

    async def cas_session(
        self, session_id: str, expected: StoredSession, replacement: SessionRecord
    ) -> bool: ...

    async def invalidate_session(self, session_id: str, expected: StoredSession) -> bool: ...

    async def acquire_refresh_lock(
        self, session_id: str, refresh_version: int, owner: str
    ) -> bool: ...

    async def release_refresh_lock(
        self, session_id: str, refresh_version: int, owner: str
    ) -> bool: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


class RedisTransactionStore:
    """Keep keys one-way and every state transition atomic and expiry-bounded."""

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
            max_connections=64,
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

    def _readiness_key(self, probe_id: str, operation: str) -> str:
        return f"{self._settings.redis_key_namespace}:readiness:{probe_id}:{operation}"

    def key_for_session_id(self, session_id: str) -> str:
        digest = hashlib.sha256(
            f"{self._settings.redis_key_namespace}\x00session\x00{session_id}".encode()
        ).hexdigest()
        return f"{self._settings.redis_key_namespace}:session:{digest}"

    def key_for_refresh_lock(self, session_id: str, refresh_version: int) -> str:
        digest = hashlib.sha256(
            (
                f"{self._settings.redis_key_namespace}\x00refresh-lock\x00"
                f"{session_id}\x00{refresh_version}"
            ).encode()
        ).hexdigest()
        return f"{self._settings.redis_key_namespace}:refresh-lock:{digest}"

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
        max_age = session_max_age(record, self._settings, now=now)
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

    async def load_session(self, session_id: str) -> StoredSession | None:
        if not is_canonical_session_id(session_id):
            return None
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                serialized = await self._client.get(self.key_for_session_id(session_id))
        except RedisError, TimeoutError, OSError:
            raise TransactionStoreUnavailableError("session storage unavailable") from None
        if serialized is None:
            return None
        if type(serialized) is not bytes:
            raise InvalidSessionRecordError("invalid session document")
        return parse_session_record(serialized, self._settings, now=int(self._clock()))

    async def cas_session(
        self,
        session_id: str,
        expected: StoredSession,
        replacement: SessionRecord,
    ) -> bool:
        serialized = replacement.as_json_bytes()
        now = int(self._clock())
        max_age = session_max_age(replacement, self._settings, now=now)
        if len(serialized) > self._settings.max_session_bytes or max_age <= 0:
            raise TransactionStoreUnavailableError("session lifetime is exhausted")
        result = await self._eval(
            CAS_SESSION_SCRIPT,
            self.key_for_session_id(session_id),
            expected.serialized,
            serialized,
            max_age,
        )
        if type(result) is not int or result not in {-1, 0, 1}:
            raise TransactionStoreUnavailableError("session storage unavailable")
        return result == 1

    async def invalidate_session(self, session_id: str, expected: StoredSession) -> bool:
        result = await self._eval(
            DELETE_IF_EQUAL_SCRIPT,
            self.key_for_session_id(session_id),
            expected.serialized,
        )
        if type(result) is not int or result not in {-1, 0, 1}:
            raise TransactionStoreUnavailableError("session storage unavailable")
        return result == 1

    async def acquire_refresh_lock(self, session_id: str, refresh_version: int, owner: str) -> bool:
        if not is_canonical_session_id(session_id) or not is_canonical_session_id(owner):
            raise TransactionStoreUnavailableError("refresh coordination unavailable")
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                created = await self._client.set(
                    self.key_for_refresh_lock(session_id, refresh_version),
                    owner.encode("ascii"),
                    nx=True,
                    ex=self._settings.refresh_lock_lease_seconds,
                )
        except RedisError, TimeoutError, OSError:
            raise TransactionStoreUnavailableError("refresh coordination unavailable") from None
        if created not in {True, None, False}:
            raise TransactionStoreUnavailableError("refresh coordination unavailable")
        return created is True

    async def release_refresh_lock(self, session_id: str, refresh_version: int, owner: str) -> bool:
        result = await self._eval(
            RELEASE_LOCK_SCRIPT,
            self.key_for_refresh_lock(session_id, refresh_version),
            owner.encode("ascii"),
        )
        if type(result) is not int or result not in {-1, 0, 1}:
            raise TransactionStoreUnavailableError("refresh coordination unavailable")
        return result == 1

    async def _eval(self, script: str, key: str, *arguments: object) -> object:
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                return await self._client.eval(script, 1, key, *arguments)
        except RedisError, TimeoutError, OSError:
            raise TransactionStoreUnavailableError("session storage unavailable") from None

    async def ready(self) -> bool:
        try:
            return (
                await self._transaction_readiness_probe()
                and await self._session_readiness_probe()
                and await self._refresh_lock_readiness_probe()
            )
        except RedisError, TimeoutError, OSError, TransactionStoreUnavailableError:
            return False

    async def _transaction_readiness_probe(self) -> bool:
        probe_id = secrets.token_hex(32)
        marker = secrets.token_bytes(32)
        key = self._readiness_key(probe_id, "oauth-transaction")
        async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
            created = await self._client.set(key, marker, nx=True, ex=READINESS_TTL_SECONDS)
            if created is not True:
                return False
            consumed = await self._client.getdel(key)
        return type(consumed) is bytes and hmac.compare_digest(consumed, marker)

    async def _session_readiness_probe(self) -> bool:
        probe_id = secrets.token_hex(32)
        first = secrets.token_bytes(32)
        second = secrets.token_bytes(32)
        key = self._readiness_key(probe_id, "session-cas")
        async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
            if await self._client.set(key, first, nx=True, ex=READINESS_TTL_SECONDS) is not True:
                return False
            loaded = await self._client.get(key)
            if type(loaded) is not bytes or not hmac.compare_digest(loaded, first):
                return False
            replaced = await self._client.eval(
                CAS_SESSION_SCRIPT, 1, key, first, second, READINESS_TTL_SECONDS
            )
            if replaced != 1:
                return False
            stale = await self._client.eval(
                CAS_SESSION_SCRIPT, 1, key, first, secrets.token_bytes(32), READINESS_TTL_SECONDS
            )
            if stale != -1:
                return False
            loaded = await self._client.get(key)
            if type(loaded) is not bytes or not hmac.compare_digest(loaded, second):
                return False
            deleted = await self._client.eval(DELETE_IF_EQUAL_SCRIPT, 1, key, second)
            return deleted == 1 and await self._client.get(key) is None

    async def _refresh_lock_readiness_probe(self) -> bool:
        probe_id = secrets.token_hex(32)
        owner = secrets.token_bytes(32)
        other = secrets.token_bytes(32)
        key = self._readiness_key(probe_id, "refresh-lock")
        async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
            if await self._client.set(key, owner, nx=True, ex=READINESS_TTL_SECONDS) is not True:
                return False
            if await self._client.set(key, other, nx=True, ex=READINESS_TTL_SECONDS) is not None:
                return False
            if await self._client.eval(RELEASE_LOCK_SCRIPT, 1, key, other) != -1:
                return False
            loaded = await self._client.get(key)
            if type(loaded) is not bytes or not hmac.compare_digest(loaded, owner):
                return False
            released = await self._client.eval(RELEASE_LOCK_SCRIPT, 1, key, owner)
            return released == 1 and await self._client.get(key) is None

    async def close(self) -> None:
        try:
            async with asyncio.timeout(self._settings.redis_operation_timeout_seconds):
                await self._client.aclose()
        except RedisError, TimeoutError, OSError:
            return
