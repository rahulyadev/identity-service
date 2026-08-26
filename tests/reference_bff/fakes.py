from __future__ import annotations

from reference_bff.config import Settings
from reference_bff.flow import CallbackFlowError
from reference_bff.session_flow import SessionReadError, SessionReadResult
from reference_bff.sessions import SessionHandle, SessionRecord, StoredSession, opaque_session_id
from reference_bff.store import TransactionStoreUnavailableError
from reference_bff.transactions import AuthorizationTransaction, new_transaction


class FakeTransactionStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.transactions: list[AuthorizationTransaction] = []
        self.available = True
        self.closed = False
        self.session_records: list[SessionRecord] = []
        self.session_handles: list[SessionHandle] = []
        self.consume_failure: Exception | None = None
        self.stored_sessions: dict[str, StoredSession] = {}
        self.refresh_locks: dict[tuple[str, int], str] = {}

    async def create(self, return_to: str) -> AuthorizationTransaction:
        if not self.available:
            raise TransactionStoreUnavailableError("unavailable")
        transaction = new_transaction(
            return_to=return_to,
            callback_uri=self.settings.callback_uri,
            ttl_seconds=self.settings.oauth_transaction_ttl_seconds,
            now=1_900_000_000,
        )
        self.transactions.append(transaction)
        return transaction

    async def consume(self, state: str) -> AuthorizationTransaction | None:
        for index, transaction in enumerate(self.transactions):
            if transaction.state == state:
                consumed = self.transactions.pop(index)
                if self.consume_failure is not None:
                    raise self.consume_failure
                return consumed
        return None

    async def create_session(self, record: SessionRecord) -> SessionHandle:
        if not self.available:
            raise TransactionStoreUnavailableError("unavailable")
        handle = SessionHandle(session_id=opaque_session_id(), max_age=43_200)
        self.session_records.append(record)
        self.session_handles.append(handle)
        self.stored_sessions[handle.session_id] = StoredSession.from_record(record)
        return handle

    async def load_session(self, session_id: str) -> StoredSession | None:
        if not self.available:
            raise TransactionStoreUnavailableError("unavailable")
        return self.stored_sessions.get(session_id)

    async def cas_session(
        self, session_id: str, expected: StoredSession, replacement: SessionRecord
    ) -> bool:
        if not self.available:
            raise TransactionStoreUnavailableError("unavailable")
        current = self.stored_sessions.get(session_id)
        if current is None or current.serialized != expected.serialized:
            return False
        self.stored_sessions[session_id] = StoredSession.from_record(replacement)
        return True

    async def invalidate_session(self, session_id: str, expected: StoredSession) -> bool:
        if not self.available:
            raise TransactionStoreUnavailableError("unavailable")
        current = self.stored_sessions.get(session_id)
        if current is None or current.serialized != expected.serialized:
            return False
        del self.stored_sessions[session_id]
        return True

    async def acquire_refresh_lock(self, session_id: str, refresh_version: int, owner: str) -> bool:
        if not self.available:
            raise TransactionStoreUnavailableError("unavailable")
        key = (session_id, refresh_version)
        if key in self.refresh_locks:
            return False
        self.refresh_locks[key] = owner
        return True

    async def release_refresh_lock(self, session_id: str, refresh_version: int, owner: str) -> bool:
        key = (session_id, refresh_version)
        if self.refresh_locks.get(key) != owner:
            return False
        del self.refresh_locks[key]
        return True

    async def ready(self) -> bool:
        return self.available

    async def close(self) -> None:
        self.closed = True


class FakeCallbackService:
    def __init__(self) -> None:
        self.available = True
        self.closed = False
        self.calls: list[tuple[str, AuthorizationTransaction]] = []
        self.handle = SessionHandle(session_id=opaque_session_id(), max_age=43_200)
        self.failure: CallbackFlowError | None = None

    async def complete(self, code: str, transaction: AuthorizationTransaction) -> SessionHandle:
        self.calls.append((code, transaction))
        if self.failure is not None:
            raise self.failure
        return self.handle

    async def ready(self) -> bool:
        return self.available

    async def close(self) -> None:
        self.closed = True


class FakeSessionReader:
    def __init__(self) -> None:
        now = "2026-08-25T00:00:00+00:00"
        self.result = SessionReadResult(
            profile={
                "user_id": "1526af3c-c76a-4e01-a507-347205fb3c93",
                "email": "synthetic@example.invalid",
                "email_verified": True,
                "display_name": None,
                "avatar_url": None,
                "version": 1,
                "created_at": now,
                "updated_at": now,
            },
            etag='"v1"',
            max_age=43_200,
        )
        self.failure: SessionReadError | None = None
        self.calls: list[str] = []
        self.available = True
        self.closed = False

    async def read(self, session_id: str) -> SessionReadResult:
        self.calls.append(session_id)
        if self.failure is not None:
            raise self.failure
        return self.result

    async def ready(self) -> bool:
        return self.available

    async def close(self) -> None:
        self.closed = True
