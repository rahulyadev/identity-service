from __future__ import annotations

from reference_bff.config import Settings
from reference_bff.flow import CallbackFlowError
from reference_bff.sessions import SessionHandle, SessionRecord, opaque_session_id
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
        return handle

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
