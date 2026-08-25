from __future__ import annotations

from reference_bff.config import Settings
from reference_bff.store import TransactionStoreUnavailableError
from reference_bff.transactions import AuthorizationTransaction, new_transaction


class FakeTransactionStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.transactions: list[AuthorizationTransaction] = []
        self.available = True
        self.closed = False

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
        for transaction in self.transactions:
            if transaction.state == state:
                return transaction
        return None

    async def ready(self) -> bool:
        return self.available

    async def close(self) -> None:
        self.closed = True
