"""Callback exchange, verification, bootstrap, and session orchestration."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from reference_bff.auth_diagnostics import TokenFailureCategory
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient, CodeExchangeUnavailableError
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityBootstrapClient, IdentityBootstrapUnavailableError
from reference_bff.jwks import AsyncJwksCache
from reference_bff.sessions import SessionHandle, SessionRecord, new_csrf_token
from reference_bff.store import TransactionStore, TransactionStoreUnavailableError
from reference_bff.tokens import (
    CognitoTokenVerifier,
    InvalidProviderTokenError,
    TokenVerificationUnavailableError,
)
from reference_bff.transactions import AuthorizationTransaction


@dataclass(frozen=True, slots=True)
class CallbackFlowError(Exception):
    status: int
    code: str
    category: TokenFailureCategory | None = None


class CallbackCompleter(Protocol):
    async def complete(self, code: str, transaction: AuthorizationTransaction) -> SessionHandle: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


class CallbackFlow:
    def __init__(
        self,
        *,
        settings: Settings,
        upstream: AsyncUpstreamClient,
        jwks: AsyncJwksCache,
        exchange: AuthorizationCodeClient,
        verifier: CognitoTokenVerifier,
        identity: IdentityBootstrapClient,
        store: TransactionStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._upstream = upstream
        self._jwks = jwks
        self._exchange = exchange
        self._verifier = verifier
        self._identity = identity
        self._store = store
        self._clock = clock

    async def complete(
        self,
        code: str,
        transaction: AuthorizationTransaction,
    ) -> SessionHandle:
        try:
            exchanged = await self._exchange.exchange(code, transaction)
        except CodeExchangeUnavailableError:
            raise CallbackFlowError(503, "authentication_unavailable") from None
        try:
            verified = await self._verifier.verify(
                id_token=exchanged.id_token,
                access_token=exchanged.access_token,
                refresh_token=exchanged.refresh_token,
                expected_nonce=transaction.nonce,
            )
        except InvalidProviderTokenError as error:
            raise CallbackFlowError(400, "authentication_failed", error.category) from None
        except TokenVerificationUnavailableError:
            raise CallbackFlowError(503, "authentication_unavailable") from None
        try:
            profile = await self._identity.bootstrap(verified.access_token)
        except IdentityBootstrapUnavailableError:
            raise CallbackFlowError(503, "identity_unavailable") from None
        now = int(self._clock())
        settings = self._settings
        record = SessionRecord(
            issuer=verified.issuer,
            subject=verified.subject,
            client_id=verified.client_id,
            user_id=profile.user_id,
            nonce=transaction.nonce,
            token_family_id=verified.token_family_id,
            csrf_token=new_csrf_token(),
            access_token=verified.access_token,
            id_token=verified.id_token,
            refresh_token=verified.refresh_token,
            access_expires_at=verified.access_expires_at,
            created_at=now,
            last_activity_at=now,
            absolute_expires_at=now + settings.session_absolute_seconds,
        )
        try:
            return await self._store.create_session(record)
        except TransactionStoreUnavailableError:
            raise CallbackFlowError(503, "session_store_unavailable") from None

    async def ready(self) -> bool:
        return await self._jwks.ready()

    async def close(self) -> None:
        self._jwks.close()
        await self._upstream.close()
