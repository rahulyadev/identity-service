from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest
from reference_bff.config import Settings
from reference_bff.exchange import AuthorizationCodeClient
from reference_bff.flow import CallbackFlow, CallbackFlowError
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import IdentityBootstrapClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.sessions import is_canonical_session_id
from reference_bff.tokens import CognitoTokenVerifier
from reference_bff.transactions import AuthorizationTransaction, new_transaction

from tests.reference_bff.fakes import FakeTransactionStore
from tests.reference_bff.provider import SyntheticProvider


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def configured(
    bff_settings_factory: Callable[..., Settings],
) -> tuple[
    Settings, AuthorizationTransaction, SyntheticProvider, FakeTransactionStore, CallbackFlow
]:
    settings = bff_settings_factory()
    transaction = new_transaction(
        return_to="/profile?tab=security",
        callback_uri=settings.callback_uri,
        ttl_seconds=settings.oauth_transaction_ttl_seconds,
    )
    provider = SyntheticProvider(settings)
    provider.configure(transaction)
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(provider.handle))
    upstream = AsyncUpstreamClient(settings, transport=transport)
    jwks = AsyncJwksCache(settings, upstream)
    store = FakeTransactionStore(settings)
    flow = CallbackFlow(
        settings=settings,
        upstream=upstream,
        jwks=jwks,
        exchange=AuthorizationCodeClient(settings, upstream),
        verifier=CognitoTokenVerifier(settings, jwks),
        identity=IdentityBootstrapClient(settings, upstream),
        store=store,
    )
    return settings, transaction, provider, store, flow


@pytest.mark.parametrize("bootstrap_status", [200, 201])
def test_complete_flow_bootstraps_before_storing_bounded_session(
    bff_settings_factory: Callable[..., Settings], bootstrap_status: int
) -> None:
    settings, transaction, provider, store, flow = configured(bff_settings_factory)
    provider.identity_status = bootstrap_status

    async def scenario() -> None:
        handle = await flow.complete(provider.code, transaction)
        assert handle.max_age == settings.session_idle_seconds
        assert len(handle.session_id) == 43
        assert await flow.ready() is True
        await flow.close()

    run(scenario())
    assert provider.events[:3] == ["token", "jwks", "identity"]
    assert len(store.session_records) == 1
    record = store.session_records[0]
    assert record.issuer == settings.cognito_issuer
    assert record.subject == provider.subject
    assert record.client_id == settings.client_id
    assert record.user_id == "1526af3c-c76a-4e01-a507-347205fb3c93"
    assert record.access_token == provider.access_token
    assert record.id_token == provider.id_token
    assert record.refresh_token == provider.refresh_token
    assert is_canonical_session_id(record.csrf_token)
    assert record.csrf_token not in {
        record.nonce,
        record.token_family_id,
        store.session_handles[0].session_id,
        transaction.transaction_id,
        transaction.state,
    }
    assert record.refresh_version == 0
    assert record.last_activity_at == record.created_at
    assert record.absolute_expires_at - record.created_at == settings.session_absolute_seconds
    rendered = repr(record)
    assert provider.subject not in rendered
    assert provider.access_token not in rendered
    assert provider.refresh_token not in rendered
    assert record.csrf_token not in rendered


@pytest.mark.parametrize(
    ("failure", "status", "code", "events"),
    [
        ("token", 503, "authentication_unavailable", ["token"]),
        ("jwks", 503, "authentication_unavailable", ["token", "jwks"]),
        ("identity", 503, "identity_unavailable", ["token", "jwks", "identity"]),
        ("signature", 400, "authentication_failed", ["token", "jwks"]),
        ("session", 503, "session_store_unavailable", ["token", "jwks", "identity"]),
    ],
)
def test_every_failure_before_session_issuance_is_fixed_and_cookie_safe(
    bff_settings_factory: Callable[..., Settings],
    failure: str,
    status: int,
    code: str,
    events: list[str],
) -> None:
    _settings, transaction, provider, store, flow = configured(bff_settings_factory)
    if failure == "token":
        provider.token_status = 503
    elif failure == "jwks":
        provider.jwks_status = 503
    elif failure == "identity":
        provider.identity_status = 503
    elif failure == "signature":
        provider.access_token = provider.access_token.rsplit(".", maxsplit=1)[0] + "." + "A" * 342
    else:
        store.available = False

    async def scenario() -> None:
        with pytest.raises(CallbackFlowError) as captured:
            await flow.complete(provider.code, transaction)
        assert captured.value.status == status
        assert captured.value.code == code
        assert provider.access_token not in str(captured.value)
        await flow.close()

    run(scenario())
    assert provider.events == events
    assert store.session_records == []


def test_invalid_provider_signature_never_reaches_identity_or_redis(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    _settings, transaction, provider, store, flow = configured(bff_settings_factory)
    provider.access_token = provider.access_token.rsplit(".", maxsplit=1)[0] + "." + "B" * 342

    async def scenario() -> None:
        with pytest.raises(CallbackFlowError) as captured:
            await flow.complete(provider.code, transaction)
        assert captured.value.code == "authentication_failed"
        await flow.close()

    run(scenario())
    assert provider.events == ["token", "jwks"]
    assert store.session_records == []
